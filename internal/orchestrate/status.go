package orchestrate

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// DatabaseSize is one database engine instance's own size breakdown —
// a single postgres/mariadb container can itself hold several
// distinct databases/schemas, each sized separately, since "the mysql
// container is 400GB" is far less useful than knowing which of its
// three schemas actually accounts for that.
type DatabaseSize struct {
	Container string           `json:"container"`
	Kind      string           `json:"kind"`
	Databases map[string]int64 `json:"databases"`
}

// StatusReport is a read-only snapshot of one server's backup
// state — what's in the repo, when it was last touched, and how big
// it is. Unlike Backup/Verify, an unonboarded server isn't an error
// here: RepoInitialized false with everything else zero is itself a
// valid, useful answer ("nothing to show yet"), not a failure.
type StatusReport struct {
	ServerID        string `json:"server_id"`
	RepoInitialized bool   `json:"repo_initialized"`
	// AppendOnlyLifted mirrors state.ProviderState's own field of the
	// same name: true means a prior onboard run was killed between
	// temporarily lifting the automation key's append-only restriction
	// (a borg limitation workaround, SPEC.md §5) and restoring it — the
	// key may currently be able to delete backups, not just append to
	// them. Re-running onboard restores it; this exists so that's
	// visible here instead of the operator having zero signal.
	AppendOnlyLifted  bool           `json:"append_only_lifted,omitempty"`
	LastBackup        *time.Time     `json:"last_backup,omitempty"`
	LastPassingVerify *time.Time     `json:"last_passing_verify,omitempty"`
	Databases         []DatabaseSize `json:"databases,omitempty"`
	// ArchivePaths lists fleet.yaml's *currently configured* archive
	// paths — not a per-archive record of what a specific past backup
	// actually included, since Manifest never stored that (only
	// per-database dump baselines). If fleet.yaml's archive: list has
	// changed since the last backup ran, this reflects what the *next*
	// backup will include, not necessarily an exact match for the
	// latest archive already in the repo — this is called out in the
	// rendered output, not left implicit.
	ArchivePaths []string `json:"archive_paths,omitempty"`
	// ArchivePathSizes is each configured archive path's current
	// on-disk size on the target (`du -sb`), keyed by path — the
	// current live size of what would be archived, not a per-archive
	// borg contribution (borg doesn't break an archive's size down by
	// top-level source path). A path missing from this map means its
	// du call failed (e.g. permission denied, gone since fleet.yaml was
	// written) — status degrades gracefully per-path rather than
	// failing the whole report over one bad entry.
	ArchivePathSizes map[string]int64   `json:"archive_path_sizes,omitempty"`
	Archives         []string           `json:"archives,omitempty"`
	LatestArchive    *borg.ArchiveStats `json:"latest_archive,omitempty"`
	Repo             *borg.RepoStats    `json:"repo,omitempty"`
}

// Status reports what's actually in a server's repo: every archive
// present, the latest one's size, the whole repo's deduplicated size,
// and the locally-recorded last-backup/last-passing-verify timestamps
// (SPEC.md §4 — those timestamps only ever exist locally, so a status
// run against a server whose control host state was lost would show
// archives with no last-backup timestamp, not a fabricated one).
func Status(ctx context.Context, d Deps) (StatusReport, error) {
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return StatusReport{}, fmt.Errorf("status: load state: %w", err)
	}

	report := StatusReport{
		ServerID:          d.ServerID,
		RepoInitialized:   st.Provider.RepoInitialized,
		AppendOnlyLifted:  st.Provider.AppendOnlyLifted,
		LastBackup:        st.Timestamps.LastBackup,
		LastPassingVerify: st.Timestamps.LastPassingVerify,
	}
	for _, p := range d.Server.Archive {
		if p.Glob != "" {
			report.ArchivePaths = append(report.ArchivePaths, p.Path+"/"+p.Glob)
			continue
		}
		report.ArchivePaths = append(report.ArchivePaths, p.Path)
	}

	// Database and folder sizes come from the target server itself
	// (docker exec, du) — available regardless of onboarding status,
	// unlike the repo/archive inspection below, which needs a
	// confirmed Hetzner destination.
	resolvedAuth, err := resolveAuthRefs(ctx, d)
	if err != nil {
		return StatusReport{}, fmt.Errorf("status: %w", err)
	}
	if err := withProgress(d, "reading database sizes", func() error {
		report.Databases = databaseSizes(ctx, d, st.Databases, resolvedAuth)
		return nil
	}); err != nil {
		return StatusReport{}, fmt.Errorf("status: %w", err)
	}
	if err := withProgress(d, "reading archive path sizes", func() error {
		report.ArchivePathSizes = archivePathSizes(ctx, d, report.ArchivePaths)
		return nil
	}); err != nil {
		return StatusReport{}, fmt.Errorf("status: %w", err)
	}

	if !report.RepoInitialized {
		_ = SaveStatusCache(d.StateDir, report) // best-effort — a caching failure must never fail an otherwise-successful status read
		return report, nil
	}

	// GetDestination, never CreateIsolatedDestination — same reasoning
	// as backup.go/verify.go: status must never bring a subaccount into
	// existence, only inspect one that already exists.
	_, repoPath, passphrase, err := confirmDestinationAndPassphrase(ctx, d, st)
	if err != nil {
		return StatusReport{}, fmt.Errorf("status: %w", err)
	}

	var archives []string
	if err := withProgress(d, "listing archives", func() error {
		var err error
		archives, err = d.Backend.ListArchives(ctx, repoPath, passphrase, automationKeyPath)
		return err
	}); err != nil {
		return StatusReport{}, fmt.Errorf("status: %w", err)
	}
	sort.Strings(archives)
	report.Archives = archives

	if len(archives) > 0 {
		latest := archives[len(archives)-1]
		if err := withProgress(d, fmt.Sprintf("reading archive %s size", latest), func() error {
			stats, err := d.Backend.ArchiveInfo(ctx, repoPath, borg.ArchiveID(latest), passphrase, automationKeyPath)
			report.LatestArchive = &stats
			return err
		}); err != nil {
			return StatusReport{}, fmt.Errorf("status: %w", err)
		}
	}

	if err := withProgress(d, "reading repo total size", func() error {
		stats, err := d.Backend.RepoInfo(ctx, repoPath, passphrase, automationKeyPath)
		report.Repo = &stats
		return err
	}); err != nil {
		return StatusReport{}, fmt.Errorf("status: %w", err)
	}

	_ = SaveStatusCache(d.StateDir, report) // best-effort — a caching failure must never fail an otherwise-successful status read
	return report, nil
}

// databaseSizes queries each database instance's own size breakdown,
// best-effort: a database whose query fails (container gone, auth
// resolution failed) is silently skipped rather than failing the
// whole status report — status is an inspection tool, not a
// correctness-critical operation like backup/verify.
func databaseSizes(ctx context.Context, d Deps, databases []discover.DatabaseInstance, resolvedAuth map[string]string) []DatabaseSize {
	var sizes []DatabaseSize
	for _, db := range databases {
		var breakdown map[string]int64
		var err error
		switch {
		case db.DumpStrategy == discover.DumpStrategyNative && db.Kind == "postgres":
			breakdown, err = d.Backend.NativePostgresDatabaseSizes(ctx, resolvedAuth[db.Container])
		case db.DumpStrategy == discover.DumpStrategyNative && db.Kind == "mariadb":
			breakdown, err = d.Backend.NativeMySQLSchemaSizes(ctx, resolvedAuth[db.Container])
		case db.Kind == "postgres":
			breakdown, err = d.Backend.PostgresDatabaseSizes(ctx, db.Container, resolvedAuth[db.Container], db.Username)
		case db.Kind == "mariadb":
			breakdown, err = d.Backend.MariaDBSchemaSizes(ctx, db.Container, resolvedAuth[db.Container])
		case db.Kind == "cockroachdb":
			// CockroachDB has no per-database size the way postgres/
			// mariadb do — one unified distributed store backs every
			// database in the cluster — so this reports the whole
			// store's size under one synthetic entry rather than
			// pretending a breakdown that doesn't exist.
			var size int64
			size, err = d.Backend.CockroachClusterSize(ctx, db.Container)
			breakdown = map[string]int64{"(whole cluster)": size}
		default:
			continue
		}
		if err != nil {
			continue
		}
		sizes = append(sizes, DatabaseSize{Container: db.Container, Kind: db.Kind, Databases: breakdown})
	}
	return sizes
}

// archivePathSizes runs `du -sb` on the target for each configured
// archive path — best-effort, same reasoning as databaseSizes: a path
// that's gone or unreadable since fleet.yaml was written is silently
// omitted rather than failing the whole report.
func archivePathSizes(ctx context.Context, d Deps, paths []string) map[string]int64 {
	sizes := make(map[string]int64)
	for _, p := range paths {
		result, err := d.Target.Run(ctx, sshx.ReadOnly, "du", []string{"-sb", p}, sshx.RunOptions{})
		if err != nil {
			continue
		}
		sizeStr, _, ok := strings.Cut(strings.TrimSpace(result.Stdout), "\t")
		if !ok {
			continue
		}
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			continue
		}
		sizes[p] = size
	}
	return sizes
}
