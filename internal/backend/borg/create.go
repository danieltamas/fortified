package borg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
)

// CreateArchive stages every database's dump into workspaceDir on the
// target (the same disk the borg key and repo live on — SPEC.md §3's
// execution topology), checking each dump's exit code as it
// completes. Only if every dump succeeds does it create the archive;
// if any dump fails, the workspace is deleted, no archive is created,
// and the error is returned — a partial archive that looks complete
// is worse than a run that visibly failed (SPEC.md §4).
//
// databases is discover's recorded DatabaseInstance list, consumed
// verbatim — never re-derived from a container name. resolvedAuth maps
// container name to an already-resolved credential for a database
// discover couldn't auto-resolve auth for (config's auth_ref, resolved
// by the caller via internal/secrets — SPEC.md §3); a database absent
// from this map falls back to its own container env. sourcePaths are
// host-level paths (compose files, TLS certs, etc.) archived alongside
// the dumps; excludes are absolute paths under them that borg skips
// (fleet.yaml's archive[].exclude). lastRunTotalDumpSize feeds the free-space pre-flight
// (0 means "first run").
//
// progress, if non-nil, is called with a start/done line around each
// database's own dump (same nil-safe func(string) convention as
// orchestrate.Deps.Progress) — otherwise a multi-hour backup reports
// nothing at all until the whole thing finishes. liveOutput, if
// non-nil, receives the `borg create` step's own --progress/--stats
// output live as it's produced (a raw tee, not parsed) — borg already
// reports its own upload progress; this just lets the operator watch
// it instead of it only surfacing once the command exits. The same
// writer also carries each database's own dump progress (pg_dumpall/
// mysqldump/cockroach dump report nothing on their own, unlike borg) —
// a background poller watches the growing dump file's size and writes
// a self-overwriting line, the same convention borg's own --progress
// output uses on this writer.
func (b Backend) CreateArchive(
	ctx context.Context,
	repoPath, passphrase, identityPath, workspaceDir, archiveName string,
	databases []discover.DatabaseInstance,
	resolvedAuth map[string]string,
	sourcePaths []string,
	excludes []string,
	lastRunTotalDumpSize int64,
	progress func(string),
	liveOutput io.Writer,
) (ArchiveID, Manifest, error) {
	if err := b.FreeSpacePreflight(ctx, workspaceDir, databases, resolvedAuth, lastRunTotalDumpSize); err != nil {
		return "", Manifest{}, err
	}

	if _, err := b.Runner.Run(ctx, sshx.Mutating, "mkdir", []string{"-p", workspaceDir}, sshx.RunOptions{}); err != nil {
		return "", Manifest{}, fmt.Errorf("borg: create workspace %s: %w", workspaceDir, err)
	}
	// The workspace is always transient — deleted whether this run
	// succeeds or fails, since a successful run has already archived
	// it and a failed one must leave no trace (SPEC.md §4).
	defer b.deleteWorkspace(ctx, workspaceDir)

	manifest := Manifest{Databases: make([]DatabaseManifest, 0, len(databases))}
	for _, db := range databases {
		if progress != nil {
			progress("dumping " + db.Container + "...")
		}
		dumpStart := time.Now()
		dm, err := b.dumpDatabase(ctx, workspaceDir, db, resolvedAuth[db.Container], liveOutput)
		if err != nil {
			return "", Manifest{}, fmt.Errorf("borg: dump for %s failed, no archive created: %w", db.Container, err)
		}
		manifest.Databases = append(manifest.Databases, dm)
		if progress != nil {
			progress(fmt.Sprintf("dumping %s: done (%s)", db.Container, time.Since(dumpStart).Round(time.Millisecond)))
		}
	}

	if err := b.writeManifest(ctx, workspaceDir, manifest); err != nil {
		return "", Manifest{}, fmt.Errorf("borg: write manifest: %w", err)
	}

	archivePaths := append([]string{workspaceDir}, sourcePaths...)
	archiveSpec := fmt.Sprintf("%s::%s", repoPath, archiveName)
	args := []string{"create", "--progress", "--stats"}
	for _, ex := range excludes {
		// pp: is borg's path-prefix pattern: it matches ex and
		// everything under it, never a sibling that merely shares the
		// name as a prefix the way a bare fnmatch pattern could.
		args = append(args, "--exclude", "pp:"+ex)
	}
	args = append(append(args, archiveSpec), archivePaths...)
	if progress != nil {
		progress("creating archive " + archiveName)
	}
	start := time.Now()
	result, err := b.Runner.Run(ctx, sshx.Mutating, "borg", args, sshx.RunOptions{
		Env:        remoteRepoEnv(passphrase, identityPath),
		Timeout:    sshx.LongRunningTimeout,
		LiveStderr: liveOutput,
	})
	// borg's own exit-code convention (documented, applies to every
	// subcommand): 0 = success, 1 = warning (the operation reached its
	// normal end, but something noteworthy happened), 2+ = genuine
	// error (the operation did not complete). Verified live: a
	// bind-mounted app-data directory containing a live SQLite
	// database in WAL mode (Uptime Kuma's kuma.db-shm) changed mid-read
	// while borg walked it — exactly the kind of benign, expected
	// event exit 1 exists to report — and the archive itself was still
	// created completely and correctly (full stats block, real
	// fingerprint). Treating exit 1 as fatal here aborted an otherwise
	// fully successful backup. This distinction is deliberately scoped
	// to `create`: check's exit 1 gates the destructive `prune` step
	// and stays conservative (any non-zero exit still fails) rather
	// than risk pruning against a repo a warning was trying to flag.
	if err != nil && result.ExitCode != 1 {
		return "", Manifest{}, fmt.Errorf("borg: create archive %s: %w", archiveSpec, err)
	}
	if err != nil && progress != nil {
		// Exit 1 covers more than the "file changed mid-read" case the
		// doc comment above verified live — borg uses it for its whole
		// warning class (permission denied on one configured path,
		// vanished file, etc.), some of which mean the archive is
		// missing data it was supposed to have, not just racing a live
		// write. Report the real warning text rather than asserting a
		// specific, possibly wrong cause — the operator (or a future,
		// more selective check here) needs to actually read it, not be
		// told it was surely benign.
		progress(fmt.Sprintf("creating archive %s: done with a warning (%s) — archive created, but borg reported: %s",
			archiveName, time.Since(start).Round(time.Millisecond), err))
	} else if progress != nil {
		progress(fmt.Sprintf("creating archive %s: done (%s)", archiveName, time.Since(start).Round(time.Millisecond)))
	}

	return ArchiveID(archiveName), manifest, nil
}

func (b Backend) writeManifest(ctx context.Context, workspaceDir string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	script := fmt.Sprintf("cat > %s/manifest.json", shellSingleQuote(workspaceDir))
	if _, err := b.Runner.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{Stdin: string(data)}); err != nil {
		return fmt.Errorf("write %s/manifest.json: %w", workspaceDir, err)
	}
	return nil
}

// deleteWorkspace removes the temp staging directory. Its own failure
// is not itself a fatal error for the caller (the archive decision has
// already been made); it never panics or blocks cleanup of an
// already-failed run.
func (b Backend) deleteWorkspace(ctx context.Context, workspaceDir string) {
	_, _ = b.Runner.Run(ctx, sshx.Mutating, "rm", []string{"-rf", workspaceDir}, sshx.RunOptions{})
}
