package discover

import (
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/sshx"
)

// EmitConfig builds a ready-to-review fleet.yaml stanza for serverID
// from report — archive paths inferred from discovered compose files,
// one Database entry per classified DatabaseInstance with auth_ref:
// TODO wherever discover couldn't resolve auth automatically (SPEC.md
// §5). The operator fills every TODO before onboard will accept it —
// config.Load's ErrUnresolvedTODO enforces that structurally.
func EmitConfig(report *Report, target sshx.Target, provider, destination string) *config.Fleet {
	srv := config.Server{
		SSH: config.SSH{
			Host: target.Host,
			Port: target.Port,
			User: target.User,
		},
		Provider:         provider,
		Destination:      destination,
		Archive:          archiveCandidates(report),
		Databases:        databaseEntries(report.Databases),
		EncryptionKeyRef: "TODO",
	}
	// The Hetzner Storage Box main account and API token aren't
	// discoverable from the target server itself — they're operator
	// knowledge (NOTES.md) — so this stanza is deliberately incomplete
	// here; config.Load's TODO check is what makes the operator fill it
	// in rather than onboard silently running against placeholder auth.
	if provider == "hetzner" {
		srv.Hetzner = &config.HetznerConfig{
			MainAccount:    config.SSH{Host: "TODO", Port: 22, User: "TODO"},
			HCloudTokenRef: "TODO",
		}
	}
	return &config.Fleet{Servers: map[string]config.Server{report.ServerID: srv}}
}

// RenderYAML marshals fleet as the YAML the operator reviews and
// saves as fleet.yaml.
func RenderYAML(fleet *config.Fleet) ([]byte, error) {
	return yaml.Marshal(fleet)
}

// ResolvedDestination is everything about a backup destination that
// EmitConfig used to leave as "TODO" for the operator to type in by
// hand — the Storage Box, its main account, and the token used to
// reach it, all resolved up front by the caller (cmd/fortified's
// discover command, which can talk to the Hetzner API and prompt
// interactively) so BuildOrMergeServerConfig never has to invent a
// placeholder.
type ResolvedDestination struct {
	Provider         string
	Destination      string
	HCloudTokenRef   string
	MainAccountHost  string
	MainAccountUser  string
	EncryptionKeyRef string
}

// BuildOrMergeServerConfig returns serverID's config.Server entry.
// Passing existing == nil builds a brand-new entry from scratch.
// Passing an existing entry preserves every field it already has set
// — an operator's own hand edits always win — and only fills in
// whatever is still zero-valued from report/dest. This is what lets
// discover safely re-run against a server that's already partially
// configured without clobbering anything: a field already resolved
// (by the operator or a previous discover run) is never overwritten.
func BuildOrMergeServerConfig(existing *config.Server, report *Report, target sshx.Target, dest ResolvedDestination) config.Server {
	var srv config.Server
	if existing != nil {
		srv = *existing
	}

	if srv.SSH == (config.SSH{}) {
		srv.SSH = config.SSH{Host: target.Host, Port: target.Port, User: target.User}
	}
	if srv.Provider == "" {
		srv.Provider = dest.Provider
	}
	if srv.Destination == "" {
		srv.Destination = dest.Destination
	}
	if len(srv.Archive) == 0 {
		srv.Archive = archiveCandidates(report)
	}
	if len(srv.Databases) == 0 {
		srv.Databases = databaseEntries(report.Databases)
	}
	if srv.EncryptionKeyRef == "" {
		srv.EncryptionKeyRef = dest.EncryptionKeyRef
	}
	if srv.Hetzner == nil && dest.Provider == "hetzner" {
		srv.Hetzner = &config.HetznerConfig{
			MainAccount:    config.SSH{Host: dest.MainAccountHost, Port: 23, User: dest.MainAccountUser},
			HCloudTokenRef: dest.HCloudTokenRef,
		}
	}
	return srv
}

// archivePaths unions compose-project directories, the fixed
// well-known-state paths (cmdWireguardDir et al.), and every
// container's own bind-mount source paths into one sorted, deduped
// candidate list — all three are proposals for operator review, never
// auto-accepted, but combining them here means the emitted config
// doesn't silently drop state just because one heuristic happened to
// fill the field first. containerBindMounts specifically closes the
// gap a compose-file-only heuristic can't: a container started
// without a nearby compose file (plain `docker run`) has no compose
// directory to propose, even though its real bind-mount source is
// exactly as discoverable via `docker inspect` (verified live).
//
// projectDirs (compose working-dir labels) are proposed like compose
// file directories. dataDirs are database engines' live data
// directories: never proposed themselves, and excluded from whichever
// proposed path contains them, so a database's compose project — its
// compose file, engine config, auth files — is archived while the data
// the engine dump already covers is not copied raw.
func archivePaths(composeFiles, projectDirs, knownStatePaths, containerBindMounts, dataDirs []string) []config.ArchivePath {
	seen := make(map[string]bool)
	var dirs []string
	add := func(p string) {
		if seen[p] || underAny(p, dataDirs) {
			return
		}
		seen[p] = true
		dirs = append(dirs, p)
	}
	for _, f := range composeFiles {
		add(filepath.Dir(f))
	}
	for _, group := range [][]string{projectDirs, knownStatePaths, containerBindMounts} {
		for _, p := range group {
			add(p)
		}
	}
	sort.Strings(dirs)
	dirs = dropSubpaths(dirs)

	sortedDataDirs := append([]string(nil), dataDirs...)
	sort.Strings(sortedDataDirs)
	paths := make([]config.ArchivePath, 0, len(dirs))
	for _, d := range dirs {
		ap := config.ArchivePath{Path: d}
		for _, dd := range sortedDataDirs {
			if dd != d && underAny(dd, []string{d}) {
				ap.Exclude = append(ap.Exclude, dd)
			}
		}
		paths = append(paths, ap)
	}
	return paths
}

// archiveCandidates is archivePaths over everything report found —
// the one candidate list both discover's proposal and backup's
// coverage check (UncoveredPaths) are built from.
func archiveCandidates(report *Report) []config.ArchivePath {
	var projectDirs, dataDirs []string
	for _, c := range report.Containers {
		if c.ProjectDir != "" {
			projectDirs = append(projectDirs, c.ProjectDir)
		}
	}
	for _, db := range report.Databases {
		if db.DataDir != "" {
			dataDirs = append(dataDirs, db.DataDir)
		}
	}
	return archivePaths(report.ComposeFiles, projectDirs, report.KnownStatePaths, report.ContainerBindMounts, dataDirs)
}

// underAny reports whether p equals or sits under any of parents.
func underAny(p string, parents []string) bool {
	for _, parent := range parents {
		if p == parent || strings.HasPrefix(p, strings.TrimSuffix(parent, "/")+"/") {
			return true
		}
	}
	return false
}

// dropSubpaths removes any path already covered by a shorter path
// earlier in sorted (lexicographic sort always places a parent
// directory before its own children) — verified live this matters: a
// container's individual bind-mount sources nested under a directory
// already proposed via its own compose file or a known-state path
// (e.g. /home/psql/data and /home/psql/pgbouncer/pgbouncer.ini once
// /home/psql itself is already proposed from its docker-compose.yml)
// produced a wall of redundant entries an operator would have to
// manually prune by hand — archiving the parent already covers them.
func dropSubpaths(sorted []string) []string {
	var kept []string
	for _, p := range sorted {
		redundant := false
		for _, k := range kept {
			if strings.HasPrefix(p, k+"/") {
				redundant = true
				break
			}
		}
		if !redundant {
			kept = append(kept, p)
		}
	}
	return kept
}

func databaseEntries(databases []DatabaseInstance) []config.Database {
	entries := make([]config.Database, 0, len(databases))
	for _, d := range databases {
		entry := config.Database{
			Kind:         d.Kind,
			Container:    d.Container,
			DumpStrategy: string(d.DumpStrategy),
		}
		if !d.AuthResolved {
			entry.AuthRef = "TODO"
		}
		entries = append(entries, entry)
	}
	return entries
}
