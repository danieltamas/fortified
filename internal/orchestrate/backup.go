package orchestrate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// backupWorkspaceDir is the per-server staging directory on the
// target — a fixed, predictable name (not a random temp dir) so a
// killed run's leftover workspace is always found at the same place
// on the next attempt, and cleanup never has to guess.
//
// workspaceRoot overrides where this lives: empty (the default) stages
// under the SSH login's own home directory, same as always — a bare
// relative name. A non-empty override (config.Server.WorkspaceDir)
// anchors it under that absolute path instead, e.g. an attached volume
// with real headroom — verified live this matters: a large database's
// SQL-text dump can need meaningfully more scratch space than the root
// filesystem has free.
func backupWorkspaceDir(serverID, workspaceRoot string) string {
	name := "fortified-backup-workspace-" + serverID
	if workspaceRoot == "" {
		return name
	}
	return strings.TrimSuffix(workspaceRoot, "/") + "/" + name
}

// Backup runs SPEC.md §4's staged-dump-then-archive sequence for one
// server: free-space pre-flight, per-database dumps into a workspace,
// archive creation with the recorded verification manifest — through
// the append-only key Onboard already installed. It refuses to run
// against a server that hasn't completed onboarding.
//
// lastRunTotalDumpSize is deliberately always 0 (the "first run,
// engine-reported size estimate" path — SPEC.md §4) rather than 1.5×
// an actually-tracked prior dump size: the manifest schema doesn't
// record a total size today. The estimate path sizes the data a dump
// actually writes × 1.25 (borg.dumpSizeHeadroom), which is not always
// more conservative than 1.5× a real prior dump (mysqldump measured at
// 1.20× its data_length, so 1.5× that dump asks for more) — flagged
// here rather than silently assumed.
func Backup(ctx context.Context, d Deps) error {
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return fmt.Errorf("backup: load state: %w", err)
	}
	if !st.Provider.RepoInitialized {
		return fmt.Errorf("backup: %s has not completed onboarding (no initialized repo) — run onboard first", d.ServerID)
	}

	// GetDestination, never CreateIsolatedDestination: backup must never
	// bring a new subaccount into existence — only onboard does that.
	// If the destination is gone (deleted since onboarding), this must
	// fail clearly, not silently recreate a blank one with no repo and
	// no automation key on it.
	_, repoPath, passphrase, err := confirmDestinationAndPassphrase(ctx, d, st)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	var resolvedAuth map[string]string
	var sourcePaths []string
	if err := withProgress(d, "resolving database auth and archive paths", func() error {
		var err error
		resolvedAuth, err = resolveAuthRefs(ctx, d)
		if err != nil {
			return err
		}
		sourcePaths, err = resolveArchiveSourcePaths(ctx, d)
		return err
	}); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	workspaceDir := backupWorkspaceDir(d.ServerID, d.Server.WorkspaceDir)
	archiveName := time.Now().UTC().Format("2006-01-02T15-04-05Z")

	var manifest borg.Manifest
	label := fmt.Sprintf("staging %d database dump(s) and creating the archive", len(st.Databases))
	if err := withProgress(d, label, func() error {
		var err error
		_, manifest, err = d.Backend.CreateArchive(ctx, repoPath, passphrase, automationKeyPath, workspaceDir, archiveName,
			st.Databases, resolvedAuth, sourcePaths, 0, d.Progress, d.LiveOutput)
		return err
	}); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	now := time.Now().UTC()
	st.Timestamps.LastBackup = &now
	st.LastManifest = toStateManifest(manifest)
	if err := state.Save(d.StateDir, st); err != nil {
		return fmt.Errorf("backup: save state: %w", err)
	}
	return nil
}

// toStateManifest copies a borg.Manifest into state's own Manifest
// shape (state deliberately doesn't import borg's type directly — see
// state.Manifest's doc comment).
func toStateManifest(m borg.Manifest) *state.Manifest {
	out := &state.Manifest{Databases: make([]state.DatabaseManifest, len(m.Databases))}
	for i, dm := range m.Databases {
		out.Databases[i] = state.DatabaseManifest{Container: dm.Container, SHA256: dm.SHA256, RowCounts: dm.RowCounts}
	}
	return out
}

// resolveAuthRefs resolves every configured database's auth_ref up
// front — CreateArchive consumes a plain map, never a secret
// reference, so resolution happens exactly once per backup run here,
// not scattered across dump call sites.
func resolveAuthRefs(ctx context.Context, d Deps) (map[string]string, error) {
	resolved := make(map[string]string)
	for _, cfgDB := range d.Server.Databases {
		if cfgDB.AuthRef == "" {
			continue
		}
		val, err := d.Secrets.Resolve(ctx, cfgDB.AuthRef)
		if err != nil {
			return nil, fmt.Errorf("resolve auth_ref for %s: %w", cfgDB.Container, err)
		}
		resolved[cfgDB.Container] = val
	}
	return resolved, nil
}

// resolveArchiveSourcePaths expands each configured ArchivePath into
// concrete paths: a glob-less entry is used as-is, a glob'd one is
// expanded on the target with a shell glob loop rather than `ls`,
// specifically so "the pattern matched nothing" and "the command
// itself failed" are distinguishable — `ls -d pattern 2>/dev/null`
// can't tell those apart (both look like a non-zero exit with no
// stdout), which previously meant an SSH hiccup, a permission error,
// or a shell syntax problem silently dropped a configured archive
// path (a compose file, a TLS cert) with the run still reporting
// success. A glob loop with `[ -e "$f" ]` always exits 0 — it just
// never echoes anything when the pattern matches nothing — so a
// non-nil error here is always a genuine failure, never "no matches",
// and now propagates instead of being swallowed.
func resolveArchiveSourcePaths(ctx context.Context, d Deps) ([]string, error) {
	var resolved []string
	for _, p := range d.Server.Archive {
		if p.Glob == "" {
			resolved = append(resolved, p.Path)
			continue
		}
		// p.Path is single-quoted like any other fleet.yaml-derived
		// path (it doesn't need shell glob semantics), but p.Glob can't
		// be: it's interpolated into `for f in <pattern>` specifically
		// so the shell expands *, ?, [...] — quoting it would disable
		// the very expansion this exists for. validateGlobIsShellSafe
		// is what actually closes the injection surface a raw,
		// unrestricted interpolation would otherwise leave open (a
		// stray ";" or backtick in fleet.yaml running arbitrary
		// commands on the target) without breaking real globs.
		if err := validateGlobIsShellSafe(p.Glob); err != nil {
			return nil, fmt.Errorf("archive path %s: glob %q: %w", p.Path, p.Glob, err)
		}
		pattern := shellSingleQuote(p.Path) + "/" + p.Glob
		script := fmt.Sprintf(`for f in %s; do [ -e "$f" ] && echo "$f"; done`, pattern)
		result, err := d.Target.Run(ctx, sshx.ReadOnly, "sh", []string{"-c", script}, sshx.RunOptions{})
		if err != nil {
			return nil, fmt.Errorf("expand archive glob %q: %w", pattern, err)
		}
		resolved = append(resolved, splitNonEmptyLines(result.Stdout)...)
	}
	return resolved, nil
}

// validateGlobIsShellSafe rejects any character outside the standard
// POSIX glob/filename set. archive.glob is meant to function as a
// live shell glob pattern (needs *, ?, [, ] to do anything at all),
// so unlike an ordinary path it can't just be single-quoted — this is
// the boundary check that takes its place.
func validateGlobIsShellSafe(glob string) error {
	for _, r := range glob {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(`.-_*?[]! /`, r):
		default:
			return fmt.Errorf("contains %q, which isn't a valid glob character", r)
		}
	}
	return nil
}

func splitNonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
