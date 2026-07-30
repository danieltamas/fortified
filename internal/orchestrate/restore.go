package orchestrate

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// RestoreOptions carries restore's operator-supplied inputs.
type RestoreOptions struct {
	// Archive is an exact archive name or "latest". Empty means "just
	// list archives and return" (SPEC.md §5: run without --archive, it
	// lists the repo's archives and exits — no separate list command).
	Archive string
	// Into is the target directory on the *protected server* to
	// extract into — never the control host (restore runs where the
	// automation key lives, same execution topology as everything
	// else). Required whenever Archive is set.
	Into string
	// DB, if set, restores only that database's own dump file instead
	// of the whole archive.
	DB string
}

// RestoreResult is what actually happened — Archives is populated in
// list mode; Restored/Into/ExtractedPath are populated after a real
// restore.
type RestoreResult struct {
	Archives      []string `json:"archives,omitempty"`
	Restored      string   `json:"restored,omitempty"`
	Into          string   `json:"into,omitempty"`
	ExtractedPath string   `json:"extracted_path,omitempty"`
}

// Restore extracts an archive (or, with DB, just one database's dump
// file) into a directory on the target — SPEC.md §5's "dropped table /
// bad migration" and "live corruption" recovery tiers made runnable.
// Non-destructive by construction: refuses any Into path that already
// has content, or that matches any discovered database's own live
// DataMountPaths — swapping restored data into a live service is
// deliberately a manual operator action this tool never automates.
func Restore(ctx context.Context, d Deps, opts RestoreOptions) (RestoreResult, error) {
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("restore: load state: %w", err)
	}
	if !st.Provider.RepoInitialized {
		return RestoreResult{}, fmt.Errorf("restore: %s has not completed onboarding — run onboard first", d.ServerID)
	}

	_, repoPath, passphrase, err := confirmDestinationAndPassphrase(ctx, d, st)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("restore: %w", err)
	}

	var archives []string
	if err := withProgress(d, "listing archives", func() error {
		var err error
		archives, err = d.Backend.ListArchives(ctx, repoPath, passphrase, automationKeyPath)
		return err
	}); err != nil {
		return RestoreResult{}, fmt.Errorf("restore: %w", err)
	}
	sort.Strings(archives)

	if opts.Archive == "" {
		return RestoreResult{Archives: archives}, nil
	}
	if len(archives) == 0 {
		return RestoreResult{}, fmt.Errorf("restore: %s's repo has no archives yet — run backup first", d.ServerID)
	}

	archiveID := opts.Archive
	if archiveID == "latest" {
		archiveID = latestArchive(archives)
	} else if !contains(archives, archiveID) {
		return RestoreResult{}, fmt.Errorf("restore: archive %q not found — run without --archive to list what's actually in the repo", archiveID)
	}

	if opts.Into == "" {
		return RestoreResult{}, fmt.Errorf("restore: --into is required when restoring an archive")
	}
	if err := ensureRestoreTargetIsSafe(ctx, d, opts.Into, st.Databases); err != nil {
		return RestoreResult{}, fmt.Errorf("restore: %w", err)
	}

	var extractPaths []string
	extractedPath := opts.Into
	if opts.DB != "" {
		if findDatabaseInstance(st.Databases, opts.DB) == nil {
			return RestoreResult{}, fmt.Errorf("restore: %q is not one of %s's known databases (see the last discover result)", opts.DB, d.ServerID)
		}
		dumpPath := backupWorkspaceDir(d.ServerID, d.Server.WorkspaceDir) + "/" + opts.DB + ".sql"
		extractPaths = []string{dumpPath}
		// Verified live against a real borg repo: borg's own extract
		// correctly matches an absolute path filter against its
		// slash-stripped internal storage (an absolute source is
		// archived without its leading slash, but extract normalizes
		// this transparently) — a configured workspace_dir's absolute
		// dumpPath here doesn't break the actual extraction. filepath.Join
		// (rather than string concatenation) just keeps the reported
		// ExtractedPath free of the double slash a bare "+" would leave
		// when dumpPath is already absolute.
		extractedPath = filepath.Join(opts.Into, dumpPath)
	}

	if err := withProgress(d, fmt.Sprintf("restoring archive %s into %s", archiveID, opts.Into), func() error {
		return d.Backend.RestoreArchive(ctx, repoPath, borg.ArchiveID(archiveID), passphrase, automationKeyPath, opts.Into, extractPaths...)
	}); err != nil {
		return RestoreResult{}, fmt.Errorf("restore: %w", err)
	}

	return RestoreResult{Restored: archiveID, Into: opts.Into, ExtractedPath: extractedPath}, nil
}

// ensureRestoreTargetIsSafe refuses a restore target that's a live
// database's own data mount (restoring on top of what a running
// service is actively using is exactly the kind of accident this
// check exists to prevent) or that already has content — a
// nonexistent directory is fine (mkdir -p happens as part of the
// extract itself, via borg's own Dir option) and reads as "empty".
func ensureRestoreTargetIsSafe(ctx context.Context, d Deps, into string, databases []discover.DatabaseInstance) error {
	for _, db := range databases {
		for _, p := range db.DataMountPaths {
			if p == into {
				return fmt.Errorf("restore target %s is %s's own live data mount — restoring there would overwrite a running service's data; move restored data into place manually, never automatically", into, db.Container)
			}
		}
	}

	quoted := shellSingleQuote(into)
	script := fmt.Sprintf("mkdir -p %s && ls -A %s", quoted, quoted)
	result, err := d.Target.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{})
	if err != nil {
		return fmt.Errorf("check restore target %s: %w", into, err)
	}
	if strings.TrimSpace(result.Stdout) != "" {
		return fmt.Errorf("restore target %s is not empty — refusing to restore into a non-empty directory", into)
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
