package orchestrate

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// drillKeyPath is where the operator-supplied identity file is
// staged, temporarily, on the throwaway target — a bare relative name
// (no subdirectory), same convention as automationKeyPath.
const drillKeyPath = "fortified-drill-key"

// DrillOptions carries drill's operator-supplied inputs.
type DrillOptions struct {
	// IdentityPath is a private key file on the control host, already
	// authorized to read the server's repo (an escrowed copy of the
	// automation key, or the unrestricted prune key) — fortified never
	// generates or stores one for this. SKILL.md's full-host-loss
	// drill must prove recovery works from the *escrowed* copy, never
	// a copy still sitting on the very server being drilled against —
	// which is also why this never touches d.Target at all.
	IdentityPath string
	// Archive to restore; "" means the latest.
	Archive string
	// Into is the directory on the throwaway target to restore into —
	// required, and never defaulted, since a wrong guess here would
	// write a full archive's worth of data somewhere unintended.
	Into string
}

// DrillResult is what a completed drill proved.
type DrillResult struct {
	Archive string        `json:"archive"`
	Into    string        `json:"into"`
	Elapsed time.Duration `json:"elapsed"`
}

// Drill proves SKILL.md's full-host-loss recovery tier actually
// works, made runnable rather than theorized (SPEC.md §5): it
// restores a server's latest (or a named) archive onto a genuinely
// separate throwaway target, timed, recording a passing drill in
// state so "when did we last actually prove this fleet recoverable"
// is a fact status can surface, not a memory.
//
// throwaway is the target's own runner — deliberately not d.Target,
// which belongs to the server whose repo is being drilled against.
// Drill's entire point is proving recovery onto a *different*
// machine, using only what an operator holds out-of-band (the
// escrowed passphrase, and an identity file authorized to read the
// repo) — never a credential still sitting on the server being
// drilled.
func Drill(ctx context.Context, d Deps, throwaway sshx.Runner, opts DrillOptions) (DrillResult, error) {
	start := time.Now()

	if opts.Into == "" {
		return DrillResult{}, fmt.Errorf("drill: --into is required — the throwaway target directory to restore into")
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return DrillResult{}, fmt.Errorf("drill: load state: %w", err)
	}
	if !st.Provider.RepoInitialized {
		return DrillResult{}, fmt.Errorf("drill: %s has not completed onboarding — run onboard first", d.ServerID)
	}

	keyBytes, err := os.ReadFile(opts.IdentityPath) //nolint:gosec // operator-supplied path, explicit per invocation, never persisted
	if err != nil {
		return DrillResult{}, fmt.Errorf("drill: read identity file: %w", err)
	}

	dest, err := d.Provider.GetDestination(ctx, d.ServerID)
	if err != nil {
		return DrillResult{}, fmt.Errorf("drill: %w", err)
	}
	repoPath := RemoteRepoTarget(dest)

	passphrase, err := d.Secrets.Resolve(ctx, d.Server.EncryptionKeyRef)
	if err != nil {
		return DrillResult{}, fmt.Errorf("drill: resolve encryption_key_ref: %w", err)
	}

	if err := withProgress(d, "installing borg on the throwaway target if missing", func() error {
		return ensureBorgInstalled(ctx, throwaway)
	}); err != nil {
		return DrillResult{}, fmt.Errorf("drill: %w", err)
	}

	if err := withProgress(d, "staging the supplied identity file on the throwaway target", func() error {
		_, err := throwaway.Run(ctx, sshx.Mutating, "sh",
			[]string{"-c", fmt.Sprintf("cat > %s && chmod 600 %s", drillKeyPath, drillKeyPath)},
			sshx.RunOptions{Stdin: string(keyBytes)})
		return err
	}); err != nil {
		return DrillResult{}, fmt.Errorf("drill: %w", err)
	}
	// Best-effort cleanup regardless of outcome — the identity file is
	// only ever needed for the duration of this one drill.
	defer func() {
		_, _ = throwaway.Run(ctx, sshx.Mutating, "rm", []string{"-f", drillKeyPath}, sshx.RunOptions{})
	}()

	backend := borg.Backend{Runner: throwaway}

	archiveID := opts.Archive
	if archiveID == "" {
		var archives []string
		if err := withProgress(d, "listing archives", func() error {
			var err error
			archives, err = backend.ListArchives(ctx, repoPath, passphrase, drillKeyPath)
			return err
		}); err != nil {
			return DrillResult{}, fmt.Errorf("drill: %w", err)
		}
		if len(archives) == 0 {
			return DrillResult{}, fmt.Errorf("drill: %s's repo has no archives yet", d.ServerID)
		}
		sort.Strings(archives)
		archiveID = archives[len(archives)-1]
	}

	if err := withProgress(d, fmt.Sprintf("preparing %s on the throwaway target", opts.Into), func() error {
		return ensureDrillTargetIsSafe(ctx, throwaway, opts.Into)
	}); err != nil {
		return DrillResult{}, fmt.Errorf("drill: %w", err)
	}

	if err := withProgress(d, fmt.Sprintf("restoring %s onto the throwaway target", archiveID), func() error {
		return backend.RestoreArchive(ctx, repoPath, borg.ArchiveID(archiveID), passphrase, drillKeyPath, opts.Into)
	}); err != nil {
		return DrillResult{}, fmt.Errorf("drill: %w", err)
	}

	now := time.Now().UTC()
	st.Timestamps.LastDrill = &now
	if err := state.Save(d.StateDir, st); err != nil {
		return DrillResult{}, fmt.Errorf("drill: save state: %w", err)
	}

	return DrillResult{Archive: archiveID, Into: opts.Into, Elapsed: time.Since(start)}, nil
}

// ensureDrillTargetIsSafe mirrors restore.go's ensureRestoreTargetIsSafe
// for the throwaway target — a real gap found by cross-vendor review:
// unlike the ordinary restore command, Drill never created opts.Into
// at all before calling RestoreArchive, which sets Dir on the
// underlying `borg extract` call (`cd opts.Into && ...` — see
// absIdentityPath's own doc comment on why Dir matters here); `cd`
// into a directory that doesn't exist yet fails outright. There's no
// DataMountPaths check here (unlike the real restore path) because
// the throwaway target is a genuinely different machine from the
// server whose repo is being drilled — its own paths have no
// relationship to that server's live data mounts.
func ensureDrillTargetIsSafe(ctx context.Context, throwaway sshx.Runner, into string) error {
	quoted := shellSingleQuote(into)
	script := fmt.Sprintf("mkdir -p %s && ls -A %s", quoted, quoted)
	result, err := throwaway.Run(ctx, sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{})
	if err != nil {
		return fmt.Errorf("check drill target %s: %w", into, err)
	}
	if strings.TrimSpace(result.Stdout) != "" {
		return fmt.Errorf("drill target %s is not empty — refusing to restore into a non-empty directory", into)
	}
	return nil
}
