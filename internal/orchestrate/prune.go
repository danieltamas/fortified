package orchestrate

import (
	"context"
	"fmt"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/state"
)

// PruneOptions carries prune's operator-supplied inputs.
type PruneOptions struct {
	// PruneKeyPath is the one credential this whole tool ever requires
	// supplied explicitly, every time — SPEC.md §5: never cached, never
	// read from the same secrets path as everything else. Required.
	PruneKeyPath string
}

// Prune enforces the configured retention policy against the repo —
// the one command in the whole tool that touches the unrestricted key
// capable of deleting old archives (SPEC.md §5's dual-key discipline:
// the automation key everything else uses can only ever append). Runs
// Check first automatically and refuses to prune a repo that just
// failed integrity check — pruning a repo already known to be corrupt
// only destroys evidence, never fixes anything.
func Prune(ctx context.Context, d Deps, opts PruneOptions) error {
	if opts.PruneKeyPath == "" {
		return fmt.Errorf("prune: --prune-key is required — the unrestricted key is never read from config or cached")
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return fmt.Errorf("prune: load state: %w", err)
	}
	if !st.Provider.RepoInitialized {
		return fmt.Errorf("prune: %s has not completed onboarding — run onboard first", d.ServerID)
	}

	if err := Check(ctx, d); err != nil {
		return fmt.Errorf("prune: refusing to prune — integrity check failed: %w", err)
	}

	// Check just re-loaded and re-saved state (recording LastCheck) —
	// reload so the passphrase/destination confirmation below sees
	// that update, not a stale copy from before Check ran.
	st, err = state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return fmt.Errorf("prune: load state: %w", err)
	}

	_, repoPath, passphrase, err := confirmDestinationAndPassphrase(ctx, d, st)
	if err != nil {
		return fmt.Errorf("prune: %w", err)
	}

	retention := d.Server.Retention
	if retention == nil {
		retention = &config.DefaultRetention
	}
	policy := borg.Policy{KeepDaily: retention.KeepDaily, KeepWeekly: retention.KeepWeekly, KeepMonthly: retention.KeepMonthly}

	// Prune must never run through d.Backend (the target's own SSH
	// session): that would require --prune-key to be a path readable
	// from the *protected server's* filesystem, exactly the exposure
	// the dual-key model exists to prevent — see borg.Backend.Prune's
	// own doc comment: "whatever opens the connection for a Prune call
	// must open a *separate* session ... never reuse the automation
	// Session". d.Local dials the Storage Box directly from the control
	// host instead (where the operator just supplied --prune-key from,
	// fresh, per SPEC.md §5) — which does mean the control host itself
	// needs borg installed, a real, narrow new requirement, but only
	// for this one destructive command.
	localBackend := borg.Backend{Runner: d.Local}
	return withProgress(d, "pruning old archives", func() error {
		return localBackend.Prune(ctx, repoPath, passphrase, policy, opts.PruneKeyPath, automationKeyPath)
	})
}
