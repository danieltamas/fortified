package orchestrate

import (
	"context"
	"fmt"
	"time"

	"github.com/danieltamas/fortified/internal/state"
)

// Check runs borg's own integrity check against the repo (SPEC.md §5)
// and records the timestamp — this is what `prune` requires to have
// passed recently before it will run, and what `status` surfaces as
// "days since last check".
func Check(ctx context.Context, d Deps) error {
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return fmt.Errorf("check: load state: %w", err)
	}
	if !st.Provider.RepoInitialized {
		return fmt.Errorf("check: %s has not completed onboarding — run onboard first", d.ServerID)
	}

	_, repoPath, passphrase, err := confirmDestinationAndPassphrase(ctx, d, st)
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}

	if err := withProgress(d, "running integrity check", func() error {
		return d.Backend.Check(ctx, repoPath, passphrase, automationKeyPath)
	}); err != nil {
		return fmt.Errorf("check: %w", err)
	}

	now := time.Now().UTC()
	st.Timestamps.LastCheck = &now
	if err := state.Save(d.StateDir, st); err != nil {
		return fmt.Errorf("check: save state: %w", err)
	}
	return nil
}
