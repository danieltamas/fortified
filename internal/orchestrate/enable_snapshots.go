package orchestrate

import (
	"context"
	"fmt"

	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/state"
)

// EnableSnapshots turns on the destination's native snapshot schedule
// — deliberately a separate command from onboard, run strictly after
// a passing verify, never as part of a batch of steps that might
// itself be broken (SPEC.md §5). hetzner.Provider itself also refuses
// this without a passing verify (its own defense-in-depth check); this
// refusal exists so the operator gets a clear, state-grounded message
// before ever reaching the API call.
func EnableSnapshots(ctx context.Context, d Deps, schedule hetzner.Schedule) error {
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return fmt.Errorf("enable-snapshots: load state: %w", err)
	}
	if !st.Verify.EverPassed {
		return fmt.Errorf("enable-snapshots: %s has no passing verify recorded — run verify first (SPEC.md §4)", d.ServerID)
	}

	// GetDestination, never CreateIsolatedDestination — see backup.go's
	// identical comment: only onboard should ever bring a subaccount
	// into existence.
	var dest hetzner.Destination
	if err := withProgress(d, "confirming destination", func() error {
		var err error
		dest, err = d.Provider.GetDestination(ctx, d.ServerID)
		return err
	}); err != nil {
		return fmt.Errorf("enable-snapshots: confirm destination: %w", err)
	}

	if err := withProgress(d, "enabling snapshot schedule", func() error {
		return d.Provider.EnableSnapshotSchedule(ctx, dest, schedule, st.Verify.EverPassed)
	}); err != nil {
		return fmt.Errorf("enable-snapshots: %w", err)
	}
	return nil
}
