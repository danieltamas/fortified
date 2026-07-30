package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/state"
)

func newEnableSnapshotsCmd() *cobra.Command {
	var (
		configPath   string
		maxSnapshots int
		hour         int
		minute       int
		wait         bool
		dryRun       bool
	)

	cmd := &cobra.Command{
		Use:   "enable-snapshots <server-id>",
		Short: "Turn on the destination's native snapshot schedule (refuses without a passing verify)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			// Lock before buildDeps — see onboard.go's identical comment.
			// Unlike onboard/backup/verify, this command is a single API
			// call with no interleaved mutate-then-read-back chain, so
			// --dry-run gets the real, fine-grained treatment:
			// hetzner.Provider.DryRun (set via buildDeps) skips the actual
			// enable call and prints a plan line instead.
			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			schedule := hetzner.Schedule{MaxSnapshots: maxSnapshots, Hour: hour, Minute: minute}
			return state.WithLock(stateDir, serverID, "enable-snapshots", wait, func() error {
				wired, err := buildDeps(ctx, "enable-snapshots", configPath, serverID, dryRun, cmd.OutOrStdout(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				defer wired.Cleanup()

				if err := orchestrate.EnableSnapshots(ctx, wired.Deps, schedule); err != nil {
					return err
				}

				if !dryRun {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: snapshot schedule enabled (daily at %02d:%02d UTC, keeping %d).\n",
						serverID, hour, minute, maxSnapshots)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().IntVar(&maxSnapshots, "max-snapshots", 7, "how many native snapshots the destination keeps")
	cmd.Flags().IntVar(&hour, "hour", 3, "hour (UTC) the destination takes its daily snapshot")
	cmd.Flags().IntVar(&minute, "minute", 0, "minute (UTC) the destination takes its daily snapshot")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	addDryRunFlag(cmd, &dryRun)

	return cmd
}
