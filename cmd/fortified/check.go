package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/state"
)

func newCheckCmd() *cobra.Command {
	var (
		configPath string
		wait       bool
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "check <server-id>",
		Short: "Run borg's own integrity check against the repo (SPEC.md §5) — should run before any prune",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"[dry-run] would run `borg check` against %s's repo and record the timestamp.\n", serverID)
				return nil
			}

			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			return state.WithLock(stateDir, serverID, "check", wait, func() error {
				wired, err := buildDeps(ctx, "check", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				defer wired.Cleanup()

				if err := orchestrate.Check(ctx, wired.Deps); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: integrity check passed.\n", serverID)
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	addDryRunFlag(cmd, &dryRun)

	return cmd
}
