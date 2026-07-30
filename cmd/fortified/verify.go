package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/state"
)

func newVerifyCmd() *cobra.Command {
	var (
		configPath string
		wait       bool
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "verify <server-id>",
		Short: "Restore the latest archive and prove it matches the recorded backup manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			// verify's read-only comparison steps (SHA-256, row counts)
			// only make sense against a restore that actually happened —
			// wrapping its runner the way onboard/backup do would leave
			// dry-run producing confusing real errors (sha256sum against
			// a dump that was never extracted) instead of a clean plan.
			// So --dry-run here is a coarse, honest summary instead of a
			// per-command transcript: it never calls orchestrate.Verify.
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"[dry-run] would restore %s's latest archive into a scratch directory and compare SHA-256 + row counts (per throwaway container) against the recorded manifest — no plan-level detail below step granularity for verify (see PROGRESS.md).\n",
					serverID)
				return nil
			}

			// Lock before buildDeps — see onboard.go's identical comment.
			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			return state.WithLock(stateDir, serverID, "verify", wait, func() error {
				wired, err := buildDeps(ctx, "verify", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				defer wired.Cleanup()

				if err := orchestrate.Verify(ctx, wired.Deps); err != nil {
					return err
				}

				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: verify passed — SHA-256 and row counts match the recorded manifest.\n", serverID)
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "`fortified enable-snapshots` is now unlocked for this server.")

				// Refresh status's own cache the same way backup does —
				// otherwise `status --all`'s cached "last passing verify"
				// column stays stuck at whatever it was before this run,
				// since orchestrate.Verify itself only updates state.json,
				// not the separate status-cache file. Best-effort: a
				// failure here must never turn a successful verify into a
				// reported failure.
				if rep, err := orchestrate.Status(ctx, wired.Deps); err == nil {
					_, _ = fmt.Fprintln(cmd.OutOrStdout())
					_ = report.WriteTable(cmd.OutOrStdout(), statusTable(rep))
					printStatusPathLists(cmd.OutOrStdout(), rep)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	addDryRunFlag(cmd, &dryRun)

	return cmd
}
