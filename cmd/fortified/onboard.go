package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/state"
)

func newOnboardCmd() *cobra.Command {
	var (
		configPath         string
		escrowAcknowledged bool
		wait               bool
		dryRun             bool
	)

	cmd := &cobra.Command{
		Use:   "onboard <server-id>",
		Short: "Provision a server's isolated backup destination and append-only key (SPEC.md §5)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			// Step 4 (keypair generation) immediately reads back what it
			// just wrote (cat the generated pubkey, fingerprint it) —
			// skipping only the mutating half and still running that
			// readback for real would fail against a file that was never
			// created. So --dry-run here is a coarse, honest summary, not
			// a per-step transcript — see verify's identical reasoning —
			// and it never touches state (a preview has no side effects).
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"[dry-run] would run %s's incomplete onboard steps (discover, install borg if missing, confirm destination, generate+install the append-only automation key, init the repo) — no plan-level detail below step granularity for onboard (see PROGRESS.md).\n",
					serverID)
				return nil
			}

			// The lock must be acquired before buildDeps, not after: it
			// opens an SSH master session and resolves the hcloud token
			// secret, both of which cost real time and can themselves
			// fail — a contending invocation should fail fast on "locked
			// by pid X" immediately, not after first paying for (and
			// possibly failing at) that setup work.
			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			return state.WithLock(stateDir, serverID, "onboard", wait, func() error {
				wired, err := buildDeps(ctx, "onboard", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				defer wired.Cleanup()

				if err := orchestrate.Onboard(ctx, wired.Deps, orchestrate.OnboardOptions{EscrowAcknowledged: escrowAcknowledged}); err != nil {
					return err
				}

				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s onboarded: destination confirmed, append-only key installed, repo initialized.\n", serverID)
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Snapshots remain disabled until `fortified verify` passes (SPEC.md §4).")
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&escrowAcknowledged, "escrow-acknowledged", false,
		"confirm the repo encryption passphrase has been escrowed — required to reach step 5 (SKILL.md's key custody rule)")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	addDryRunFlag(cmd, &dryRun)

	return cmd
}
