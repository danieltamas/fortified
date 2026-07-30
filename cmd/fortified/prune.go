package main

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/state"
)

func newPruneCmd() *cobra.Command {
	var (
		configPath string
		wait       bool
		dryRun     bool
		pruneKey   string
		yesIMeanIt bool
	)

	cmd := &cobra.Command{
		Use:   "prune <server-id> --prune-key <path>",
		Short: "Enforce the retention policy against the repo — the one command that requires the unrestricted key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"[dry-run] would run an integrity check against %s's repo, then (only if it passes) enforce the configured retention policy using the supplied --prune-key.\n", serverID)
				return nil
			}

			if !yesIMeanIt {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"prune will permanently delete %s's archives outside the configured retention policy — this cannot be undone.\n", serverID)
				_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Type \"yes\" to continue (default: abort), or pass --yes-i-mean-it to skip this prompt: ")
				scanner := bufio.NewScanner(cmd.InOrStdin())
				if !scanner.Scan() || strings.TrimSpace(strings.ToLower(scanner.Text())) != "yes" {
					return fmt.Errorf("prune: aborted — nothing was pruned")
				}
			}

			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			return state.WithLock(stateDir, serverID, "prune", wait, func() error {
				wired, err := buildDeps(ctx, "prune", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				defer wired.Cleanup()

				if err := orchestrate.Prune(ctx, wired.Deps, orchestrate.PruneOptions{PruneKeyPath: pruneKey}); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: pruned to the configured retention policy.\n", serverID)
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	cmd.Flags().StringVar(&pruneKey, "prune-key", "", "path to the unrestricted prune key — required, supplied explicitly every time, never cached")
	cmd.Flags().BoolVar(&yesIMeanIt, "yes-i-mean-it", false, "skip the interactive confirmation prompt — for scripted/cron use")
	addDryRunFlag(cmd, &dryRun)

	return cmd
}
