package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/state"
)

// newAuditKeysCmd lists every key authorized on a server's isolated
// Storage Box destination, and optionally removes one by its exact
// comment. This is a lock-taking, mutating-when---remove-is-set
// command like onboard/backup/verify/enable-snapshots, sharing the
// same buildDeps wiring — even the read-only report path takes the
// lock, since it reads the same remote authorized_keys file a
// concurrent onboard/backup/verify run might be mid-write to.
func newAuditKeysCmd(jsonOutput *bool) *cobra.Command {
	var (
		configPath string
		wait       bool
		remove     string
	)

	cmd := &cobra.Command{
		Use:   "audit-keys <server-id>",
		Short: "List every key authorized on a server's isolated backup destination, and optionally remove one",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			return state.WithLock(stateDir, serverID, "audit-keys", wait, func() error {
				wired, err := buildDeps(ctx, "audit-keys", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				defer wired.Cleanup()

				if remove != "" {
					if err := orchestrate.RemoveKeyByComment(ctx, wired.Deps, remove); err != nil {
						return err
					}
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: removed authorized_keys entry with comment %q.\n", serverID, remove)
					return nil
				}

				entries, err := orchestrate.AuditKeys(ctx, wired.Deps)
				if err != nil {
					return err
				}
				r := report.Reporter{JSON: *jsonOutput}
				return r.Render(cmd.OutOrStdout(), entries, func() report.Table { return auditKeysTable(entries) })
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	cmd.Flags().StringVar(&remove, "remove", "",
		"remove the authorized_keys entry with this exact comment — review the report first; never removes fortified's own automation key")

	return cmd
}

func auditKeysTable(entries []hetzner.AuthorizedKeyEntry) report.Table {
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		restricted := "no"
		if e.Restricted {
			restricted = "yes: " + e.Command
		}
		owned := "no"
		if e.FortifiedOwned {
			owned = "yes"
		}
		rows = append(rows, []string{e.Comment, e.Format, restricted, owned})
	}
	return report.Table{Headers: []string{"COMMENT", "FORMAT", "RESTRICTED", "FORTIFIED-OWNED"}, Rows: rows}
}
