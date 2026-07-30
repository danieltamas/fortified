package main

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/state"
)

func newBackupCmd() *cobra.Command {
	var (
		configPath string
		all        bool
		wait       bool
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "backup [server-id]",
		Short: "Run the staged-dump-then-archive backup sequence for a server, or every server with --all",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return fmt.Errorf("backup: pass either a server-id or --all, not both")
				}
				fleet, err := config.Load(configPath)
				if err != nil {
					return err
				}
				return backupAll(cmd, configPath, fleet, wait, dryRun)
			}

			if len(args) != 1 {
				return fmt.Errorf("backup: exactly one server-id is required (or --all)")
			}
			return backupOne(cmd, configPath, args[0], wait, dryRun)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&all, "all", false, "back up every configured server sequentially")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until a server's lock is free instead of failing fast")
	addDryRunFlag(cmd, &dryRun)

	return cmd
}

func backupOne(cmd *cobra.Command, configPath, serverID string, wait, dryRun bool) error {
	ctx := cmd.Context()

	// Every dump step immediately reads back what it just wrote (a
	// SHA-256, a row count) to build the verification manifest — there
	// is no way to skip only the mutating half of that chain and still
	// run the read half meaningfully (it would read a file that was
	// never created). So --dry-run here is a coarse, honest summary,
	// not a per-command transcript — see verify's identical reasoning.
	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"[dry-run] would stage each configured database's dump, record its SHA-256 + row counts, and create a new archive in %s's repo — no plan-level detail below step granularity for backup (see PROGRESS.md).\n",
			serverID)
		return nil
	}

	// Lock before buildDeps — see onboard.go's identical comment.
	stateDir, err := defaultStateDir()
	if err != nil {
		return err
	}
	return state.WithLock(stateDir, serverID, "backup", wait, func() error {
		wired, err := buildDeps(ctx, "backup", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		defer wired.Cleanup()

		if err := orchestrate.Backup(ctx, wired.Deps); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: backup complete.\n", serverID)

		// Reuse status's own summary (databases/sizes/archive info) so
		// a backup run ends with the same "what actually got backed
		// up, and how big" answer status gives on demand — printed
		// best-effort: a failure here must never turn an otherwise
		// successful backup into a reported failure.
		if rep, err := orchestrate.Status(ctx, wired.Deps); err == nil {
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
			_ = report.WriteTable(cmd.OutOrStdout(), statusTable(rep))
			printStatusPathLists(cmd.OutOrStdout(), rep)
		}
		return nil
	})
}

// backupAll runs every configured server sequentially: one server's
// failure never stops the others, and the command exits non-zero if
// *any* server failed, with a per-server summary — SPEC.md §5's
// "one cron entry covers the fleet" semantics. This is the dead-man
// switch: cron's alerting hangs off this command's exit code.
func backupAll(cmd *cobra.Command, configPath string, fleet *config.Fleet, wait, dryRun bool) error {
	ids := make([]string, 0, len(fleet.Servers))
	for id := range fleet.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var failed []string
	for _, id := range ids {
		if err := backupOne(cmd, configPath, id, wait, dryRun); err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: FAILED: %v\n", id, err)
			failed = append(failed, id)
			continue
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: ok\n", id)
	}

	if len(failed) > 0 {
		return fmt.Errorf("backup --all: %d/%d servers failed: %v", len(failed), len(ids), failed)
	}
	return nil
}
