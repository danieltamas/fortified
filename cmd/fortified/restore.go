package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/state"
)

func newRestoreCmd(jsonOutput *bool) *cobra.Command {
	var (
		configPath string
		wait       bool
		archive    string
		into       string
		db         string
	)

	cmd := &cobra.Command{
		Use:   "restore <server-id>",
		Short: "Extract an archive (or one database's dump) into a directory on the target — run without --archive to list archives",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			return state.WithLock(stateDir, serverID, "restore", wait, func() error {
				wired, err := buildDeps(ctx, "restore", configPath, serverID, false, cmd.OutOrStdout(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				defer wired.Cleanup()

				rep, err := orchestrate.Restore(ctx, wired.Deps, orchestrate.RestoreOptions{Archive: archive, Into: into, DB: db})
				if err != nil {
					return err
				}

				if archive == "" {
					r := report.Reporter{JSON: *jsonOutput}
					return r.Render(cmd.OutOrStdout(), rep, func() report.Table { return restoreArchivesTable(rep) })
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: restored archive %s into %s.\n", serverID, rep.Restored, rep.Into)
				if rep.ExtractedPath != rep.Into {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Database dump extracted to: %s\n", rep.ExtractedPath)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	cmd.Flags().StringVar(&archive, "archive", "", "archive name to restore, or \"latest\" — omit to list archives instead")
	cmd.Flags().StringVar(&into, "into", "", "target directory on the server to extract into — must not exist with content, and must not be a live database's own data mount")
	cmd.Flags().StringVar(&db, "db", "", "restore only this database's own dump file, not the whole archive")

	return cmd
}

func restoreArchivesTable(rep orchestrate.RestoreResult) report.Table {
	rows := make([][]string, 0, len(rep.Archives))
	for _, a := range rep.Archives {
		rows = append(rows, []string{a})
	}
	if len(rows) == 0 {
		rows = [][]string{{"(none)"}}
	}
	return report.Table{Headers: []string{"ARCHIVE"}, Rows: rows}
}
