package main

import "github.com/spf13/cobra"

// newRootCmd builds the fortified command tree. The --json flag is
// persistent so every subcommand can pass it straight to a
// report.Reporter without redeclaring it.
func newRootCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:           "fortified",
		Short:         "Deterministic backup and disaster-recovery CLI for a self-hosted server fleet",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	cmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "render output as JSON instead of a table")
	cmd.AddCommand(newVersionCmd(&jsonOutput))
	cmd.AddCommand(newDiscoverCmd(&jsonOutput))
	cmd.AddCommand(newOnboardCmd())
	cmd.AddCommand(newBackupCmd())
	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newEnableSnapshotsCmd())
	cmd.AddCommand(newAuditKeysCmd(&jsonOutput))
	cmd.AddCommand(newStatusCmd(&jsonOutput))
	cmd.AddCommand(newCheckCmd())
	cmd.AddCommand(newRestoreCmd(&jsonOutput))
	cmd.AddCommand(newPruneCmd())
	cmd.AddCommand(newDrillCmd(&jsonOutput))
	cmd.AddCommand(newSettingsCmd())
	cmd.AddCommand(newRenameCmd())

	return cmd
}
