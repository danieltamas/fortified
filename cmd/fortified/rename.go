package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/audit"
	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// newRenameCmd syncs an onboarded server's Storage Box subaccount and
// local state to a server ID already changed in fleet.yaml. Every
// other command re-derives its Hetzner subaccount name and local state
// filename fresh from the server ID on every call (GetDestination,
// state.Load) — so editing fleet.yaml's server key alone (the obvious
// thing to do after renaming an SSH connection) silently strands the
// subaccount and local history under the old name, surfacing much
// later and confusingly as "no Storage Box subaccount named ...".
func newRenameCmd() *cobra.Command {
	var (
		configPath string
		dryRun     bool
		wait       bool
	)

	cmd := &cobra.Command{
		Use:   "rename <old-server-id> <new-server-id>",
		Short: "Sync an already-onboarded server's Storage Box subaccount and local state to a server ID you changed in fleet.yaml",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldID, newID := args[0], args[1]
			if oldID == newID {
				return fmt.Errorf("rename: old and new server IDs are identical")
			}

			fleet, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("rename: %w", err)
			}
			srv, ok := fleet.Servers[newID]
			if !ok {
				return fmt.Errorf("rename: %s is not configured in %s — fleet.yaml's server key is the source of truth this command syncs everything else to; rename it there first", newID, configPath)
			}
			if srv.Hetzner == nil {
				return fmt.Errorf("rename: %s has no hetzner: config block", newID)
			}

			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}

			doRename := func() error {
				// Local state first, and always for real even under
				// --dry-run's Hetzner side below: it's a same-host file
				// move, not a call to a shared remote system, and opening
				// newID's audit log (next) must append to real history
				// rather than a stub, which only happens if the move
				// already ran.
				if err := orchestrate.RenameServerState(stateDir, oldID, newID, dryRun, cmd.OutOrStdout()); err != nil {
					return fmt.Errorf("rename: %w", err)
				}

				ctx := cmd.Context()
				resolver := secrets.Resolver{Runner: sshx.ExecRunner{}}
				hcloudToken, err := resolver.Resolve(ctx, srv.Hetzner.HCloudTokenRef)
				if err != nil {
					return fmt.Errorf("rename: resolve hcloud_token_ref: %w", err)
				}
				storageBoxID, err := strconv.ParseInt(srv.Destination, 10, 64)
				if err != nil {
					return fmt.Errorf("rename: destination %q is not a valid Hetzner Storage Box ID: %w", srv.Destination, err)
				}

				invocationID, err := audit.NewInvocationID()
				if err != nil {
					return fmt.Errorf("rename: %w", err)
				}
				writer, err := audit.OpenWriter(filepath.Join(stateDir, newID+".audit.jsonl"))
				if err != nil {
					return fmt.Errorf("rename: %w", err)
				}
				defer func() { _ = writer.Close() }()

				httpClient := &http.Client{Transport: audit.RoundTripper{
					Next: http.DefaultTransport, Writer: writer, Command: "rename", InvocationID: invocationID,
				}}
				hcloudClient := hcloud.NewClient(hcloud.WithToken(hcloudToken), hcloud.WithHTTPClient(httpClient))

				// The main account's SFTP calls (moving the actual repo/keys
				// between subaccount home directories) run from the control
				// host, never a protected server — same as onboard's own
				// InstallServerKey (NOTES.md).
				storageBoxRunner := audit.Runner{Next: sshx.ExecRunner{}, Writer: writer, Command: "rename", InvocationID: invocationID}
				main := hetzner.MainAccount{Target: sshx.Target{
					Host: srv.Hetzner.MainAccount.Host, Port: srv.Hetzner.MainAccount.Port, User: srv.Hetzner.MainAccount.User,
				}}

				provider := hetzner.Provider{Client: hcloudClient, StorageBoxID: storageBoxID, DryRun: dryRun, Out: cmd.OutOrStdout()}
				dest, err := provider.RenameDestination(ctx, storageBoxRunner, main, oldID, newID)
				if err != nil {
					return fmt.Errorf("rename: %w", err)
				}

				if !dryRun {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: renamed to %s (Storage Box subaccount %d, home %s)\n", oldID, newID, dest.SubaccountID, dest.HomeDirectory)
				}
				return nil
			}

			// Hold both oldID's and newID's per-server locks for the
			// whole rename — without this, a backup/verify/etc. running
			// concurrently against either ID can race the file moves
			// (state.Save mid-flight re-creating a file this just moved
			// away) or the Hetzner-side rename, leaving state split
			// between the two IDs. Always lock in the same (sorted)
			// order regardless of which is "old" vs "new" so two
			// concurrent renames can never deadlock against each other.
			first, second := oldID, newID
			if second < first {
				first, second = second, first
			}
			return state.WithLock(stateDir, first, "rename", wait, func() error {
				return state.WithLock(stateDir, second, "rename", wait, doRename)
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	addDryRunFlag(cmd, &dryRun)
	cmd.Flags().BoolVar(&wait, "wait", false, "block until both server's locks are free instead of failing fast")

	return cmd
}
