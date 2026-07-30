package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// newDrillCmd wires SKILL.md's full-host-loss recovery tier, made
// runnable (SPEC.md §5): restore a server's backup onto a genuinely
// separate throwaway host, timed, with a passing drill recorded in
// state. Deliberately lighter wiring than buildDeps, same reasoning as
// status --direct: this never touches the server being drilled at
// all — only the Hetzner API (to find its destination) and local
// secrets resolution (to get the passphrase) — because proving
// recovery works must not depend on a credential still sitting on the
// very server a drill is supposed to prove you can survive losing.
func newDrillCmd(jsonOutput *bool) *cobra.Command {
	var (
		configPath string
		wait       bool
		targetHost string
		targetPort int
		targetUser string
		identity   string
		archive    string
		into       string
	)

	cmd := &cobra.Command{
		Use:   "drill <server-id> --target <throwaway-host> --identity <key-path> --into <path>",
		Short: "Prove a server's backup is actually recoverable, onto a genuinely separate throwaway host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]
			ctx := cmd.Context()

			if targetHost == "" {
				return fmt.Errorf("drill: --target is required — a throwaway host, never the server being drilled")
			}
			if identity == "" {
				return fmt.Errorf("drill: --identity is required — a private key file already authorized to read the repo")
			}
			if into == "" {
				return fmt.Errorf("drill: --into is required — the throwaway target directory to restore into")
			}

			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}
			return state.WithLock(stateDir, serverID, "drill", wait, func() error {
				fleet, err := config.Load(configPath)
				if err != nil {
					return err
				}
				srv, ok := fleet.Servers[serverID]
				if !ok {
					return fmt.Errorf("drill: %s is not configured in %s", serverID, configPath)
				}
				if srv.Hetzner == nil {
					return fmt.Errorf("drill: %s has no hetzner: config block", serverID)
				}

				resolver := secrets.Resolver{Runner: sshx.ExecRunner{}}
				hcloudToken, err := resolver.Resolve(ctx, srv.Hetzner.HCloudTokenRef)
				if err != nil {
					return fmt.Errorf("drill: resolve hcloud_token_ref: %w", err)
				}
				storageBoxID, err := strconv.ParseInt(srv.Destination, 10, 64)
				if err != nil {
					return fmt.Errorf("drill: destination %q is not a valid Storage Box ID: %w", srv.Destination, err)
				}
				hcloudClient := hcloud.NewClient(hcloud.WithToken(hcloudToken))

				d := orchestrate.Deps{
					Provider: hetzner.Provider{Client: hcloudClient, StorageBoxID: storageBoxID},
					Secrets:  resolver,
					StateDir: stateDir,
					Server:   srv,
					ServerID: serverID,
					Progress: func(msg string) { _, _ = fmt.Fprintln(cmd.ErrOrStderr(), msg) },
				}

				controlPath := fmt.Sprintf("/tmp/fortified-drill-%d-%s.sock", os.Getpid(), targetHost)
				throwawayTarget := sshx.Target{Host: targetHost, Port: targetPort, User: targetUser}
				session, err := sshx.OpenSession(ctx, sshx.ExecRunner{}, throwawayTarget, controlPath)
				if err != nil {
					return fmt.Errorf("drill: connect to throwaway target %s: %w", targetHost, err)
				}
				defer func() { _ = session.Close(ctx) }()

				result, err := orchestrate.Drill(ctx, d, session, orchestrate.DrillOptions{
					IdentityPath: identity,
					Archive:      archive,
					Into:         into,
				})
				if err != nil {
					return err
				}

				r := report.Reporter{JSON: *jsonOutput}
				return r.Render(cmd.OutOrStdout(), result, func() report.Table { return drillResultTable(result) })
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&wait, "wait", false, "block until the server's lock is free instead of failing fast")
	cmd.Flags().StringVar(&targetHost, "target", "", "the throwaway host to restore onto — required, never the server being drilled")
	cmd.Flags().IntVar(&targetPort, "target-port", 22, "SSH port for --target")
	cmd.Flags().StringVar(&targetUser, "target-user", "root", "SSH user for --target")
	cmd.Flags().StringVar(&identity, "identity", "", "a private key file already authorized to read the repo (an escrowed copy of the automation key, or the prune key) — required; fortified never generates or stores one for this")
	cmd.Flags().StringVar(&archive, "archive", "", "archive to restore — defaults to the latest")
	cmd.Flags().StringVar(&into, "into", "", "directory on the throwaway target to restore into — required")

	return cmd
}

func drillResultTable(result orchestrate.DrillResult) report.Table {
	return report.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
		{"archive", result.Archive},
		{"restored into", result.Into},
		{"elapsed", result.Elapsed.Round(time.Second).String()},
	}}
}
