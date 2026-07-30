package main

import (
	"fmt"
	"strconv"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
)

// statusDirect answers "what's actually backed up" without ever
// contacting the target server — deliberately lighter wiring than
// buildDeps, which unconditionally opens an SSH session to the target
// before doing anything else and would hang or fail outright if the
// target is exactly the thing that's gone (SPEC.md's disaster-
// recovery case this flag exists for). It needs nothing from the
// target: fleet.yaml gives the destination/encryption_key_ref, the
// Hetzner API gives the Storage Box subaccount, and identityPath is
// the operator's own key file, supplied fresh every invocation —
// fortified never generates or stores one for this path.
func statusDirect(cmd *cobra.Command, configPath, serverID, identityPath string, jsonOutput bool) error {
	ctx := cmd.Context()

	fleet, err := config.Load(configPath)
	if err != nil {
		return err
	}
	srv, ok := fleet.Servers[serverID]
	if !ok {
		return fmt.Errorf("status --direct: %s is not configured in %s", serverID, configPath)
	}
	if srv.Hetzner == nil {
		return fmt.Errorf("status --direct: %s has no hetzner: config block", serverID)
	}

	resolver := secrets.Resolver{Runner: sshx.ExecRunner{}}
	hcloudToken, err := resolver.Resolve(ctx, srv.Hetzner.HCloudTokenRef)
	if err != nil {
		return fmt.Errorf("status --direct: resolve hcloud_token_ref: %w", err)
	}
	storageBoxID, err := strconv.ParseInt(srv.Destination, 10, 64)
	if err != nil {
		return fmt.Errorf("status --direct: destination %q is not a valid Storage Box ID: %w", srv.Destination, err)
	}
	hcloudClient := hcloud.NewClient(hcloud.WithToken(hcloudToken))

	d := orchestrate.Deps{
		Provider: hetzner.Provider{Client: hcloudClient, StorageBoxID: storageBoxID},
		// Runner executes locally, on the control host — never through
		// an SSH session to the target — which is the whole point.
		Backend:  borg.Backend{Runner: sshx.ExecRunner{}},
		Secrets:  resolver,
		Server:   srv,
		ServerID: serverID,
	}

	rep, err := orchestrate.StatusDirect(ctx, d, identityPath)
	if err != nil {
		return err
	}
	r := report.Reporter{JSON: jsonOutput}
	return r.Render(cmd.OutOrStdout(), rep, func() report.Table { return statusTable(rep) })
}
