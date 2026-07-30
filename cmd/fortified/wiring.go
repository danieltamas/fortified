package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/audit"
	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/orchestrate"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
)

// defaultStateDir is where every server's state record, lock file, and
// audit log live (SPEC.md §4) — a private git repo is fine for an
// operator to point this at, since the directory holds only names and
// facts, never resolved secret values.
//
// It creates the directory before returning: state.WithLock needs it
// to already exist to even attempt the lock file, and every caller
// calls this immediately before WithLock — on a fresh install with no
// state directory yet, WithLock would otherwise fail with "no such
// file or directory" before ever reaching the code that would have
// created it (verified live — this is not hypothetical).
func defaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	dir := filepath.Join(home, ".config", "fortified", "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create state directory: %w", err)
	}
	return dir, nil
}

// addDryRunFlag registers the --dry-run flag every lock-taking command
// shares (SPEC.md §5), so its help text and name never drift between
// commands.
func addDryRunFlag(cmd *cobra.Command, dryRun *bool) {
	cmd.Flags().BoolVar(dryRun, "dry-run", false, "print what this command would do instead of running it — nothing is mutated")
}

// wiredDeps bundles an orchestrate.Deps ready to use with a cleanup
// function the caller must run when done (closes the SSH session and
// the audit log).
type wiredDeps struct {
	Deps    orchestrate.Deps
	Cleanup func()
}

// buildDeps loads config, opens the target session and the audit log,
// and assembles everything internal/orchestrate needs for one command
// invocation against one server — every lock-taking command
// (onboard/backup/verify/enable-snapshots) shares this exact wiring,
// so the composition order that keeps secrets out of the audit log
// (audit.Runner wraps the Session, never the raw runner beneath it —
// see internal/discover.Inspect's doc comment for why) only has to be
// gotten right once.
//
// out carries real, potentially-pipeable command output (dry-run plan
// lines); errOut carries Deps.Progress's step-by-step reporting — kept
// on separate streams so a command's stdout never gets progress lines
// mixed into it (see discover.go's identical split, and the bug that
// motivated it: --emit-config's stdout is piped straight into a
// fleet.yaml file).
//
// dryRun sets Provider.DryRun/Out (hetzner.Provider's doc comment
// explains why enable-snapshots is the one command whose --dry-run
// can be handled this precisely — its Hetzner API call has no
// interleaved mutate-then-read-back step depending on it). onboard,
// backup, and verify implement --dry-run as a coarser, command-level
// summary instead, for the reason documented at each of their call
// sites: their core logic immediately reads back what it just wrote
// (a checksum, a row count) to build or check a verification
// baseline, so skipping only the mutating half and still running the
// read half for real would just produce a confusing "file not found"
// instead of a clean plan.
func buildDeps(ctx context.Context, command, configPath, serverID string, dryRun bool, out, errOut io.Writer) (wiredDeps, error) {
	fleet, err := config.Load(configPath)
	if err != nil {
		return wiredDeps{}, fmt.Errorf("%s: %w", command, err)
	}
	srv, ok := fleet.Servers[serverID]
	if !ok {
		return wiredDeps{}, fmt.Errorf("%s: %s is not configured in %s", command, serverID, configPath)
	}
	if srv.Hetzner == nil {
		return wiredDeps{}, fmt.Errorf("%s: %s has no hetzner: config block", command, serverID)
	}

	stateDir, err := defaultStateDir()
	if err != nil {
		return wiredDeps{}, fmt.Errorf("%s: %w", command, err)
	}

	invocationID, err := audit.NewInvocationID()
	if err != nil {
		return wiredDeps{}, fmt.Errorf("%s: %w", command, err)
	}
	writer, err := audit.OpenWriter(filepath.Join(stateDir, serverID+".audit.jsonl"))
	if err != nil {
		return wiredDeps{}, fmt.Errorf("%s: %w", command, err)
	}

	controlPath := fmt.Sprintf("/tmp/fortified-%s-%d.sock", serverID, os.Getpid())
	target := sshx.Target{Host: srv.SSH.Host, Port: srv.SSH.Port, User: srv.SSH.User}
	session, err := sshx.OpenSession(ctx, sshx.ExecRunner{}, target, controlPath)
	if err != nil {
		_ = writer.Close()
		return wiredDeps{}, fmt.Errorf("%s: %w", command, err)
	}

	targetRunner := audit.Runner{Next: session, Writer: writer, Command: command, InvocationID: invocationID}
	storageBoxRunner := audit.Runner{Next: sshx.ExecRunner{}, Writer: writer, Command: command, InvocationID: invocationID}
	secretsRunner := audit.Runner{Next: sshx.ExecRunner{}, Writer: writer, Command: command, InvocationID: invocationID}
	resolver := secrets.Resolver{Runner: secretsRunner}

	cleanup := func() {
		_ = session.Close(ctx)
		_ = writer.Close()
	}

	hcloudToken, err := resolver.Resolve(ctx, srv.Hetzner.HCloudTokenRef)
	if err != nil {
		cleanup()
		return wiredDeps{}, fmt.Errorf("%s: resolve hcloud_token_ref: %w", command, err)
	}
	storageBoxID, err := strconv.ParseInt(srv.Destination, 10, 64)
	if err != nil {
		cleanup()
		return wiredDeps{}, fmt.Errorf("%s: destination %q is not a valid Hetzner Storage Box ID: %w", command, srv.Destination, err)
	}

	httpClient := &http.Client{Transport: audit.RoundTripper{
		Next: http.DefaultTransport, Writer: writer, Command: command, InvocationID: invocationID,
	}}
	hcloudClient := hcloud.NewClient(hcloud.WithToken(hcloudToken), hcloud.WithHTTPClient(httpClient))

	return wiredDeps{
		Deps: orchestrate.Deps{
			Target:     targetRunner,
			StorageBox: storageBoxRunner,
			// Same underlying mechanism as storageBoxRunner (local exec,
			// audited) — reused rather than built twice, since both are
			// "runs on the control host, never the target."
			Local:    storageBoxRunner,
			Provider: hetzner.Provider{Client: hcloudClient, StorageBoxID: storageBoxID, DryRun: dryRun, Out: out},
			Backend:  borg.Backend{Runner: targetRunner},
			Secrets:  resolver,
			StateDir: stateDir,
			Server:   srv,
			ServerID: serverID,
			// Progress goes to errOut (stderr), never out (stdout) — same
			// reasoning as discover.go: a command's stdout must stay
			// pipeable, and progress lines are logging, not data.
			Progress: func(msg string) { _, _ = fmt.Fprintln(errOut, msg) },
			// LiveOutput also goes to errOut — same pipeable-stdout
			// reasoning. borg's own --progress output manages its
			// terminal line itself (carriage returns), so this is a raw
			// passthrough, not line-buffered like Progress.
			LiveOutput: errOut,
		},
		Cleanup: cleanup,
	}, nil
}
