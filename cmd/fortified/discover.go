package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/report"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "fortified", "fleet.yaml")
}

// resolveTarget builds the SSH target for serverID: explicit --host
// wins; otherwise it's looked up from an existing config; failing
// that (no config file yet, or the server just isn't in it yet), it
// falls back to treating serverID itself as the SSH destination —
// exactly like typing `ssh <serverID>` yourself, which lets a
// ~/.ssh/config Host alias (HostName/IdentityFile/ProxyJump/...)
// resolve the rest. This only ever kicks in for the "not configured
// yet" cases: a config file that exists but fails to load for a real
// reason (bad YAML, an unresolved TODO, a plaintext secret) is
// surfaced as an error instead of silently falling through to a
// confusing SSH connection failure.
func resolveTarget(configPath, serverID, host string, port int, user string) (sshx.Target, error) {
	if host != "" {
		return sshx.Target{Host: host, Port: port, User: user}, nil
	}

	fleet, err := config.Load(configPath)
	switch {
	case err == nil:
		if srv, ok := fleet.Servers[serverID]; ok {
			return sshx.Target{Host: srv.SSH.Host, Port: srv.SSH.Port, User: srv.SSH.User}, nil
		}
	case errors.Is(err, os.ErrNotExist):
		// No config file yet at all — expected on a first-ever discover.
	default:
		return sshx.Target{}, fmt.Errorf("discover: %s is not configured and --host was not given; load %s failed: %w", serverID, configPath, err)
	}

	return sshx.Target{Host: serverID, Port: port, User: user}, nil
}

func newDiscoverCmd(jsonOutput *bool) *cobra.Command {
	var (
		host             string
		port             int
		user             string
		configPath       string
		emitConfig       bool
		provider         string
		destination      string
		refreshDatabases bool
	)

	cmd := &cobra.Command{
		Use:   "discover <server-id>",
		Short: "Inspect a target server's real layout over SSH (read-only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serverID := args[0]

			if refreshDatabases && emitConfig {
				return fmt.Errorf("discover: --refresh-databases and --emit-config are mutually exclusive")
			}

			// Port/User only override the target's own ~/.ssh/config Host
			// alias (Port/User/IdentityFile/ProxyJump, ...) when the
			// operator actually typed --port/--user — an unconditional
			// -p 22 on argv beats that alias's own `Port 15086` line, so
			// the flags' mere defaults must never reach resolveTarget as
			// if they'd been chosen (see sshx.Target's doc comment).
			effectivePort := 0
			if cmd.Flags().Changed("port") {
				effectivePort = port
			}
			effectiveUser := ""
			if cmd.Flags().Changed("user") {
				effectiveUser = user
			}
			target, err := resolveTarget(configPath, serverID, host, effectivePort, effectiveUser)
			if err != nil {
				return err
			}

			// Session lifecycle lives here, at the call site, rather than
			// inside Inspect — that's the seam a future audit-log wire-up
			// (SPEC.md §4) needs: audit.Runner must wrap this *Session,
			// never the raw runner underneath it (see discover.Inspect's
			// doc comment for why the order matters).
			controlPath := fmt.Sprintf("/tmp/fortified-discover-%d-%s.sock", os.Getpid(), serverID)
			session, err := sshx.OpenSession(cmd.Context(), sshx.ExecRunner{}, target, controlPath)
			if err != nil {
				return fmt.Errorf("discover: %w", err)
			}
			defer func() { _ = session.Close(cmd.Context()) }()

			// Progress goes to stderr, never stdout: --emit-config pipes
			// stdout straight into a fleet.yaml file, and progress lines
			// mixed into that stream would corrupt it (verified live —
			// this is not hypothetical).
			progress := func(msg string) { _, _ = fmt.Fprintln(cmd.ErrOrStderr(), msg) }
			rep, err := discover.Inspect(cmd.Context(), session, serverID, discover.RealEgressIP, progress)
			if err != nil {
				return fmt.Errorf("discover: %w", err)
			}

			if emitConfig {
				fleet := discover.EmitConfig(rep, target, provider, destination)
				yamlBytes, err := discover.RenderYAML(fleet)
				if err != nil {
					return fmt.Errorf("discover: render config: %w", err)
				}
				_, err = cmd.OutOrStdout().Write(yamlBytes)
				return err
			}

			stateDir, err := defaultStateDir()
			if err != nil {
				return err
			}

			if refreshDatabases {
				if err := refreshDatabaseState(stateDir, serverID, rep, cmd.ErrOrStderr()); err != nil {
					return err
				}
				r := report.Reporter{JSON: *jsonOutput}
				return r.Render(cmd.OutOrStdout(), rep, func() report.Table { return discoverTable(rep) })
			}

			if err := writeDiscoveredConfig(cmd.Context(), configPath, stateDir, serverID, destination, rep, target, cmd.InOrStdin(), cmd.ErrOrStderr()); err != nil {
				return err
			}

			r := report.Reporter{JSON: *jsonOutput}
			return r.Render(cmd.OutOrStdout(), rep, func() report.Table { return discoverTable(rep) })
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "SSH host — required the first time a server isn't yet in --config")
	cmd.Flags().IntVar(&port, "port", 22, "SSH port — only applied if explicitly set; otherwise a ~/.ssh/config Host alias's own Port applies")
	cmd.Flags().StringVar(&user, "user", "root", "SSH user — only applied if explicitly set; otherwise a ~/.ssh/config Host alias's own User applies")
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "path to fleet.yaml")
	cmd.Flags().BoolVar(&emitConfig, "emit-config", false, "print a fleet.yaml stanza to stdout instead of writing it — for scripting; the default already writes/merges into --config for you")
	cmd.Flags().StringVar(&provider, "provider", "hetzner", "provider name for --emit-config")
	cmd.Flags().StringVar(&destination, "destination", "", "Storage Box ID to use — with --emit-config, required; otherwise optional, skips the destination prompt for a new server")
	cmd.Flags().BoolVar(&refreshDatabases, "refresh-databases", false, "re-run discovery and update this already-onboarded server's known database list in state — leaves config, keys, and the repo untouched; the next backup/verify picks up any added or removed database")

	return cmd
}

// refreshDatabaseState updates serverID's state.Databases from a fresh
// discover run without touching config, keys, or the repo — the one
// gap onboard's one-time step-1 discovery and a plain discover run
// both leave open: onboard skips its discover step once
// LastCompletedStep >= 1, and writeDiscoveredConfig refuses to touch
// an already-onboarded server's config at all (by design, to protect
// its keys/destination). Without this, a database container added to
// a server after onboarding is invisible to backup/verify forever —
// they read state.Databases, not a fresh live inspection.
func refreshDatabaseState(stateDir, serverID string, rep *discover.Report, out io.Writer) error {
	st, err := state.Load(stateDir, serverID)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if !st.Provider.RepoInitialized {
		return fmt.Errorf("discover: %s has not completed onboarding yet — run onboard first, which discovers databases as part of its own step 1", serverID)
	}
	if rep.Incomplete {
		return fmt.Errorf("discover result is incomplete (%s) — refusing to refresh; re-run once the target is fully reachable",
			strings.Join(rep.IncompleteReasons, "; "))
	}

	before := containerNames(st.Databases)
	st.Databases = rep.Databases
	if err := state.Save(stateDir, st); err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	after := containerNames(st.Databases)

	added, removed := diffContainerNames(before, after)
	switch {
	case len(added) == 0 && len(removed) == 0:
		_, _ = fmt.Fprintf(out, "%s: refreshed — no change to the known database list\n", serverID)
	default:
		if len(added) > 0 {
			_, _ = fmt.Fprintf(out, "%s: now tracking %s (included starting with the next backup)\n", serverID, strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			_, _ = fmt.Fprintf(out, "%s: no longer tracking %s (container is gone)\n", serverID, strings.Join(removed, ", "))
		}
	}
	return nil
}

func containerNames(dbs []discover.DatabaseInstance) []string {
	names := make([]string, len(dbs))
	for i, db := range dbs {
		names[i] = db.Container
	}
	sort.Strings(names)
	return names
}

func diffContainerNames(before, after []string) (added, removed []string) {
	beforeSet := make(map[string]bool, len(before))
	for _, n := range before {
		beforeSet[n] = true
	}
	afterSet := make(map[string]bool, len(after))
	for _, n := range after {
		afterSet[n] = true
	}
	for _, n := range after {
		if !beforeSet[n] {
			added = append(added, n)
		}
	}
	for _, n := range before {
		if !afterSet[n] {
			removed = append(removed, n)
		}
	}
	return added, removed
}

// writeDiscoveredConfig adds serverID to configPath's fleet.yaml (or
// fills in whatever's still missing on an existing-but-not-yet-
// onboarded entry) from a fresh discover run — no more manual
// --emit-config-then-paste-by-hand step. It leaves the config alone
// in exactly one case: serverID is already onboarded and working
// (state.Server.Provider.RepoInitialized), since a re-run of discover
// against a live, working server must never silently rewrite its
// destination/keys out from under it.
func writeDiscoveredConfig(ctx context.Context, configPath, stateDir, serverID, explicitDestination string, rep *discover.Report, target sshx.Target, in io.Reader, out io.Writer) error {
	fleet, err := config.Load(configPath)
	switch {
	case err == nil:
		// fall through
	case errors.Is(err, os.ErrNotExist):
		fleet = &config.Fleet{Servers: map[string]config.Server{}}
	default:
		return fmt.Errorf("discover: %w", err)
	}

	existing, hasExisting := fleet.Servers[serverID]

	if hasExisting {
		st, err := state.Load(stateDir, serverID)
		if err != nil {
			return fmt.Errorf("discover: %w", err)
		}
		if st.Provider.RepoInitialized {
			_, _ = fmt.Fprintf(out, "%s: already onboarded — leaving %s untouched\n", serverID, configPath)
			return nil
		}
	}

	var existingPtr *config.Server
	if hasExisting {
		existingPtr = &existing
	}

	dest := discover.ResolvedDestination{EncryptionKeyRef: defaultEncryptionKeyRef(serverID)}
	if !hasExisting || existing.Destination == "" {
		resolved, err := resolveDestination(ctx, fleet, explicitDestination, http.DefaultClient, bufio.NewScanner(in), out)
		if err != nil {
			return fmt.Errorf("discover: resolve destination: %w", err)
		}
		dest = resolved
		dest.EncryptionKeyRef = defaultEncryptionKeyRef(serverID)
	}

	resolvedTarget := target
	if !hasExisting || existing.SSH.Port == 0 || existing.SSH.User == "" {
		resolvedTarget = resolveSSHConfigDefaults(serverID, target)
	}

	merged := discover.BuildOrMergeServerConfig(existingPtr, rep, resolvedTarget, dest)

	attempt := &config.Fleet{Servers: make(map[string]config.Server, len(fleet.Servers)+1)}
	for id, srv := range fleet.Servers {
		// config.Load silently back-fills a nil Retention with
		// DefaultRetention on every server it reads (see load.go) —
		// harmless as long as nothing re-persists it, but writing
		// attempt straight back out would bake that implicit default
		// into every other, untouched server's entry just because one
		// new server was being added. Undo it for anything we're not
		// actually touching, so the only visible diff is serverID's own
		// entry.
		if id != serverID && srv.Retention != nil && *srv.Retention == config.DefaultRetention {
			srv.Retention = nil
		}
		attempt.Servers[id] = srv
	}
	attempt.Servers[serverID] = merged

	if err := config.Validate(attempt); err != nil {
		if errors.Is(err, config.ErrUnresolvedTODO) {
			return writeDraftConfig(configPath, serverID, merged, out)
		}
		return fmt.Errorf("discover: %w", err)
	}

	if err := config.Save(configPath, attempt); err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if hasExisting {
		_, _ = fmt.Fprintf(out, "%s: filled in missing config in %s\n", serverID, configPath)
	} else {
		_, _ = fmt.Fprintf(out, "%s: added to %s — set %s, then run onboard\n", serverID, configPath, merged.EncryptionKeyRef)
	}
	return nil
}

// writeDraftConfig handles the one case a fresh discover run can't
// fully resolve on its own: a database whose auth couldn't be
// auto-detected, left as "TODO" by databaseEntries. Writing that
// straight into the shared fleet.yaml would fail Validate for every
// other, unrelated server too (config.Load re-validates the whole
// file on every command) — so it goes to its own draft file instead,
// exactly like --emit-config's stanza, for the operator to finish and
// merge in by hand.
func writeDraftConfig(configPath, serverID string, srv config.Server, out io.Writer) error {
	draftPath := filepath.Join(filepath.Dir(configPath), serverID+".pending.yaml")
	yamlBytes, err := discover.RenderYAML(&config.Fleet{Servers: map[string]config.Server{serverID: srv}})
	if err != nil {
		return fmt.Errorf("discover: render draft config: %w", err)
	}
	if err := os.WriteFile(draftPath, yamlBytes, 0o600); err != nil {
		return fmt.Errorf("discover: write draft config: %w", err)
	}
	_, _ = fmt.Fprintf(out, "%s: some fields need your input (marked TODO, usually a database's auth_ref) — wrote a draft to %s; resolve the TODO(s), then merge its servers.%s entry into %s\n",
		serverID, draftPath, serverID, configPath)
	return nil
}

func discoverTable(rep *discover.Report) report.Table {
	rows := [][]string{
		{"volume manager", volumeManagerSummary(rep)},
		{"raid", strconv.FormatBool(rep.RAID.Present)},
		{"containers", strconv.Itoa(len(rep.Containers))},
		{"databases", strconv.Itoa(len(rep.Databases))},
		{"exposure findings", strconv.Itoa(len(rep.Exposure))},
		{"known state paths found", knownStatePathsSummary(rep)},
		{"borg installed", strconv.FormatBool(rep.Prerequisites.BorgInstalled)},
		{"docker installed", strconv.FormatBool(rep.Prerequisites.DockerInstalled)},
		{"incomplete", strconv.FormatBool(rep.Incomplete)},
	}
	return report.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

// knownStatePathsSummary lists the fixed well-known stateful paths
// discover found present (WireGuard, Tailscale, native nginx, ...) —
// these are candidates for --emit-config's archive: list, surfaced
// here so a plain (non-emit-config) discover run also shows what a
// docker-compose-only heuristic would otherwise miss silently.
func knownStatePathsSummary(rep *discover.Report) string {
	if len(rep.KnownStatePaths) == 0 {
		return "none"
	}
	return strings.Join(rep.KnownStatePaths, ", ")
}

func volumeManagerSummary(rep *discover.Report) string {
	if rep.VolumeManager.NoLiveSnapshot() {
		return "none (database backups must go through the engine, never raw file copy)"
	}
	var kinds []string
	if rep.VolumeManager.HasLVM {
		kinds = append(kinds, "LVM")
	}
	if rep.VolumeManager.HasZFS {
		kinds = append(kinds, "ZFS")
	}
	if rep.VolumeManager.HasBtrfs {
		kinds = append(kinds, "Btrfs")
	}
	summary := kinds[0]
	for _, k := range kinds[1:] {
		summary += ", " + k
	}
	return summary
}
