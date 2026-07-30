package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

func TestResolveTargetHostFlagWins(t *testing.T) {
	got, err := resolveTarget(filepath.Join(t.TempDir(), "missing.yaml"), "host-2-example", "1.2.3.4", 22, "root")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	want := sshx.Target{Host: "1.2.3.4", Port: 22, User: "root"}
	if got != want {
		t.Errorf("resolveTarget = %+v, want %+v", got, want)
	}
}

func TestResolveTargetFallsBackToServerIDWhenConfigMissing(t *testing.T) {
	got, err := resolveTarget(filepath.Join(t.TempDir(), "missing.yaml"), "host-2-example", "", 2222, "deploy")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	want := sshx.Target{Host: "host-2-example", Port: 2222, User: "deploy"}
	if got != want {
		t.Errorf("resolveTarget = %+v, want %+v (should fall back to the server-id as SSH destination)", got, want)
	}
}

func TestResolveTargetFallsBackWhenServerNotInConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	writeMinimalFleetConfig(t, path, "some-other-server")

	got, err := resolveTarget(path, "host-2-example", "", 22, "root")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	want := sshx.Target{Host: "host-2-example", Port: 22, User: "root"}
	if got != want {
		t.Errorf("resolveTarget = %+v, want %+v (should fall back — server isn't configured yet)", got, want)
	}
}

func TestResolveTargetUsesConfiguredServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	writeMinimalFleetConfig(t, path, "host-2-example")

	got, err := resolveTarget(path, "host-2-example", "", 22, "root")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	want := sshx.Target{Host: "configured.example.com", Port: 2200, User: "svc"}
	if got != want {
		t.Errorf("resolveTarget = %+v, want %+v (should use fleet.yaml's SSH details, not fall back)", got, want)
	}
}

func TestResolveTargetSurfacesBrokenConfigInsteadOfFallingBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml"), 0o600); err != nil {
		t.Fatalf("write broken config: %v", err)
	}

	_, err := resolveTarget(path, "host-2-example", "", 22, "root")
	if err == nil {
		t.Fatal("resolveTarget: expected an error for a broken config file, got nil")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("resolveTarget: got a not-exist error for a config that exists but is broken: %v", err)
	}
}

func TestRefreshDatabaseStateRequiresOnboarding(t *testing.T) {
	dir := t.TempDir()
	// state.Load returns a fresh zero-value record when nothing's been
	// onboarded yet — RepoInitialized stays false.
	rep := &discover.Report{Databases: []discover.DatabaseInstance{{Container: "psql"}}}

	err := refreshDatabaseState(dir, "not-onboarded", rep, &bytes.Buffer{})
	if err == nil {
		t.Fatal("refreshDatabaseState: expected an error for a server that hasn't completed onboarding")
	}
	if !strings.Contains(err.Error(), "run onboard first") {
		t.Errorf("refreshDatabaseState error = %q, want it to mention running onboard first", err)
	}
}

func TestRefreshDatabaseStateRefusesIncompleteDiscover(t *testing.T) {
	dir := t.TempDir()
	saveOnboardedState(t, dir, "nakama.example.org", nil)

	rep := &discover.Report{Incomplete: true, IncompleteReasons: []string{"docker not reachable"}}
	err := refreshDatabaseState(dir, "nakama.example.org", rep, &bytes.Buffer{})
	if err == nil {
		t.Fatal("refreshDatabaseState: expected an error for an incomplete discover result")
	}
	if !strings.Contains(err.Error(), "docker not reachable") {
		t.Errorf("refreshDatabaseState error = %q, want it to surface the incomplete reason", err)
	}
}

func TestRefreshDatabaseStateAddsNewlyDiscoveredDatabase(t *testing.T) {
	dir := t.TempDir()
	serverID := "nakama.example.org"
	saveOnboardedState(t, dir, serverID, []discover.DatabaseInstance{{Container: "psql"}})

	rep := &discover.Report{Databases: []discover.DatabaseInstance{
		{Container: "psql"},
		{Container: "live.example.org-cockroachdb"},
	}}

	var out bytes.Buffer
	if err := refreshDatabaseState(dir, serverID, rep, &out); err != nil {
		t.Fatalf("refreshDatabaseState: %v", err)
	}
	if !strings.Contains(out.String(), "live.example.org-cockroachdb") {
		t.Errorf("refreshDatabaseState output = %q, want it to mention the newly tracked container", out.String())
	}

	st, err := state.Load(dir, serverID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if len(st.Databases) != 2 {
		t.Fatalf("state.Databases after refresh = %+v, want 2 entries", st.Databases)
	}
}

func TestRefreshDatabaseStateReportsNoChange(t *testing.T) {
	dir := t.TempDir()
	serverID := "host-2-example"
	dbs := []discover.DatabaseInstance{{Container: "psql"}, {Container: "mysql"}}
	saveOnboardedState(t, dir, serverID, dbs)

	rep := &discover.Report{Databases: dbs}
	var out bytes.Buffer
	if err := refreshDatabaseState(dir, serverID, rep, &out); err != nil {
		t.Fatalf("refreshDatabaseState: %v", err)
	}
	if !strings.Contains(out.String(), "no change") {
		t.Errorf("refreshDatabaseState output = %q, want it to report no change", out.String())
	}
}

func TestDiffContainerNames(t *testing.T) {
	added, removed := diffContainerNames([]string{"psql"}, []string{"psql", "cockroachdb"})
	if len(added) != 1 || added[0] != "cockroachdb" {
		t.Errorf("added = %+v, want [cockroachdb]", added)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %+v, want none", removed)
	}

	added, removed = diffContainerNames([]string{"psql", "mysql"}, []string{"psql"})
	if len(added) != 0 {
		t.Errorf("added = %+v, want none", added)
	}
	if len(removed) != 1 || removed[0] != "mysql" {
		t.Errorf("removed = %+v, want [mysql]", removed)
	}
}

func saveOnboardedState(t *testing.T, dir, serverID string, dbs []discover.DatabaseInstance) {
	t.Helper()
	st := &state.Server{
		SchemaVersion: state.SchemaVersion,
		ServerID:      serverID,
		Provider:      state.ProviderState{RepoInitialized: true},
		Databases:     dbs,
	}
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
}

func writeMinimalFleetConfig(t *testing.T, path, serverID string) {
	t.Helper()
	contents := `servers:
  ` + serverID + `:
    ssh:
      host: configured.example.com
      port: 2200
      user: svc
    provider: hetzner
    destination: host-backup
    hetzner:
      main_account:
        host: u123456.your-storagebox.de
        port: 22
        user: u123456
      hcloud_token_ref: env://HCLOUD_TOKEN
    encryption_key_ref: secret://fortified/` + serverID + `/borg-passphrase
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}
}
