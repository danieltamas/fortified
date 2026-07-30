package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

func newServerConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "fleet.yaml")
}

// validExistingServer is a fully valid config.Server — every field
// config.Validate requires (SSH, Provider, Destination,
// EncryptionKeyRef, Hetzner) is set. This is the only shape an entry
// can have and still survive config.Load in the first place: Load
// re-validates the whole file on every read, so a "partial" entry
// missing any required field would already break every other,
// unrelated server's commands too — Archive/Databases are the only
// fields that can legitimately still be empty on an entry already
// sitting in a loadable fleet.yaml.
func validExistingServer() config.Server {
	srv := hetznerServer("433593")
	srv.SSH = config.SSH{Host: "203.0.113.10", Port: 15086, User: "root"}
	srv.EncryptionKeyRef = "env://BORG_PASSPHRASE_HOST_2_EXAMPLE"
	return srv
}

// TestWriteDiscoveredConfigAddsBrandNewServer proves discover on a
// server with no existing fleet.yaml entry at all writes a complete
// one — reusing the fleet's one existing Storage Box automatically,
// no --destination needed and no prompt hit (an empty stdin would
// make the test hang if resolveDestination tried to read from it).
func TestWriteDiscoveredConfigAddsBrandNewServer(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "test-token")
	configPath := newServerConfigPath(t)
	seed := &config.Fleet{Servers: map[string]config.Server{"host-2-example": validExistingServer()}}
	if err := config.Save(configPath, seed); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	stateDir := t.TempDir()

	rep := &discover.Report{ServerID: "example-nodejs"}
	target := sshx.Target{Host: "1.2.3.4", Port: 22, User: "root"}
	var out bytes.Buffer

	err := writeDiscoveredConfig(context.Background(), configPath, stateDir, "example-nodejs", "", rep, target, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("writeDiscoveredConfig: %v", err)
	}

	fleet, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load(written config): %v", err)
	}
	srv, ok := fleet.Servers["example-nodejs"]
	if !ok {
		t.Fatal("expected example-nodejs to have been added")
	}
	if srv.Destination != "433593" {
		t.Errorf("Destination = %q, want the fleet's existing 433593 reused", srv.Destination)
	}
	if srv.EncryptionKeyRef != "env://BORG_PASSPHRASE_EXAMPLE_NODEJS" {
		t.Errorf("EncryptionKeyRef = %q, want the auto-generated ref", srv.EncryptionKeyRef)
	}
	if srv.SSH != (config.SSH{Host: "1.2.3.4", Port: 22, User: "root"}) {
		t.Errorf("SSH = %+v, want the target's own connection details", srv.SSH)
	}
	// host-2-example must be completely untouched.
	if fleet.Servers["host-2-example"].Destination != "433593" {
		t.Error("expected host-2-example to remain untouched")
	}
	if !strings.Contains(out.String(), "added to") {
		t.Errorf("out = %q, want a note that the server was added", out.String())
	}

	// config.Load silently back-fills a nil Retention with
	// DefaultRetention on every server it reads — writing the raw
	// loaded fleet back out must not bake that implicit default into
	// host-2-example's own entry just because example-nodejs was
	// added; verified live: this exact bug produced a spurious diff
	// on the real fleet.yaml touching every unrelated server.
	raw, err := os.ReadFile(configPath) //nolint:gosec // configPath is the test's own temp file
	if err != nil {
		t.Fatalf("read raw config: %v", err)
	}
	if bytes.Contains(raw, []byte("retention:")) {
		t.Errorf("config = %s, want no retention: block written for an untouched server", raw)
	}
}

// TestWriteDiscoveredConfigLeavesAlreadyOnboardedServerUntouched
// proves a re-run of discover against a server that's already
// onboarded and working never rewrites its config out from under it —
// state.Provider.RepoInitialized is the signal, not fleet.yaml
// presence alone.
func TestWriteDiscoveredConfigLeavesAlreadyOnboardedServerUntouched(t *testing.T) {
	configPath := newServerConfigPath(t)
	seed := &config.Fleet{Servers: map[string]config.Server{"host-2-example": validExistingServer()}}
	if err := config.Save(configPath, seed); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	stateDir := t.TempDir()
	st := &state.Server{ServerID: "host-2-example"}
	st.Provider.RepoInitialized = true
	if err := state.Save(stateDir, st); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	rep := &discover.Report{ServerID: "host-2-example", ComposeFiles: []string{"/home/new/docker-compose.yml"}}
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	var out bytes.Buffer

	err := writeDiscoveredConfig(context.Background(), configPath, stateDir, "host-2-example", "", rep, target, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("writeDiscoveredConfig: %v", err)
	}

	fleet, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if len(fleet.Servers["host-2-example"].Archive) != 0 {
		t.Errorf("Archive = %+v, want it left untouched (empty) since the server is already onboarded", fleet.Servers["host-2-example"].Archive)
	}
	if !strings.Contains(out.String(), "already onboarded") {
		t.Errorf("out = %q, want a note explaining nothing was written", out.String())
	}
}

// TestWriteDiscoveredConfigFillsInMissingFieldsOnPartialEntry proves a
// server that's already fully configured (SSH/destination/keys — the
// only shape that can survive config.Load at all, since Load rejects
// any entry missing a required field) but never onboarded and with no
// archive/database findings yet gets those filled in from a fresh
// discover run, without disturbing anything already set.
func TestWriteDiscoveredConfigFillsInMissingFieldsOnPartialEntry(t *testing.T) {
	existing := validExistingServer()
	existing.SSH = config.SSH{Host: "custom.example.com", Port: 2222, User: "svc"} // an operator's own hand-set value
	configPath := newServerConfigPath(t)
	seed := &config.Fleet{Servers: map[string]config.Server{"example-nodejs": existing}}
	if err := config.Save(configPath, seed); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	stateDir := t.TempDir()

	rep := &discover.Report{ServerID: "example-nodejs", ComposeFiles: []string{"/home/app/docker-compose.yml"}}
	target := sshx.Target{Host: "1.2.3.4", Port: 22, User: "root"} // must be ignored: existing.SSH already set
	var out bytes.Buffer

	err := writeDiscoveredConfig(context.Background(), configPath, stateDir, "example-nodejs", "", rep, target, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("writeDiscoveredConfig: %v", err)
	}

	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	srv := loaded.Servers["example-nodejs"]
	if srv.SSH != existing.SSH {
		t.Errorf("SSH = %+v, want the hand-set value %+v preserved, not the target's", srv.SSH, existing.SSH)
	}
	if srv.Destination != existing.Destination {
		t.Errorf("Destination = %q, want the existing value preserved", srv.Destination)
	}
	if len(srv.Archive) == 0 {
		t.Error("expected Archive to be filled in from the fresh discover report")
	}
	if !strings.Contains(out.String(), "filled in missing config") {
		t.Errorf("out = %q, want a note about filling in missing config", out.String())
	}
}

// TestWriteDiscoveredConfigWritesDraftWhenTODORemains proves a
// database whose auth couldn't be resolved (databaseEntries leaves
// auth_ref: TODO) never reaches the shared fleet.yaml — it would fail
// Validate for every other server too — and instead lands in its own
// draft file.
func TestWriteDiscoveredConfigWritesDraftWhenTODORemains(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "test-token")
	configPath := newServerConfigPath(t)
	seed := &config.Fleet{Servers: map[string]config.Server{"host-2-example": validExistingServer()}}
	if err := config.Save(configPath, seed); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	stateDir := t.TempDir()

	rep := &discover.Report{
		ServerID:  "example-nodejs",
		Databases: []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", AuthResolved: false}},
	}
	target := sshx.Target{Host: "1.2.3.4", Port: 22, User: "root"}
	var out bytes.Buffer

	err := writeDiscoveredConfig(context.Background(), configPath, stateDir, "example-nodejs", "", rep, target, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("writeDiscoveredConfig: %v", err)
	}

	if _, ok, _ := loadIfExists(configPath, "example-nodejs"); ok {
		t.Error("expected example-nodejs NOT to be written into the shared fleet.yaml while a TODO remains")
	}

	draftPath := filepath.Join(filepath.Dir(configPath), "example-nodejs.pending.yaml")
	draft, err := os.ReadFile(draftPath) //nolint:gosec // draftPath is derived from the test's own temp dir
	if err != nil {
		t.Fatalf("expected a draft file at %s: %v", draftPath, err)
	}
	if !strings.Contains(string(draft), "TODO") {
		t.Errorf("draft = %s, want it to contain the unresolved TODO for the operator to fill in", draft)
	}
	if !strings.Contains(out.String(), "wrote a draft to") {
		t.Errorf("out = %q, want a note pointing at the draft file", out.String())
	}
}

func loadIfExists(configPath, serverID string) (config.Server, bool, error) {
	fleet, err := config.Load(configPath)
	if err != nil {
		return config.Server{}, false, err
	}
	srv, ok := fleet.Servers[serverID]
	return srv, ok, nil
}
