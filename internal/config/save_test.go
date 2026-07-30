package config

import (
	"errors"
	"path/filepath"
	"testing"
)

func validServer() Server {
	return Server{
		SSH:              SSH{Host: "1.2.3.4", Port: 22, User: "root"},
		Provider:         "hetzner",
		Destination:      "433593",
		EncryptionKeyRef: "env://BORG_PASSPHRASE_TEST",
		Hetzner: &HetznerConfig{ //nolint:gosec // HCloudTokenRef below is a secret *reference* (env var name), never a literal credential
			MainAccount:    SSH{Host: "u123456.your-storagebox.de", Port: 23, User: "u123456"},
			HCloudTokenRef: "env://HCLOUD_TOKEN",
		},
	}
}

func TestSaveRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	fleet := &Fleet{Servers: map[string]Server{"test-server": validServer()}}

	if err := Save(path, fleet); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load(saved config): %v", err)
	}
	srv, ok := loaded.Servers["test-server"]
	if !ok {
		t.Fatal("expected test-server in the round-tripped config")
	}
	if srv.SSH.Host != "1.2.3.4" || srv.Destination != "433593" {
		t.Errorf("srv = %+v, want the saved fields preserved", srv)
	}
}

// TestSaveRefusesUnresolvedTODO proves Save never writes a TODO
// placeholder to disk — fleet.yaml is shared by every server this
// tool knows about, and Load re-validates the whole file on every
// command, so one broken entry would break every other, already-
// working server too.
func TestSaveRefusesUnresolvedTODO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	srv := validServer()
	srv.EncryptionKeyRef = "TODO"
	fleet := &Fleet{Servers: map[string]Server{"test-server": srv}}

	err := Save(path, fleet)
	if !errors.Is(err, ErrUnresolvedTODO) {
		t.Fatalf("Save error = %v, want ErrUnresolvedTODO", err)
	}
	if _, statErr := Load(path); statErr == nil {
		t.Fatal("expected Save to have written nothing at all when validation fails")
	}
}

// TestSaveDoesNotDisturbOtherServers proves saving after adding one
// new server leaves every already-configured server's fields exactly
// as they were.
func TestSaveDoesNotDisturbOtherServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	existing := validServer()
	existing.SSH.Host = "9.9.9.9"
	fleet := &Fleet{Servers: map[string]Server{"existing-server": existing}}
	if err := Save(path, fleet); err != nil {
		t.Fatalf("Save (seed): %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load (seed): %v", err)
	}
	loaded.Servers["new-server"] = validServer()
	if err := Save(path, loaded); err != nil {
		t.Fatalf("Save (with new server added): %v", err)
	}

	final, err := Load(path)
	if err != nil {
		t.Fatalf("Load (final): %v", err)
	}
	if final.Servers["existing-server"].SSH.Host != "9.9.9.9" {
		t.Errorf("existing-server.ssh.host = %q, want untouched 9.9.9.9", final.Servers["existing-server"].SSH.Host)
	}
	if _, ok := final.Servers["new-server"]; !ok {
		t.Error("expected new-server to also be present")
	}
}
