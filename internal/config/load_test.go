package config

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfigGolden(t *testing.T) {
	fleet, err := Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("Load(valid.yaml): %v", err)
	}

	got, err := json.MarshalIndent(fleet, "", "  ")
	if err != nil {
		t.Fatalf("marshal fleet: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "valid.golden.json")
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	want, err := os.ReadFile(goldenPath) //nolint:gosec // goldenPath is a fixed testdata path, not untrusted input
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Load(valid.yaml) mismatch (-update to refresh):\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestConfigRejectsTodo(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "todo.yaml"))
	if !errors.Is(err, ErrUnresolvedTODO) {
		t.Fatalf("Load(todo.yaml) error = %v, want ErrUnresolvedTODO", err)
	}
}

func TestConfigRejectsPlaintextSecret(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "plaintext_secret.yaml"))
	if !errors.Is(err, ErrPlaintextSecret) {
		t.Fatalf("Load(plaintext_secret.yaml) error = %v, want ErrPlaintextSecret", err)
	}
}

func TestConfigRejectsUnknownKey(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "unknown_key.yaml"))
	if err == nil {
		t.Fatal("Load(unknown_key.yaml) should have failed strict decoding")
	}
}

func TestConfigRejectsMissingField(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "missing_field.yaml"))
	if !errors.Is(err, ErrMissingField) {
		t.Fatalf("Load(missing_field.yaml) error = %v, want ErrMissingField", err)
	}
}

func TestConfigRejectsMissingHetznerBlock(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "missing_hetzner_block.yaml"))
	if !errors.Is(err, ErrMissingField) {
		t.Fatalf("Load(missing_hetzner_block.yaml) error = %v, want ErrMissingField", err)
	}
}

func TestConfigAppliesDefaultRetention(t *testing.T) {
	fleet, err := Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("Load(valid.yaml): %v", err)
	}
	srv := fleet.Servers["host-2-example"]
	if srv.Retention == nil || *srv.Retention != DefaultRetention {
		t.Errorf("Retention = %+v, want default %+v", srv.Retention, DefaultRetention)
	}
}
