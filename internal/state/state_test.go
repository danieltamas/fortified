package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieltamas/fortified/internal/discover"
)

func TestStateLoadMissingReturnsFreshRecord(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "host-2-example")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.ServerID != "host-2-example" || s.SchemaVersion != SchemaVersion {
		t.Errorf("fresh record = %+v, want ServerID=host-2-example SchemaVersion=%d", s, SchemaVersion)
	}
	if s.Onboard.LastCompletedStep != 0 {
		t.Errorf("fresh record should have no completed onboard steps, got %d", s.Onboard.LastCompletedStep)
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)

	want := &Server{
		ServerID: "host-2-example",
		Provider: ProviderState{
			DestinationID:    "host2-backup",
			KeyFingerprint:   "SHA256:abc",
			RepoInitialized:  true,
			EncryptionKeyRef: "secret://fortified/host-2-example/borg-passphrase",
			EscrowAcked:      true,
		},
		Databases: []discover.DatabaseInstance{
			{Kind: "postgres", Container: "psql", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true},
		},
		Onboard: OnboardState{LastCompletedStep: 4},
		Verify:  VerifyState{EverPassed: true},
		Timestamps: Timestamps{
			LastBackup:        &now,
			LastPassingVerify: &now,
		},
	}

	if err := Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(dir, "host-2-example")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.Provider != want.Provider {
		t.Errorf("Provider = %+v, want %+v", got.Provider, want.Provider)
	}
	if len(got.Databases) != 1 || got.Databases[0].Kind != "postgres" {
		t.Errorf("Databases = %+v, want one postgres entry", got.Databases)
	}
	if got.Onboard != want.Onboard {
		t.Errorf("Onboard = %+v, want %+v", got.Onboard, want.Onboard)
	}
	if got.Verify != want.Verify {
		t.Errorf("Verify = %+v, want %+v", got.Verify, want.Verify)
	}
	if got.Timestamps.LastBackup == nil || !got.Timestamps.LastBackup.Equal(now) {
		t.Errorf("LastBackup = %v, want %v", got.Timestamps.LastBackup, now)
	}
}

func TestStateLoadRejectsCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "host-x.json"), []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := Load(dir, "host-x"); err == nil {
		t.Fatal("expected an error loading a corrupt state file")
	}
}

func TestStateRejectsUnknownSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "host-x.json"), []byte(`{"schema_version": 99, "server_id": "host-x"}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := Load(dir, "host-x"); err == nil {
		t.Fatal("expected an error loading an unknown schema_version, got nil")
	}
}

func TestSaveFailsWhenDirMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	err := Save(dir, &Server{ServerID: "host-2-example"})
	if err == nil {
		t.Fatal("expected an error saving into a nonexistent directory")
	}
}

func TestSaveFailsWhenRenameTargetIsADirectory(t *testing.T) {
	dir := t.TempDir()
	// final would be dir/host-2-example.json — pre-create that path as
	// a non-empty directory so the temp-file write succeeds but the
	// final rename fails, exercising Save's rename-error branch.
	final := recordPath(dir, "host-2-example")
	if err := os.MkdirAll(filepath.Join(final, "not-empty"), 0o750); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}

	err := Save(dir, &Server{ServerID: "host-2-example"})
	if err == nil {
		t.Fatal("expected an error renaming a temp file onto an existing directory")
	}
}

func TestStateAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	original := &Server{ServerID: "host-2-example", Onboard: OnboardState{LastCompletedStep: 2}}
	if err := Save(dir, original); err != nil {
		t.Fatalf("Save original: %v", err)
	}

	// Simulate a process killed mid-write: a partial temp file exists,
	// but rename into place never happened.
	tmp := recordPath(dir, "host-2-example") + ".tmp"
	if err := os.WriteFile(tmp, []byte("{not valid json, write interrupted"), 0o600); err != nil {
		t.Fatalf("write partial temp file: %v", err)
	}

	got, err := Load(dir, "host-2-example")
	if err != nil {
		t.Fatalf("Load after simulated kill mid-write: %v", err)
	}
	if got.Onboard.LastCompletedStep != 2 {
		t.Errorf("state after simulated crash = %+v, want the original record intact (step 2)", got)
	}
}
