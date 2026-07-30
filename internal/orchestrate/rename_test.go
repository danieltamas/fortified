package orchestrate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/state"
)

func seedRenameableState(t *testing.T, dir, id string) {
	t.Helper()
	st, err := state.Load(dir, id)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	st.Provider.RepoInitialized = true
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	if err := SaveStatusCache(dir, StatusReport{ServerID: id, RepoInitialized: true}); err != nil {
		t.Fatalf("SaveStatusCache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".lock"), []byte(`{"pid":1,"command":"backup"}`), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".audit.jsonl"), []byte(`{"command":"backup"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
}

// TestRenameServerStateMovesEveryFileAndRelabelsServerID pins the bug
// a hand-fixed rename hit live: state.Save and SaveStatusCache derive
// their *next* write's path from the "server_id" field embedded in the
// file, not from whatever filename they were loaded from — a plain
// mv without also patching that field would silently resurrect the
// old filename the next time either got saved.
func TestRenameServerStateMovesEveryFileAndRelabelsServerID(t *testing.T) {
	dir := t.TempDir()
	seedRenameableState(t, dir, "n8n.example.net")

	if err := RenameServerState(dir, "n8n.example.net", "n8n-wam-app", false, &bytes.Buffer{}); err != nil {
		t.Fatalf("RenameServerState: %v", err)
	}

	for _, suffix := range []string{".json", ".status-cache.json", ".lock", ".audit.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, "n8n.example.net"+suffix)); !os.IsNotExist(err) {
			t.Errorf("old file n8n.example.net%s still exists (err=%v)", suffix, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "n8n-wam-app"+suffix)); err != nil {
			t.Errorf("new file n8n-wam-app%s missing: %v", suffix, err)
		}
	}

	st, err := state.Load(dir, "n8n-wam-app")
	if err != nil {
		t.Fatalf("state.Load(new): %v", err)
	}
	if !st.Provider.RepoInitialized {
		t.Error("moved state record lost its RepoInitialized=true")
	}
	if st.ServerID != "n8n-wam-app" {
		t.Errorf("st.ServerID = %q, want n8n-wam-app", st.ServerID)
	}

	// The real regression: save the moved record again, exactly like
	// backup/verify/check do after every run, and confirm it writes to
	// the *new* filename, not a resurrected old one.
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("state.Save after rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "n8n.example.net.json")); !os.IsNotExist(err) {
		t.Fatal("saving the renamed record resurrected the old filename — server_id field was not relabeled")
	}

	rep, ok, err := LoadStatusCache(dir, "n8n-wam-app")
	if err != nil || !ok {
		t.Fatalf("LoadStatusCache(new) = %v, %v, %v", rep, ok, err)
	}
	if rep.ServerID != "n8n-wam-app" {
		t.Errorf("rep.ServerID = %q, want n8n-wam-app", rep.ServerID)
	}
	if err := SaveStatusCache(dir, rep); err != nil {
		t.Fatalf("SaveStatusCache after rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "n8n.example.net.status-cache.json")); !os.IsNotExist(err) {
		t.Fatal("saving the renamed status cache resurrected the old filename — server_id field was not relabeled")
	}
}

// TestRenameServerStateIsIdempotentWhenAlreadyRenamed is today's actual
// recovery shape: local state was already fixed by hand, only the
// remote subaccount still needs renaming — RenameServerState must
// treat that as already done, not error.
func TestRenameServerStateIsIdempotentWhenAlreadyRenamed(t *testing.T) {
	dir := t.TempDir()
	seedRenameableState(t, dir, "n8n-wam-app")

	if err := RenameServerState(dir, "n8n.example.net", "n8n-wam-app", false, &bytes.Buffer{}); err != nil {
		t.Fatalf("RenameServerState: %v, want success (already renamed)", err)
	}
}

func TestRenameServerStateRefusesWhenNeitherExists(t *testing.T) {
	dir := t.TempDir()
	err := RenameServerState(dir, "ghost-old", "ghost-new", false, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error when neither ID has a state record")
	}
}

func TestRenameServerStateRefusesWhenBothExist(t *testing.T) {
	dir := t.TempDir()
	seedRenameableState(t, dir, "old-id")
	seedRenameableState(t, dir, "new-id")

	err := RenameServerState(dir, "old-id", "new-id", false, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error when both old and new already have a state record")
	}
	if !strings.Contains(err.Error(), "resolve manually") {
		t.Errorf("err = %v, want it to say this needs manual resolution", err)
	}
}

// TestRenameServerStateDoesNotOrphanRemainingFilesAfterAPartialMove
// pins a bug shape none of the other rename tests can catch: the
// idempotency guard at the top of RenameServerState only ever checks
// for oldID's/newID's ".json" file, not all four suffixes. If the
// suffix loop fails partway through (disk full, a permission error,
// or — reproduced here — the destination path already occupied by
// something un-renameable) after ".json" has already moved but before
// ".lock"/".audit.jsonl" have, a retry sees "!oldExists && newExists"
// (based on .json alone) and returns nil — "already renamed" — without
// ever finishing the move, permanently stranding whatever didn't make
// it under the old ID.
func TestRenameServerStateDoesNotOrphanRemainingFilesAfterAPartialMove(t *testing.T) {
	dir := t.TempDir()
	seedRenameableState(t, dir, "n8n.example.net")

	// Force os.Rename to fail specifically for the .lock suffix (the
	// third suffix in stateFileSuffixes, after .json and
	// .status-cache.json) by occupying its destination path with a
	// non-empty directory — os.Rename cannot replace a directory with a
	// file. This simulates any real partial failure mid-loop (a full
	// disk hitting exactly the wrong file included) without needing to
	// mock the filesystem.
	blockedDest := filepath.Join(dir, "n8n-wam-app.lock")
	if err := os.Mkdir(blockedDest, 0o700); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blockedDest, "keep-me-nonempty"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker dir: %v", err)
	}

	firstErr := RenameServerState(dir, "n8n.example.net", "n8n-wam-app", false, &bytes.Buffer{})
	if firstErr == nil {
		t.Fatal("expected the first (partial) rename attempt to fail while .lock's destination is blocked")
	}

	// Clear the obstruction, exactly like an operator fixing a full disk
	// and re-running the command — this is the retry RenameServerState's
	// own doc comment promises is safe.
	if err := os.RemoveAll(blockedDest); err != nil {
		t.Fatalf("remove blocker: %v", err)
	}

	if err := RenameServerState(dir, "n8n.example.net", "n8n-wam-app", false, &bytes.Buffer{}); err != nil {
		t.Fatalf("RenameServerState retry: %v, want the retry to finish moving what the first attempt left behind", err)
	}

	for _, suffix := range []string{".json", ".status-cache.json", ".lock", ".audit.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, "n8n.example.net"+suffix)); !os.IsNotExist(err) {
			t.Errorf("old file n8n.example.net%s still exists after the retry (err=%v) — the partial-failure idempotency check let this get orphaned", suffix, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "n8n-wam-app"+suffix)); err != nil {
			t.Errorf("new file n8n-wam-app%s missing after the retry: %v", suffix, err)
		}
	}
}

func TestRenameServerStateDryRunMovesNothing(t *testing.T) {
	dir := t.TempDir()
	seedRenameableState(t, dir, "n8n.example.net")

	var out bytes.Buffer
	if err := RenameServerState(dir, "n8n.example.net", "n8n-wam-app", true, &out); err != nil {
		t.Fatalf("RenameServerState: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "n8n.example.net.json")); err != nil {
		t.Errorf("dry-run must not move anything, but old file is gone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "n8n-wam-app.json")); !os.IsNotExist(err) {
		t.Error("dry-run must not move anything, but new file exists")
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Errorf("expected a dry-run plan line, got %q", out.String())
	}
}
