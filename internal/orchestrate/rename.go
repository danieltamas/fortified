package orchestrate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danieltamas/fortified/internal/state"
)

// stateFileSuffixes are every local-footprint file one server ID owns
// in the state directory — the state record and status cache embed
// their own "server_id" field (fixed up separately below, since
// state.Save/SaveStatusCache derive their *next* write's path from
// that field, not from whatever filename they were loaded from —
// leaving it stale would silently resurrect the old filename the next
// time either is saved); the lock and audit log carry no such field,
// so a plain rename is enough for those two.
var stateFileSuffixes = []string{".json", ".status-cache.json", ".lock", ".audit.jsonl"}

// RenameServerState moves oldID's local footprint (state record, lock
// file, audit log, cached status) to newID. This is the local half of
// a fleet.yaml server-ID rename — RenameDestination (internal/provider/
// hetzner) is the remote half; a full rename needs both, since every
// command looks its server up locally by the current ID and remotely
// by the same ID re-derived fresh each time.
//
// Existence of the ".json" record alone decides whether to proceed at
// all — refusing only when neither ID has one (nothing to rename) or
// both do (picking one to keep silently would discard real backup
// history the operator needs to reconcile by hand). Past that guard,
// the move and the server_id relabel below always run unconditionally
// rather than being skipped on an "already renamed" fast path: each
// step is independently idempotent (a suffix already at its new path
// is simply skipped; a record whose embedded server_id already matches
// needs no re-save), so this correctly finishes a prior attempt that
// got only partway through — moved ".json" but died before ".lock"/
// ".audit.jsonl", or moved every file but died before the relabel —
// instead of a blanket "already renamed" return declaring victory over
// whatever got left behind (verified live: exactly this half-finished
// state is what a real partial failure produces).
func RenameServerState(stateDir, oldID, newID string, dryRun bool, out io.Writer) error {
	oldExists := fileExists(filepath.Join(stateDir, oldID+".json"))
	newExists := fileExists(filepath.Join(stateDir, newID+".json"))

	switch {
	case !oldExists && !newExists:
		return fmt.Errorf("neither %s nor %s has a local state record — nothing to rename", oldID, newID)
	case oldExists && newExists:
		return fmt.Errorf("both %s and %s already have a local state record — resolve manually before renaming (picking one silently would discard real backup history)", oldID, newID)
	}

	if dryRun {
		_, _ = fmt.Fprintf(out, "[dry-run] would move %s's local state (record, lock, audit log, cached status) to %s\n", oldID, newID)
		return nil
	}

	for _, suffix := range stateFileSuffixes {
		old := filepath.Join(stateDir, oldID+suffix)
		if !fileExists(old) {
			continue
		}
		if err := os.Rename(old, filepath.Join(stateDir, newID+suffix)); err != nil {
			return fmt.Errorf("move %s: %w", suffix, err)
		}
	}

	st, err := state.Load(stateDir, newID)
	if err != nil {
		return fmt.Errorf("reload state record for %s: %w", newID, err)
	}
	if st.ServerID != newID {
		st.ServerID = newID
		if err := state.Save(stateDir, st); err != nil {
			return fmt.Errorf("relabel state record: %w", err)
		}
	}

	if rep, ok, err := LoadStatusCache(stateDir, newID); err != nil {
		return fmt.Errorf("reload status cache for %s: %w", newID, err)
	} else if ok && rep.ServerID != newID {
		rep.ServerID = newID
		if err := SaveStatusCache(stateDir, rep); err != nil {
			return fmt.Errorf("relabel status cache: %w", err)
		}
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
