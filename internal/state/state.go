// Package state manages each server's local state record (SPEC.md
// §4): provider destination, key/repo status, the last DatabaseInstance
// list discover produced, onboarding progress, and verify/backup/
// check/drill timestamps. Load/Save are atomic (temp file + rename);
// locking lives in lock.go.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/danieltamas/fortified/internal/discover"
)

// SchemaVersion is bumped whenever the on-disk record shape changes
// incompatibly. Load refuses to guess how to migrate an unexpected
// version.
const SchemaVersion = 1

// Server is one server's full state record.
type Server struct {
	SchemaVersion int                         `json:"schema_version"`
	ServerID      string                      `json:"server_id"`
	Provider      ProviderState               `json:"provider"`
	Databases     []discover.DatabaseInstance `json:"databases,omitempty"`
	Onboard       OnboardState                `json:"onboard"`
	Verify        VerifyState                 `json:"verify"`
	Timestamps    Timestamps                  `json:"timestamps"`
	LastManifest  *Manifest                   `json:"last_manifest,omitempty"`
}

// Manifest mirrors a backend's verification baseline recorded at
// backup time (SPEC.md §4) — kept as its own type here, rather than
// importing a specific backend package's Manifest, so state stays
// decoupled from any one Backend implementation (borg is the only one
// in v1, but the interface is meant to be swappable).
type Manifest struct {
	Databases []DatabaseManifest `json:"databases"`
}

// DatabaseManifest is one database's baseline: a SHA-256 of its dump
// file and per-table row counts — verify's ground truth.
type DatabaseManifest struct {
	Container string           `json:"container"`
	SHA256    string           `json:"sha256"`
	RowCounts map[string]int64 `json:"row_counts"`
}

// ProviderState is what onboard has established at the backup
// destination — everything here must be reconstructible by re-running
// discover/onboard, per SPEC.md §4's "control host is a SPOF" rule.
type ProviderState struct {
	DestinationID    string `json:"destination_id,omitempty"`
	KeyFingerprint   string `json:"key_fingerprint,omitempty"`
	RepoInitialized  bool   `json:"repo_initialized"`
	EncryptionKeyRef string `json:"encryption_key_ref,omitempty"`
	EscrowAcked      bool   `json:"escrow_acked"`

	// AppendOnlyLifted is true only for the brief window onboard's step
	// 5 needs the automation key unrestricted to work around borg's own
	// "init through an append-only forced command" limitation — set
	// just before lifting the restriction, cleared just after it's
	// confirmed restored. If a run is killed inside that window, this
	// stays true on disk: the one on-disk signal that the key may
	// currently be unrestricted, so status/backup/verify can warn
	// instead of the operator having zero indication their repo lost
	// its immutability backstop.
	AppendOnlyLifted bool `json:"append_only_lifted,omitempty"`
}

// OnboardState tracks resumable onboarding progress (SPEC.md §5's
// numbered onboard steps).
type OnboardState struct {
	LastCompletedStep int    `json:"last_completed_step"`
	FailureReason     string `json:"failure_reason,omitempty"`
}

// VerifyState records whether verify has ever passed for this server
// — the fact that gates enable-snapshots (SPEC.md §4).
type VerifyState struct {
	EverPassed bool `json:"ever_passed"`
}

// Timestamps are facts that only exist locally and die with the
// control host (SPEC.md §4) — status must show a server with no
// LastPassingVerify as unverified, never as unknown-but-probably-fine.
type Timestamps struct {
	LastBackup        *time.Time `json:"last_backup,omitempty"`
	LastPassingVerify *time.Time `json:"last_passing_verify,omitempty"`
	LastCheck         *time.Time `json:"last_check,omitempty"`
	LastDrill         *time.Time `json:"last_drill,omitempty"`
}

func recordPath(dir, serverID string) string {
	return filepath.Join(dir, serverID+".json")
}

// Load reads serverID's state record from dir. A missing file is not
// an error: it means this server has never been onboarded, and Load
// returns a fresh zero-value record for it.
func Load(dir, serverID string) (*Server, error) {
	data, err := os.ReadFile(recordPath(dir, serverID))
	if errors.Is(err, os.ErrNotExist) {
		return &Server{SchemaVersion: SchemaVersion, ServerID: serverID}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", serverID, err)
	}

	var s Server
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", serverID, err)
	}
	if s.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("state: %s has schema_version %d, fortified expects %d", serverID, s.SchemaVersion, SchemaVersion)
	}
	return &s, nil
}

// Save writes s to dir atomically: a temp file is written and synced,
// then renamed into place, so a process killed mid-write never leaves
// the previous good record corrupted.
func Save(dir string, s *Server) error {
	s.SchemaVersion = SchemaVersion
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("state: marshal %s: %w", s.ServerID, err)
	}

	final := recordPath(dir, s.ServerID)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // tmp is derived from our own recordPath(dir, serverID), not untrusted input
	if err != nil {
		return fmt.Errorf("state: open temp file for %s: %w", s.ServerID, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("state: write temp file for %s: %w", s.ServerID, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("state: sync temp file for %s: %w", s.ServerID, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("state: close temp file for %s: %w", s.ServerID, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("state: rename into place for %s: %w", s.ServerID, err)
	}
	return nil
}
