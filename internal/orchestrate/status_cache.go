package orchestrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func statusCachePath(stateDir, serverID string) string {
	return filepath.Join(stateDir, serverID+".status-cache.json")
}

// SaveStatusCache persists rep as serverID's last-known status,
// atomically (temp file + rename, mirroring internal/state.Save).
// Status calls this itself after every live check, so status --all
// can read a whole fleet's worth of "what's backed up, when, how big"
// instantly from local disk — without contacting every server over
// SSH just to answer that, and without depending on every server
// still being reachable to do it.
func SaveStatusCache(stateDir string, rep StatusReport) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("status cache: marshal %s: %w", rep.ServerID, err)
	}
	final := statusCachePath(stateDir, rep.ServerID)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { //nolint:gosec // tmp is derived from our own statusCachePath(stateDir, serverID), not untrusted input
		return fmt.Errorf("status cache: write temp file for %s: %w", rep.ServerID, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("status cache: rename into place for %s: %w", rep.ServerID, err)
	}
	return nil
}

// LoadStatusCache reads serverID's last-cached status. ok is false
// (with a nil error) when no cache exists yet — a server that's never
// had Status or a backup run against it since caching was
// introduced — distinct from a real read failure.
func LoadStatusCache(stateDir, serverID string) (rep StatusReport, ok bool, err error) {
	data, err := os.ReadFile(statusCachePath(stateDir, serverID)) //nolint:gosec // path is derived from stateDir+serverID, not untrusted input
	if err != nil {
		if os.IsNotExist(err) {
			return StatusReport{}, false, nil
		}
		return StatusReport{}, false, fmt.Errorf("status cache: read %s: %w", serverID, err)
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return StatusReport{}, false, fmt.Errorf("status cache: parse %s: %w", serverID, err)
	}
	return rep, true, nil
}
