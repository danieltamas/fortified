package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Save validates fleet and writes it to path as YAML, atomically (a
// temp file + rename, mirroring internal/state.Save). Validate runs
// first, unconditionally: fleet.yaml is shared by every server this
// tool knows about, and Load re-validates the whole file on every
// single command — writing one broken or TODO-laden entry here would
// break every other, already-working server's commands too, not just
// the one being changed.
func Save(path string, fleet *Fleet) error {
	if err := Validate(fleet); err != nil {
		return err
	}

	data, err := yaml.Marshal(fleet)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: create config directory: %w", err)
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // tmp is derived from the caller's own path, not untrusted input
	if err != nil {
		return fmt.Errorf("config: open temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("config: write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("config: sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("config: close temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: rename into place: %w", err)
	}
	return nil
}
