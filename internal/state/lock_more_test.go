package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithLockFailsWhenLockPathIsADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(lockPath(dir, "host-2-example"), 0o750); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}

	err := WithLock(dir, "host-2-example", "backup", false, func() error {
		t.Fatal("fn should not run when the lock itself cannot be acquired")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "acquire lock") {
		t.Fatalf("WithLock error = %v, want it to mention acquiring the lock failed", err)
	}
}

func TestLockedErrorMessage(t *testing.T) {
	err := &LockedError{ServerID: "host-2-example", Holder: LockHolder{PID: 4242, Command: "backup"}}
	msg := err.Error()
	if !strings.Contains(msg, "host-2-example") || !strings.Contains(msg, "4242") || !strings.Contains(msg, "backup") {
		t.Errorf("LockedError.Error() = %q, want it to mention server, pid, and command", msg)
	}
}

func TestReadLockHolderMissingFile(t *testing.T) {
	if _, err := readLockHolder(filepath.Join(t.TempDir(), "missing.lock")); err == nil {
		t.Fatal("expected an error reading a nonexistent lock file")
	}
}

func TestReadLockHolderCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.lock")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := readLockHolder(path); err == nil {
		t.Fatal("expected an error reading a corrupt lock file")
	}
}
