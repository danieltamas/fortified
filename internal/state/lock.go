package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// LockHolder describes who currently holds a server's lock, for the
// "who's holding it" error a contending invocation reports (SPEC.md
// §4) instead of queueing silently.
type LockHolder struct {
	PID     int       `json:"pid"`
	Command string    `json:"command"`
	Since   time.Time `json:"since"`
}

// LockedError is returned by WithLock when another invocation
// currently holds serverID's lock.
type LockedError struct {
	ServerID string
	Holder   LockHolder
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("state: %s is locked by pid %d (%s) since %s",
		e.ServerID, e.Holder.PID, e.Holder.Command, e.Holder.Since.Format(time.RFC3339))
}

func lockPath(dir, serverID string) string {
	return filepath.Join(dir, serverID+".lock")
}

// WithLock takes an exclusive advisory lock on serverID before running
// fn. Without wait, a lock already held by another invocation fails
// fast with *LockedError naming the holder; with wait, it blocks until
// the lock is free instead. status (SPEC.md §4) never calls this — it
// is lock-exempt by design.
func WithLock(dir, serverID, command string, wait bool, fn func() error) error {
	path := lockPath(dir, serverID)
	fl := flock.New(path)

	var locked bool
	var err error
	if wait {
		err = fl.Lock()
		locked = err == nil
	} else {
		locked, err = fl.TryLock()
	}
	if err != nil {
		return fmt.Errorf("state: acquire lock for %s: %w", serverID, err)
	}
	if !locked {
		holder, herr := readLockHolder(path)
		if herr != nil {
			return fmt.Errorf("state: %s is locked by another invocation (holder metadata unreadable: %w)", serverID, herr)
		}
		return &LockedError{ServerID: serverID, Holder: holder}
	}
	defer func() { _ = fl.Unlock() }()

	holder := LockHolder{PID: os.Getpid(), Command: command, Since: time.Now().UTC()}
	data, err := json.Marshal(holder)
	if err != nil {
		return fmt.Errorf("state: marshal lock holder for %s: %w", serverID, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("state: write lock holder metadata for %s: %w", serverID, err)
	}

	return fn()
}

func readLockHolder(path string) (LockHolder, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is our own lockPath(dir, serverID), not untrusted input
	if err != nil {
		return LockHolder{}, err
	}
	var h LockHolder
	if err := json.Unmarshal(data, &h); err != nil {
		return LockHolder{}, err
	}
	return h, nil
}
