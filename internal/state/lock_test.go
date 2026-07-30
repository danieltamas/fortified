package state

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestLockContentionFailsFast(t *testing.T) {
	dir := t.TempDir()

	holderEntered := make(chan struct{})
	release := make(chan struct{})
	holderErr := make(chan error, 1)

	go func() {
		holderErr <- WithLock(dir, "host-2-example", "backup", false, func() error {
			close(holderEntered)
			<-release
			return nil
		})
	}()

	<-holderEntered
	err := WithLock(dir, "host-2-example", "verify", false, func() error {
		t.Fatal("second WithLock should not have run fn while the first holds the lock")
		return nil
	})

	var lockedErr *LockedError
	if !errors.As(err, &lockedErr) {
		t.Fatalf("second WithLock error = %v, want *LockedError", err)
	}
	if lockedErr.Holder.Command != "backup" {
		t.Errorf("holder.Command = %q, want backup", lockedErr.Holder.Command)
	}
	if lockedErr.Holder.PID == 0 {
		t.Error("holder.PID should be set")
	}

	close(release)
	if err := <-holderErr; err != nil {
		t.Fatalf("holder WithLock returned error: %v", err)
	}
}

func TestLockWaitBlocksThenAcquires(t *testing.T) {
	dir := t.TempDir()

	holderEntered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var order []string

	go func() {
		_ = WithLock(dir, "host-2-example", "backup", false, func() error {
			mu.Lock()
			order = append(order, "holder-start")
			mu.Unlock()
			close(holderEntered)
			<-release
			mu.Lock()
			order = append(order, "holder-end")
			mu.Unlock()
			return nil
		})
	}()

	<-holderEntered
	waiterDone := make(chan struct{})
	go func() {
		_ = WithLock(dir, "host-2-example", "verify --wait", true, func() error {
			mu.Lock()
			order = append(order, "waiter-start")
			mu.Unlock()
			return nil
		})
		close(waiterDone)
	}()

	time.Sleep(50 * time.Millisecond)
	close(release)

	select {
	case <-waiterDone:
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never acquired the lock")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 || order[0] != "holder-start" || order[1] != "holder-end" || order[2] != "waiter-start" {
		t.Errorf("execution order = %v, want [holder-start holder-end waiter-start]", order)
	}
}
