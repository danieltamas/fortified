package sshx

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestIsTransientConnectionError(t *testing.T) {
	cases := map[string]bool{
		"": false,
		"borg: init repo: exit 2: some real borg error":                                              false,
		"ssh: Could not resolve hostname u123456-sub4.your-storagebox.de: Name or service not known": true,
		"exit 2: Connection closed by remote host":                                                   true,
		"dial tcp: Connection refused":                                                               true,
		"Connection timed out during handshake":                                                      true,
	}
	for msg, want := range cases {
		var err error
		if msg != "" {
			err = errors.New(msg)
		}
		if got := IsTransientConnectionError(err); got != want {
			t.Errorf("IsTransientConnectionError(%q) = %v, want %v", msg, got, want)
		}
	}
}

// TestIsTransientConnectionErrorRecognizesClientTimeoutKill pins
// ExecRunner's own wrapping (runner.go): a client-side timeout kill
// must be retried exactly like a recognized network-error string,
// since both mean "the connection never got established" — a fresh
// subaccount route that's merely slow to become reachable can produce
// either, and RetryOnTransientConnectionError's whole point is to give
// that case cumulative patience across attempts.
func TestIsTransientConnectionErrorRecognizesClientTimeoutKill(t *testing.T) {
	err := fmt.Errorf("borg init: no response within 3m0s, killed client-side before the remote process could report anything: %w", context.DeadlineExceeded)
	if !IsTransientConnectionError(err) {
		t.Errorf("IsTransientConnectionError(%v) = false, want true — it wraps context.DeadlineExceeded", err)
	}
}

func TestRetryOnTransientConnectionErrorSucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	err := RetryOnTransientConnectionError(context.Background(), 5, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return errors.New("ssh: Could not resolve hostname sub4.your-storagebox.de")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RetryOnTransientConnectionError: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want exactly 3 (2 transient failures then success)", calls)
	}
}

func TestRetryOnTransientConnectionErrorReturnsImmediatelyOnRealError(t *testing.T) {
	calls := 0
	realErr := errors.New("borg: passphrase supplied in BORG_PASSPHRASE is incorrect")
	err := RetryOnTransientConnectionError(context.Background(), 5, time.Millisecond, func() error {
		calls++
		return realErr
	})
	if !errors.Is(err, realErr) {
		t.Fatalf("err = %v, want realErr returned unchanged", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want exactly 1 — a non-transient error must never be retried", calls)
	}
}

func TestRetryOnTransientConnectionErrorGivesUpAfterAttemptsExhausted(t *testing.T) {
	calls := 0
	err := RetryOnTransientConnectionError(context.Background(), 3, time.Millisecond, func() error {
		calls++
		return errors.New("Connection refused")
	})
	if err == nil {
		t.Fatal("expected an error once attempts are exhausted")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want exactly 3 (the attempts bound)", calls)
	}
}
