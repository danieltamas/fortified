package sshx

import (
	"context"
	"errors"
	"strings"
	"time"
)

// transientConnectionSignatures are stderr fragments SSH/borg produce
// when the underlying network connection itself couldn't be
// established — DNS not resolving, the port refusing/timing out —
// distinct from an application-level result (borg's own error, or a
// Storage Box forced command correctly refusing an interactive
// session). Verified live: a freshly created Hetzner Storage Box
// subaccount's own distinct hostname (e.g.
// u123456-sub4.your-storagebox.de) can take a few seconds to become
// reachable after the CreateSubaccount API call already returned
// success, racing the very first connection ever made to it.
var transientConnectionSignatures = []string{
	"Could not resolve hostname",
	"Temporary failure in name resolution",
	"Connection closed by remote host",
	"Connection refused",
	"Connection timed out",
	"Network is unreachable",
	"No route to host",
}

// IsTransientConnectionError reports whether err looks like one of
// transientConnectionSignatures, or a client-side timeout kill
// (ExecRunner wraps those with context.DeadlineExceeded specifically
// so this catches them too — a slow-to-route brand-new destination and
// a hard connection refusal deserve the same retry treatment, since
// both are about the connection never being established, never an
// application-level result) — a signal worth retrying, never a
// generic "retry any error" check (retrying a real application
// failure, e.g. a wrong passphrase or path, would only waste time and
// obscure which attempt's error actually matters).
func IsTransientConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, signature := range transientConnectionSignatures {
		if strings.Contains(msg, signature) {
			return true
		}
	}
	return false
}

// RetryOnTransientConnectionError calls fn up to attempts times,
// retrying only while it fails with IsTransientConnectionError — the
// very first real connection to a just-created subaccount hostname is
// exactly the case that needs this; any other error (or success)
// returns immediately, and ctx cancellation is honored between
// attempts.
func RetryOnTransientConnectionError(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil || !IsTransientConnectionError(err) {
			return err
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return err
}
