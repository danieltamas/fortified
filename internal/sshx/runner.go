// Package sshx wraps exec'ing the system ssh/scp binaries (and,
// through the same Runner interface, any other subprocess a fortified
// package needs to run) behind an injectable interface — this is what
// makes every other package testable without live SSH/borg access.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// Class declares whether a Runner call can mutate remote or local
// state. It is a required argument on every Run call — not a
// convention a caller can forget — because internal/audit's
// classification and --dry-run (SPEC.md §5) both key off it.
type Class int

const (
	ReadOnly Class = iota
	Mutating
)

// String renders Class for audit log / --dry-run output.
func (c Class) String() string {
	if c == Mutating {
		return "mutating"
	}
	return "read-only"
}

// DefaultTimeout applies when RunOptions.Timeout is zero.
const DefaultTimeout = 60 * time.Second

// LongRunningTimeout is for commands whose duration scales with data
// volume rather than fixed admin work — database dumps, hashing a
// dump file, and borg create/check/extract/prune. DefaultTimeout's 60s
// ceiling is fine for a df or docker inspect, but verified live it
// silently killed a pg_dumpall on a 59GB database partway through.
const LongRunningTimeout = 6 * time.Hour

// FirstConnectTimeout is for a command's very first connection attempt
// to a destination that may not be immediately reachable yet — e.g.
// InitRepo dialing a Hetzner Storage Box subaccount moments after its
// creation API call returned, before Hetzner's own edge has finished
// routing it (verified live: "No route to host" persisting for tens of
// seconds is normal here, not a real failure). DefaultTimeout's 60s is
// too tight a single-attempt budget for that — but this is still one
// connection attempt, not a data transfer, so it stays far below
// LongRunningTimeout: a call using this should also be wrapped in
// RetryOnTransientConnectionError for the cumulative patience, rather
// than leaning on one very long timeout that would otherwise leave an
// operator staring at nothing for hours if the destination is actually
// unreachable.
const FirstConnectTimeout = 3 * time.Minute

// RunOptions carries the parts of an invocation that aren't the
// command name/args: environment (e.g. a resolved BORG_PASSPHRASE —
// secrets travel this way, never via argv), stdin (e.g. a pubkey
// piped to `install-ssh-key`), a working directory (e.g. for `borg
// extract`, which extracts into the current directory), a per-call
// timeout override, and an optional live-stderr sink.
type RunOptions struct {
	Env     []string
	Stdin   string
	Dir     string
	Timeout time.Duration
	// LiveStderr, when set, receives the command's stderr as it's
	// produced (a raw tee, in addition to Result.Stderr still
	// capturing everything) — for a long-running command that reports
	// its own progress on stderr (e.g. `borg create --progress`),
	// letting the operator watch it live instead of it only surfacing
	// once the whole command finishes.
	LiveStderr io.Writer
}

// Result is a completed subprocess's outcome.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes a command. Every fortified package that shells out
// (discover, provider/hetzner, backend/borg, secrets) does so through
// this interface rather than os/exec directly, so tests can supply a
// fake and assert the exact argv/env/stdin/class constructed.
type Runner interface {
	Run(ctx context.Context, class Class, cmd string, args []string, opts RunOptions) (Result, error)
}

// ExecRunner is the real Runner, backed by os/exec.
type ExecRunner struct{}

// Run executes cmd with args, applying opts.Timeout (or DefaultTimeout)
// as a context deadline. class is not consulted here — ExecRunner just
// runs the command; classification is what audit/dry-run wrappers act
// on further up the call chain.
func (ExecRunner) Run(ctx context.Context, _ Class, cmd string, args []string, opts RunOptions) (Result, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := exec.CommandContext(runCtx, cmd, args...) //nolint:gosec // running an arbitrary cmd/args is Runner's entire purpose; callers are trusted, argv-asserting tests are the safety net
	if len(opts.Env) > 0 {
		// Extend the process environment, never replace it — a bare
		// os/exec.Cmd.Env assignment drops PATH/HOME/etc. entirely,
		// which breaks anything the child needs to exec itself (a
		// remote-repo borg needing `ssh` on PATH, a shell resolving
		// `docker`). This must extend, exactly like Session.Run's
		// remote `env VAR=val cmd` leaves the remote login env intact.
		c.Env = append(os.Environ(), opts.Env...)
	}
	c.Dir = opts.Dir
	if opts.Stdin != "" {
		c.Stdin = bytes.NewBufferString(opts.Stdin)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	if opts.LiveStderr != nil {
		c.Stderr = io.MultiWriter(&stderr, opts.LiveStderr)
	} else {
		c.Stderr = &stderr
	}

	err := c.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}

	// A command killed by runCtx's own deadline (not the caller's ctx —
	// checked via ctx.Err() to rule out an upstream cancellation racing
	// the same instant) surfaces from exec.Cmd as an ordinary-looking
	// *exec.ExitError with ExitCode() -1 and empty output, identical to
	// the remote command itself failing with no output at all. Reported
	// this way instead, so it's never mistaken for that (verified live:
	// this exact ambiguity swallowed a real onboarding bug — see
	// LongRunningTimeout's doc comment). Wrapping context.DeadlineExceeded
	// also lets IsTransientConnectionError recognize and retry it.
	if err != nil && ctx.Err() == nil && errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("%s %v: no response within %s, killed client-side before the remote process could report anything: %w",
			cmd, args, timeout, context.DeadlineExceeded)
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, fmt.Errorf("%s %v: exit %d: %s", cmd, args, result.ExitCode, stderr.String())
	}
	if err != nil {
		return result, fmt.Errorf("%s %v: %w", cmd, args, err)
	}
	return result, nil
}

var _ Runner = ExecRunner{}

// Target identifies a server reachable over SSH. Building the actual
// ssh invocation is Session's job (session.go) — Target is just the
// connection details.
//
// Port == 0 and User == "" are meaningful, not just unset: they tell
// Session to omit an explicit `-p`/`user@` on the ssh command line so
// a ~/.ssh/config Host alias's own Port/User/IdentityFile/ProxyJump
// settings apply instead of being silently overridden by them (a
// literal `-p 22` on argv beats a config file's `Port 15086` for the
// same alias — this is what caused discover to hang for a full
// DefaultTimeout dialing the wrong port before erroring). Every
// Target built from an already-resolved fleet.yaml entry should still
// set both explicitly; only the "let ssh's own alias resolve it"
// bootstrapping path leaves either zero.
type Target struct {
	Host string
	Port int
	User string
}
