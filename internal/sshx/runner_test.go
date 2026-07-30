package sshx

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerSuccess(t *testing.T) {
	r := ExecRunner{}
	result, err := r.Run(context.Background(), ReadOnly, "echo", []string{"hello"}, RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "hello" {
		t.Errorf("Stdout = %q, want hello", result.Stdout)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
}

func TestExecRunnerNonZeroExit(t *testing.T) {
	r := ExecRunner{}
	result, err := r.Run(context.Background(), Mutating, "sh", []string{"-c", "echo boom >&2; exit 3"}, RunOptions{})
	if err == nil {
		t.Fatal("expected an error for a nonzero exit")
	}
	if result.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", result.ExitCode)
	}
	if !strings.Contains(result.Stderr, "boom") {
		t.Errorf("Stderr = %q, want it to contain boom", result.Stderr)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %v, want it to include captured stderr", err)
	}
}

func TestExecRunnerRespectsEnvAndStdin(t *testing.T) {
	r := ExecRunner{}
	result, err := r.Run(context.Background(), ReadOnly, "sh", []string{"-c", "echo $GREETING; cat"}, RunOptions{
		Env:   []string{"GREETING=hi-there"},
		Stdin: "from-stdin",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(result.Stdout, "hi-there") {
		t.Errorf("Stdout = %q, want it to contain the env var value", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "from-stdin") {
		t.Errorf("Stdout = %q, want it to contain the piped stdin", result.Stdout)
	}
}

func TestExecRunnerTimeout(t *testing.T) {
	r := ExecRunner{}
	_, err := r.Run(context.Background(), ReadOnly, "sleep", []string{"5"}, RunOptions{Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
}

// TestExecRunnerTimeoutIsDistinguishableFromARealFailure pins the
// exact bug a silent client-side timeout kill caused live: exec.Cmd
// reports it as an ordinary *exec.ExitError with ExitCode() -1 and
// empty output, identical to the remote command itself failing with
// nothing to say — Run must instead say plainly that it was killed by
// its own timeout, and wrap context.DeadlineExceeded so
// IsTransientConnectionError can recognize and retry it.
func TestExecRunnerTimeoutIsDistinguishableFromARealFailure(t *testing.T) {
	r := ExecRunner{}
	_, err := r.Run(context.Background(), ReadOnly, "sleep", []string{"5"}, RunOptions{Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "killed client-side") {
		t.Errorf("err = %v, want it to plainly say it was killed client-side", err)
	}
}

// TestExecRunnerRealNonZeroExitIsNotMistakenForATimeout proves the new
// timeout detection doesn't swallow a genuine fast application failure
// — only ctx's own deadline firing should produce the timeout message.
func TestExecRunnerRealNonZeroExitIsNotMistakenForATimeout(t *testing.T) {
	r := ExecRunner{}
	_, err := r.Run(context.Background(), ReadOnly, "sh", []string{"-c", "exit 1"}, RunOptions{Timeout: time.Minute})
	if err == nil {
		t.Fatal("expected an error for a nonzero exit")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want a plain exit error, not a wrapped DeadlineExceeded", err)
	}
}

func TestExecRunnerCommandNotFound(t *testing.T) {
	r := ExecRunner{}
	if _, err := r.Run(context.Background(), ReadOnly, "this-binary-does-not-exist", nil, RunOptions{}); err == nil {
		t.Fatal("expected an error for a missing binary")
	}
}

// TestExecRunnerLiveStderrTeesWithoutAffectingResult proves LiveStderr
// receives the same bytes as Result.Stderr — a live progress sink,
// not a replacement for the captured result a caller's error handling
// still relies on.
func TestExecRunnerLiveStderrTeesWithoutAffectingResult(t *testing.T) {
	r := ExecRunner{}
	var live bytes.Buffer
	result, err := r.Run(context.Background(), ReadOnly, "sh", []string{"-c", "echo progress-line >&2"}, RunOptions{
		LiveStderr: &live,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(result.Stderr, "progress-line") {
		t.Errorf("Result.Stderr = %q, want it to still contain progress-line", result.Stderr)
	}
	if !strings.Contains(live.String(), "progress-line") {
		t.Errorf("LiveStderr = %q, want it to contain progress-line", live.String())
	}
}

// TestExecRunnerNilLiveStderrIsANoOp proves omitting LiveStderr
// (every caller before this field existed) behaves exactly as before.
func TestExecRunnerNilLiveStderrIsANoOp(t *testing.T) {
	r := ExecRunner{}
	result, err := r.Run(context.Background(), ReadOnly, "sh", []string{"-c", "echo x >&2"}, RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(result.Stderr, "x") {
		t.Errorf("Result.Stderr = %q, want it to contain x", result.Stderr)
	}
}

func TestClassString(t *testing.T) {
	if ReadOnly.String() != "read-only" {
		t.Errorf("ReadOnly.String() = %q, want read-only", ReadOnly.String())
	}
	if Mutating.String() != "mutating" {
		t.Errorf("Mutating.String() = %q, want mutating", Mutating.String())
	}
}
