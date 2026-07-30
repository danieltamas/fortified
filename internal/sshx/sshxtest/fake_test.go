package sshxtest

import (
	"context"
	"errors"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

func TestFakeRunnerRecordsCallsAndReturnsScriptedResponses(t *testing.T) {
	boom := errors.New("boom")
	f := &FakeRunner{
		Responses: []Response{
			{Result: sshx.Result{Stdout: "first"}},
			{Err: boom},
		},
	}

	r1, err1 := f.Run(context.Background(), sshx.ReadOnly, "borg", []string{"info"}, sshx.RunOptions{Env: []string{"A=1"}, Stdin: "in"})
	if err1 != nil || r1.Stdout != "first" {
		t.Fatalf("first call = (%+v, %v), want (Stdout=first, nil)", r1, err1)
	}

	_, err2 := f.Run(context.Background(), sshx.Mutating, "borg", []string{"create"}, sshx.RunOptions{})
	if !errors.Is(err2, boom) {
		t.Fatalf("second call error = %v, want boom", err2)
	}

	// A call beyond the scripted responses gets a zero result, not a panic.
	r3, err3 := f.Run(context.Background(), sshx.ReadOnly, "borg", []string{"list"}, sshx.RunOptions{})
	if err3 != nil || r3 != (sshx.Result{}) {
		t.Fatalf("unscripted call = (%+v, %v), want zero Result and nil error", r3, err3)
	}

	if len(f.Calls) != 3 {
		t.Fatalf("expected 3 recorded calls, got %d", len(f.Calls))
	}
	if f.Calls[0].Class != sshx.ReadOnly || f.Calls[0].Env[0] != "A=1" || f.Calls[0].Stdin != "in" {
		t.Errorf("first recorded call = %+v, want Class=ReadOnly Env=[A=1] Stdin=in", f.Calls[0])
	}
	if got := f.CallCount(); got != 3 {
		t.Errorf("CallCount() = %d, want 3", got)
	}
}
