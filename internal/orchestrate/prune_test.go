package orchestrate

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

func TestPruneRequiresPruneKey(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	err := Prune(context.Background(), d, PruneOptions{})
	if err == nil || !strings.Contains(err.Error(), "--prune-key") {
		t.Fatalf("Prune error = %v, want it to mention --prune-key", err)
	}
	if len(target.Calls) != 0 {
		t.Errorf("expected no calls before onboarding/state is even checked, got %+v", target.Calls)
	}
}

func TestPruneRefusesWithoutOnboarding(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	err := Prune(context.Background(), d, PruneOptions{PruneKeyPath: "/operator/prune-key"})
	if err == nil || !strings.Contains(err.Error(), "onboard") {
		t.Fatalf("Prune error = %v, want it to mention onboarding", err)
	}
}

// TestPruneRefusesWhenCheckFails proves prune runs Check first and never
// even attempts borg prune when the integrity check fails — SPEC.md §5:
// "refuses to prune a repo that just failed integrity check."
func TestPruneRefusesWhenCheckFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errBoom}, // borg check
	}}
	local := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	d.Local = local
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Prune(context.Background(), d, PruneOptions{PruneKeyPath: "/operator/prune-key"})
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("Prune error = %v, want it to mention the failed integrity check", err)
	}
	if len(target.Calls) != 1 {
		t.Fatalf("expected only the borg check call, got %+v", target.Calls)
	}
	if len(local.Calls) != 0 {
		t.Errorf("expected zero local (prune) calls when check fails, got %+v", local.Calls)
	}
}

// TestPruneRunsThroughALocalConnectionNeverTheTarget pins the dual-key
// fix: borg check runs through the target's own session (that's fine,
// it uses the append-only key like everything else), but borg prune
// itself must run through a *separate* local connection — never
// target — since --prune-key is a control-host path that must never
// be read from the protected server's filesystem (SPEC.md §5,
// borg.Backend.Prune's own doc comment).
func TestPruneRunsThroughALocalConnectionNeverTheTarget(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // borg check
	}}
	local := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // borg prune
	}}
	d := testDeps(t, target)
	d.Local = local
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Prune(context.Background(), d, PruneOptions{PruneKeyPath: "/operator/prune-key"}); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	if len(target.Calls) != 1 {
		t.Fatalf("expected exactly one target call (borg check), got %+v", target.Calls)
	}
	checkCall := target.Calls[0]
	if checkCall.Cmd != "borg" || checkCall.Args[0] != "check" {
		t.Errorf("target call = %q %v, want borg check ...", checkCall.Cmd, checkCall.Args)
	}

	if len(local.Calls) != 1 {
		t.Fatalf("expected exactly one local call (borg prune), got %+v", local.Calls)
	}
	pruneCall := local.Calls[0]
	if pruneCall.Cmd != "borg" || pruneCall.Args[0] != "prune" {
		t.Errorf("local call = %q %v, want borg prune ...", pruneCall.Cmd, pruneCall.Args)
	}
	wantArgs := []string{"prune", "--keep-daily=7", "--keep-weekly=4", "--keep-monthly=6"}
	for i, want := range wantArgs {
		if pruneCall.Args[i] != want {
			t.Errorf("prune args = %v, want prefix %v", pruneCall.Args, wantArgs)
			break
		}
	}
	if pruneCall.Class != sshx.Mutating {
		t.Errorf("prune call class = %v, want Mutating", pruneCall.Class)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Timestamps.LastCheck == nil {
		t.Error("expected LastCheck to be recorded by the internal Check run")
	}
}
