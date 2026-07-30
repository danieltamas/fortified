package orchestrate

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

func TestCheckRefusesWithoutOnboarding(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	err := Check(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "onboard") {
		t.Fatalf("Check error = %v, want it to mention onboarding", err)
	}
}

func TestCheckHappyPathRecordsTimestamp(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // borg check
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Check(context.Background(), d); err != nil {
		t.Fatalf("Check: %v", err)
	}

	checkCall := target.Calls[0]
	if checkCall.Cmd != "borg" || checkCall.Args[0] != "check" {
		t.Errorf("check call = %q %v, want borg check ...", checkCall.Cmd, checkCall.Args)
	}
	if checkCall.Class != sshx.ReadOnly {
		t.Errorf("check call class = %v, want ReadOnly", checkCall.Class)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Timestamps.LastCheck == nil {
		t.Error("expected LastCheck to be recorded after a passing check")
	}
}

func TestCheckPropagatesBorgCheckFailure(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errBoom},
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Check(context.Background(), d); err == nil {
		t.Fatal("expected Check to propagate a failing borg check")
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Timestamps.LastCheck != nil {
		t.Error("expected LastCheck to remain unset after a failing check")
	}
}
