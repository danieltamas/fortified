package orchestrate

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

// TestOnboardReportsProgress proves Deps.Progress actually gets called
// as onboard's steps run, in order, naming each step — a nil Progress
// (every other test in this package) being a safe no-op is necessary
// but not sufficient; this is the test that the feature itself works.
func TestOnboardReportsProgress(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := discoverResponses()
	resp = append(resp, freshKeyInstallResponses("fortified-host-2-example")...)
	resp = append(resp, step5Responses("fortified-host-2-example")...) // step 5
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)

	var messages []string
	d.Progress = func(msg string) { messages = append(messages, msg) }

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	if len(messages) == 0 {
		t.Fatal("expected Progress to have been called at least once")
	}

	wantSubstrings := []string{
		"[1/5] discovering server layout...",
		"[1/5] discovering server layout: done",
		"[2/5] installing borg if missing...",
		"[3/5] confirming isolated destination...",
		"[4/5] generating and installing the append-only automation key...",
		"[5/5] initializing the borg repository...",
	}
	joined := strings.Join(messages, "\n")
	for _, want := range wantSubstrings {
		if !strings.Contains(joined, want) {
			t.Errorf("progress messages = %v, want one containing %q", messages, want)
		}
	}
}

// TestVerifyReportsProgressPerDatabase proves each database gets its
// own named progress line — valuable specifically because verifying a
// database can take tens of seconds (the throwaway container's
// readiness wait), so knowing *which* one is in flight is the whole
// point of this feature for verify.
func TestVerifyReportsProgressPerDatabase(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},                                       // mkdir scratch dir
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},                                       // borg extract
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}},
			{}, {}, {}, {}, // docker run + 3 ready probes
			{}, // load dump
			{Result: sshx.Result{Stdout: "postgres\n"}},
			{Result: sshx.Result{Stdout: "public.users\n"}},
			{Result: sshx.Result{Stdout: "public.users|5\n"}},
			{}, // docker rm -f throwaway
			{}, // rm -rf scratch dir
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "postgres:16-alpine", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	var messages []string
	d.Progress = func(msg string) { messages = append(messages, msg) }

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	joined := strings.Join(messages, "\n")
	if !strings.Contains(joined, "verifying psql") {
		t.Errorf("progress messages = %v, want one naming the database being verified (psql)", messages)
	}
}
