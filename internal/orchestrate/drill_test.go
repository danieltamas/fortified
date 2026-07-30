package orchestrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

func writeTestIdentityFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "drill-key")
	if err := os.WriteFile(path, []byte("fake private key material\n"), 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	return path
}

func TestDrillRequiresInto(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	throwaway := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	_, err := Drill(context.Background(), d, throwaway, DrillOptions{IdentityPath: writeTestIdentityFile(t)})
	if err == nil || !strings.Contains(err.Error(), "--into") {
		t.Fatalf("Drill error = %v, want it to mention --into", err)
	}
	if len(throwaway.Calls) != 0 {
		t.Errorf("expected zero calls to the throwaway target, got %+v", throwaway.Calls)
	}
}

func TestDrillRefusesWithoutOnboarding(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	throwaway := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	_, err := Drill(context.Background(), d, throwaway, DrillOptions{IdentityPath: writeTestIdentityFile(t), Into: "/restore"})
	if err == nil || !strings.Contains(err.Error(), "onboard") {
		t.Fatalf("Drill error = %v, want it to mention onboarding", err)
	}
}

func TestDrillHappyPath(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{}
	throwaway := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // borg --version: already installed
		{}, // stage identity file
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n2026-07-23T00-00-00Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: ""}},                                             // mkdir -p && ls -A: empty
		{Result: sshx.Result{Stdout: "/home\n"}},                                      // pwd (resolve drillKeyPath to an absolute path)
		{},                                                                            // borg extract
		{},                                                                            // rm -f identity file (cleanup)
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	result, err := Drill(context.Background(), d, throwaway, DrillOptions{
		IdentityPath: writeTestIdentityFile(t),
		Into:         "/mnt/drill-restore",
	})
	if err != nil {
		t.Fatalf("Drill: %v", err)
	}
	if result.Archive != "2026-07-23T00-00-00Z" {
		t.Errorf("Archive = %q, want the latest archive selected", result.Archive)
	}
	if result.Into != "/mnt/drill-restore" {
		t.Errorf("Into = %q, want /mnt/drill-restore", result.Into)
	}
	if result.Elapsed <= 0 {
		t.Error("expected a positive elapsed duration")
	}

	extractCall := throwaway.Calls[5]
	if extractCall.Cmd != "borg" || extractCall.Args[0] != "extract" {
		t.Errorf("extract call = %q %v, want borg extract ...", extractCall.Cmd, extractCall.Args)
	}
	cleanupCall := throwaway.Calls[6]
	if cleanupCall.Cmd != "rm" {
		t.Errorf("cleanup call = %q %v, want rm -f the staged identity file", cleanupCall.Cmd, cleanupCall.Args)
	}

	// The source server's own runner must never be touched — drill
	// proves recovery independent of the server being drilled.
	if len(target.Calls) != 0 {
		t.Errorf("expected zero calls to the source server's own runner, got %+v", target.Calls)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Timestamps.LastDrill == nil {
		t.Error("expected LastDrill to be recorded after a passing drill")
	}
}

func TestDrillInstallsBorgOnThrowawayWhenMissing(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{}
	throwaway := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("command not found")},              // borg --version: missing
		{Result: sshx.Result{Stdout: "/usr/bin/apt-get\n"}}, // detectPackageManager
		{}, // install command
		{Result: sshx.Result{Stdout: "borg 1.2.4\n"}}, // post-install verify
		{}, // stage identity file
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: ""}},                       // mkdir -p && ls -A: empty
		{Result: sshx.Result{Stdout: "/home\n"}},                // pwd (resolve drillKeyPath to an absolute path)
		{},                                                      // borg extract
		{},                                                      // rm -f identity file
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if _, err := Drill(context.Background(), d, throwaway, DrillOptions{
		IdentityPath: writeTestIdentityFile(t),
		Into:         "/mnt/drill-restore",
	}); err != nil {
		t.Fatalf("Drill: %v", err)
	}

	installCall := throwaway.Calls[2]
	if installCall.Cmd != "sh" || !strings.Contains(strings.Join(installCall.Args, " "), "apt-get install") {
		t.Errorf("install call = %+v, want an apt-get install invocation", installCall)
	}
}

func TestDrillCleansUpIdentityFileEvenOnRestoreFailure(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{}
	throwaway := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // borg --version: already installed
		{}, // stage identity file
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: ""}},                       // mkdir -p && ls -A: empty
		{Result: sshx.Result{Stdout: "/home\n"}},                // pwd (resolve drillKeyPath to an absolute path)
		{Err: errBoom},                                          // borg extract fails
		{},                                                      // rm -f identity file (cleanup still runs)
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	_, err := Drill(context.Background(), d, throwaway, DrillOptions{
		IdentityPath: writeTestIdentityFile(t),
		Into:         "/mnt/drill-restore",
	})
	if err == nil {
		t.Fatal("expected Drill to propagate the restore failure")
	}
	if len(throwaway.Calls) != 7 {
		t.Fatalf("expected 7 calls (version, stage, list, mkdir/ls, pwd, failed extract, cleanup running via defer regardless), got %d: %+v", len(throwaway.Calls), throwaway.Calls)
	}
	cleanupCall := throwaway.Calls[6]
	if cleanupCall.Cmd != "rm" {
		t.Errorf("last call = %q %v, want the identity file cleanup to still run after a failed extract", cleanupCall.Cmd, cleanupCall.Args)
	}

	st, loadErr := state.Load(d.StateDir, d.ServerID)
	if loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	if st.Timestamps.LastDrill != nil {
		t.Error("expected LastDrill to remain unset after a failed drill")
	}
}

// TestDrillRefusesNonEmptyTarget is a regression guard for a real gap
// found by cross-vendor review: Drill never prepared or validated
// opts.Into on the throwaway target at all before calling
// RestoreArchive — which both means a nonexistent target directory
// would make the underlying `cd opts.Into` fail outright, and a
// non-empty one would silently mix a prior drill's leftovers into the
// new restore. ensureDrillTargetIsSafe closes both gaps the same way
// restore.go's own ensureRestoreTargetIsSafe does for the ordinary
// restore command.
func TestDrillRefusesNonEmptyTarget(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{}
	throwaway := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // borg --version: already installed
		{}, // stage identity file
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}},      // borg list
		{Result: sshx.Result{Stdout: "leftover-from-prior-drill\n"}}, // mkdir -p && ls -A: not empty
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	_, err := Drill(context.Background(), d, throwaway, DrillOptions{
		IdentityPath: writeTestIdentityFile(t),
		Into:         "/mnt/drill-restore",
	})
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("Drill error = %v, want it to refuse a non-empty throwaway target", err)
	}
}

func TestDrillUsesExplicitArchiveWithoutListing(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{}
	throwaway := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{},                                       // borg --version: already installed
		{},                                       // stage identity file
		{Result: sshx.Result{Stdout: ""}},        // mkdir -p && ls -A: empty
		{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve drillKeyPath to an absolute path)
		{},                                       // borg extract (no list call at all)
		{},                                       // rm -f identity file
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	result, err := Drill(context.Background(), d, throwaway, DrillOptions{
		IdentityPath: writeTestIdentityFile(t),
		Into:         "/mnt/drill-restore",
		Archive:      "2026-06-01T00-00-00Z",
	})
	if err != nil {
		t.Fatalf("Drill: %v", err)
	}
	if result.Archive != "2026-06-01T00-00-00Z" {
		t.Errorf("Archive = %q, want the explicitly requested archive, unchanged", result.Archive)
	}
	if len(throwaway.Calls) != 6 {
		t.Fatalf("expected exactly 6 calls (no list call when --archive is explicit), got %d: %+v", len(throwaway.Calls), throwaway.Calls)
	}
}
