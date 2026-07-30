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

func TestRestoreRefusesWithoutOnboarding(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	_, err := Restore(context.Background(), d, RestoreOptions{})
	if err == nil || !strings.Contains(err.Error(), "onboard") {
		t.Fatalf("Restore error = %v, want it to mention onboarding", err)
	}
}

// TestRestoreListsArchivesWithoutArchiveFlag proves omitting --archive
// lists the repo's archives and returns without ever touching the
// target (no mutating calls) — SPEC.md §5: "run without --archive, it
// lists the repo's archives and exits — no separate list command
// needed."
func TestRestoreListsArchivesWithoutArchiveFlag(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n2026-07-23T00-00-00Z\n"}}, // borg list
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	rep, err := Restore(context.Background(), d, RestoreOptions{})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(rep.Archives) != 2 || rep.Restored != "" {
		t.Errorf("rep = %+v, want just the archive list, nothing restored", rep)
	}
	for _, c := range target.Calls {
		if c.Class == sshx.Mutating {
			t.Errorf("expected no mutating calls in list mode, got %+v", c)
		}
	}
}

func TestRestoreRefusesUnknownArchive(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	_, err := Restore(context.Background(), d, RestoreOptions{Archive: "does-not-exist", Into: "/restore"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Restore error = %v, want it to mention the archive wasn't found", err)
	}
}

func TestRestoreRefusesLiveDataMountPathAsTarget(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
	}}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", DataMountPaths: []string{"/home/docker/psql/data"}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, nil, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	_, err := Restore(context.Background(), d, RestoreOptions{Archive: "latest", Into: "/home/docker/psql/data"})
	if err == nil || !strings.Contains(err.Error(), "live data mount") {
		t.Fatalf("Restore error = %v, want it to refuse a live data mount path", err)
	}
	// The refusal must happen before ever touching the target with a
	// mutating call (no accidental mkdir on a live data path).
	for _, c := range target.Calls {
		if c.Class == sshx.Mutating {
			t.Errorf("expected no mutating calls when refusing a live data mount target, got %+v", c)
		}
	}
}

func TestRestoreRefusesNonEmptyTarget(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}},   // borg list
		{Result: sshx.Result{Stdout: "some-leftover-file.txt\n"}}, // mkdir -p && ls -A: not empty
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	_, err := Restore(context.Background(), d, RestoreOptions{Archive: "latest", Into: "/restore"})
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("Restore error = %v, want it to refuse a non-empty target", err)
	}
}

// TestRestoreQuotesIntoAgainstShellInjection pins a real injection
// surface: --into is interpolated into `mkdir -p <into> && ls -A
// <into>` on the target. Since it's an operator-typed CLI flag (not
// necessarily hand-checked the way a reviewed fleet.yaml might be —
// e.g. a wrapper script passing it through), it must be single-quoted
// before reaching the target's shell, not trusted as already safe.
func TestRestoreQuotesIntoAgainstShellInjection(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
		{}, // mkdir -p && ls -A: empty
		{}, // borg extract
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	const malicious = "/tmp/r; touch /tmp/pwned; #"
	if _, err := Restore(context.Background(), d, RestoreOptions{Archive: "latest", Into: malicious}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	checkCall := target.Calls[1]
	if checkCall.Cmd != "sh" {
		t.Fatalf("call 1 = %q, want sh (the mkdir/ls safety check)", checkCall.Cmd)
	}
	quoted := shellSingleQuote(malicious)
	if !strings.Contains(checkCall.Args[1], "mkdir -p "+quoted) {
		t.Errorf("safety-check script = %q, want the target single-quoted: %s", checkCall.Args[1], quoted)
	}
	if strings.Contains(checkCall.Args[1], "touch /tmp/pwned") && !strings.Contains(checkCall.Args[1], quoted) {
		t.Fatalf("safety-check script = %q, the injected command reached unquoted argv", checkCall.Args[1])
	}
}

func TestRestoreHappyPathFullArchive(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n2026-07-23T00-00-00Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: ""}},                                             // mkdir -p && ls -A: empty
		{Result: sshx.Result{Stdout: "/home\n"}},                                      // pwd (resolve automationKeyPath to an absolute path)
		{},                                                                            // borg extract
	}}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	rep, err := Restore(context.Background(), d, RestoreOptions{Archive: "latest", Into: "/restore"})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if rep.Restored != "2026-07-23T00-00-00Z" || rep.Into != "/restore" || rep.ExtractedPath != "/restore" {
		t.Errorf("rep = %+v, want the latest archive restored fully into /restore", rep)
	}

	extractCall := target.Calls[3]
	if extractCall.Cmd != "borg" || extractCall.Args[0] != "extract" {
		t.Errorf("extract call = %q %v, want borg extract ...", extractCall.Cmd, extractCall.Args)
	}
	if len(extractCall.Args) != 2 {
		t.Errorf("extract args = %v, want just [extract repo::archive] — no selective paths for a full restore", extractCall.Args)
	}
}

func TestRestoreHappyPathSingleDatabase(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: ""}},                       // mkdir -p && ls -A: empty
		{Result: sshx.Result{Stdout: "/home\n"}},                // pwd (resolve automationKeyPath to an absolute path)
		{},                                                      // borg extract
	}}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql"}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, nil, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	rep, err := Restore(context.Background(), d, RestoreOptions{Archive: "latest", Into: "/restore", DB: "psql"})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	wantExtractedPath := "/restore/" + backupWorkspaceDir(d.ServerID, "") + "/psql.sql"
	if rep.ExtractedPath != wantExtractedPath {
		t.Errorf("ExtractedPath = %q, want %q", rep.ExtractedPath, wantExtractedPath)
	}

	extractCall := target.Calls[3]
	wantSelectivePath := backupWorkspaceDir(d.ServerID, "") + "/psql.sql"
	if len(extractCall.Args) != 3 || extractCall.Args[2] != wantSelectivePath {
		t.Errorf("extract args = %v, want [extract repo::archive %s]", extractCall.Args, wantSelectivePath)
	}
}

// TestRestoreSingleDatabaseWithWorkspaceDirReportsCleanExtractedPath
// proves that when Server.WorkspaceDir is configured (an absolute
// path, same as TestBackupHonorsConfiguredWorkspaceDir), --db restore
// reports an ExtractedPath with no double slash — verified live
// against a real borg repo that borg extract's own path-filter
// matching already handles this workspace_dir's absolute dumpPath
// correctly (an absolute archive source is stored without its leading
// slash, but extract normalizes an absolute filter against that
// transparently); filepath.Join here is a cosmetic cleanup of the
// reported path string, not a fix to a real extraction failure.
func TestRestoreSingleDatabaseWithWorkspaceDirReportsCleanExtractedPath(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: ""}},                       // mkdir -p && ls -A: empty
		{Result: sshx.Result{Stdout: "/home\n"}},                // pwd (resolve automationKeyPath to an absolute path)
		{},                                                      // borg extract
	}}
	d := testDeps(t, target)
	d.Server.WorkspaceDir = "/mnt/HC_Volume_21111084"
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql"}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, nil, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	rep, err := Restore(context.Background(), d, RestoreOptions{Archive: "latest", Into: "/restore", DB: "psql"})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	wantExtractedPath := "/restore" + backupWorkspaceDir(d.ServerID, d.Server.WorkspaceDir) + "/psql.sql"
	if rep.ExtractedPath != wantExtractedPath || strings.Contains(rep.ExtractedPath, "//") {
		t.Errorf("ExtractedPath = %q, want %q with no double slash", rep.ExtractedPath, wantExtractedPath)
	}
}

func TestRestoreRefusesUnknownDatabase(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: ""}},                       // mkdir -p && ls -A: empty
	}}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql"}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, nil, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	_, err := Restore(context.Background(), d, RestoreOptions{Archive: "latest", Into: "/restore", DB: "not-a-real-db"})
	if err == nil || !strings.Contains(err.Error(), "not one of") {
		t.Fatalf("Restore error = %v, want it to refuse an unknown database name", err)
	}
}
