package orchestrate

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

var errBoom = errors.New("boom")

func onboardedState(serverID string) *state.Server {
	return &state.Server{
		ServerID: serverID,
		Provider: state.ProviderState{
			DestinationID:    "9",
			RepoInitialized:  true,
			EncryptionKeyRef: "env://FORTIFIED_TEST_PASSPHRASE",
			EscrowAcked:      true,
		},
		Onboard: state.OnboardState{LastCompletedStep: 4},
	}
}

func TestBackupRefusesWithoutOnboarding(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	// No state seeded at all — a fresh record has RepoInitialized=false.

	err := Backup(context.Background(), d)
	if err == nil {
		t.Fatal("expected Backup to refuse against a server that hasn't completed onboarding")
	}
	if !strings.Contains(err.Error(), "onboard") {
		t.Errorf("error = %v, want it to mention onboarding", err)
	}
	if len(target.Calls) != 0 {
		t.Errorf("expected zero calls to target, got %d: %+v", len(target.Calls), target.Calls)
	}
}

func TestBackupHappyPathNoDatabases(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df (free-space preflight, zero databases to estimate)
			{}, // mkdir workspace
			{}, // writeManifest
			{}, // borg create
			{}, // rm -rf workspace
		},
	}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Backup(context.Background(), d); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Timestamps.LastBackup == nil {
		t.Error("expected LastBackup to be recorded")
	}
	if st.LastManifest == nil {
		t.Error("expected LastManifest to be recorded")
	}

	createCall := target.Calls[3]
	if createCall.Cmd != "borg" || createCall.Args[0] != "create" {
		t.Errorf("call 3 = %q %v, want borg create ...", createCall.Cmd, createCall.Args)
	}
}

// TestBackupHonorsConfiguredWorkspaceDir proves Server.WorkspaceDir,
// when set, anchors the staging directory under that absolute path
// instead of the SSH login's own home directory — verified live this
// matters: a large database's SQL-text dump can need meaningfully
// more scratch space than the root filesystem has free, and a server
// can have an attached volume with real headroom sitting unused.
func TestBackupHonorsConfiguredWorkspaceDir(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir workspace
			{}, // writeManifest
			{}, // borg create
			{}, // rm -rf workspace
		},
	}
	d := testDeps(t, target)
	d.Server.WorkspaceDir = "/mnt/HC_Volume_21111084"
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Backup(context.Background(), d); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	mkdirCall := target.Calls[1]
	wantDir := "/mnt/HC_Volume_21111084/fortified-backup-workspace-" + d.ServerID
	if mkdirCall.Cmd != "mkdir" || len(mkdirCall.Args) != 2 || mkdirCall.Args[1] != wantDir {
		t.Errorf("mkdir call = %+v, want mkdir -p %s", mkdirCall, wantDir)
	}
}

func TestBackupResolvesArchiveGlobs(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "/home/psql/docker-compose.yml\n"}}, // ls -d glob expansion (resolved before CreateArchive runs)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},             // df
			{}, // mkdir workspace
			{}, // writeManifest
			{}, // borg create
			{}, // rm -rf workspace
		},
	}
	d := testDeps(t, target)
	d.Server.Archive = []config.ArchivePath{{Path: "/home", Glob: "*/docker-compose.yml"}}
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Backup(context.Background(), d); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	globCall := target.Calls[0]
	if globCall.Cmd != "sh" || !strings.Contains(globCall.Args[1], "'/home'/*/docker-compose.yml") {
		t.Errorf("call 0 = %q %v, want the glob expansion command with the path portion single-quoted", globCall.Cmd, globCall.Args)
	}

	createCall := target.Calls[4]
	if createCall.Cmd != "borg" {
		t.Fatalf("call 4 = %q, want borg create", createCall.Cmd)
	}
	found := false
	for _, a := range createCall.Args {
		if a == "/home/psql/docker-compose.yml" {
			found = true
		}
	}
	if !found {
		t.Errorf("borg create args = %v, want the glob-expanded compose file among them", createCall.Args)
	}
}

// TestBackupRefusesShellMetacharactersInArchiveGlob pins the fix for a
// real injection surface: archive.glob is interpolated into a live
// `for f in <pattern>` shell loop on the target so real globs (*, ?,
// [...]) keep working — which means it can't just be single-quoted
// like an ordinary path. A fleet.yaml glob containing a shell
// metacharacter (a stray ";" here) must be refused outright, before
// ever reaching the target, rather than executing on it.
func TestBackupRefusesShellMetacharactersInArchiveGlob(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	d.Server.Archive = []config.ArchivePath{{Path: "/home", Glob: "*; touch /tmp/pwned; echo *"}}
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Backup(context.Background(), d)
	if err == nil {
		t.Fatal("expected Backup to refuse a glob containing shell metacharacters")
	}
	if !strings.Contains(err.Error(), "glob") {
		t.Errorf("error = %v, want it to mention the glob", err)
	}
	if len(target.Calls) != 0 {
		t.Errorf("expected zero target calls — the malicious glob must never reach the target, got %+v", target.Calls)
	}
}

func TestBackupFailsWhenDestinationLookupFails(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	transport := newFakeTransport(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", storageBoxGetJSON)
	transport.stubStatus(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 500, serviceErrorJSON)
	d := testDepsWithTransport(t, target, transport)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Backup(context.Background(), d)
	if err == nil {
		t.Fatal("expected Backup to fail when confirming the destination fails")
	}
	if !strings.Contains(err.Error(), "confirm destination") {
		t.Errorf("error = %v, want it to mention confirming the destination", err)
	}
}

func TestBackupFailsWhenPassphraseUnresolvable(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	seeded := onboardedState(d.ServerID)
	seeded.Provider.EncryptionKeyRef = "env://FORTIFIED_TEST_UNSET_PASSPHRASE_REF"
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Backup(context.Background(), d)
	if err == nil {
		t.Fatal("expected Backup to fail when the encryption_key_ref can't be resolved")
	}
	if !strings.Contains(err.Error(), "encryption_key_ref") {
		t.Errorf("error = %v, want it to mention encryption_key_ref", err)
	}
	if len(target.Calls) != 0 {
		t.Errorf("expected zero calls to target — passphrase resolution must happen before any dump work, got %d", len(target.Calls))
	}
}

// TestBackupSkipsGlobsThatMatchNothing: a configured compose-file glob
// matching zero files on a particular server isn't an error — it's
// normal for a server with no compose-managed services. The glob-loop
// expansion script always exits 0, so "no matches" is exactly empty
// stdout with a nil error — never anything that looks like a failure.
func TestBackupSkipsGlobsThatMatchNothing(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: ""}},                    // glob expansion: no matches (exit 0, empty stdout)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir workspace
			{}, // writeManifest
			{}, // borg create
			{}, // rm -rf workspace
		},
	}
	d := testDeps(t, target)
	d.Server.Archive = []config.ArchivePath{{Path: "/home", Glob: "*/docker-compose.yml"}}
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Backup(context.Background(), d); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	createCall := target.Calls[4]
	if createCall.Cmd != "borg" {
		t.Fatalf("call 4 = %q, want borg create", createCall.Cmd)
	}
	if len(createCall.Args) != 5 {
		t.Errorf("borg create args = %v, want just [create --progress --stats archiveSpec workspaceDir] — no extra source paths", createCall.Args)
	}
}

// TestBackupFailsWhenGlobExpansionGenuinelyFails: unlike "no matches"
// above, a real failure (SSH hiccup, permission error, shell syntax
// problem) expanding a configured archive glob must propagate as an
// error — silently dropping a configured path and still reporting a
// successful backup was the bug (Codex cross-vendor review).
func TestBackupFailsWhenGlobExpansionGenuinelyFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Err: errBoom}, // glob expansion: a genuine failure, not "no matches"
		},
	}
	d := testDeps(t, target)
	d.Server.Archive = []config.ArchivePath{{Path: "/home", Glob: "*/docker-compose.yml"}}
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Backup(context.Background(), d)
	if err == nil {
		t.Fatal("expected Backup to fail when archive glob expansion genuinely fails, not silently drop the path")
	}
	if !strings.Contains(err.Error(), "expand archive glob") {
		t.Errorf("error = %v, want it to mention glob expansion", err)
	}
}

func TestBackupFailsWhenAuthRefUnresolvable(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	d.Server.Databases = []config.Database{
		{Kind: "mariadb", Container: "mysql", DumpStrategy: "docker-exec", AuthRef: "env://FORTIFIED_TEST_UNSET_AUTH_REF"},
	}
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Backup(context.Background(), d)
	if err == nil {
		t.Fatal("expected Backup to fail when a configured auth_ref can't be resolved")
	}
	if !strings.Contains(err.Error(), "auth_ref") {
		t.Errorf("error = %v, want it to mention the auth_ref", err)
	}
	if len(target.Calls) != 0 {
		t.Errorf("expected zero calls to target — auth resolution must happen before any dump work, got %d", len(target.Calls))
	}
}

func TestBackupWorkspaceDirDefaultsToHomeRelativeName(t *testing.T) {
	got := backupWorkspaceDir("host-2-example", "")
	want := "fortified-backup-workspace-host-2-example"
	if got != want {
		t.Errorf("backupWorkspaceDir(id, \"\") = %q, want %q", got, want)
	}
}

func TestBackupWorkspaceDirAnchorsUnderConfiguredRoot(t *testing.T) {
	cases := map[string]string{
		"/mnt/HC_Volume_21111084":  "/mnt/HC_Volume_21111084/fortified-backup-workspace-host-2-example",
		"/mnt/HC_Volume_21111084/": "/mnt/HC_Volume_21111084/fortified-backup-workspace-host-2-example", // trailing slash tolerated
	}
	for root, want := range cases {
		if got := backupWorkspaceDir("host-2-example", root); got != want {
			t.Errorf("backupWorkspaceDir(id, %q) = %q, want %q", root, got, want)
		}
	}
}
