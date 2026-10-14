package orchestrate

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

// TestEndToEndOnboardBackupVerifyEnableSnapshots is PLAN.md §5's named
// end-to-end test: one scripted FakeRunner "server" walked through the
// entire real sequence a fresh server goes through — discover, onboard
// (all 4 steps), backup, verify, enable-snapshots — asserting each
// stage's state effects and the full ordered target-runner transcript,
// not just each function in isolation. Zero discovered databases keeps
// the dump/restore/throwaway-container mechanics (already covered by
// TestVerifyHappyPathPostgres/MariaDB and TestBackupHappyPathNoDatabases)
// out of scope here — this test's job is proving the sequence itself,
// not re-proving each step's internals.
func TestEndToEndOnboardBackupVerifyEnableSnapshots(t *testing.T) {
	responses := []sshxtest.Response{
		// --- onboard step 1: discover (13 fixed read-only commands
		// + borg/docker --version + 12 well-known-state-path checks) ---
		{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {},
		{Result: sshx.Result{Stdout: "borg 1.2.4\n"}},
		{Result: sshx.Result{Stdout: "Docker 27.0.0\n"}},
		{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {},
		// --- onboard step 1 (cont.): 7 native-database probes ---
		{}, {}, {}, {}, {}, {}, {},
		// --- onboard step 2: ensureBorgInstalled's own borg --version check ---
		{Result: sshx.Result{Stdout: "borg 1.2.4\n"}},
	}
	responses = append(responses, freshKeyInstallResponses("fortified-e2e")...) // onboard step 4
	responses = append(responses,
		sshxtest.Response{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz fortified-e2e\n"}}, // step 5: read pubkey (lift append-only for init)
		sshxtest.Response{}, // onboard step 5: init repo
		sshxtest.Response{Err: errors.New("permission denied (publickey)")}, // step 5: verify append-only restored
		// --- backup ---
		sshxtest.Response{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df (free-space preflight)
		sshxtest.Response{}, // mkdir workspace
		sshxtest.Response{}, // writeManifest
		sshxtest.Response{}, // borg create
		sshxtest.Response{}, // rm -rf workspace
		// --- backup's archive coverage scan: docker ps, compose search,
		// custom systemd units + 11 well-known-state-path checks
		// (no containers, so no docker inspect) ---
		sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{},
		sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{},
		sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{}, sshxtest.Response{},
		// --- verify ---
		sshxtest.Response{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},    // borg list
		sshxtest.Response{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
		sshxtest.Response{Result: sshx.Result{Stdout: "Avail\n999999999999"}},       // df (free-space preflight)
		sshxtest.Response{}, // mkdir scratch dir
		sshxtest.Response{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
		sshxtest.Response{}, // borg extract
		sshxtest.Response{}, // rm -rf scratch dir
	)
	target := &sshxtest.FakeRunner{Responses: responses}
	storageBox := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // sftp get (existing authorized_keys: none found) — step 4
			{}, // sftp put (merged authorized_keys write) — step 4
			{}, // sftp get (existing authorized_keys) — step 5, lift append-only
			{}, // sftp put (unrestricted key) — step 5, lift append-only
			{}, // sftp get (existing authorized_keys) — step 5, restore append-only
			{}, // sftp put (restricted key) — step 5, restore append-only
		},
	}

	transport := newFakeTransport(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", existingSubaccountJSON)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/actions/enable_snapshot_plan",
		`{"action":{"id":2,"status":"success","command":"enable_snapshot_plan","progress":100,"started":"2026-01-01T00:00:00Z","finished":"2026-01-01T00:00:01Z","resources":[]}}`)

	d := testDepsWithTransport(t, target, transport)
	d.StorageBox = storageBox
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("Onboard: %v", err)
	}
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load after onboard: %v", err)
	}
	if st.Onboard.LastCompletedStep != 5 || !st.Provider.RepoInitialized {
		t.Fatalf("state after onboard = %+v, want all 5 steps complete and repo initialized", st)
	}

	if err := Backup(context.Background(), d); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	st, err = state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load after backup: %v", err)
	}
	if st.Timestamps.LastBackup == nil || st.LastManifest == nil {
		t.Fatalf("state after backup = %+v, want LastBackup and LastManifest recorded", st)
	}

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	st, err = state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load after verify: %v", err)
	}
	if !st.Verify.EverPassed || st.Timestamps.LastPassingVerify == nil {
		t.Fatalf("state after verify = %+v, want EverPassed and LastPassingVerify recorded", st)
	}

	if err := EnableSnapshots(context.Background(), d, hetzner.Schedule{MaxSnapshots: 7, Hour: 3}); err != nil {
		t.Fatalf("EnableSnapshots: %v", err)
	}

	// The full ordered transcript: 34 (discover: 13 initial fixed
	// checks + 2 borg/docker --version + 12 well-known-state-path
	// checks + 7 native-database probes) + 1 (step 2's own borg
	// --version check) + 6 (step 4 key install) + 3 (step 5: read
	// pubkey, init, verify append-only restored) = 44 from onboard,
	// then 5 from backup plus 14 from its archive coverage scan, then 7 from verify (list, borg list
	// --json-lines for the free-space preflight's workspace-dump-size
	// estimate, df, mkdir scratch dir, pwd to resolve
	// automationKeyPath to an absolute path before RestoreArchive's
	// own Dir changes cwd, then extract) — enable-snapshots touches
	// only the hcloud fake transport, not the target runner.
	if len(target.Calls) != 70 {
		t.Fatalf("target transcript has %d calls, want 70 (44 onboard + 5 backup + 14 coverage scan + 7 verify): %+v",
			len(target.Calls), target.Calls)
	}
	if len(storageBox.Calls) != 6 {
		t.Fatalf("storageBox transcript has %d calls, want 6 (step 4: get+put; step 5: get+put lift, get+put restore)", len(storageBox.Calls))
	}

	keygenCall := target.Calls[37]
	if keygenCall.Cmd != "ssh-keygen" {
		t.Errorf("call 37 = %q, want ssh-keygen (onboard step 4's keypair generation)", keygenCall.Cmd)
	}
	initRepoCall := target.Calls[42]
	if initRepoCall.Cmd != "borg" || initRepoCall.Args[0] != "init" {
		t.Errorf("call 42 = %q %v, want borg init ... (onboard step 5)", initRepoCall.Cmd, initRepoCall.Args)
	}
	backupCreateCall := target.Calls[47]
	if backupCreateCall.Cmd != "borg" || backupCreateCall.Args[0] != "create" {
		t.Errorf("call 47 = %q %v, want borg create ... (backup)", backupCreateCall.Cmd, backupCreateCall.Args)
	}
	verifyExtractCall := target.Calls[68]
	if verifyExtractCall.Cmd != "borg" || verifyExtractCall.Args[0] != "extract" {
		t.Errorf("call 68 = %q %v, want borg extract ... (verify)", verifyExtractCall.Cmd, verifyExtractCall.Args)
	}
}
