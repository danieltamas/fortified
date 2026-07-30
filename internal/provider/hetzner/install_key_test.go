package hetzner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func testMain() MainAccount {
	return MainAccount{Target: sshx.Target{Host: "u123456.your-storagebox.de", Port: 22, User: "u123456"}}
}

func testDest() Destination {
	return Destination{SubaccountID: 9, Username: "u123456-sub9", HomeDirectory: "backups/host-2-example", Server: "u123456.your-storagebox.de"}
}

// TestInstallKeyArgv asserts the exact sftp invocations and stdin
// batch scripts InstallServerKey constructs for an append-only key —
// this is the mechanism NOTES.md verified (direct authorized_keys
// provisioning by the main account), not the install-ssh-key protocol
// command, which cannot attach a forced command. writeAuthorizedKeys
// fetches the file before writing it (merge, not overwrite — see
// TestMergeAuthorizedKeysLine), so a successful install is two sftp
// calls: get, then put.
func TestInstallKeyArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	p := Provider{}

	req := InstallKeyRequest{
		Main:        testMain(),
		Destination: testDest(),
		PublicKey:   "ssh-ed25519 AAAAC3Nz fortified-host-2-example",
		AppendOnly:  true,
		RepoPath:    "backups/host-2-example/repo",
	}
	if err := p.InstallServerKey(context.Background(), fake, fake, req); err != nil {
		t.Fatalf("InstallServerKey: %v", err)
	}

	if len(fake.Calls) != 2 {
		t.Fatalf("expected 2 calls (get existing, then put merged), got %d: %+v", len(fake.Calls), fake.Calls)
	}

	getCall := fake.Calls[0]
	if getCall.Cmd != "sftp" {
		t.Fatalf("get cmd = %q, want sftp", getCall.Cmd)
	}
	if !strings.Contains(getCall.Stdin, "-get backups/host-2-example/.ssh/authorized_keys") {
		t.Errorf("get stdin = %q, want a -get of the remote authorized_keys", getCall.Stdin)
	}
	if getCall.Class != sshx.ReadOnly {
		t.Errorf("get class = %v, want ReadOnly", getCall.Class)
	}

	putCall := fake.Calls[1]
	if putCall.Cmd != "sftp" {
		t.Fatalf("put cmd = %q, want sftp", putCall.Cmd)
	}
	wantTrailingArgs := []string{"-b", "-", "-P", "22", "u123456@u123456.your-storagebox.de"}
	if !hasTrailingArgs(putCall.Args, wantTrailingArgs) {
		t.Errorf("put args = %v, want it to end with %v", putCall.Args, wantTrailingArgs)
	}
	assertMultiplexed(t, putCall.Args)
	if putCall.Class != sshx.Mutating {
		t.Errorf("put class = %v, want Mutating", putCall.Class)
	}

	if !strings.Contains(putCall.Stdin, "-mkdir backups/host-2-example/.ssh") {
		t.Errorf("put stdin = %q, want it to mkdir the .ssh dir (ignoring failure)", putCall.Stdin)
	}
	if !strings.Contains(putCall.Stdin, "put ") || !strings.Contains(putCall.Stdin, "backups/host-2-example/.ssh/authorized_keys") {
		t.Errorf("put stdin = %q, want a put into .ssh/authorized_keys", putCall.Stdin)
	}
}

func TestAuthorizedKeysLine(t *testing.T) {
	plain := authorizedKeysLine("ssh-ed25519 AAAA operator-prune-key", false, "")
	if plain != "ssh-ed25519 AAAA operator-prune-key" {
		t.Errorf("plain key line = %q, want the pubkey unchanged", plain)
	}

	appendOnly := authorizedKeysLine("ssh-ed25519 AAAA fortified-automation", true, "backups/host-2-example/repo")
	want := `command="borg serve --append-only --restrict-to-repository backups/host-2-example/repo",restrict ssh-ed25519 AAAA fortified-automation`
	if appendOnly != want {
		t.Errorf("append-only line = %q, want %q", appendOnly, want)
	}
}

func TestInstallKeyPlainKeyHasNoForcedCommand(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	p := Provider{}

	req := InstallKeyRequest{
		Main:        testMain(),
		Destination: testDest(),
		PublicKey:   "ssh-ed25519 AAAAC3Nz operator-prune-key",
		AppendOnly:  false,
	}
	if err := p.InstallServerKey(context.Background(), fake, fake, req); err != nil {
		t.Fatalf("InstallServerKey: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("expected 2 calls (get, put), got %d", len(fake.Calls))
	}
}

func TestInstallKeyFetchExistingFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{{Err: errors.New("sftp: connection refused")}},
	}
	p := Provider{}

	req := InstallKeyRequest{
		Main:        testMain(),
		Destination: testDest(),
		PublicKey:   "ssh-ed25519 AAAAC3Nz operator-prune-key",
		AppendOnly:  false,
	}
	if err := p.InstallServerKey(context.Background(), fake, fake, req); err == nil {
		t.Fatal("expected the existing-authorized_keys fetch failure to propagate")
	}
	if len(fake.Calls) != 1 {
		t.Fatalf("expected exactly 1 call (get, never reaching put), got %d", len(fake.Calls))
	}
}

func TestInstallKeyWriteFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // get existing (none found)
			{Err: errors.New("sftp: connection refused")}, // put fails
		},
	}
	p := Provider{}

	req := InstallKeyRequest{
		Main:        testMain(),
		Destination: testDest(),
		PublicKey:   "ssh-ed25519 AAAAC3Nz operator-prune-key",
		AppendOnly:  false,
	}
	if err := p.InstallServerKey(context.Background(), fake, fake, req); err == nil {
		t.Fatal("expected the authorized_keys write failure to propagate")
	}
}

func TestInstallKeyAppendOnlyRequiresRepoPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	p := Provider{}

	req := InstallKeyRequest{
		Main:        testMain(),
		Destination: testDest(),
		PublicKey:   "ssh-ed25519 AAAAC3Nz fortified-host-2-example",
		AppendOnly:  true,
		// RepoPath deliberately omitted.
	}
	if err := p.InstallServerKey(context.Background(), fake, fake, req); err == nil {
		t.Fatal("expected an error when AppendOnly is set without a RepoPath")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero calls when refusing early, got %d", len(fake.Calls))
	}
}

// TestInstallKeyAppendOnlyUnconfirmedFails: if the post-install
// verification connection (SFTP using the just-installed key) does
// NOT fail, the forced command didn't take effect — InstallServerKey
// must surface that as a hard error, never proceed as if protected
// (SPEC.md §5).
func TestInstallKeyAppendOnlyUnconfirmedFails(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{},         // get existing (none found)
			{},         // authorized_keys write succeeds
			{Err: nil}, // verification SFTP call "succeeds" — the bad case
		},
	}
	p := Provider{}

	req := InstallKeyRequest{
		Main:          testMain(),
		Destination:   testDest(),
		PublicKey:     "ssh-ed25519 AAAAC3Nz fortified-host-2-example",
		AppendOnly:    true,
		RepoPath:      "backups/host-2-example/repo",
		VerifyKeyPath: "/tmp/fortified-host-2-example-key",
	}
	err := p.InstallServerKey(context.Background(), fake, fake, req)
	if err == nil {
		t.Fatal("expected InstallServerKey to fail when append-only enforcement could not be confirmed")
	}
	if len(fake.Calls) != 3 {
		t.Fatalf("expected 3 calls (get, put, verify), got %d: %+v", len(fake.Calls), fake.Calls)
	}
}

func TestInstallKeyAppendOnlyConfirmedSucceeds(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // get existing (none found)
			{}, // authorized_keys write succeeds
			{Err: errors.New("permission denied (publickey)")}, // verification SFTP call fails — the good case: refused
		},
	}
	p := Provider{}

	req := InstallKeyRequest{
		Main:          testMain(),
		Destination:   testDest(),
		PublicKey:     "ssh-ed25519 AAAAC3Nz fortified-host-2-example",
		AppendOnly:    true,
		RepoPath:      "backups/host-2-example/repo",
		VerifyKeyPath: "/tmp/fortified-host-2-example-key",
	}
	if err := p.InstallServerKey(context.Background(), fake, fake, req); err != nil {
		t.Fatalf("InstallServerKey: %v", err)
	}

	verifyCall := fake.Calls[2]
	if verifyCall.Cmd != "sftp" {
		t.Fatalf("verify cmd = %q, want sftp", verifyCall.Cmd)
	}
	wantArgs := []string{"-i", "/tmp/fortified-host-2-example-key", "-P", "23", "-o", "BatchMode=yes", "u123456-sub9@u123456.your-storagebox.de"}
	if strings.Join(verifyCall.Args, "|") != strings.Join(wantArgs, "|") {
		t.Errorf("verify args = %v, want %v", verifyCall.Args, wantArgs)
	}
	if verifyCall.Class != sshx.ReadOnly {
		t.Errorf("verify class = %v, want ReadOnly", verifyCall.Class)
	}
}

// TestInstallKeyAppendOnlyRetriesThroughTransientConnectionFailure
// proves a freshly-created subaccount's own hostname not resolving yet
// (verified live — Hetzner's CreateSubaccount API can return success
// before the subaccount's distinct hostname is actually reachable)
// gets retried rather than being misread as "the forced command
// refused the session", which would be a false pass.
func TestInstallKeyAppendOnlyRetriesThroughTransientConnectionFailure(t *testing.T) {
	orig := appendOnlyVerifyRetryDelay
	appendOnlyVerifyRetryDelay = time.Millisecond
	t.Cleanup(func() { appendOnlyVerifyRetryDelay = orig })

	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // get existing (none found)
			{}, // authorized_keys write succeeds
			{Err: errors.New("ssh: Could not resolve hostname u123456-sub9.your-storagebox.de")}, // verify attempt 1: transient
			{Err: errors.New("permission denied (publickey)")},                                   // verify attempt 2: the real, expected refusal
		},
	}
	p := Provider{}

	req := InstallKeyRequest{
		Main:          testMain(),
		Destination:   testDest(),
		PublicKey:     "ssh-ed25519 AAAAC3Nz fortified-host-2-example",
		AppendOnly:    true,
		RepoPath:      "backups/host-2-example/repo",
		VerifyKeyPath: "/tmp/fortified-host-2-example-key",
	}
	if err := p.InstallServerKey(context.Background(), fake, fake, req); err != nil {
		t.Fatalf("InstallServerKey: %v", err)
	}
	if len(fake.Calls) != 4 {
		t.Fatalf("expected 4 calls (get, put, verify x2), got %d: %+v", len(fake.Calls), fake.Calls)
	}
}

// TestInstallKeyAppendOnlyFailsClosedWhenNeverReachable pins the
// fail-open gap this fixed: if every retry attempt fails at the
// network layer (never once reaching the subaccount to actually
// observe the forced command), that must surface as a hard failure —
// we've confirmed nothing about the restriction, only that the
// network was down. The previous behavior treated any non-nil error
// here as proof of success, which silently "certified" a key whose
// restriction was never actually tested.
func TestInstallKeyAppendOnlyFailsClosedWhenNeverReachable(t *testing.T) {
	origAttempts, origDelay := appendOnlyVerifyRetryAttempts, appendOnlyVerifyRetryDelay
	appendOnlyVerifyRetryAttempts = 3
	appendOnlyVerifyRetryDelay = time.Millisecond
	t.Cleanup(func() {
		appendOnlyVerifyRetryAttempts, appendOnlyVerifyRetryDelay = origAttempts, origDelay
	})

	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // get existing (none found)
			{}, // authorized_keys write succeeds
			{Err: errors.New("ssh: Could not resolve hostname u123456-sub9.your-storagebox.de")},                    // verify attempt 1: transient
			{Err: errors.New("ssh: connect to host u123456-sub9.your-storagebox.de port 23: Connection timed out")}, // attempt 2: transient
			{Err: errors.New("ssh: connect to host u123456-sub9.your-storagebox.de port 23: Connection timed out")}, // attempt 3: transient, budget exhausted
		},
	}
	p := Provider{}

	req := InstallKeyRequest{
		Main:          testMain(),
		Destination:   testDest(),
		PublicKey:     "ssh-ed25519 AAAAC3Nz fortified-host-2-example",
		AppendOnly:    true,
		RepoPath:      "backups/host-2-example/repo",
		VerifyKeyPath: "/tmp/fortified-host-2-example-key",
	}
	err := p.InstallServerKey(context.Background(), fake, fake, req)
	if err == nil {
		t.Fatal("expected InstallServerKey to fail when every verify attempt only ever hit a network-layer error — nothing about the restriction was confirmed")
	}
	if !strings.Contains(err.Error(), "could not confirm") {
		t.Errorf("err = %v, want it to say the restriction could not be confirmed, not that it was", err)
	}
}

// TestInstallKeyUsesDistinctRunners proves InstallServerKey actually
// routes the authorized_keys write and the append-only verification
// through the two runners it's given, rather than silently using only
// one of them — production wiring depends on these being genuinely
// different connections (SPEC.md §3: the main account write runs from
// the control host, the verify step runs from the target server,
// since that's the only place the automation private key exists).
func TestInstallKeyUsesDistinctRunners(t *testing.T) {
	mainRunner := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // get existing (none found)
			{}, // authorized_keys write succeeds
		},
	}
	verifyRunner := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Err: errors.New("permission denied (publickey)")}, // refused — the good case
		},
	}
	p := Provider{}

	req := InstallKeyRequest{
		Main:          testMain(),
		Destination:   testDest(),
		PublicKey:     "ssh-ed25519 AAAAC3Nz fortified-host-2-example",
		AppendOnly:    true,
		RepoPath:      "backups/host-2-example/repo",
		VerifyKeyPath: "/tmp/fortified-host-2-example-key",
	}
	if err := p.InstallServerKey(context.Background(), mainRunner, verifyRunner, req); err != nil {
		t.Fatalf("InstallServerKey: %v", err)
	}

	if len(mainRunner.Calls) != 2 {
		t.Errorf("mainRunner got %d calls, want 2 (get, put) — the write must never reach verifyRunner", len(mainRunner.Calls))
	}
	if len(verifyRunner.Calls) != 1 {
		t.Errorf("verifyRunner got %d calls, want 1 (verify) — the write must never reach verifyRunner", len(verifyRunner.Calls))
	}
}

// TestMergeAuthorizedKeysLine proves the actual fix: reinstalling a
// key replaces its own entry (matched by key blob, ignoring any
// command="..." prefix or trailing comment) without disturbing
// unrelated entries — e.g. installing the append-only automation key
// must never delete an already-installed prune key, and vice versa
// (NOTES.md's dual-key model).
func TestMergeAuthorizedKeysLine(t *testing.T) {
	pruneLine := "ssh-ed25519 AAAAPRUNE operator-prune-key"
	autoLine := `command="borg serve --append-only --restrict-to-repository backups/host-2-example/repo",restrict ssh-ed25519 AAAAAUTO fortified-automation`

	t.Run("first install with nothing existing", func(t *testing.T) {
		got := mergeAuthorizedKeysLine("", autoLine)
		if got != autoLine+"\n" {
			t.Errorf("merged = %q, want just the new line", got)
		}
	})

	t.Run("preserves an unrelated existing key", func(t *testing.T) {
		got := mergeAuthorizedKeysLine(pruneLine+"\n", autoLine)
		want := pruneLine + "\n" + autoLine + "\n"
		if got != want {
			t.Errorf("merged = %q, want %q (prune key preserved, automation key appended)", got, want)
		}
	})

	t.Run("replaces its own prior entry instead of duplicating", func(t *testing.T) {
		oldAutoLine := `command="borg serve --append-only --restrict-to-repository backups/OLD/repo",restrict ssh-ed25519 AAAAAUTO fortified-automation`
		got := mergeAuthorizedKeysLine(pruneLine+"\n"+oldAutoLine+"\n", autoLine)
		want := pruneLine + "\n" + autoLine + "\n"
		if got != want {
			t.Errorf("merged = %q, want %q (old automation entry replaced, not duplicated)", got, want)
		}
	})
}

// hasTrailingArgs reports whether args ends with exactly want, in
// order — used instead of exact-equality now that mainAccountSFTPArgs
// prepends multiplexing options whose control-path component embeds
// the test process's own PID, so it can't be hardcoded.
func hasTrailingArgs(args, want []string) bool {
	if len(args) < len(want) {
		return false
	}
	got := args[len(args)-len(want):]
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// assertMultiplexed pins the exact bug the operator hit live: every
// main-account SFTP call (get, put, mkdir) was spawning its own fresh
// SSH connection — no ControlMaster/ControlPath at all — while
// Deps.Target's own Session already multiplexed via exactly this
// mechanism. Onboard step 5's lift/restore dance alone triggered 5
// separate reconnect/Touch-ID prompts before this fix.
func assertMultiplexed(t *testing.T, args []string) {
	t.Helper()
	joined := strings.Join(args, " ")
	for _, want := range []string{"-o ControlMaster=auto", "-o ControlPersist=60", "-o ControlPath="} {
		if !strings.Contains(joined, want) {
			t.Errorf("args = %v, want it to include %q so repeated main-account calls reuse one connection", args, want)
		}
	}
}
