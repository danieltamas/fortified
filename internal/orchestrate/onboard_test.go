package orchestrate

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

const storageBoxGetJSON = `{"storage_box":{"id":123,"username":null,"status":"active","name":"main","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":"u123456.your-storagebox.de","system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"}}`

const existingSubaccountJSON = `{"subaccounts":[{"id":9,"name":"host-2-example","username":"u123456-sub9","home_directory":"backups/host-2-example","server":"u123456.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`

// testDeps builds a Deps wired against a fake hcloud transport (stubbed
// for CreateIsolatedDestination's idempotent-lookup path against an
// already-existing subaccount) and target as the runner for the
// protected server.
func testDeps(t *testing.T, target *sshxtest.FakeRunner) Deps {
	t.Helper()
	return testDepsWithTransport(t, target, defaultTransport(t))
}

// defaultTransport returns a fakeTransport pre-stubbed for the happy
// path (an already-existing subaccount) — tests that need to make the
// Provider fail construct their own transport and call stubStatus.
func defaultTransport(t *testing.T) *fakeTransport {
	t.Helper()
	transport := newFakeTransport(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", existingSubaccountJSON)
	return transport
}

func testDepsWithTransport(t *testing.T, target *sshxtest.FakeRunner, transport *fakeTransport) Deps {
	t.Helper()
	client := hcloud.NewClient(
		hcloud.WithToken("test-token"),
		hcloud.WithHTTPClient(&http.Client{Transport: transport}),
	)

	return Deps{
		Target:     target,
		StorageBox: &sshxtest.FakeRunner{},
		Local:      &sshxtest.FakeRunner{},
		Provider:   hetzner.Provider{Client: client, StorageBoxID: 123},
		Backend:    borg.Backend{Runner: target},
		Secrets:    secrets.Resolver{},
		StateDir:   t.TempDir(),
		Server:     testServer(),
		ServerID:   "host-2-example",
	}
}

func testServer() config.Server {
	return config.Server{
		SSH:      config.SSH{Host: "203.0.113.10", Port: 15086, User: "root"},
		Provider: "hetzner",
		Hetzner: &config.HetznerConfig{ //nolint:gosec // HCloudTokenRef below is a secret *reference* (env var name), never a literal credential
			MainAccount:    config.SSH{Host: "u123456.your-storagebox.de", Port: 22, User: "u123456"},
			HCloudTokenRef: "env://HCLOUD_TOKEN",
		},
		EncryptionKeyRef: "env://FORTIFIED_TEST_PASSPHRASE",
	}
}

// discoverResponses scripts the 15 fixed read-only commands
// discover.Inspect issues, in order, for a "complete, borg installed,
// zero containers" pass, plus one more response for step 2's own
// standalone `borg --version` check (ensureBorgInstalled) reporting
// borg already present — the minimal shape onboard's steps 1 and 2
// need to succeed without re-asserting discover's own argv (that's
// discover's own test's job) or exercising the auto-install path
// (that's TestOnboardStep2InstallsBorgWhenMissing's job).
func discoverResponses() []sshxtest.Response {
	return []sshxtest.Response{
		{}, // lsblk
		{}, // pvs
		{}, // vgs
		{}, // lvs
		{}, // zpool list
		{}, // btrfs filesystem show
		{}, // cat /proc/mdstat
		{}, // docker ps -a --format json (empty -> zero containers)
		{}, // find compose files
		{}, // ss -tlnp
		{}, // iptables -S
		{}, // nft list ruleset
		{}, // ufw status verbose
		{Result: sshx.Result{Stdout: "borg 1.2.4\n"}},    // borg --version (discover's own check)
		{Result: sshx.Result{Stdout: "Docker 27.0.0\n"}}, // docker --version
		{}, // ls -d /etc/wireguard
		{}, // ls -d /var/lib/tailscale
		{}, // ls -d /etc/nginx
		{}, // ls -d /etc/ufw
		{}, // ls -d /etc/iptables
		{}, // find /etc/systemd/system -maxdepth 1 -name *.service
		{}, // ls -d /etc/docker
		{}, // ls -d /root
		{}, // ls -d /var/spool/cron/crontabs
		{}, // ls -d /etc/ssh
		{}, // ls -d /etc/letsencrypt
		{}, // ls -d /etc/cloudflared
		{}, // systemctl is-active postgresql (native)
		{}, // su - postgres -c psql -tAc "SELECT 1" (native postgres auth probe)
		{}, // systemctl is-active mysql (native)
		{}, // systemctl is-active mariadb (native)
		{}, // test -r /etc/mysql/debian.cnf (native mysql creds)
		{}, // su - postgres -c psql --version (native postgres version, for verify's image)
		{}, // mysql --version (native mysql/mariadb version, for verify's image)
		{Result: sshx.Result{Stdout: "borg 1.2.4\n"}}, // step 2: ensureBorgInstalled's own borg --version check
	}
}

// freshKeyInstallResponses scripts onboard step 3's full sequence when
// no automation key exists yet on the target: the initial existence
// check (cat) fails, so generateAutomationKeypair clears any stale
// material (rm -f, tolerating "nothing to remove") and generates a
// fresh key, which is then read back, fingerprinted, and installed —
// the install's append-only verification is scripted as "refused",
// the good case (SPEC.md §5).
func freshKeyInstallResponses(comment string) []sshxtest.Response {
	return []sshxtest.Response{
		{Err: errors.New("no such file or directory")}, // cat pub key: doesn't exist yet
		{}, // rm -f (clear any stale key material)
		{}, // ssh-keygen
		{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz " + comment + "\n"}},     // cat pub key (now exists)
		{Result: sshx.Result{Stdout: "256 SHA256:abc " + comment + " (ED25519)\n"}}, // fingerprint
		{Err: errors.New("permission denied (publickey)")},                          // append-only verify: refused (good)
	}
}

// step5Responses scripts the responses onboard step 5 needs on
// d.Target for the happy path, once step 4 has already installed the
// automation key: reading its public key back (to temporarily lift
// the append-only restriction before InitRepo — borg init through a
// borg serve --append-only connection is a documented borg limitation,
// github.com/borgbackup/borg issues #2413/#5497), running InitRepo,
// then verifying append-only is restored afterward (SFTP refused =
// success, same convention as step 4's own verification).
func step5Responses(comment string) []sshxtest.Response {
	return []sshxtest.Response{
		{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz " + comment + "\n"}}, // read pubkey
		{}, // InitRepo
		{Err: errors.New("permission denied (publickey)")}, // verify append-only restored
	}
}

// TestRemoteRepoTargetIsARealRemoteSSHURL pins three exact bugs found
// in a live onboarding run: (1) RemoteRepoTarget must produce an
// ssh:// URL connecting to the subaccount, never a bare path — a bare
// path (what this codebase produced before an earlier fix) is
// silently treated as a path on whichever host runs the borg client,
// which in production is the *target server itself* (Deps.Target),
// not the Storage Box; (2) RepoPath must be a leading-slash absolute
// path (within the subaccount's own jail), not a bare relative name —
// borg serve's --restrict-to-repository check compares the incoming
// request's *resolved* absolute path as a literal string; (3) RepoPath
// must live under "/home/" specifically — verified live, borg init's
// own os.mkdir failed with "Read-only file system" at the jail's top
// level regardless of host key, identity, or append-only state all
// being correct, and only succeeded once nested under "/home/"
// (Hetzner's Storage Box only allows writes there). RepoPath (the same
// value install_key.go's --restrict-to-repository is configured with)
// must appear verbatim as RemoteRepoTarget's path component — they
// must agree exactly, or the Storage Box's forced `borg serve` refuses
// the connection.
func TestRemoteRepoTargetIsARealRemoteSSHURL(t *testing.T) {
	dest := hetzner.Destination{
		SubaccountID:  99,
		Username:      "u123456-sub2",
		HomeDirectory: "backups/host-2-example",
		Server:        "u123456-sub2.your-storagebox.de",
	}

	repoPath := RepoPath(dest)
	target := RemoteRepoTarget(dest)

	wantTarget := "ssh://u123456-sub2@u123456-sub2.your-storagebox.de:23/home/repo"
	if target != wantTarget {
		t.Fatalf("RemoteRepoTarget = %q, want %q", target, wantTarget)
	}
	if !strings.HasPrefix(target, "ssh://") {
		t.Fatalf("RemoteRepoTarget = %q, want an ssh:// URL, not a bare path a local borg client would misread", target)
	}
	if repoPath != "/home/repo" {
		t.Fatalf("RepoPath = %q, want the leading-slash absolute form \"/home/repo\" — the only writable location on a Storage Box", repoPath)
	}
	if !strings.HasSuffix(target, repoPath) {
		t.Errorf("RemoteRepoTarget = %q, want it to end with RepoPath %q verbatim (no extra slash) — install_key.go's --restrict-to-repository must match this exactly", target, repoPath)
	}
	if strings.Contains(target, "//repo") {
		t.Errorf("RemoteRepoTarget = %q, has a double slash before repo — a different, unintended meaning in Borg's URL syntax", target)
	}
	if strings.Contains(target, dest.HomeDirectory) {
		t.Errorf("RemoteRepoTarget = %q, must not repeat HomeDirectory %q — the subaccount's own SSH session is already jailed there", target, dest.HomeDirectory)
	}
}

// TestOnboardStep2InstallsBorgWhenMissing proves step 2 auto-installs
// borg via whichever package manager it detects, rather than refusing
// and making the operator SSH in and do it by hand — installing borg
// is a plain OS package, not a Hetzner-specific concern.
func TestOnboardStep2InstallsBorgWhenMissing(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := discoverResponses()
	resp[13] = sshxtest.Response{}                                              // discover's own borg --version check: empty (informational only now)
	resp[len(resp)-1] = sshxtest.Response{Err: errors.New("command not found")} // step 2's own borg --version check: still missing
	resp = append(resp,
		sshxtest.Response{Result: sshx.Result{Stdout: "/usr/bin/apt-get\n"}}, // detectPackageManager
		sshxtest.Response{}, // the install command itself
		sshxtest.Response{Result: sshx.Result{Stdout: "borg 1.2.4\n"}}, // post-install verify
	)
	resp = append(resp, freshKeyInstallResponses("fortified-host-2-example")...)
	resp = append(resp, step5Responses("fortified-host-2-example")...) // step 5
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	installCall := target.Calls[36]
	if installCall.Cmd != "sh" || !strings.Contains(strings.Join(installCall.Args, " "), "apt-get install") {
		t.Errorf("install call = %+v, want an apt-get install invocation", installCall)
	}
	if installCall.Class != sshx.Mutating {
		t.Errorf("install call class = %v, want Mutating", installCall.Class)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Onboard.LastCompletedStep < 2 {
		t.Errorf("LastCompletedStep = %d, want step 2 (install borg) to have completed", st.Onboard.LastCompletedStep)
	}
}

// TestBorgInstallCommandAptGetToleratesUpdateFailure proves apt-get
// update's own exit code can never block the install attempt —
// verified live against a real server: apt-get update returned exit
// 100 solely because a third-party repo (apt.postgresql.org's
// focal-pgdg component) had dropped its EOL distro codename, even
// though every other repo — including whichever one actually ships
// borgbackup — refreshed fine. The old `apt-get update && apt-get
// install` chain aborted before ever attempting the install; `|| true`
// between them means a broken, unrelated third-party repo can no
// longer block it.
func TestBorgInstallCommandAptGetToleratesUpdateFailure(t *testing.T) {
	cmd, args, err := borgInstallCommand("apt-get")
	if err != nil {
		t.Fatalf("borgInstallCommand: %v", err)
	}
	if cmd != "sh" || len(args) != 2 || args[0] != "-c" {
		t.Fatalf("borgInstallCommand = %q %v, want sh -c \"...\"", cmd, args)
	}
	script := args[1]
	if !strings.Contains(script, "apt-get update || true") {
		t.Errorf("script = %q, want apt-get update's exit code ignored", script)
	}
	if !strings.Contains(script, "apt-get install") {
		t.Errorf("script = %q, want it to still attempt the install", script)
	}
	updateIdx := strings.Index(script, "apt-get update")
	installIdx := strings.Index(script, "apt-get install")
	if updateIdx < 0 || installIdx < 0 || updateIdx > installIdx {
		t.Errorf("script = %q, want update to run before install", script)
	}
}

// TestEnsureBorgInstalledRetriesWithSudoWhenPlainInstallFails proves a
// non-root SSH login (verified live: a real server logging in as a
// non-root sudoer, unlike the rest of the fleet, which all log in as
// root) automatically retries via non-interactive sudo instead of
// failing outright on the plain install's dpkg-lock permission error.
func TestEnsureBorgInstalledRetriesWithSudoWhenPlainInstallFails(t *testing.T) {
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("command not found")},                       // borg --version: missing
		{Result: sshx.Result{Stdout: "/usr/bin/apt-get\n"}},          // detectPackageManager
		{Err: errors.New("exit 100: Permission denied (dpkg lock)")}, // plain install: fails, not root
		{}, // sudo -n install: succeeds
		{Result: sshx.Result{Stdout: "borg 1.2.4\n"}}, // post-install verify
	}}

	if err := ensureBorgInstalled(context.Background(), target); err != nil {
		t.Fatalf("ensureBorgInstalled: %v", err)
	}

	sudoCall := target.Calls[3]
	if sudoCall.Cmd != "sudo" || len(sudoCall.Args) < 2 || sudoCall.Args[0] != "-n" || sudoCall.Args[1] != "sh" {
		t.Errorf("sudo retry call = %+v, want sudo -n sh -c \"...\"", sudoCall)
	}
}

// TestEnsureBorgInstalledFailsClearlyWhenSudoAlsoFails proves that
// when neither a plain install nor non-interactive sudo works
// (verified live: passwordless sudo isn't configured for this login),
// the error names both failures and tells the operator exactly what
// to do, instead of surfacing only the confusing generic apt error.
func TestEnsureBorgInstalledFailsClearlyWhenSudoAlsoFails(t *testing.T) {
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("command not found")},                       // borg --version: missing
		{Result: sshx.Result{Stdout: "/usr/bin/apt-get\n"}},          // detectPackageManager
		{Err: errors.New("exit 100: Permission denied (dpkg lock)")}, // plain install: fails
		{Err: errors.New("sudo: a password is required")},            // sudo -n: also fails
	}}

	err := ensureBorgInstalled(context.Background(), target)
	if err == nil {
		t.Fatal("expected an error when both the plain install and sudo -n fail")
	}
	if !strings.Contains(err.Error(), "passwordless sudo") {
		t.Errorf("error = %v, want it to suggest configuring passwordless sudo", err)
	}
	if !strings.Contains(err.Error(), "a password is required") {
		t.Errorf("error = %v, want it to include sudo's own failure reason", err)
	}
}

// TestOnboardStep2FailsWhenNoPackageManagerFound proves onboard still
// surfaces a clear, actionable error when borg is missing and no
// supported package manager exists on the target — auto-install is a
// convenience, not a guarantee, and a target this unusual still needs
// the operator to intervene rather than fail silently or loop forever.
func TestOnboardStep2FailsWhenNoPackageManagerFound(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := discoverResponses()
	resp[13] = sshxtest.Response{}                                              // discover's own borg --version check: empty
	resp[len(resp)-1] = sshxtest.Response{Err: errors.New("command not found")} // step 2's own borg --version check: missing
	resp = append(resp, sshxtest.Response{})                                    // detectPackageManager: nothing found (empty stdout)
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)

	if err := Onboard(context.Background(), d, OnboardOptions{}); err == nil {
		t.Fatal("expected Onboard to fail when no supported package manager is found")
	} else if !strings.Contains(err.Error(), "no supported package manager") {
		t.Errorf("error = %v, want it to explain no package manager was found", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Onboard.LastCompletedStep != 1 {
		t.Errorf("LastCompletedStep = %d, want 1 (step 1 succeeded, step 2 failed)", st.Onboard.LastCompletedStep)
	}
}

// TestOnboardStep1PropagatesDiscoverFailure: discover.Inspect's own
// Run calls ignore errors from the runner (a command that simply
// fails still leaves a Capture entry — that's how a missing tool is
// distinguished from a network blip), so the one way a live discover
// pass genuinely fails is a response Parse can't make sense of at all
// — e.g. malformed docker ps JSON. onboard must surface that as a
// wrapped error, never silently proceed as if discover had produced
// something usable.
func TestOnboardStep1PropagatesDiscoverFailure(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := discoverResponses()
	resp[7] = sshxtest.Response{Result: sshx.Result{Stdout: "{not valid json"}} // docker ps: unparseable
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)

	err := Onboard(context.Background(), d, OnboardOptions{})
	if err == nil {
		t.Fatal("expected Onboard to fail when discover itself errors")
	}
	if !strings.Contains(err.Error(), "discover:") {
		t.Errorf("error = %v, want it to be wrapped as a discover failure", err)
	}
}

// TestOnboardStepsResumeFromLastCompletedStep: seeded at step 3
// (borg installed, destination confirmed, key not yet installed), a
// re-run must skip straight to step 4 — proven by the very first call
// to target being ssh-keygen's (step 4's), never one of discover's
// fixed commands or step 2's own borg-presence check.
func TestOnboardStepsResumeFromLastCompletedStep(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: freshKeyInstallResponses("fortified-host-2-example")}
	d := testDeps(t, target)

	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	// escrow isn't acknowledged, so step 5 refuses right after step 4
	// completes — expected; this test only cares that steps 1-3 are skipped.
	_ = Onboard(context.Background(), d, OnboardOptions{})

	if len(target.Calls) == 0 || target.Calls[0].Cmd != "cat" {
		t.Errorf("expected the first target call to be step 4's key-existence check (steps 1-3 skipped), got %+v", target.Calls)
	}
}

// TestOnboardStep4ReusesExistingKeyOnResume: if the automation key was
// already generated by a prior attempt (whose completion just wasn't
// recorded — e.g. the install or the state save afterward failed), a
// re-run must reuse it, not regenerate — proven by zero ssh-keygen or
// rm calls, just a read-back and re-install.
func TestOnboardStep4ReusesExistingKeyOnResume(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz fortified-host-2-example\n"}},     // cat pub key: already exists
			{Result: sshx.Result{Stdout: "256 SHA256:abc fortified-host-2-example (ED25519)\n"}}, // fingerprint
			{Err: errors.New("permission denied (publickey)")},                                   // append-only verify: refused (good)
		},
	}
	d := testDeps(t, target)
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Onboard(context.Background(), d, OnboardOptions{}); err != nil && !strings.Contains(err.Error(), "escrow") {
		t.Fatalf("Onboard: %v", err)
	}

	if len(target.Calls) != 3 {
		t.Fatalf("expected 3 calls (cat, fingerprint, verify) — no ssh-keygen/rm when the key already exists, got %d: %+v", len(target.Calls), target.Calls)
	}
	for _, c := range target.Calls {
		if c.Cmd == "ssh-keygen" && len(c.Args) > 0 && c.Args[0] != "-lf" {
			t.Errorf("expected no keypair generation on resume, got %+v", c)
		}
		if c.Cmd == "rm" {
			t.Errorf("expected no stale-key cleanup when the key already exists, got %+v", c)
		}
	}
}

func TestOnboardStep5RefusesWithoutEscrowAcknowledgment(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: freshKeyInstallResponses("fortified-host-2-example")}
	d := testDeps(t, target)

	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: false})
	if err == nil {
		t.Fatal("expected Onboard to refuse step 5 without escrow acknowledgment")
	}
	if !strings.Contains(err.Error(), "escrow") {
		t.Errorf("error = %v, want it to mention escrow", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Onboard.LastCompletedStep != 4 {
		t.Errorf("LastCompletedStep = %d, want 4 (step 4 completed, step 5 refused)", st.Onboard.LastCompletedStep)
	}
	if st.Provider.RepoInitialized {
		t.Error("expected RepoInitialized to remain false — the repo must never be initialized without escrow acknowledgment")
	}
}

func TestOnboardHappyPathAllSteps(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := discoverResponses()
	resp = append(resp, freshKeyInstallResponses("fortified-host-2-example")...)
	resp = append(resp, step5Responses("fortified-host-2-example")...) // step 5
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st.Onboard.LastCompletedStep != 5 {
		t.Errorf("LastCompletedStep = %d, want 5", st.Onboard.LastCompletedStep)
	}
	if !st.Provider.RepoInitialized || !st.Provider.EscrowAcked {
		t.Errorf("Provider state = %+v, want RepoInitialized and EscrowAcked", st.Provider)
	}
	if st.Provider.DestinationID != "9" {
		t.Errorf("DestinationID = %q, want 9 (the existing subaccount)", st.Provider.DestinationID)
	}
	if st.Provider.KeyFingerprint == "" {
		t.Error("expected a recorded key fingerprint")
	}
	if len(st.Databases) != 0 {
		t.Errorf("Databases = %+v, want empty (zero containers discovered)", st.Databases)
	}
	if st.Provider.AppendOnlyLifted {
		t.Error("AppendOnlyLifted = true after a clean onboard run, want false (restore succeeded)")
	}

	// The last call is step 5's post-init append-only restoration
	// verify (SFTP, expected refused) — borg init itself is second to
	// last, sandwiched between lifting and restoring the restriction.
	initCall := target.Calls[len(target.Calls)-2]
	if initCall.Cmd != "borg" || initCall.Args[0] != "init" {
		t.Errorf("second-to-last call = %q %v, want borg init ...", initCall.Cmd, initCall.Args)
	}
}

func TestOnboardIsIdempotentOnRerun(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := discoverResponses()
	resp = append(resp, freshKeyInstallResponses("fortified-host-2-example")...)
	resp = append(resp, step5Responses("fortified-host-2-example")...) // step 5
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("first Onboard: %v", err)
	}
	callsAfterFirst := len(target.Calls)

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("second Onboard: %v", err)
	}
	if len(target.Calls) != callsAfterFirst {
		t.Errorf("second Onboard issued %d more target calls, want 0 (every step already complete)", len(target.Calls)-callsAfterFirst)
	}
}

func TestOnboardStep4FailsWhenKeygenFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("no such file or directory")}, // cat pub key: doesn't exist yet
		{}, // rm -f
		{Err: errors.New("no space left on device")}, // ssh-keygen fails
	}}
	d := testDeps(t, target)
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{})
	if err == nil {
		t.Fatal("expected Onboard to fail when ssh-keygen fails on the target")
	}
	if !strings.Contains(err.Error(), "generate automation keypair") {
		t.Errorf("error = %v, want it to mention keypair generation", err)
	}
}

func TestOnboardStep4FailsWhenPublicKeyEmpty(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Err: errors.New("no such file or directory")}, // cat pub key: doesn't exist yet
			{},                                  // rm -f
			{},                                  // ssh-keygen succeeds
			{Result: sshx.Result{Stdout: "\n"}}, // cat pub key: empty
		},
	}
	d := testDeps(t, target)
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{})
	if err == nil {
		t.Fatal("expected Onboard to fail when the generated public key file is empty")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %v, want it to mention the empty public key", err)
	}
}

func TestOnboardStep4FailsWhenFingerprintFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Err: errors.New("no such file or directory")}, // cat pub key: doesn't exist yet
			{}, // rm -f
			{}, // ssh-keygen succeeds
			{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz fortified-host-2-example\n"}},
			{Err: errors.New("no such file")}, // fingerprint fails
		},
	}
	d := testDeps(t, target)
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{})
	if err == nil {
		t.Fatal("expected Onboard to fail when fingerprinting the generated key fails")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("error = %v, want it to mention fingerprinting", err)
	}
}

func TestOnboardStep3FailsWhenDestinationCreationFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: discoverResponses()}
	transport := newFakeTransport(t)
	transport.stubStatus(http.MethodGet, "/v1/storage_boxes/123", 500, serviceErrorJSON)
	d := testDepsWithTransport(t, target, transport)

	err := Onboard(context.Background(), d, OnboardOptions{})
	if err == nil {
		t.Fatal("expected Onboard to fail when creating/confirming the destination fails")
	}
	if !strings.Contains(err.Error(), "create/confirm destination") {
		t.Errorf("error = %v, want it to mention the destination step", err)
	}

	st, loadErr := state.Load(d.StateDir, d.ServerID)
	if loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	if st.Onboard.LastCompletedStep != 2 {
		t.Errorf("LastCompletedStep = %d, want 2 (steps 1-2 succeeded, step 3 failed)", st.Onboard.LastCompletedStep)
	}
}

// TestOnboardFailsFastOnUnresolvablePassphraseBeforeAnyWork proves an
// unresolvable encryption_key_ref is caught before any of onboard's
// real work runs (discover, subaccount creation, key install) — not
// just eventually, deep in step 5. Verified live: this used to only
// surface after ~45s of real SSH round trips and a real subaccount
// being created, all of which would have to be repeated on retry
// anyway once the operator actually set the missing env var.
func TestOnboardFailsFastOnUnresolvablePassphraseBeforeAnyWork(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	d.Server.EncryptionKeyRef = "env://FORTIFIED_TEST_UNSET_ONBOARD_PASSPHRASE"

	err := Onboard(context.Background(), d, OnboardOptions{})
	if err == nil {
		t.Fatal("expected Onboard to fail when encryption_key_ref can't be resolved")
	}
	if !strings.Contains(err.Error(), "resolve encryption_key_ref before starting") {
		t.Errorf("error = %v, want it to mention resolving encryption_key_ref before starting", err)
	}
	if len(target.Calls) != 0 {
		t.Errorf("target.Calls = %+v, want zero calls — this must fail before any real work starts", target.Calls)
	}

	st, loadErr := state.Load(d.StateDir, d.ServerID)
	if loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	if st.Onboard.LastCompletedStep != 0 {
		t.Errorf("LastCompletedStep = %d, want 0 — nothing should have run yet", st.Onboard.LastCompletedStep)
	}
}

// TestOnboardStep5FailsWhenPassphraseUnresolvable uses a ref with no
// valid scheme at all (neither env:// nor secret://) specifically so
// this exercises "genuinely unresolvable, onboard must refuse" — an
// unset *env://* ref with --escrow-acknowledged now takes a different
// path (generate one instead of failing, see
// TestOnboardGeneratesPassphraseWhenEnvRefUnsetAndEscrowAcknowledged).
func TestOnboardStep5FailsWhenPassphraseUnresolvable(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	d.Server.EncryptionKeyRef = "not-a-valid-ref-scheme"
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true})
	if err == nil {
		t.Fatal("expected Onboard to fail when encryption_key_ref can't be resolved")
	}
	if !strings.Contains(err.Error(), "resolve encryption_key_ref") {
		t.Errorf("error = %v, want it to mention resolving encryption_key_ref", err)
	}
}

// TestOnboardGeneratesPassphraseWhenEnvRefUnsetAndEscrowAcknowledged
// proves onboard generates a passphrase (rather than refusing) when
// the configured env:// ref is unset AND --escrow-acknowledged was
// passed — setting it in the environment and completing the run with
// it, and printing the actual generated value so the operator can go
// escrow it (never just a generic "a passphrase was generated"
// message with no way to know what it was).
func TestOnboardGeneratesPassphraseWhenEnvRefUnsetAndEscrowAcknowledged(t *testing.T) {
	const varName = "FORTIFIED_TEST_GENERATE_ME_PASSPHRASE"
	_ = os.Unsetenv(varName) // ensure a clean slate regardless of test order
	t.Cleanup(func() { _ = os.Unsetenv(varName) })

	target := &sshxtest.FakeRunner{Responses: step5Responses("fortified-host-2-example")}
	d := testDeps(t, target)
	d.Server.EncryptionKeyRef = "env://" + varName
	var messages []string
	d.Progress = func(msg string) { messages = append(messages, msg) }
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 4}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	generated := os.Getenv(varName)
	if generated == "" {
		t.Fatal("expected the generated passphrase to be set in the environment")
	}

	joined := strings.Join(messages, "\n")
	if !strings.Contains(joined, "generated a new repo encryption passphrase") {
		t.Errorf("progress messages = %v, want one announcing the generated passphrase", messages)
	}
	if !strings.Contains(joined, generated) {
		t.Errorf("progress messages = %v, want the actual generated value printed so the operator can escrow it", messages)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if !st.Provider.RepoInitialized {
		t.Error("expected RepoInitialized = true — onboard should have completed using the generated passphrase")
	}
}

// TestOnboardDoesNotGenerateWithoutEscrowAcknowledgment proves an
// unset env:// ref still refuses outright (today's exact behavior)
// when --escrow-acknowledged wasn't passed — generation only ever
// happens when the operator has already asserted escrow
// responsibility for whatever gets generated.
func TestOnboardDoesNotGenerateWithoutEscrowAcknowledgment(t *testing.T) {
	const varName = "FORTIFIED_TEST_DO_NOT_GENERATE_ME_PASSPHRASE"
	_ = os.Unsetenv(varName)
	t.Cleanup(func() { _ = os.Unsetenv(varName) })

	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	d.Server.EncryptionKeyRef = "env://" + varName
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 4}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: false})
	if err == nil {
		t.Fatal("expected Onboard to refuse rather than generate a passphrase without --escrow-acknowledged")
	}
	if os.Getenv(varName) != "" {
		t.Error("expected no passphrase to have been generated/set without --escrow-acknowledged")
	}
}

func TestOnboardStep5FailsWhenInitRepoFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := freshKeyInstallResponses("fortified-host-2-example")
	resp = append(resp,
		sshxtest.Response{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz fortified-host-2-example\n"}}, // step 5: read pubkey
		sshxtest.Response{Err: errBoom},                                     // InitRepo fails
		sshxtest.Response{Err: errors.New("permission denied (publickey)")}, // verify append-only restored (runs regardless of init failure)
	)
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true})
	if err == nil {
		t.Fatal("expected Onboard to fail when InitRepo fails")
	}
	if !strings.Contains(err.Error(), "init repo") {
		t.Errorf("error = %v, want it to mention init repo", err)
	}

	st, loadErr := state.Load(d.StateDir, d.ServerID)
	if loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	if st.Provider.RepoInitialized {
		t.Error("expected RepoInitialized to remain false after InitRepo failure")
	}
}

// TestOnboardStep5RecordsAppendOnlyLiftedBeforeAttemptingIt pins the
// crash-window fix: AppendOnlyLifted must already be true on disk
// *before* the lift is even attempted (not after it succeeds) — a
// process killed during the lift itself (or one whose lift call fails
// outright, exercised here) must leave a state record that says "may
// be unrestricted", the one on-disk signal status/backup can warn on,
// rather than a state record still claiming everything is fine.
func TestOnboardStep5RecordsAppendOnlyLiftedBeforeAttemptingIt(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: step5Responses("fortified-host-2-example")}
	storageBox := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errBoom}, // step 5's lift: fetch-existing-authorized_keys fails outright
	}}
	d := testDeps(t, target)
	d.StorageBox = storageBox
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 4}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true})
	if err == nil {
		t.Fatal("expected Onboard to fail when lifting append-only fails")
	}
	if !strings.Contains(err.Error(), "lift") {
		t.Errorf("error = %v, want it to mention lifting the restriction", err)
	}

	// Neither InitRepo nor the restore ever ran — the lift failure must
	// stop step 5 immediately, not proceed as if it had succeeded.
	if len(target.Calls) != 1 {
		t.Fatalf("expected only the pubkey read on target (lift failed before InitRepo), got %d: %+v", len(target.Calls), target.Calls)
	}

	st, loadErr := state.Load(d.StateDir, d.ServerID)
	if loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	if !st.Provider.AppendOnlyLifted {
		t.Error("AppendOnlyLifted = false, want true — recorded before the lift was even attempted, so it must survive this failure")
	}
}

// TestOnboardStep5RetriesInitRepoThroughTransientConnectionFailure
// proves a freshly-created subaccount's own hostname not resolving
// yet on the very first InitRepo attempt gets retried rather than
// failing onboard outright — verified live: a genuinely just-created
// subaccount's hostname was unreachable moments after creation, then
// fine on the very next attempt.
func TestOnboardStep5RetriesInitRepoThroughTransientConnectionFailure(t *testing.T) {
	orig := initRepoRetryDelay
	initRepoRetryDelay = time.Millisecond
	t.Cleanup(func() { initRepoRetryDelay = orig })

	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := freshKeyInstallResponses("fortified-host-2-example")
	resp = append(resp,
		sshxtest.Response{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz fortified-host-2-example\n"}},     // step 5: read pubkey
		sshxtest.Response{Err: errors.New("ssh: Could not resolve hostname u123456-sub9.your-storagebox.de")}, // InitRepo attempt 1: transient
		sshxtest.Response{}, // InitRepo attempt 2: succeeds
		sshxtest.Response{Err: errors.New("permission denied (publickey)")}, // verify append-only restored
	)
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if !st.Provider.RepoInitialized {
		t.Error("expected RepoInitialized to be true after InitRepo succeeded on retry")
	}
}

// TestOnboardStep5ResumesWhenRepoAlreadyExists: if InitRepo actually
// succeeded on a prior attempt but recording that (state.Save) failed
// afterward, a re-run must treat borg's "already exists" as success,
// not a failure — otherwise onboard can never complete for a server
// whose repo really is fine.
func TestOnboardStep5ResumesWhenRepoAlreadyExists(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := freshKeyInstallResponses("fortified-host-2-example")
	resp = append(resp,
		sshxtest.Response{Result: sshx.Result{Stdout: "ssh-ed25519 AAAAC3Nz fortified-host-2-example\n"}}, // step 5: read pubkey
		sshxtest.Response{Err: errors.New("A repository already exists at /repo.")},                       // InitRepo: already done
		sshxtest.Response{Err: errors.New("permission denied (publickey)")},                               // verify append-only restored
	)
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)
	seeded := &state.Server{ServerID: d.ServerID, Onboard: state.OnboardState{LastCompletedStep: 3}}
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Onboard(context.Background(), d, OnboardOptions{EscrowAcknowledged: true}); err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	st, loadErr := state.Load(d.StateDir, d.ServerID)
	if loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	if !st.Provider.RepoInitialized || st.Onboard.LastCompletedStep != 5 {
		t.Errorf("state = %+v, want RepoInitialized and step 5 complete despite borg reporting the repo already exists", st)
	}
}

// TestOnboardRecordFailureAlsoReportsSaveFailure: when a step fails
// AND persisting that failure reason also fails (e.g. the state
// directory vanished), the returned error must surface both — an
// operator debugging a failed onboard should never see only the
// second, more confusing failure.
func TestOnboardRecordFailureAlsoReportsSaveFailure(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	resp := discoverResponses()
	resp[7] = sshxtest.Response{Result: sshx.Result{Stdout: "{not valid json"}} // docker ps: unparseable -> step 1 fails
	target := &sshxtest.FakeRunner{Responses: resp}
	d := testDeps(t, target)
	d.StateDir = "/nonexistent/definitely-not-a-real-directory"

	err := Onboard(context.Background(), d, OnboardOptions{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "discover:") || !strings.Contains(err.Error(), "saving the failure reason also failed") {
		t.Errorf("error = %v, want it to mention both the original cause and the save failure", err)
	}
}
