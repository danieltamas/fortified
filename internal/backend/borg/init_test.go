package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestInitRepoArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	if err := b.InitRepo(context.Background(), "/repo/host-2-example", "s3cr3t-passphrase", "/identity-key"); err != nil {
		t.Fatalf("InitRepo: %v", err)
	}

	if len(fake.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(fake.Calls))
	}
	call := fake.Calls[0]
	if call.Cmd != "borg" {
		t.Errorf("cmd = %q, want borg", call.Cmd)
	}
	wantArgs := []string{"init", "--encryption=repokey-blake2", "/repo/host-2-example"}
	if strings.Join(call.Args, "|") != strings.Join(wantArgs, "|") {
		t.Errorf("args = %v, want %v", call.Args, wantArgs)
	}
	if call.Class != sshx.Mutating {
		t.Errorf("class = %v, want Mutating", call.Class)
	}
}

func TestInitRepoPassphraseNeverInArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}
	const sentinel = "sentinel-repo-passphrase"

	if err := b.InitRepo(context.Background(), "/repo/x", sentinel, "/identity-key"); err != nil {
		t.Fatalf("InitRepo: %v", err)
	}

	call := fake.Calls[0]
	if strings.Contains(strings.Join(call.Args, " "), sentinel) {
		t.Fatalf("passphrase leaked into argv: %v", call.Args)
	}
	found := false
	for _, e := range call.Env {
		if e == "BORG_PASSPHRASE="+sentinel {
			found = true
		}
	}
	if !found {
		t.Errorf("expected BORG_PASSPHRASE=%s in Env, got %v", sentinel, call.Env)
	}
}

// TestRemoteRepoEnvPinsHostKeyChecking pins two exact bugs found in a
// live onboarding run: (1) without StrictHostKeyChecking=accept-new,
// borg's own internal ssh call (made from wherever this Backend's
// Runner executes — the protected target server, connecting onward to
// the Storage Box) fails outright with "Host key verification failed"
// the first time that target ever talks to its Storage Box
// subaccount, since its own known_hosts starts empty and there's no
// TTY to answer the interactive prompt; (2) without -i/-o
// IdentitiesOnly naming the automation key specifically, that same ssh
// call falls back to the target's *default* identity (an agent's
// offered keys, ~/.ssh/id_*) — none of which are authorized on the
// subaccount — and fails with "Permission denied (publickey,password)"
// even once the host key itself is accepted.
func TestRemoteRepoEnvPinsHostKeyChecking(t *testing.T) {
	env := remoteRepoEnv("s3cr3t", "/identity-key")
	want := "BORG_RSH=ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i /identity-key"
	found := false
	for _, e := range env {
		if e == want {
			found = true
		}
	}
	if !found {
		t.Errorf("remoteRepoEnv(...) = %v, want it to include %q", env, want)
	}
}

func TestInitRepoFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if err := b.InitRepo(context.Background(), "/repo/x", "pw", "/identity-key"); err == nil {
		t.Fatal("expected InitRepo to propagate the runner error")
	}
}
