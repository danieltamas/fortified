package sshx_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

var errBoom = errors.New("boom")

func TestSessionOpenRunCloseArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	const controlPath = "/tmp/fortified-ssh-test.sock"

	session, err := sshx.OpenSession(context.Background(), fake, target, controlPath)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if _, err := session.Run(context.Background(), sshx.ReadOnly, "lsblk", []string{"-J"}, sshx.RunOptions{}); err != nil {
		t.Fatalf("session.Run: %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("session.Close: %v", err)
	}

	if len(fake.Calls) != 3 {
		t.Fatalf("expected 3 calls (open, run, close), got %d", len(fake.Calls))
	}

	open := fake.Calls[0]
	if open.Cmd != "ssh" || !containsAll(open.Args, "-MNf", "-o", "ControlMaster=auto", "-o", "ControlPath="+controlPath, "-p", "15086", "root@203.0.113.10") {
		t.Errorf("open argv = %v, want it to include the master-connection flags", open.Args)
	}

	run := fake.Calls[1]
	wantRunArgs := []string{"-o", "ControlPath=" + controlPath, "-p", "15086", "root@203.0.113.10", "--", "lsblk", "-J"}
	if strings.Join(run.Args, "|") != strings.Join(wantRunArgs, "|") {
		t.Errorf("run argv = %v, want %v", run.Args, wantRunArgs)
	}

	closeCall := fake.Calls[2]
	if !containsAll(closeCall.Args, "-O", "exit", "-o", "ControlPath="+controlPath) {
		t.Errorf("close argv = %v, want it to include -O exit and the control path", closeCall.Args)
	}
}

// TestSessionOmitsPortAndUserWhenUnset proves a zero Port / empty User
// never reaches the ssh argv as an explicit -p/user@ — see Target's
// doc comment: an explicit -p 22 on the command line silently beats a
// ~/.ssh/config Host alias's own `Port 15086`, which is exactly what
// made discover hang dialing the wrong port before this fix.
func TestSessionOmitsPortAndUserWhenUnset(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	target := sshx.Target{Host: "host-2-example"}
	const controlPath = "/tmp/fortified-ssh-test-alias.sock"

	session, err := sshx.OpenSession(context.Background(), fake, target, controlPath)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if _, err := session.Run(context.Background(), sshx.ReadOnly, "lsblk", []string{"-J"}, sshx.RunOptions{}); err != nil {
		t.Fatalf("session.Run: %v", err)
	}

	for _, call := range fake.Calls {
		for _, a := range call.Args {
			if a == "-p" {
				t.Errorf("argv %v includes an explicit -p despite Port being unset", call.Args)
			}
		}
		if !containsAll(call.Args, "host-2-example") {
			t.Errorf("argv %v missing the bare host-2-example destination (no user@ prefix expected)", call.Args)
		}
	}
}

func containsAll(haystack []string, needles ...string) bool {
	set := make(map[string]bool, len(haystack))
	for _, h := range haystack {
		set[h] = true
	}
	for _, n := range needles {
		if !set[n] {
			return false
		}
	}
	return true
}

func TestSessionRunDeliversEnvViaStdin(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	session, err := sshx.OpenSession(context.Background(), fake, target, "/tmp/fortified-ssh-env-test.sock")
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	if _, err := session.Run(context.Background(), sshx.Mutating, "borg",
		[]string{"create", "::archive", "/data"},
		sshx.RunOptions{Env: []string{"BORG_PASSPHRASE=hunter2"}, Stdin: "payload"}); err != nil {
		t.Fatalf("session.Run: %v", err)
	}

	run := fake.Calls[1]
	for _, arg := range run.Args {
		if strings.Contains(arg, "hunter2") {
			t.Fatal("secret reached ssh argv")
		}
	}
	if run.Stdin != "BORG_PASSPHRASE=hunter2\n\npayload" {
		t.Errorf("stdin = %q, want env, blank line, then payload", run.Stdin)
	}
	if !containsAll(run.Args, "borg", "create", "::archive", "/data") {
		t.Errorf("run argv = %v, missing logical command", run.Args)
	}
	// The local ssh process itself must not also receive the secret via
	// its own Env — vanilla ssh wouldn't forward it anyway, and doing so
	// would be a second, redundant place the value could leak from.
	if len(run.Env) != 0 {
		t.Errorf("expected the underlying local Runner.Run call to receive no Env, got %v", run.Env)
	}
}

func TestSessionRunWithDirWrapsInShell(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	session, err := sshx.OpenSession(context.Background(), fake, target, "/tmp/fortified-ssh-dir-test.sock")
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	if _, err := session.Run(context.Background(), sshx.ReadOnly, "borg",
		[]string{"extract", "::archive"},
		sshx.RunOptions{Dir: "/tmp/restore-scratch", Env: []string{"BORG_PASSPHRASE=hunter2"}}); err != nil {
		t.Fatalf("session.Run: %v", err)
	}

	run := fake.Calls[1]
	for _, arg := range run.Args {
		if strings.Contains(arg, "hunter2") {
			t.Fatal("secret reached ssh argv")
		}
	}
	if !strings.Contains(strings.Join(run.Args, " "), `cd /tmp/restore-scratch && exec "$@"`) {
		t.Errorf("run argv = %v, want cd before exec", run.Args)
	}
	if run.Stdin != "BORG_PASSPHRASE=hunter2\n\n" {
		t.Errorf("stdin = %q, want env followed by blank line", run.Stdin)
	}
	if len(run.Env) != 0 {
		t.Fatal("local runner received Env")
	}
}

// TestSessionRunFailureNeverLeaksEnvIntoError: ExecRunner formats its
// own errors using the args it was given — for a Session call, that's
// sshArgs, which embeds opts.Env's assignments as literal words
// (env.go's remoteWords). If Session.Run ever returned that error
// as-is, a failed borg/mysqldump call would put the passphrase in
// plain text into any log or terminal output that prints the error —
// exactly what SPEC.md's "never argv or logs" forbids.
func TestSessionRunFailureNeverLeaksEnvIntoError(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // open
			{
				Result: sshx.Result{Stderr: "repository already exists", ExitCode: 2},
				// Simulates ExecRunner's own error formatting, which bakes
				// its args (sshArgs, secret-bearing for a Session call)
				// into the message — exactly what Session.Run must never
				// let escape.
				Err: errors.New(`ssh [-o ControlPath=/tmp/x -p 15086 root@203.0.113.10 -- env BORG_PASSPHRASE=hunter2 borg create ::archive /data]: exit 2: repository already exists`),
			},
		},
	}
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	session, err := sshx.OpenSession(context.Background(), fake, target, "/tmp/fortified-ssh-leak-test.sock")
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	_, runErr := session.Run(context.Background(), sshx.Mutating, "borg",
		[]string{"create", "::archive", "/data"},
		sshx.RunOptions{Env: []string{"BORG_PASSPHRASE=hunter2"}})
	if runErr == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(runErr.Error(), "hunter2") {
		t.Fatalf("session.Run's error leaked the secret: %q", runErr.Error())
	}
	if !strings.Contains(runErr.Error(), "borg") || !strings.Contains(runErr.Error(), "create") {
		t.Errorf("session.Run's error = %q, want it to still name the logical command that failed", runErr.Error())
	}
}

func TestSessionOpenFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	_, err := sshx.OpenSession(context.Background(), fake, sshx.Target{Host: "h", Port: 22, User: "root"}, "/tmp/x.sock")
	if err == nil {
		t.Fatal("expected OpenSession to surface the runner's error")
	}
}
