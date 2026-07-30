package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestRestoreArchiveArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	if err := b.RestoreArchive(context.Background(), "/repo/host-2-example", ArchiveID("2026-07-17"), "pw", "/identity-key", "/restore/scratch"); err != nil {
		t.Fatalf("RestoreArchive: %v", err)
	}

	call := fake.Calls[0]
	if call.Cmd != "borg" {
		t.Errorf("cmd = %q, want borg", call.Cmd)
	}
	wantArgs := []string{"extract", "/repo/host-2-example::2026-07-17"}
	if strings.Join(call.Args, "|") != strings.Join(wantArgs, "|") {
		t.Errorf("args = %v, want %v", call.Args, wantArgs)
	}
	if call.Class != sshx.Mutating {
		t.Errorf("class = %v, want Mutating", call.Class)
	}
}

// TestRestoreArchiveResolvesRelativeIdentityPathToAbsolute is a
// regression guard for a real bug found by cross-vendor review:
// RestoreArchive always sets Dir on the underlying borg extract call
// (borg extract writes into the current directory — there's no
// destination-path flag), which sshx.Session wraps as `cd targetPath
// && ...`. A relative identityPath (e.g. the bare "fortified-
// automation-key" filename staged once at onboard time in whatever
// directory the SSH login shell defaults to) would then have its `-i`
// argument resolved by ssh against the NEW cwd (targetPath) once borg
// invokes it, not wherever the key file actually lives — breaking
// every restore/verify/drill run that uses a relative identity path
// with a distinct target directory. RestoreArchive must resolve it to
// an absolute path first, via one extra `pwd` call.
func TestRestoreArchiveResolvesRelativeIdentityPathToAbsolute(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "/home/fortified\n"}}, // pwd
		{}, // borg extract
	}}
	b := Backend{Runner: fake}

	if err := b.RestoreArchive(context.Background(), "/repo/host-2-example", ArchiveID("2026-07-17"), "pw", "fortified-automation-key", "/restore/scratch"); err != nil {
		t.Fatalf("RestoreArchive: %v", err)
	}

	if fake.Calls[0].Cmd != "pwd" {
		t.Fatalf("call 0 = %+v, want pwd (resolving the relative identity path)", fake.Calls[0])
	}

	extractCall := fake.Calls[1]
	if extractCall.Cmd != "borg" || extractCall.Args[0] != "extract" {
		t.Fatalf("call 1 = %+v, want borg extract ...", extractCall)
	}
	if len(extractCall.Env) != 2 || extractCall.Env[1] != "BORG_RSH=ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i /home/fortified/fortified-automation-key" {
		t.Errorf("extract env = %v, want BORG_RSH's -i to be the absolute /home/fortified/fortified-automation-key, not the bare relative name", extractCall.Env)
	}
}

// TestRestoreArchiveSkipsPwdForAlreadyAbsoluteIdentityPath proves the
// common case (a caller that already knows the identity file's real
// absolute path) never pays for the extra round trip.
func TestRestoreArchiveSkipsPwdForAlreadyAbsoluteIdentityPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	if err := b.RestoreArchive(context.Background(), "/repo/host-2-example", ArchiveID("2026-07-17"), "pw", "/identity-key", "/restore/scratch"); err != nil {
		t.Fatalf("RestoreArchive: %v", err)
	}

	if len(fake.Calls) != 1 || fake.Calls[0].Cmd != "borg" {
		t.Fatalf("calls = %+v, want a single borg extract call, no pwd round trip", fake.Calls)
	}
}

func TestListArchives(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{{Result: sshx.Result{Stdout: "2026-07-16\n2026-07-17\n"}}},
	}
	b := Backend{Runner: fake}

	archives, err := b.ListArchives(context.Background(), "/repo/host-2-example", "pw", "/identity-key")
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 2 || archives[0] != "2026-07-16" || archives[1] != "2026-07-17" {
		t.Errorf("archives = %v, want [2026-07-16 2026-07-17]", archives)
	}

	call := fake.Calls[0]
	if call.Class != sshx.ReadOnly {
		t.Errorf("class = %v, want ReadOnly", call.Class)
	}
	wantArgs := []string{"list", "--short", "/repo/host-2-example"}
	if strings.Join(call.Args, "|") != strings.Join(wantArgs, "|") {
		t.Errorf("args = %v, want %v", call.Args, wantArgs)
	}
}
