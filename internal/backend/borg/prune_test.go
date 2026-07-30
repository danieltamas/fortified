package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestPruneArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	policy := Policy{KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 6}
	err := b.Prune(context.Background(), "/repo/host-2-example", "pw", policy, "/operator/prune-key", "/server/append-only-key")
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}

	call := fake.Calls[0]
	if call.Cmd != "borg" {
		t.Errorf("cmd = %q, want borg", call.Cmd)
	}
	wantArgs := []string{"prune", "--keep-daily=7", "--keep-weekly=4", "--keep-monthly=6", "/repo/host-2-example"}
	if strings.Join(call.Args, "|") != strings.Join(wantArgs, "|") {
		t.Errorf("args = %v, want %v", call.Args, wantArgs)
	}
	if call.Class != sshx.Mutating {
		t.Errorf("class = %v, want Mutating", call.Class)
	}
}

// TestPrunePassesPassphrase: every other borg operation passes
// BORG_PASSPHRASE; prune must too, or it can never open an encrypted
// repo (the bug this test guards against actually shipped once).
func TestPrunePassesPassphrase(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	if err := b.Prune(context.Background(), "/repo/x", "s3cr3t", Policy{}, "/prune-key", "/append-only-key"); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	call := fake.Calls[0]
	found := false
	for _, e := range call.Env {
		if e == "BORG_PASSPHRASE=s3cr3t" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected BORG_PASSPHRASE=s3cr3t in Env, got %v", call.Env)
	}
}

func TestPruneRefusesWithoutKeyPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	err := b.Prune(context.Background(), "/repo/x", "pw", Policy{}, "", "/server/append-only-key")
	if err == nil {
		t.Fatal("expected Prune to refuse an empty prune key path")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero calls when refusing, got %d", len(fake.Calls))
	}
}

// TestPruneRefusesWithAppendOnlyKeyPath: the one call in the whole
// tool that takes the unrestricted key must never be constructable
// with the append-only automation key path (SPEC.md §5) — that key
// can create archives but must never delete/overwrite.
func TestPruneRefusesWithAppendOnlyKeyPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	const appendOnlyKeyPath = "/server/append-only-key"
	err := b.Prune(context.Background(), "/repo/x", "pw", Policy{}, appendOnlyKeyPath, appendOnlyKeyPath)
	if err == nil {
		t.Fatal("expected Prune to refuse when pruneKeyPath matches the append-only key path")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero calls when refusing, got %d", len(fake.Calls))
	}
}

// TestPruneRefusesWithUnnormalizedAppendOnlyKeyPath: a trivially
// different spelling of the same path (a "./" segment, in this case)
// must not bypass the refusal.
func TestPruneRefusesWithUnnormalizedAppendOnlyKeyPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}

	err := b.Prune(context.Background(), "/repo/x", "pw", Policy{}, "/server/./append-only-key", "/server/append-only-key")
	if err == nil {
		t.Fatal("expected Prune to refuse a differently-spelled but equal path")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero calls when refusing, got %d", len(fake.Calls))
	}
}

func TestPruneFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if err := b.Prune(context.Background(), "/repo/x", "pw", Policy{}, "/prune-key", "/append-only-key"); err == nil {
		t.Fatal("expected Prune to propagate the runner error")
	}
}
