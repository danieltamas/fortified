package borg

import (
	"context"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// TestFreeSpacePreflight: insufficient free space fails before any
// dump subprocess is issued (SPEC.md §4).
func TestFreeSpacePreflightInsufficientFailsBeforeDumps(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "999999999999\n"}}, // engine-reported size estimate (huge)
			{Result: sshx.Result{Stdout: "Avail\n100\n"}},   // df: almost no free space
		},
	}
	b := Backend{Runner: fake}

	_, _, err := b.CreateArchive(context.Background(),
		"/repo/host-2-example", "pw", "/identity-key", "/work/host-2-example", "2026-07-18",
		onePostgresDB(), nil, nil, 0, nil, nil) // lastRunTotalDumpSize=0 -> first run, estimate path
	if err == nil {
		t.Fatal("expected CreateArchive to refuse when free space is insufficient")
	}

	if len(fake.Calls) != 2 {
		t.Fatalf("expected exactly 2 calls (estimate + df), zero dump calls, got %d: %+v", len(fake.Calls), fake.Calls)
	}
}

func TestFreeSpacePreflightUsesLastRunSizeWhenAvailable(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999\n"}}, // df only — no estimate call expected
		},
	}
	b := Backend{Runner: fake}

	if err := b.FreeSpacePreflight(context.Background(), "/work/host-2-example", onePostgresDB(), nil, 1_000_000); err != nil {
		t.Fatalf("FreeSpacePreflight: %v", err)
	}
	if len(fake.Calls) != 1 {
		t.Fatalf("expected exactly 1 call (df), got %d: %+v", len(fake.Calls), fake.Calls)
	}
}

func TestFreeSpacePreflightSufficientPasses(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999\n"}},
		},
	}
	b := Backend{Runner: fake}
	if err := b.FreeSpacePreflight(context.Background(), "/work/x", nil, nil, 1000); err != nil {
		t.Fatalf("FreeSpacePreflight: %v", err)
	}
}
