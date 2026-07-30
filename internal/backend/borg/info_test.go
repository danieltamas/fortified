package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// archiveInfoJSON and repoInfoJSON are real `borg info --json` output,
// captured live against an actual local repo (borg 1.2.4) — not
// guessed at, same discipline as this codebase's other borg-output
// fixtures.
const archiveInfoJSON = `{
    "archives": [
        {
            "name": "archive2",
            "start": "2026-07-23T22:13:58.000000",
            "end": "2026-07-23T22:13:58.000000",
            "stats": {
                "compressed_size": 7000215,
                "deduplicated_size": 4319530,
                "nfiles": 1,
                "original_size": 7000000
            }
        }
    ],
    "cache": {"stats": {"total_chunks": 13, "total_csize": 12000387, "total_size": 12000000, "total_unique_chunks": 10, "unique_csize": 9320606, "unique_size": 9320394}}
}`

const repoInfoJSON = `{
    "archives": [],
    "cache": {"stats": {"total_chunks": 13, "total_csize": 12000387, "total_size": 12000000, "total_unique_chunks": 10, "unique_csize": 9320606, "unique_size": 9320394}}
}`

func TestArchiveInfoArgvAndParsing(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Result: sshx.Result{Stdout: archiveInfoJSON}}}}
	b := Backend{Runner: fake}

	stats, err := b.ArchiveInfo(context.Background(), "/repo/host-2-example", "archive2", "pw", "/identity-key")
	if err != nil {
		t.Fatalf("ArchiveInfo: %v", err)
	}

	call := fake.Calls[0]
	if call.Cmd != "borg" || strings.Join(call.Args, "|") != "info|--json|/repo/host-2-example::archive2" {
		t.Errorf("cmd/args = %q %v, want borg [info --json /repo/host-2-example::archive2]", call.Cmd, call.Args)
	}
	if call.Class != sshx.ReadOnly {
		t.Errorf("class = %v, want ReadOnly", call.Class)
	}

	want := ArchiveStats{
		Name: "archive2", Start: "2026-07-23T22:13:58.000000", End: "2026-07-23T22:13:58.000000",
		NFiles: 1, OriginalSize: 7000000, CompressedSize: 7000215, DeduplicatedSize: 4319530,
	}
	if stats != want {
		t.Errorf("ArchiveInfo = %+v, want %+v", stats, want)
	}
}

func TestArchiveInfoFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.ArchiveInfo(context.Background(), "/repo/x", "archive1", "pw", "/identity-key"); err == nil {
		t.Fatal("expected ArchiveInfo to propagate the runner error")
	}
}

func TestArchiveInfoNoArchiveInResponseIsAnError(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Result: sshx.Result{Stdout: repoInfoJSON}}}}
	b := Backend{Runner: fake}
	if _, err := b.ArchiveInfo(context.Background(), "/repo/x", "does-not-exist", "pw", "/identity-key"); err == nil {
		t.Fatal("expected ArchiveInfo to fail when the response has no archive stats")
	}
}

func TestRepoInfoArgvAndParsing(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Result: sshx.Result{Stdout: repoInfoJSON}}}}
	b := Backend{Runner: fake}

	stats, err := b.RepoInfo(context.Background(), "/repo/host-2-example", "pw", "/identity-key")
	if err != nil {
		t.Fatalf("RepoInfo: %v", err)
	}

	call := fake.Calls[0]
	if call.Cmd != "borg" || strings.Join(call.Args, "|") != "info|--json|/repo/host-2-example" {
		t.Errorf("cmd/args = %q %v, want borg [info --json /repo/host-2-example]", call.Cmd, call.Args)
	}

	want := RepoStats{TotalSize: 12000000, TotalCompressedSize: 12000387, UniqueSize: 9320394, UniqueCompressedSize: 9320606, TotalChunks: 13, TotalUniqueChunks: 10}
	if stats != want {
		t.Errorf("RepoInfo = %+v, want %+v", stats, want)
	}
}

func TestRepoInfoFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.RepoInfo(context.Background(), "/repo/x", "pw", "/identity-key"); err == nil {
		t.Fatal("expected RepoInfo to propagate the runner error")
	}
}
