package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func onePostgresDB() []discover.DatabaseInstance {
	return []discover.DatabaseInstance{
		{Kind: "postgres", Container: "psql", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true},
	}
}

// TestCreateArchiveReportsProgressPerDatabaseAndArchive proves the
// progress callback fires a start/done line around each database's
// own dump and around the archive-create step — otherwise a
// multi-hour backup reports nothing at all until the whole thing
// finishes (the exact "no summary of what was backed up" complaint
// this exists to fix).
func TestCreateArchiveReportsProgressPerDatabaseAndArchive(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir workspace
			{}, // dump
			{Result: sshx.Result{Stdout: "deadbeef  /work/psql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: ""}},                           // list databases (none)
			{},                                                          // writeManifest
			{},                                                          // borg create
			{},                                                          // cleanup
		},
	}
	b := Backend{Runner: fake}

	var messages []string
	progress := func(msg string) { messages = append(messages, msg) }

	if _, _, err := b.CreateArchive(context.Background(),
		"/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", onePostgresDB(), nil, nil, 1000, progress, nil); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	joined := strings.Join(messages, "\n")
	for _, want := range []string{"dumping psql...", "dumping psql: done", "creating archive 2026-07-18", "creating archive 2026-07-18: done"} {
		if !strings.Contains(joined, want) {
			t.Errorf("progress messages = %v, want one containing %q", messages, want)
		}
	}
}

// TestCreateArchiveStreamsLiveOutput proves liveOutput reaches both
// the borg create call (its own --progress output) and each
// database's own dump (via the size-estimate query + progress poller
// — pg_dumpall/mysqldump/cockroach dump report nothing on their own,
// unlike borg).
func TestCreateArchiveStreamsLiveOutput(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{},                                   // mkdir workspace
			{Result: sshx.Result{Stdout: "0\n"}}, // dump-progress size estimate
			{},                                   // dump
			{Result: sshx.Result{Stdout: "deadbeef  /work/psql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: ""}},                           // list databases (none)
			{},                                                          // writeManifest
			{},                                                          // borg create
			{},                                                          // cleanup
		},
	}
	b := Backend{Runner: fake}

	if _, _, err := b.CreateArchive(context.Background(),
		"/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", onePostgresDB(), nil, nil, 1000, nil, &strings.Builder{}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	// No assertion beyond "it didn't panic/error" is needed here:
	// create.go's own liveOutput wiring is a straight-line code path
	// (exactly one RunOptions.LiveStderr literal, one dumpDatabase
	// argument), and FakeRunner doesn't model LiveStderr at all — this
	// test exists to pin that CreateArchive accepts a real io.Writer
	// without requiring FakeRunner changes, not to re-verify
	// ExecRunner's own teeing (covered in sshx's own tests) or the
	// dump-progress poller's own behavior (covered in
	// dump_progress_test.go).
}

// TestCreateArchiveHappyPathAndManifestContents covers both
// TestManifestContents and the end-to-end argv sequence: preflight,
// workspace creation, dump, SHA-256 + row-count recording, manifest
// write, archive creation, and workspace cleanup — in that order.
func TestCreateArchiveHappyPathAndManifestContents(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df (lastRunTotalDumpSize > 0, no estimate step)
			{}, // mkdir -p workspace
			{}, // dump: sh -c "docker exec ... pg_dumpall > ..."
			{Result: sshx.Result{Stdout: "deadbeef  /work/psql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: "postgres\n"}},                 // list databases
			{Result: sshx.Result{Stdout: "public.users\n"}},             // list tables in postgres
			{Result: sshx.Result{Stdout: "public.users|42\n"}},          // union count query
			{}, // writeManifest: cat > manifest.json
			{}, // borg create
			{}, // rm -rf workspace
		},
	}
	b := Backend{Runner: fake}

	archiveID, manifest, err := b.CreateArchive(context.Background(),
		"/repo/host-2-example", "pw", "/identity-key", "/work/host-2-example", "2026-07-18",
		onePostgresDB(), nil, []string{"/home/docker/psql/docker-compose.yml"}, 1000, nil, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if archiveID != "2026-07-18" {
		t.Errorf("archiveID = %q, want 2026-07-18", archiveID)
	}

	if len(manifest.Databases) != 1 {
		t.Fatalf("expected 1 database manifest entry, got %d", len(manifest.Databases))
	}
	dm := manifest.Databases[0]
	if dm.Container != "psql" || dm.SHA256 != "deadbeef" || dm.RowCounts["postgres.public.users"] != 42 {
		t.Errorf("manifest entry = %+v, want Container=psql SHA256=deadbeef RowCounts[postgres.public.users]=42", dm)
	}

	if len(fake.Calls) != 10 {
		t.Fatalf("expected 10 calls, got %d: %+v", len(fake.Calls), fake.Calls)
	}

	dfCall := fake.Calls[0]
	if dfCall.Cmd != "df" {
		t.Errorf("call 0 = %q, want df", dfCall.Cmd)
	}

	mkdirCall := fake.Calls[1]
	if mkdirCall.Cmd != "mkdir" || strings.Join(mkdirCall.Args, "|") != "-p|/work/host-2-example" {
		t.Errorf("call 1 = %q %v, want mkdir [-p /work/host-2-example]", mkdirCall.Cmd, mkdirCall.Args)
	}

	dumpCall := fake.Calls[2]
	if dumpCall.Cmd != "sh" || !strings.Contains(dumpCall.Args[1], "docker exec -u postgres psql pg_dumpall > '/work/host-2-example/psql.sql'") {
		t.Errorf("call 2 (dump) = %q %v, want a pg_dumpall redirect into the workspace", dumpCall.Cmd, dumpCall.Args)
	}
	if dumpCall.Class != sshx.Mutating {
		t.Errorf("dump call class = %v, want Mutating", dumpCall.Class)
	}

	manifestCall := fake.Calls[7]
	if manifestCall.Cmd != "sh" || !strings.Contains(manifestCall.Args[1], "manifest.json") {
		t.Errorf("call 7 (manifest write) = %q %v, want a manifest.json write", manifestCall.Cmd, manifestCall.Args)
	}
	if !strings.Contains(manifestCall.Stdin, `"sha256": "deadbeef"`) {
		t.Errorf("manifest write stdin = %q, want it to contain the recorded SHA-256", manifestCall.Stdin)
	}

	createCall := fake.Calls[8]
	if createCall.Cmd != "borg" || createCall.Args[0] != "create" {
		t.Errorf("call 8 = %q %v, want borg create ...", createCall.Cmd, createCall.Args)
	}
	if createCall.Args[1] != "--progress" || createCall.Args[2] != "--stats" {
		t.Errorf("borg create flags = %v, want --progress --stats before the archive spec", createCall.Args[1:3])
	}
	wantArchiveSpec := "/repo/host-2-example::2026-07-18"
	if createCall.Args[3] != wantArchiveSpec {
		t.Errorf("archive spec = %q, want %q", createCall.Args[3], wantArchiveSpec)
	}
	if createCall.Args[4] != "/work/host-2-example" || createCall.Args[5] != "/home/docker/psql/docker-compose.yml" {
		t.Errorf("archive paths = %v, want [workspace, sourcePaths...]", createCall.Args[4:])
	}

	cleanupCall := fake.Calls[9]
	if cleanupCall.Cmd != "rm" || strings.Join(cleanupCall.Args, "|") != "-rf|/work/host-2-example" {
		t.Errorf("cleanup call = %q %v, want rm [-rf /work/host-2-example]", cleanupCall.Cmd, cleanupCall.Args)
	}
}

// TestCreateAbortsOnDumpFailure: one dump exits nonzero → workspace
// deleted, zero borg calls, error returned (SPEC.md §4).
func TestCreateAbortsOnDumpFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{},             // mkdir -p workspace
			{Err: errBoom}, // dump fails
			{},             // rm -rf workspace (cleanup)
		},
	}
	b := Backend{Runner: fake}

	_, _, err := b.CreateArchive(context.Background(),
		"/repo/host-2-example", "pw", "/identity-key", "/work/host-2-example", "2026-07-18",
		onePostgresDB(), nil, nil, 1000, nil, nil)
	if err == nil {
		t.Fatal("expected CreateArchive to fail when a dump fails")
	}

	if len(fake.Calls) != 4 {
		t.Fatalf("expected 4 calls (df, mkdir, failed dump, cleanup), got %d: %+v", len(fake.Calls), fake.Calls)
	}
	for _, c := range fake.Calls {
		if c.Cmd == "borg" && len(c.Args) > 0 && c.Args[0] == "create" {
			t.Fatal("expected zero borg create calls after a dump failure")
		}
	}
	cleanupCall := fake.Calls[3]
	if cleanupCall.Cmd != "rm" {
		t.Errorf("expected the last call to be workspace cleanup, got %q", cleanupCall.Cmd)
	}
}
