package borg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestSHA256FileFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.sha256File(context.Background(), "/work/x.sql"); err == nil {
		t.Fatal("expected sha256File to propagate the runner error")
	}
}

func TestSHA256FileEmptyOutput(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Result: sshx.Result{Stdout: ""}}}}
	b := Backend{Runner: fake}
	if _, err := b.sha256File(context.Background(), "/work/x.sql"); err == nil {
		t.Fatal("expected an error when sha256sum produces no output")
	}
}

// TestExportedVerifyHelpers: SHA256File, RowCounts, and
// MariaDBRootPassword are thin exported wrappers around already
// thoroughly-tested unexported methods (internal/orchestrate's Verify
// needs public access to them) — this proves the export itself works,
// not the underlying logic again.
func TestExportedVerifyHelpers(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "deadbeef  /work/x.sql\n"}},
			{Result: sshx.Result{Stdout: "postgres\n"}},
			{Result: sshx.Result{Stdout: ""}},
		},
	}
	b := Backend{Runner: fake}

	sha, err := b.SHA256File(context.Background(), "/work/x.sql")
	if err != nil || sha != "deadbeef" {
		t.Errorf("SHA256File = %q, %v, want deadbeef, nil", sha, err)
	}

	if _, err := b.RowCounts(context.Background(), "postgres", "psql", ""); err != nil {
		t.Errorf("RowCounts: %v", err)
	}

	if _, err := b.RowCounts(context.Background(), "redis", "cache", ""); err == nil {
		t.Error("expected RowCounts to reject an unsupported kind")
	}

	if pw, err := b.MariaDBRootPassword(context.Background(), "mysql", "resolved-secret"); err != nil || pw != "resolved-secret" {
		t.Errorf("MariaDBRootPassword = %q, %v, want resolved-secret, nil", pw, err)
	}
}

func TestPostgresDatabasesListFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.postgresRowCounts(context.Background(), "psql", "", ""); err == nil {
		t.Fatal("expected an error when listing databases fails")
	}
}

func TestPostgresRowCountsListFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "postgres\n"}}, // list databases
		{Err: errBoom}, // list tables in "postgres"
	}}
	b := Backend{Runner: fake}
	if _, err := b.postgresRowCounts(context.Background(), "psql", "", ""); err == nil {
		t.Fatal("expected an error when listing tables fails")
	}
}

func TestPostgresRowCountsCountFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "postgres\n"}},
		{Result: sshx.Result{Stdout: "public.users\n"}},
		{Err: errBoom},
	}}
	b := Backend{Runner: fake}
	if _, err := b.postgresRowCounts(context.Background(), "psql", "", ""); err == nil {
		t.Fatal("expected an error when counting a table fails")
	}
}

func TestPostgresRowCountsUnparseableCount(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "postgres\n"}},
		{Result: sshx.Result{Stdout: "public.users\n"}},
		{Result: sshx.Result{Stdout: "not-a-number\n"}},
	}}
	b := Backend{Runner: fake}
	if _, err := b.postgresRowCounts(context.Background(), "psql", "", ""); err == nil {
		t.Fatal("expected an error when the count is unparseable")
	}
}

// TestPostgresRowCountsCoversNonDefaultDatabase proves the actual fix:
// a table living in an app database other than the connection's
// default ("postgres") is still counted, keyed
// "<database>.<schema>.<table>" so identically-named tables across
// databases never collide.
func TestPostgresRowCountsCoversNonDefaultDatabase(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "appdb\npostgres\n"}}, // list databases
		{Result: sshx.Result{Stdout: "public.widgets\n"}},  // list tables in appdb
		{Result: sshx.Result{Stdout: "public.widgets|5\n"}},
		{Result: sshx.Result{Stdout: ""}}, // list tables in postgres (none)
	}}
	b := Backend{Runner: fake}
	counts, err := b.postgresRowCounts(context.Background(), "psql", "", "")
	if err != nil {
		t.Fatalf("postgresRowCounts: %v", err)
	}
	if counts["appdb.public.widgets"] != 5 {
		t.Errorf("counts = %+v, want appdb.public.widgets=5", counts)
	}
	if len(counts) != 1 {
		t.Errorf("counts = %+v, want exactly one entry (postgres db has no tables)", counts)
	}

	tablesCall := fake.Calls[1]
	if !contains(tablesCall.Args, "-d") || !contains(tablesCall.Args, "appdb") {
		t.Errorf("list-tables call args = %v, want it to connect with -d appdb", tablesCall.Args)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func TestPostgresDatabaseSizeFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.postgresDatabaseSize(context.Background(), "psql", "", ""); err == nil {
		t.Fatal("expected an error when the size query fails")
	}
}

func TestMariaDBRowCountsListFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.mariaDBRowCounts(context.Background(), "mysql", "pw"); err == nil {
		t.Fatal("expected an error when listing tables fails")
	}
}

func TestMariaDBRowCountsCountFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "app.users\n"}},
		{Err: errBoom},
	}}
	b := Backend{Runner: fake}
	if _, err := b.mariaDBRowCounts(context.Background(), "mysql", "pw"); err == nil {
		t.Fatal("expected an error when counting a table fails")
	}
}

func TestMariaDBDatabaseSizeAuthFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.mariaDBDatabaseSize(context.Background(), "mysql", ""); err == nil {
		t.Fatal("expected an error when auth resolution fails")
	}
}

func TestAvailableSpaceMalformedOutput(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Result: sshx.Result{Stdout: "not enough lines"}}}}
	b := Backend{Runner: fake}
	if _, err := b.availableSpace(context.Background(), "/work"); err == nil {
		t.Fatal("expected an error for malformed df output")
	}
}

func TestAvailableSpaceFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.availableSpace(context.Background(), "/work"); err == nil {
		t.Fatal("expected df failure to propagate")
	}
}

func TestEstimateDatabaseSizesUnsupportedKind(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}
	databases := []discover.DatabaseInstance{{Kind: "redis", Container: "cache"}}
	if _, err := b.estimateDatabaseSizes(context.Background(), databases, nil); err == nil {
		t.Fatal("expected an error for an unsupported database kind")
	}
}

func TestRestoreArchiveFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if err := b.RestoreArchive(context.Background(), "/repo/x", ArchiveID("a"), "pw", "/identity-key", "/scratch"); err == nil {
		t.Fatal("expected RestoreArchive to propagate the runner error")
	}
}

func TestListArchivesFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.ListArchives(context.Background(), "/repo/x", "pw", "/identity-key"); err == nil {
		t.Fatal("expected ListArchives to propagate the runner error")
	}
}

func TestCreateArchiveMkdirFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
		{Err: errBoom},
	}}
	b := Backend{Runner: fake}
	if _, _, err := b.CreateArchive(context.Background(), "/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", onePostgresDB(), nil, nil, 1000, nil, nil); err == nil {
		t.Fatal("expected CreateArchive to fail when workspace creation fails")
	}
}

func TestCreateArchiveBorgCreateFailureCleansUpWorkspace(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir
			{}, // dump
			{Result: sshx.Result{Stdout: "deadbeef  psql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: "postgres\n"}},           // list databases
			{Result: sshx.Result{Stdout: ""}},                     // list tables in postgres
			{},                                                    // writeManifest
			{Err: errBoom},                                        // borg create fails
			{},                                                    // cleanup
		},
	}
	b := Backend{Runner: fake}
	if _, _, err := b.CreateArchive(context.Background(), "/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", onePostgresDB(), nil, nil, 1000, nil, nil); err == nil {
		t.Fatal("expected CreateArchive to fail when borg create fails")
	}
	if len(fake.Calls) != 9 {
		t.Fatalf("expected 9 calls (including cleanup after borg create failure), got %d: %+v", len(fake.Calls), fake.Calls)
	}
	if fake.Calls[8].Cmd != "rm" {
		t.Errorf("expected the last call to be workspace cleanup, got %q", fake.Calls[8].Cmd)
	}
}

// TestCreateArchiveTreatsBorgCreateExitCodeOneAsWarningNotFailure proves
// borg's own documented exit-code convention (0 success, 1 warning,
// 2+ error) is honored for `create`, not treated as uniformly fatal —
// verified live: a bind-mounted app-data directory holding a live
// SQLite database in WAL mode (Uptime Kuma's kuma.db-shm) changed
// mid-read while borg walked it, borg exited 1 ("file changed while
// we backed it up"), and the archive was still created completely and
// correctly. The old code aborted an otherwise fully successful
// backup on exactly this benign, expected event.
func TestCreateArchiveTreatsBorgCreateExitCodeOneAsWarningNotFailure(t *testing.T) {
	warnErr := errors.New(`borg [create ...]: exit 1: /home/uptimekuma/data/kuma.db-shm: file changed while we backed it up`)
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir
			{}, // dump
			{Result: sshx.Result{Stdout: "deadbeef  psql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: "postgres\n"}},           // list databases
			{Result: sshx.Result{Stdout: ""}},                     // list tables in postgres
			{},                                                    // writeManifest
			{Result: sshx.Result{ExitCode: 1}, Err: warnErr},      // borg create: warning, not error
			{}, // cleanup
		},
	}
	b := Backend{Runner: fake}

	var messages []string
	progress := func(msg string) { messages = append(messages, msg) }

	archiveID, manifest, err := b.CreateArchive(context.Background(), "/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", onePostgresDB(), nil, nil, 1000, progress, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v, want it to succeed despite borg create's exit-1 warning", err)
	}
	if archiveID != "2026-07-18" {
		t.Errorf("archiveID = %q, want 2026-07-18 (the archive was still created)", archiveID)
	}
	if len(manifest.Databases) != 1 {
		t.Errorf("manifest.Databases = %+v, want the database dump recorded despite the warning", manifest.Databases)
	}

	joined := strings.Join(messages, "\n")
	if !strings.Contains(joined, "warning") || !strings.Contains(joined, "kuma.db-shm") {
		t.Errorf("progress messages = %v, want one surfacing the warning and its cause", messages)
	}
}

// TestCreateArchiveStillFailsOnBorgCreateGenuineError proves a real
// borg create failure (exit 2+, borg's own "error" convention) still
// aborts CreateArchive — the exit-1 carve-out must not swallow actual
// failures.
func TestCreateArchiveStillFailsOnBorgCreateGenuineError(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir
			{}, // dump
			{Result: sshx.Result{Stdout: "deadbeef  psql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: "postgres\n"}},           // list databases
			{Result: sshx.Result{Stdout: ""}},                     // list tables in postgres
			{},                                                    // writeManifest
			{Result: sshx.Result{ExitCode: 2}, Err: errBoom},      // borg create: genuine error
			{}, // cleanup
		},
	}
	b := Backend{Runner: fake}
	if _, _, err := b.CreateArchive(context.Background(), "/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", onePostgresDB(), nil, nil, 1000, nil, nil); err == nil {
		t.Fatal("expected CreateArchive to fail on a genuine (exit 2) borg create error")
	}
}

func TestWriteManifestFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if err := b.writeManifest(context.Background(), "/work/x", Manifest{}); err == nil {
		t.Fatal("expected writeManifest to propagate the runner error")
	}
}
