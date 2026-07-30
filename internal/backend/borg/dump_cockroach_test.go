package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// TestCockroachDatabasesExcludesSystemCatalog proves SHOW DATABASES'
// header line is stripped and CRDB's own "system" catalog (never user
// data) is excluded — mirrors mariaDBSystemSchemas' exclusion, but
// CockroachDB only ever has the one built-in catalog to exclude.
func TestCockroachDatabasesExcludesSystemCatalog(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "database_name\ndefaultdb\nnakama\npostgres\nsystem\n"}},
	}}
	b := Backend{Runner: fake}

	databases, err := b.cockroachDatabases(context.Background(), "cockroachdb")
	if err != nil {
		t.Fatalf("cockroachDatabases: %v", err)
	}
	want := []string{"defaultdb", "nakama", "postgres"}
	if len(databases) != len(want) {
		t.Fatalf("databases = %v, want %v", databases, want)
	}
	for i := range want {
		if databases[i] != want[i] {
			t.Errorf("databases[%d] = %q, want %q", i, databases[i], want[i])
		}
	}
}

// TestDumpCockroachDBHappyPath proves each database's dump segment
// gets a CREATE DATABASE/SET database preamble — verified live: a
// plain concatenation of `cockroach dump <db>` output for several
// databases loses which database each table belongs to entirely,
// since cockroach dump itself never records that.
func TestDumpCockroachDBHappyPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "database_name\nnakama\nsystem\n"}}, // SHOW DATABASES
		{}, // the combined dump script
		{Result: sshx.Result{Stdout: "cafebabe  /work/cockroachdb.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "table_name\ngroups\n"}},              // list tables in nakama
		{Result: sshx.Result{Stdout: "col\npublic.groups|3\n"}},            // union count query
	}}
	b := Backend{Runner: fake}

	dm, err := b.dumpCockroachDB(context.Background(), "cockroachdb", "/work/cockroachdb.sql", nil)
	if err != nil {
		t.Fatalf("dumpCockroachDB: %v", err)
	}
	// Matches postgres's own established row-count key convention
	// (database.schema.table, three parts — see integration_test.go's
	// RowCounts["postgres.public.widgets"]), not a two-part shortcut.
	if dm.Container != "cockroachdb" || dm.SHA256 != "cafebabe" || dm.RowCounts["nakama.public.groups"] != 3 {
		t.Errorf("manifest = %+v, want Container=cockroachdb SHA256=cafebabe RowCounts[nakama.public.groups]=3", dm)
	}

	dumpCall := fake.Calls[1]
	if dumpCall.Cmd != "sh" {
		t.Fatalf("dump call cmd = %q, want sh", dumpCall.Cmd)
	}
	if !strings.Contains(dumpCall.Args[1], `CREATE DATABASE IF NOT EXISTS "nakama"`) || !strings.Contains(dumpCall.Args[1], `SET database = "nakama"`) {
		t.Errorf("dump script = %q, want a CREATE DATABASE/SET database preamble for nakama with the identifier quoted", dumpCall.Args[1])
	}
	if !strings.Contains(dumpCall.Args[1], "cockroach dump --insecure 'nakama'") {
		t.Errorf("dump script = %q, want the cockroach dump invocation for nakama", dumpCall.Args[1])
	}
	if strings.Contains(dumpCall.Args[1], "system") {
		t.Errorf("dump script = %q, want CRDB's own system catalog excluded", dumpCall.Args[1])
	}
}

// TestDumpCockroachDBQuotesAdversarialDatabaseName is a regression
// guard for a confirmed root-RCE shell injection: `db` (from a live
// `SHOW DATABASES`, so an operator or anyone who can create a
// database on an --insecure cluster controls its literal text) was
// previously interpolated raw into a single-quoted printf shell
// string. A database named to break out of that quoting must not
// execute anything — the generated script must contain the malicious
// name only as an inert, single-quoted/double-quoted string, never as
// live shell syntax.
func TestDumpCockroachDBQuotesAdversarialDatabaseName(t *testing.T) {
	const evil = `x'; touch /tmp/pwn; echo '`
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "database_name\n" + evil + "\nsystem\n"}}, // SHOW DATABASES
		{}, // the combined dump script
		{Result: sshx.Result{Stdout: "cafebabe  /work/cockroachdb.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "table_name\n"}},                      // list tables (none)
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpCockroachDB(context.Background(), "cockroachdb", "/work/cockroachdb.sql", nil); err != nil {
		t.Fatalf("dumpCockroachDB: %v", err)
	}

	dumpCall := fake.Calls[1]
	script := dumpCall.Args[1]
	if strings.Contains(script, "touch /tmp/pwn") && !strings.Contains(script, `'\''`) {
		t.Fatalf("script = %q, the injected command must never appear as live shell syntax outside an escaped quote", script)
	}
	// The escaped form POSIX shells use to embed a literal single quote
	// inside a single-quoted string — proof the adversarial name was
	// quoted as data, not spliced in as syntax.
	if !strings.Contains(script, `'\''`) {
		t.Errorf("script = %q, want the adversarial database name's embedded quote escaped via '\\''", script)
	}
}

func TestDumpCockroachDBFailsWhenNoUserDatabases(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "database_name\nsystem\n"}}, // only the built-in catalog
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpCockroachDB(context.Background(), "cockroachdb", "/work/cockroachdb.sql", nil); err == nil {
		t.Fatal("expected dumpCockroachDB to fail when only CRDB's own system catalog is present")
	}
}

func TestCockroachDatabaseSizeFallsBackAcrossConventionalPaths(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "1048576\t/var/lib/cockroach\n"}},
	}}
	b := Backend{Runner: fake}

	size, err := b.cockroachDatabaseSize(context.Background(), "cockroachdb")
	if err != nil {
		t.Fatalf("cockroachDatabaseSize: %v", err)
	}
	if size != 1048576 {
		t.Errorf("size = %d, want 1048576", size)
	}
}

// TestCockroachDatabaseSizeDegradesGracefully proves a wrong/missing
// data-directory guess never blocks the free-space preflight check a
// backup depends on — this engine's size estimate is best-effort by
// design (see cockroachDatabaseSize's doc comment), unlike postgres/
// mariadb's size queries, which are fatal on failure.
func TestCockroachDatabaseSizeDegradesGracefully(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errBoom},
	}}
	b := Backend{Runner: fake}

	size, err := b.cockroachDatabaseSize(context.Background(), "cockroachdb")
	if err != nil {
		t.Fatalf("cockroachDatabaseSize: %v, want no error (best-effort)", err)
	}
	if size != 0 {
		t.Errorf("size = %d, want 0 when the du fallback chain fails entirely", size)
	}
}

func TestRowCountsCockroachDBDispatchesCorrectly(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "database_name\nnakama\nsystem\n"}}, // SHOW DATABASES
		{Result: sshx.Result{Stdout: "table_name\ngroups\n"}},            // list tables
		{Result: sshx.Result{Stdout: "col\npublic.groups|5\n"}},          // union count query
	}}
	b := Backend{Runner: fake}

	counts, err := b.RowCounts(context.Background(), "cockroachdb", "cockroachdb", "")
	if err != nil {
		t.Fatalf("RowCounts: %v", err)
	}
	if counts["nakama.public.groups"] != 5 {
		t.Errorf("counts = %v, want nakama.public.groups=5", counts)
	}
}
