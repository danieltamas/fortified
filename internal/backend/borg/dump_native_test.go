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

// TestDumpNativePostgresHappyPath proves the dump uses `su - postgres`
// (never docker exec) and that the redirect happens in the outer
// (root) shell, not inside su's own context — verified live against a
// real server: postgres itself has no write access outside its own
// directories, so `su - postgres -c 'pg_dumpall > path'` would fail,
// while `su - postgres -c pg_dumpall > path` (redirect outside the
// su'd command) succeeds.
func TestDumpNativePostgresHappyPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // su - postgres -c pg_dumpall > dumpPath
		{Result: sshx.Result{Stdout: "cafebabe  /work/postgresql.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "app\n"}},                            // list databases
		{Result: sshx.Result{Stdout: "public.users\n"}},                   // list tables
		{Result: sshx.Result{Stdout: "public.users|9\n"}},                 // union count query
	}}
	b := Backend{Runner: fake}

	dm, err := b.dumpNativePostgres(context.Background(), "/work/postgresql.sql", "", nil)
	if err != nil {
		t.Fatalf("dumpNativePostgres: %v", err)
	}
	if dm.Container != "postgresql" || dm.SHA256 != "cafebabe" || dm.RowCounts["app.public.users"] != 9 {
		t.Errorf("manifest = %+v, want Container=postgresql SHA256=cafebabe RowCounts[app.public.users]=9", dm)
	}

	dumpCall := fake.Calls[0]
	if dumpCall.Cmd != "sh" || !strings.Contains(dumpCall.Args[1], "su - postgres -c pg_dumpall > '/work/postgresql.sql'") {
		t.Errorf("dump call = %+v, want su - postgres -c pg_dumpall redirected in the outer shell", dumpCall)
	}

	queryCall := fake.Calls[2]
	if queryCall.Cmd != "su" || queryCall.Args[0] != "-" || queryCall.Args[1] != "postgres" || queryCall.Args[2] != "-c" {
		t.Errorf("query call = %+v, want su - postgres -c ...", queryCall)
	}
}

// TestDumpNativePostgresFallsBackToTCPWithResolvedAuth proves a
// non-empty resolvedAuth (config's auth_ref for the synthetic
// "postgresql" container) is actually used — a real gap found by
// cross-vendor review: dumpNativePostgres previously always used peer
// auth (`su - postgres`) regardless of resolvedAuth, so a server
// discover found AuthResolved=false on (pg_hba.conf hardened to
// require a password even locally) could never be backed up, with no
// way to configure a fallback.
func TestDumpNativePostgresFallsBackToTCPWithResolvedAuth(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // PGPASSWORD=... pg_dumpall -h 127.0.0.1 -U postgres
		{Result: sshx.Result{Stdout: "cafebabe  /work/postgresql.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "app\n"}},                            // list databases
		{Result: sshx.Result{Stdout: "public.users\n"}},                   // list tables
		{Result: sshx.Result{Stdout: "public.users|9\n"}},                 // union count query
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpNativePostgres(context.Background(), "/work/postgresql.sql", "hunter2", nil); err != nil {
		t.Fatalf("dumpNativePostgres: %v", err)
	}

	dumpCall := fake.Calls[0]
	if dumpCall.Cmd != "sh" || !strings.Contains(dumpCall.Args[1], "PGPASSWORD=\"$PGPASSWORD\" pg_dumpall -h 127.0.0.1 -U postgres > '/work/postgresql.sql'") {
		t.Errorf("dump call = %+v, want a TCP/PGPASSWORD pg_dumpall, not su - postgres", dumpCall)
	}
	if strings.Contains(dumpCall.Args[1], "hunter2") {
		t.Fatalf("the literal password must never appear in the script text, got %q", dumpCall.Args[1])
	}
	if len(dumpCall.Env) != 1 || dumpCall.Env[0] != "PGPASSWORD=hunter2" {
		t.Errorf("dump call env = %v, want [PGPASSWORD=hunter2]", dumpCall.Env)
	}

	queryCall := fake.Calls[2]
	if queryCall.Cmd != "sh" {
		t.Errorf("query call = %+v, want a TCP/PGPASSWORD psql query, not su - postgres", queryCall)
	}
}

func TestDumpNativePostgresFailsWhenDumpCommandFails(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("FATAL: Peer authentication failed")},
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpNativePostgres(context.Background(), "/work/postgresql.sql", "", nil); err == nil {
		t.Fatal("expected an error when the native pg_dumpall command fails")
	}
}

// TestDumpNativeMySQLHappyPath proves the dump authenticates via the
// standard Debian/Ubuntu maintenance credential file rather than any
// operator-supplied password — verified live against two real servers.
func TestDumpNativeMySQLHappyPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // mysqldump --defaults-file=... --all-databases
		{Result: sshx.Result{Stdout: "cafebabe  /work/mysql.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "app.users\n"}},                 // list tables
		{Result: sshx.Result{Stdout: "app.users|11\n"}},              // union count query
	}}
	b := Backend{Runner: fake}

	dm, err := b.dumpNativeMySQL(context.Background(), "/work/mysql.sql", "", nil)
	if err != nil {
		t.Fatalf("dumpNativeMySQL: %v", err)
	}
	if dm.Container != "mysql" || dm.SHA256 != "cafebabe" || dm.RowCounts["app.users"] != 11 {
		t.Errorf("manifest = %+v, want Container=mysql SHA256=cafebabe RowCounts[app.users]=11", dm)
	}

	dumpCall := fake.Calls[0]
	if dumpCall.Cmd != "sh" || !strings.Contains(dumpCall.Args[1], "mysqldump --defaults-file=/etc/mysql/debian.cnf --all-databases --single-transaction > '/work/mysql.sql'") {
		t.Errorf("dump call = %+v, want mysqldump authenticated via debian.cnf", dumpCall)
	}
	if len(dumpCall.Env) != 0 {
		t.Errorf("dump call env = %v, want none — debian.cnf is a path, not a secret needing env delivery", dumpCall.Env)
	}

	queryCall := fake.Calls[2]
	if queryCall.Cmd != "mysql" || queryCall.Args[0] != "--defaults-file=/etc/mysql/debian.cnf" {
		t.Errorf("query call = %+v, want mysql --defaults-file=/etc/mysql/debian.cnf ...", queryCall)
	}
}

// TestDumpNativeMySQLFallsBackToTCPWithResolvedAuth mirrors
// TestDumpNativePostgresFallsBackToTCPWithResolvedAuth for mysql/
// mariadb — the escape hatch for a server discover found
// AuthResolved=false on (no readable debian.cnf).
func TestDumpNativeMySQLFallsBackToTCPWithResolvedAuth(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // MYSQL_PWD=... mysqldump -h 127.0.0.1 -u root
		{Result: sshx.Result{Stdout: "cafebabe  /work/mysql.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "app.users\n"}},                 // list tables
		{Result: sshx.Result{Stdout: "app.users|11\n"}},              // union count query
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpNativeMySQL(context.Background(), "/work/mysql.sql", "hunter2", nil); err != nil {
		t.Fatalf("dumpNativeMySQL: %v", err)
	}

	dumpCall := fake.Calls[0]
	if dumpCall.Cmd != "sh" || !strings.Contains(dumpCall.Args[1], `MYSQL_PWD="$MYSQL_PWD" mysqldump -h 127.0.0.1 -u root --all-databases --single-transaction > '/work/mysql.sql'`) {
		t.Errorf("dump call = %+v, want a TCP/MYSQL_PWD mysqldump, not --defaults-file", dumpCall)
	}
	if strings.Contains(dumpCall.Args[1], "hunter2") {
		t.Fatalf("the literal password must never appear in the script text, got %q", dumpCall.Args[1])
	}
	if len(dumpCall.Env) != 1 || dumpCall.Env[0] != "MYSQL_PWD=hunter2" {
		t.Errorf("dump call env = %v, want [MYSQL_PWD=hunter2]", dumpCall.Env)
	}

	queryCall := fake.Calls[2]
	if queryCall.Cmd != "sh" {
		t.Errorf("query call = %+v, want a TCP/MYSQL_PWD query, not --defaults-file", queryCall)
	}
}

func TestDumpNativeMySQLFailsWhenDumpCommandFails(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("mysqldump: Access denied")},
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpNativeMySQL(context.Background(), "/work/mysql.sql", "", nil); err == nil {
		t.Fatal("expected an error when the native mysqldump command fails")
	}
}

// TestDumpDatabaseDispatchesNativeStrategy proves dumpDatabase routes
// a discover.DumpStrategyNative instance to the native dump paths, not
// the docker-exec ones — the dispatch now switches on DumpStrategy
// before Kind, unlike before native support existed.
func TestDumpDatabaseDispatchesNativeStrategy(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // su - postgres -c pg_dumpall
		{Result: sshx.Result{Stdout: "cafebabe  /work/postgresql.sql\n"}},
		{Result: sshx.Result{Stdout: ""}}, // list databases (none)
	}}
	b := Backend{Runner: fake}

	dm, err := b.dumpDatabase(context.Background(), "/work", discover.DatabaseInstance{
		Kind: "postgres", Container: "postgresql", DumpStrategy: discover.DumpStrategyNative,
	}, "", nil)
	if err != nil {
		t.Fatalf("dumpDatabase: %v", err)
	}
	if dm.Container != "postgresql" {
		t.Errorf("manifest = %+v, want Container=postgresql", dm)
	}
	if fake.Calls[0].Cmd != "sh" || !strings.Contains(fake.Calls[0].Args[1], "su - postgres") {
		t.Errorf("dump call = %+v, want the native su - postgres path, not docker exec", fake.Calls[0])
	}
}
