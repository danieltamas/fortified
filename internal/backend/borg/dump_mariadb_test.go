package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func oneMariaDB() []discover.DatabaseInstance {
	return []discover.DatabaseInstance{
		{Kind: "mariadb", Container: "mysql", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true},
	}
}

func TestDumpMariaDBHappyPath(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: `["MYSQL_ROOT_PASSWORD=hunter2","PATH=/usr/bin"]`}}, // docker inspect env
			{}, // mysqldump
			{Result: sshx.Result{Stdout: "cafebabe  /work/mysql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: "app.users\n"}},                 // list tables
			{Result: sshx.Result{Stdout: "app.users|7\n"}},               // union count query
		},
	}
	b := Backend{Runner: fake}

	dm, err := b.dumpMariaDB(context.Background(), "mysql", "/work/mysql.sql", "", nil)
	if err != nil {
		t.Fatalf("dumpMariaDB: %v", err)
	}
	if dm.Container != "mysql" || dm.SHA256 != "cafebabe" || dm.RowCounts["app.users"] != 7 {
		t.Errorf("manifest = %+v, want Container=mysql SHA256=cafebabe RowCounts[app.users]=7", dm)
	}

	if len(fake.Calls) != 5 {
		t.Fatalf("expected 5 calls, got %d: %+v", len(fake.Calls), fake.Calls)
	}

	dumpCall := fake.Calls[1]
	if dumpCall.Cmd != "sh" {
		t.Fatalf("dump call cmd = %q, want sh", dumpCall.Cmd)
	}
	if !strings.Contains(dumpCall.Args[1], `docker exec -e MYSQL_PWD mysql mysqldump --all-databases --single-transaction -u root > '/work/mysql.sql'`) {
		t.Errorf("dump script = %q, want the mysqldump redirect using bare -e MYSQL_PWD with --single-transaction", dumpCall.Args[1])
	}
	if strings.Contains(dumpCall.Args[1], "hunter2") {
		t.Fatalf("the literal password must never appear in the script text, got %q", dumpCall.Args[1])
	}
	if len(dumpCall.Env) != 1 || dumpCall.Env[0] != "MYSQL_PWD=hunter2" {
		t.Errorf("dump call env = %v, want [MYSQL_PWD=hunter2]", dumpCall.Env)
	}

	countCall := fake.Calls[4]
	if !strings.Contains(countCall.Args[1], "concat(") || !strings.Contains(countCall.Args[1], "app.users") ||
		!strings.Contains(countCall.Args[1], "count(*)") {
		t.Errorf("count query = %q, want a single combined count of app.users", countCall.Args[1])
	}
	if len(countCall.Env) != 1 || countCall.Env[0] != "MYSQL_PWD=hunter2" {
		t.Errorf("count call env = %v, want [MYSQL_PWD=hunter2]", countCall.Env)
	}
}

// TestDumpMariaDBQuotesDumpPathContainingASpace is a regression guard
// for a real gap found by cross-vendor review: dumpPath (built from
// Server.WorkspaceDir, an operator-configured absolute path — e.g. an
// attached volume mount) was spliced unquoted into the mysqldump
// redirect, so a workspace_dir containing a space would silently
// break the dump command instead of failing loudly or working.
func TestDumpMariaDBQuotesDumpPathContainingASpace(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // mysqldump (resolvedAuth already supplied)
			{Result: sshx.Result{Stdout: "cafebabe  x\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: ""}},              // list tables (none)
		},
	}
	b := Backend{Runner: fake}

	dumpPath := "/mnt/HC Volume/fortified-backup-workspace-host/mysql.sql"
	if _, err := b.dumpMariaDB(context.Background(), "mysql", dumpPath, "resolved-secret", nil); err != nil {
		t.Fatalf("dumpMariaDB: %v", err)
	}

	dumpCall := fake.Calls[0]
	if !strings.Contains(dumpCall.Args[1], `> '/mnt/HC Volume/fortified-backup-workspace-host/mysql.sql'`) {
		t.Errorf("dump script = %q, want the space-containing dumpPath single-quoted in the redirect", dumpCall.Args[1])
	}
}

// TestDumpMariaDBUsesResolvedAuth: when a config-supplied auth_ref has
// already been resolved by the caller, dumpMariaDB must use it
// directly instead of ever inspecting the container's own env.
func TestDumpMariaDBUsesResolvedAuth(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // mysqldump (no docker inspect call first)
			{Result: sshx.Result{Stdout: "cafebabe  x\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: ""}},              // list tables (none)
		},
	}
	b := Backend{Runner: fake}

	if _, err := b.dumpMariaDB(context.Background(), "mysql", "/work/mysql.sql", "resolved-secret", nil); err != nil {
		t.Fatalf("dumpMariaDB: %v", err)
	}

	if len(fake.Calls) != 3 {
		t.Fatalf("expected 3 calls (no docker-inspect auth lookup), got %d: %+v", len(fake.Calls), fake.Calls)
	}
	dumpCall := fake.Calls[0]
	if dumpCall.Cmd != "sh" || len(dumpCall.Env) != 1 || dumpCall.Env[0] != "MYSQL_PWD=resolved-secret" {
		t.Errorf("dump call = %+v, want env MYSQL_PWD=resolved-secret and no prior inspect call", dumpCall)
	}
}

// TestMariaDBUnionCountQueryQuotesIdentifiers proves the generated
// query backtick-quotes each table reference — mirrors postgres's own
// TestPostgresUnionCountQueryQuotesMixedCaseIdentifiers. Found by
// cross-vendor review: this FROM clause was unquoted while the
// postgres sibling already handled the identical hazard (an operator-
// created table name containing a space or backtick would otherwise
// break this UNION ALL query, or be interpreted as SQL).
func TestMariaDBUnionCountQueryQuotesIdentifiers(t *testing.T) {
	query := mariaDBUnionCountQuery([]string{"app.users", "app.weird table"})

	if !strings.Contains(query, "FROM `app`.`users`") {
		t.Errorf("query = %q, want a backtick-quoted FROM for app.users", query)
	}
	if !strings.Contains(query, "FROM `app`.`weird table`") {
		t.Errorf("query = %q, want a backtick-quoted FROM for the table name containing a space", query)
	}
	// The label must stay the original, unquoted "schema.table" form —
	// what parseCountLines/the manifest key format expects.
	if !strings.Contains(query, "'app.users'") {
		t.Errorf("query = %q, want the original schema.table string preserved as the row label", query)
	}
}

func TestMysqlQuoteQualifiedIdentEscapesEmbeddedBackticks(t *testing.T) {
	got := mysqlQuoteQualifiedIdent("app.weird`table")
	want := "`app`.`weird``table`"
	if got != want {
		t.Errorf("mysqlQuoteQualifiedIdent = %q, want %q", got, want)
	}
}

func TestMysqlQuoteQualifiedIdentWithoutSchemaPrefix(t *testing.T) {
	got := mysqlQuoteQualifiedIdent("justtable")
	want := "`justtable`"
	if got != want {
		t.Errorf("mysqlQuoteQualifiedIdent = %q, want %q", got, want)
	}
}

func TestMariaDBRootPasswordMissing(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: `["PATH=/usr/bin"]`}},
		},
	}
	b := Backend{Runner: fake}
	if _, err := b.mariaDBRootPassword(context.Background(), "mysql", ""); err == nil {
		t.Fatal("expected an error when MYSQL_ROOT_PASSWORD is absent from the container's env")
	}
}

func TestMariaDBRootPasswordInspectFailure(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.mariaDBRootPassword(context.Background(), "mysql", ""); err == nil {
		t.Fatal("expected docker inspect failure to propagate")
	}
}

func TestMariaDBRootPasswordPrefersResolvedAuth(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}
	got, err := b.mariaDBRootPassword(context.Background(), "mysql", "resolved-secret")
	if err != nil {
		t.Fatalf("mariaDBRootPassword: %v", err)
	}
	if got != "resolved-secret" {
		t.Errorf("mariaDBRootPassword = %q, want resolved-secret", got)
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero calls when resolvedAuth is already supplied, got %d", len(fake.Calls))
	}
}

func TestMariaDBDatabaseSize(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: `["MYSQL_ROOT_PASSWORD=hunter2"]`}}, // docker inspect
			{Result: sshx.Result{Stdout: "123456\n"}},                        // size query
		},
	}
	b := Backend{Runner: fake}

	size, err := b.mariaDBDatabaseSize(context.Background(), "mysql", "")
	if err != nil {
		t.Fatalf("mariaDBDatabaseSize: %v", err)
	}
	if size != 123456 {
		t.Errorf("size = %d, want 123456", size)
	}
}

func TestCreateArchiveWithMariaDB(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir
			{Result: sshx.Result{Stdout: `["MYSQL_ROOT_PASSWORD=hunter2"]`}}, // docker inspect (auth)
			{}, // mysqldump
			{Result: sshx.Result{Stdout: "cafebabe  mysql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: ""}},                      // list tables (none)
			{},                                                     // writeManifest
			{},                                                     // borg create
			{},                                                     // cleanup
		},
	}
	b := Backend{Runner: fake}

	_, manifest, err := b.CreateArchive(context.Background(),
		"/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", oneMariaDB(), nil, nil, nil, 1000, nil, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if len(manifest.Databases) != 1 || manifest.Databases[0].Container != "mysql" {
		t.Errorf("manifest = %+v, want one mysql entry", manifest)
	}
}

// TestCreateArchiveUsesResolvedAuthMap confirms CreateArchive threads
// its resolvedAuth map down by container name.
func TestCreateArchiveUsesResolvedAuthMap(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir
			{}, // mysqldump (no docker inspect — resolved auth used)
			{Result: sshx.Result{Stdout: "cafebabe  mysql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: ""}},                      // list tables (none)
			{},                                                     // writeManifest
			{},                                                     // borg create
			{},                                                     // cleanup
		},
	}
	b := Backend{Runner: fake}

	_, _, err := b.CreateArchive(context.Background(),
		"/repo/x", "pw", "/identity-key", "/work/x", "2026-07-18", oneMariaDB(),
		map[string]string{"mysql": "resolved-secret"}, nil, nil, 1000, nil, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if len(fake.Calls) != 8 {
		t.Fatalf("expected 8 calls (df, mkdir, dump, sha256, list-tables, writeManifest, borg-create, cleanup — no docker-inspect auth lookup), got %d: %+v", len(fake.Calls), fake.Calls)
	}
	for _, c := range fake.Calls {
		if c.Cmd == "docker" && len(c.Args) > 0 && c.Args[0] == "inspect" {
			t.Fatal("expected zero docker inspect calls when auth was already resolved")
		}
	}
}

func TestDumpDatabaseRejectsUnsupportedKind(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}
	_, err := b.dumpDatabase(context.Background(), "/work", discover.DatabaseInstance{
		Kind: "redis", Container: "cache", DumpStrategy: discover.DumpStrategyDockerExec,
	}, "", nil)
	if err == nil {
		t.Fatal("expected an error for an unsupported database kind")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero calls for an unsupported kind, got %d", len(fake.Calls))
	}
}

func TestDumpDatabaseRejectsUnsupportedStrategy(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	b := Backend{Runner: fake}
	_, err := b.dumpDatabase(context.Background(), "/work", discover.DatabaseInstance{
		Kind: "postgres", Container: "psql", DumpStrategy: discover.DumpStrategyTCP,
	}, "", nil)
	if err == nil {
		t.Fatal("expected an error for an unsupported dump strategy")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero calls for an unsupported strategy, got %d", len(fake.Calls))
	}
}
