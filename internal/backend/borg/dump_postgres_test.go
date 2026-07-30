package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// TestPostgresUnionCountQueryQuotesMixedCaseIdentifiers proves the
// generated query double-quotes each table reference — verified live:
// a real table created with a quoted CREATE TABLE (mixed case, common
// with ORMs like Prisma) failed with "relation ... does not exist"
// when referenced unquoted, since Postgres folds an unquoted
// identifier to lowercase before comparing it against the catalog.
func TestPostgresUnionCountQueryQuotesMixedCaseIdentifiers(t *testing.T) {
	query := postgresUnionCountQuery([]string{`public._app_gamesTofiles`, "public.users"})

	if !strings.Contains(query, `FROM "public"."_app_gamesTofiles"`) {
		t.Errorf("query = %q, want a quoted FROM for the mixed-case table", query)
	}
	if !strings.Contains(query, `FROM "public"."users"`) {
		t.Errorf("query = %q, want a quoted FROM for the lowercase table too (quoting a lowercase identifier is always safe)", query)
	}
	// The label (the string literal identifying which table a count
	// row belongs to) must still be the original, unquoted
	// "schema.table" form — that's what parseCountLines/the manifest
	// key format expects, unrelated to how the FROM clause itself
	// must be quoted to actually reach the table.
	if !strings.Contains(query, `'public._app_gamesTofiles'`) {
		t.Errorf("query = %q, want the original schema.table string preserved as the row label", query)
	}
}

func TestPgQuoteQualifiedIdentEscapesEmbeddedQuotes(t *testing.T) {
	got := pgQuoteQualifiedIdent(`public.weird"table`)
	want := `"public"."weird""table"`
	if got != want {
		t.Errorf("pgQuoteQualifiedIdent = %q, want %q", got, want)
	}
}

func TestPgQuoteQualifiedIdentWithoutSchemaPrefix(t *testing.T) {
	got := pgQuoteQualifiedIdent("justtable")
	want := `"justtable"`
	if got != want {
		t.Errorf("pgQuoteQualifiedIdent = %q, want %q", got, want)
	}
}

// TestDumpPostgresWithoutPasswordUsesPeerAuth is a regression guard:
// the common case (discover's live probe confirmed peer auth works)
// must keep using the exact same docker-exec-as-OS-user invocation as
// before password support existed.
func TestDumpPostgresWithoutPasswordUsesPeerAuth(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // pg_dumpall
		{Result: sshx.Result{Stdout: "cafebabe  /work/psql.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "app\n"}},                      // list databases
		{Result: sshx.Result{Stdout: "public.users\n"}},             // list tables
		{Result: sshx.Result{Stdout: "public.users|3\n"}},           // union count query
	}}
	b := Backend{Runner: fake}

	dm, err := b.dumpPostgres(context.Background(), "psql", "/work/psql.sql", "", "", nil)
	if err != nil {
		t.Fatalf("dumpPostgres: %v", err)
	}
	if dm.SHA256 != "cafebabe" {
		t.Errorf("SHA256 = %q, want cafebabe", dm.SHA256)
	}

	dumpCall := fake.Calls[0]
	if dumpCall.Cmd != "sh" || !strings.Contains(dumpCall.Args[1], "docker exec -u postgres psql pg_dumpall > '/work/psql.sql'") {
		t.Errorf("dump call = %+v, want the peer-auth pg_dumpall invocation unchanged", dumpCall)
	}
	if len(dumpCall.Env) != 0 {
		t.Errorf("dump call env = %v, want none for the peer-auth path", dumpCall.Env)
	}
}

// TestDumpPostgresWithPasswordUsesTCPAndPGPASSWORD proves a container
// whose pg_hba.conf requires a password even locally (discover's probe
// found peer auth fails) gets a TCP loopback connection authenticated
// via PGPASSWORD instead — verified live: this exact gap ("no password
// supplied") blocked a real backup outright, since the previous code
// had no password-based path for postgres at all.
func TestDumpPostgresWithPasswordUsesTCPAndPGPASSWORD(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // pg_dumpall
		{Result: sshx.Result{Stdout: "cafebabe  /work/psql.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "app\n"}},                      // list databases
		{Result: sshx.Result{Stdout: "public.users\n"}},             // list tables
		{Result: sshx.Result{Stdout: "public.users|3\n"}},           // union count query
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpPostgres(context.Background(), "psql", "/work/psql.sql", "hunter2", "", nil); err != nil {
		t.Fatalf("dumpPostgres: %v", err)
	}

	dumpCall := fake.Calls[0]
	if dumpCall.Cmd != "sh" {
		t.Fatalf("dump call cmd = %q, want sh", dumpCall.Cmd)
	}
	if !strings.Contains(dumpCall.Args[1], `docker exec -e PGPASSWORD psql pg_dumpall -h 127.0.0.1 -U 'postgres' > '/work/psql.sql'`) {
		t.Errorf("dump script = %q, want the TCP loopback pg_dumpall invocation using bare -e PGPASSWORD", dumpCall.Args[1])
	}
	if strings.Contains(dumpCall.Args[1], "hunter2") {
		t.Fatalf("the literal password must never appear in the script text, got %q", dumpCall.Args[1])
	}
	if len(dumpCall.Env) != 1 || dumpCall.Env[0] != "PGPASSWORD=hunter2" {
		t.Errorf("dump call env = %v, want [PGPASSWORD=hunter2]", dumpCall.Env)
	}

	// Every downstream query (list databases, list tables, count) must
	// also use the password path, not silently fall back to peer auth.
	for i, call := range fake.Calls[2:] {
		if call.Cmd != "sh" || len(call.Env) != 1 || call.Env[0] != "PGPASSWORD=hunter2" {
			t.Errorf("call[%d] = %+v, want it to also authenticate via PGPASSWORD", i+2, call)
		}
	}
}

// TestDumpPostgresWithCustomUsernameConnectsAsThatUser is a regression
// guard for a real gap found live on a container started with
// POSTGRES_USER=paperclip: the official postgres image replaces the
// bootstrap superuser entirely in that case, so there is no "postgres"
// role at all — verified live that "docker exec -u paperclip" itself
// fails ("unable to find user"), since no matching OS/container
// account exists, only the database role does. The docker-exec OS
// user stays "postgres" (the one account that always exists); -U is
// what must carry the actual role, in both the passwordless and
// password paths.
func TestDumpPostgresWithCustomUsernameConnectsAsThatUser(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // pg_dumpall
		{Result: sshx.Result{Stdout: "cafebabe  /work/psql.sql\n"}}, // sha256sum
		{Result: sshx.Result{Stdout: "paperclip\n"}},                // list databases
		{Result: sshx.Result{Stdout: "public.users\n"}},             // list tables
		{Result: sshx.Result{Stdout: "public.users|3\n"}},           // union count query
	}}
	b := Backend{Runner: fake}

	if _, err := b.dumpPostgres(context.Background(), "paperclip-db", "/work/psql.sql", "", "paperclip", nil); err != nil {
		t.Fatalf("dumpPostgres: %v", err)
	}
	dumpCall := fake.Calls[0]
	if !strings.Contains(dumpCall.Args[1], "docker exec -u postgres paperclip-db pg_dumpall -U 'paperclip'") {
		t.Errorf("dump call = %+v, want docker exec as the always-present \"postgres\" OS user, connecting as the -U paperclip role", dumpCall)
	}

	fake2 := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // pg_dumpall
		{Result: sshx.Result{Stdout: "cafebabe  /work/psql.sql\n"}},
		{Result: sshx.Result{Stdout: "paperclip\n"}},
		{Result: sshx.Result{Stdout: "public.users\n"}},
		{Result: sshx.Result{Stdout: "public.users|3\n"}},
	}}
	b2 := Backend{Runner: fake2}
	if _, err := b2.dumpPostgres(context.Background(), "paperclip-db", "/work/psql.sql", "hunter2", "paperclip", nil); err != nil {
		t.Fatalf("dumpPostgres: %v", err)
	}
	dumpCall2 := fake2.Calls[0]
	if !strings.Contains(dumpCall2.Args[1], "pg_dumpall -h 127.0.0.1 -U 'paperclip'") {
		t.Errorf("dump call = %+v, want the TCP path to also connect as paperclip, not postgres", dumpCall2)
	}
}

// TestDumpPostgresQuotesAdversarialUsername is a regression guard for
// a confirmed root-RCE shell injection: Username is auto-detected from
// a container's own POSTGRES_USER env var with no validation, and was
// previously spliced unquoted into root-context sh -c scripts in both
// the peer-auth and TCP+password paths. A username crafted to break
// out of that quoting must never execute anything — the generated
// script must contain it only as an inert, single-quoted string.
func TestDumpPostgresQuotesAdversarialUsername(t *testing.T) {
	const evil = `x'; touch /tmp/pwn; echo '`

	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // pg_dumpall
		{Result: sshx.Result{Stdout: "cafebabe  /work/psql.sql\n"}},
		{Result: sshx.Result{Stdout: ""}}, // list databases (none)
	}}
	b := Backend{Runner: fake}
	if _, err := b.dumpPostgres(context.Background(), "psql", "/work/psql.sql", "", evil, nil); err != nil {
		t.Fatalf("dumpPostgres: %v", err)
	}
	script := fake.Calls[0].Args[1]
	if strings.Contains(script, "touch /tmp/pwn") && !strings.Contains(script, `'\''`) {
		t.Fatalf("peer-auth script = %q, the adversarial username must never appear as live shell syntax", script)
	}
	if !strings.Contains(script, `'\''`) {
		t.Errorf("peer-auth script = %q, want the adversarial username's embedded quote escaped via '\\''", script)
	}

	fake2 := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{}, // pg_dumpall
		{Result: sshx.Result{Stdout: "cafebabe  /work/psql.sql\n"}},
		{Result: sshx.Result{Stdout: ""}},
	}}
	b2 := Backend{Runner: fake2}
	if _, err := b2.dumpPostgres(context.Background(), "psql", "/work/psql.sql", "hunter2", evil, nil); err != nil {
		t.Fatalf("dumpPostgres: %v", err)
	}
	script2 := fake2.Calls[0].Args[1]
	if strings.Contains(script2, "touch /tmp/pwn") && !strings.Contains(script2, `'\''`) {
		t.Fatalf("TCP-path script = %q, the adversarial username must never appear as live shell syntax", script2)
	}
	if !strings.Contains(script2, `'\''`) {
		t.Errorf("TCP-path script = %q, want the adversarial username's embedded quote escaped via '\\''", script2)
	}
}
