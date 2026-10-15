package orchestrate

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

// verifyTestDumpSizeJSONLines is `borg list --json-lines <repo>::
// <archive> <workspaceDir>`'s response, scripted for Verify's own
// pre-restore ArchivePathSize call (distinct from any per-database
// size-estimate query, which it now replaces — see verify.go's
// comment on why FreeSpacePreflight is given the workspace's real
// scoped size instead of 0 here). One directory entry (size 0, not
// summed) plus one regular file entry (size 1000, summed) — matches
// the real shape verified live against `borg list --json-lines`.
const verifyTestDumpSizeJSONLines = `{"type": "d", "path": "fortified-backup-workspace", "size": 0}
{"type": "-", "path": "fortified-backup-workspace/psql.sql", "size": 1000}`

func onboardedStateWithManifest(serverID string, manifest *state.Manifest, databases []discover.DatabaseInstance) *state.Server {
	st := onboardedState(serverID)
	st.LastManifest = manifest
	st.Databases = databases
	return st
}

func TestVerifyRefusesWithoutOnboarding(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "onboard") {
		t.Fatalf("Verify error = %v, want it to mention onboarding", err)
	}
}

func TestVerifyRefusesWithoutManifest(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("Verify error = %v, want it to mention the missing manifest", err)
	}
}

func TestVerifyRefusesWhenNoArchivesExist(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: ""}}, // borg list: empty
		},
	}
	d := testDeps(t, target)
	seeded := onboardedStateWithManifest(d.ServerID, &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql"}}}, nil)
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "no archives") {
		t.Fatalf("Verify error = %v, want it to mention no archives", err)
	}
}

func TestVerifyFailsOnSHA256Mismatch(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},    // borg list
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},       // df
			{},                                       // mkdir scratch dir
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},                                       // borg extract
			{Result: sshx.Result{Stdout: "wrongsha  /path\n"}}, // sha256sum: mismatch
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "postgres:16-alpine", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("Verify error = %v, want it to mention a sha256 mismatch", err)
	}
}

func TestVerifyHappyPathPostgres(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-17T00-00-00Z\n2026-07-18T00-00-00Z\n"}}, // borg list (pick the later one)
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}},                    // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},                          // df
			{},                                       // mkdir scratch dir
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},                                       // borg extract
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}}, // sha256sum: match
			{}, // docker run (throwaway)
			{}, // ready probe 1
			{}, // ready probe 2
			{}, // ready probe 3
			{}, // load dump (sh -c docker exec ... psql < path)
			{Result: sshx.Result{Stdout: "postgres\n"}},       // RowCounts: list databases
			{Result: sshx.Result{Stdout: "public.users\n"}},   // list tables in postgres
			{Result: sshx.Result{Stdout: "public.users|5\n"}}, // count query
			{}, // docker rm -f throwaway
			{}, // rm -rf scratch dir (deferred, last)
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "postgres:16-alpine", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if !st.Verify.EverPassed {
		t.Error("expected Verify.EverPassed to be true")
	}
	if st.Timestamps.LastPassingVerify == nil {
		t.Error("expected LastPassingVerify to be recorded")
	}

	extractCall := target.Calls[5]
	if extractCall.Cmd != "borg" || extractCall.Args[0] != "extract" || !strings.Contains(extractCall.Args[1], "2026-07-18T00-00-00Z") {
		t.Errorf("extract call = %q %v, want the latest (2026-07-18) archive", extractCall.Cmd, extractCall.Args)
	}
	// Regression guard for a real bug found live: extracting the whole
	// archive (not just the database dumps under workspaceDir) means
	// verify's disk footprint on the target scales with however much
	// raw file data the server also archives (mail, old tarballs,
	// etc.), not with its database dumps — which is what ran
	// host-2-example's verify out of disk 55 minutes into a restore.
	wantWorkspaceDir := backupWorkspaceDir(d.ServerID, d.Server.WorkspaceDir)
	if len(extractCall.Args) < 3 || extractCall.Args[2] != wantWorkspaceDir {
		t.Errorf("extract call args = %v, want a third arg scoping the extract to %q (only the database dumps, not the whole archive)", extractCall.Args, wantWorkspaceDir)
	}

	// Regression guard for a real bug found live: pg_dumpall always
	// includes CREATE ROLE postgres (dumping the whole cluster), which
	// collides with the throwaway container's own bootstrap-created
	// "postgres" role under ON_ERROR_STOP=1 unless it's filtered out
	// before loading.
	loadCall := target.Calls[11]
	if loadCall.Cmd != "sh" || !strings.Contains(loadCall.Args[1], "grep -vE") || !strings.Contains(loadCall.Args[1], "CREATE ROLE postgres;") {
		t.Errorf("load call = %+v, want the dump piped through a filter dropping the postgres role's own CREATE/ALTER lines", loadCall)
	}

	lastCall := target.Calls[len(target.Calls)-1]
	if lastCall.Cmd != "rm" {
		t.Errorf("last call = %q, want the scratch-dir cleanup (rm -rf)", lastCall.Cmd)
	}
}

// TestVerifyHappyPathNativePostgres proves a native (non-Docker)
// postgres backup can actually pass verify once discover populates a
// real Image for it — verifyPostgres itself needed no changes at all
// (its throwaway container already sets POSTGRES_HOST_AUTH_METHOD=
// trust unconditionally, regardless of what the original's own auth
// looked like), so this is the same code path as
// TestVerifyHappyPathPostgres with DumpStrategy=Native — a dedicated
// test locks that in rather than leaving it to be true only by
// accident of shared code.
func TestVerifyHappyPathNativePostgres(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},    // borg list
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},       // df
			{},                                       // mkdir scratch dir
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},                                       // borg extract
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}}, // sha256sum
			{},         // docker run (throwaway)
			{}, {}, {}, // ready probes
			{}, // load dump
			{Result: sshx.Result{Stdout: "postgres\n"}},       // RowCounts: list databases
			{Result: sshx.Result{Stdout: "public.users\n"}},   // list tables
			{Result: sshx.Result{Stdout: "public.users|5\n"}}, // count query
			{}, // docker rm -f throwaway
			{}, // rm -rf scratch dir
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "postgresql", Image: "postgres:15-bookworm", DumpStrategy: discover.DumpStrategyNative, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "postgresql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if !st.Verify.EverPassed {
		t.Error("expected Verify.EverPassed to be true")
	}
}

func TestVerifyHappyPathMariaDB(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},    // borg list
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},       // df
			{},                                       // mkdir scratch dir
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},                                       // borg extract
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}}, // sha256sum
			{},         // docker run (throwaway)
			{}, {}, {}, // ready probes
			{}, // load dump
			{Result: sshx.Result{Stdout: "appdb.widgets\n"}}, // RowCounts: list tables
			{Result: sshx.Result{Stdout: "appdb.widgets|3\n"}},
			{}, // docker rm -f throwaway
			{}, // rm -rf scratch dir
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "mariadb", Container: "mysql", Image: "mariadb:10.4", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "mysql", SHA256: "deadbeef", RowCounts: map[string]int64{"appdb.widgets": 3}}}}
	seeded := onboardedStateWithManifest(d.ServerID, manifest, databases)
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	d.Server.Databases = []config.Database{{Kind: "mariadb", Container: "mysql", DumpStrategy: "docker-exec", AuthRef: "env://FORTIFIED_TEST_MARIADB_ROOT_PW"}}
	t.Setenv("FORTIFIED_TEST_MARIADB_ROOT_PW", "root-secret")

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The throwaway container's start command and readiness probe both
	// need the root password (to set it, and to authenticate against
	// it) — this is exactly the call shape that used to leak it: proves
	// the fix, not just that Verify still passes.
	for _, c := range target.Calls {
		if strings.Contains(strings.Join(c.Args, " "), "root-secret") {
			t.Fatalf("call %+v has the mariadb root password in its recorded argv — this is exactly what audit.Runner logs verbatim", c)
		}
		if strings.Contains(c.Stdin, "root-secret") {
			t.Fatalf("call %+v has the mariadb root password in stdin", c)
		}
	}
}

// TestVerifyHappyPathNativeMariaDB proves a native (non-Docker)
// mariadb backup can actually pass verify — a real gap found by
// cross-vendor review: the original code path called
// MariaDBRootPassword, which docker-inspects the manifest's own
// Container name to read MYSQL_ROOT_PASSWORD when no auth_ref is
// configured (the normal case for a native database, since there is
// no equivalent of that env var to configure at all) — but a native
// database's Container ("mysql") is a synthetic name, not a real
// Docker container, so that inspect call always failed. No call in
// this test's sequence may ever attempt to docker-inspect "mysql".
func TestVerifyHappyPathNativeMariaDB(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},    // borg list
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},       // df
			{},                                       // mkdir scratch dir
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},                                       // borg extract
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}}, // sha256sum
			{},         // docker run (throwaway) — fixed throwaway password, no lookup
			{}, {}, {}, // ready probes
			{}, // load dump
			{Result: sshx.Result{Stdout: "appdb.widgets\n"}}, // RowCounts: list tables
			{Result: sshx.Result{Stdout: "appdb.widgets|3\n"}},
			{}, // docker rm -f throwaway
			{}, // rm -rf scratch dir
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "mariadb", Container: "mysql", Image: "mariadb:11", DumpStrategy: discover.DumpStrategyNative, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "mysql", SHA256: "deadbeef", RowCounts: map[string]int64{"appdb.widgets": 3}}}}
	seeded := onboardedStateWithManifest(d.ServerID, manifest, databases)
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	for _, c := range target.Calls {
		if c.Cmd == "docker" && len(c.Args) >= 2 && c.Args[0] == "inspect" {
			t.Fatalf("call %+v: docker-inspected the synthetic \"mysql\" container name — it isn't a real container", c)
		}
	}
}

// TestVerifyHappyPathCockroachDB proves Verify's throwaway-container
// dance also works for CockroachDB: a single-node --insecure cluster
// started with an explicit command (unlike postgres/mariadb, which
// rely on env vars for init), the self-contained multi-database dump
// loaded in one shot, and row counts re-derived and compared exactly
// like the other two engines.
func TestVerifyHappyPathCockroachDB(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},    // borg list
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},       // df
			{},                                       // mkdir scratch dir
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},                                       // borg extract
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}}, // sha256sum
			{},         // docker run (throwaway, start --insecure)
			{}, {}, {}, // ready probes
			{}, // load dump
			{Result: sshx.Result{Stdout: "database_name\nnakama\nsystem\n"}}, // RowCounts: SHOW DATABASES
			{Result: sshx.Result{Stdout: "table_name\ngroups\n"}},            // list tables in nakama
			{Result: sshx.Result{Stdout: "col\npublic.groups|3\n"}},          // count query
			{}, // docker rm -f throwaway
			{}, // rm -rf scratch dir
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "cockroachdb", Container: "cockroachdb", Image: "cockroachdb/cockroach:v19.1.5", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "cockroachdb", SHA256: "deadbeef", RowCounts: map[string]int64{"nakama.public.groups": 3}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if !st.Verify.EverPassed {
		t.Error("expected Verify.EverPassed to be true")
	}

	// The throwaway container must be started with an explicit
	// "start --insecure" command — CockroachDB has no env-var-driven
	// init the way postgres/mariadb do.
	var sawStartInsecure bool
	for _, c := range target.Calls {
		if c.Cmd == "sh" && len(c.Args) > 1 && strings.Contains(c.Args[1], "docker run") && strings.Contains(c.Args[1], "start --insecure") {
			sawStartInsecure = true
		}
	}
	if !sawStartInsecure {
		t.Error("expected a docker run ... start --insecure invocation for the throwaway cluster")
	}
}

// TestVerifyThrowawayContainerNeverLeaksSecretIntoArgv is a focused
// regression test for the finding above: it asserts not just "no
// leak" but the actual mechanism — the docker run/exec commands
// reference "$MYSQL_ROOT_PASSWORD"/"$MYSQL_PWD" (shell variables),
// with the real value delivered only via each call's Env, matching
// dumpMariaDB's already-established pattern.
func TestVerifyThrowawayContainerNeverLeaksSecretIntoArgv(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}},
			{}, {}, {}, {},
			{},
			{Result: sshx.Result{Stdout: "appdb.widgets\n"}},
			{Result: sshx.Result{Stdout: "appdb.widgets|3\n"}},
			{},
			{},
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "mariadb", Container: "mysql", Image: "mariadb:10.4", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "mysql", SHA256: "deadbeef", RowCounts: map[string]int64{"appdb.widgets": 3}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	d.Server.Databases = []config.Database{{Kind: "mariadb", Container: "mysql", DumpStrategy: "docker-exec", AuthRef: "env://FORTIFIED_TEST_MARIADB_ROOT_PW_2"}}
	t.Setenv("FORTIFIED_TEST_MARIADB_ROOT_PW_2", "hunter2")

	if err := Verify(context.Background(), d); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	runCall := target.Calls[7]
	if argv := strings.Join(runCall.Args, " "); strings.Contains(argv, "hunter2") || strings.Contains(argv, "$MYSQL_ROOT_PASSWORD") || strings.Contains(argv, "$MYSQL_PWD") || !strings.Contains(argv, "-e MYSQL_ROOT_PASSWORD ") || !strings.Contains(argv, "-e MYSQL_PWD ") {
		t.Errorf("docker run call args = %v, want bare -e MYSQL_ROOT_PASSWORD and -e MYSQL_PWD flags without values or shell expansions", runCall.Args)
	}
	wantEnv := []string{"MYSQL_ROOT_PASSWORD=hunter2", "MYSQL_PWD=hunter2"}
	if !slices.Equal(runCall.Env, wantEnv) {
		t.Errorf("docker run call env = %v, want %v", runCall.Env, wantEnv)
	}

	probeCall := target.Calls[8]
	if argv := strings.Join(probeCall.Args, " "); strings.Contains(argv, "hunter2") || strings.Contains(argv, "$MYSQL_PWD") || !strings.Contains(argv, "-e MYSQL_PWD ") {
		t.Errorf("readiness probe args = %v, want a bare -e MYSQL_PWD flag without a value or shell expansion", probeCall.Args)
	}
	// MYSQL_PWD is deliberately present here too (not just
	// MYSQL_ROOT_PASSWORD) — see verifyMariaDB's own doc comment on
	// why the readiness probe needs the real password, not an empty
	// one, to avoid a false-ready signal during the official image's
	// own temporary pre-restart server.
	if !slices.Equal(probeCall.Env, wantEnv) {
		t.Errorf("readiness probe env = %v, want %v (the same env startThrowawayContainer was given)", probeCall.Env, wantEnv)
	}
}

func TestVerifyFailsWhenDatabaseNoLongerDiscovered(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},       // no databases -> no size estimate call
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},
		},
	}
	d := testDeps(t, target)
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef"}}}
	// databases deliberately nil: psql is no longer in the last discover result.
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, nil)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "no longer present") {
		t.Fatalf("Verify error = %v, want it to mention the database is no longer discovered", err)
	}
}

func TestVerifyFailsWhenRestoreFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{Err: errBoom},                           // borg extract fails
		},
	}
	d := testDeps(t, target)
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, nil)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("Verify error = %v, want it to mention the restore failure", err)
	}
}

func TestVerifyFailsWhenThrowawayContainerStartFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}},
			{Err: errBoom}, // docker run fails outright
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "postgres:16-alpine", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "start throwaway container") {
		t.Fatalf("Verify error = %v, want it to mention the throwaway container start failure", err)
	}
}

// TestVerifyFailsClearlyWhenImageIsEmpty is a regression guard for a
// real bug found live: state saved before discover's Image-population
// fix (or simply never refreshed via `discover --refresh-databases`
// since) has an empty Image, which used to silently build a malformed
// `docker run` command (missing its required IMAGE argument) and fail
// with a confusing raw Docker CLI usage error instead of naming the
// actual cause.
func TestVerifyFailsClearlyWhenImageIsEmpty(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}},
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "", DumpStrategy: discover.DumpStrategyNative, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "discover --refresh-databases") {
		t.Fatalf("Verify error = %v, want it to point at discover --refresh-databases, not a raw docker CLI error", err)
	}
}

func TestVerifyFailsWhenLoadDumpFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}},
			{},         // docker run
			{}, {}, {}, // ready probes
			{Err: errBoom}, // load dump fails
			{},             // docker rm -f throwaway (still cleaned up)
			{},             // rm -rf scratch dir
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "postgres:16-alpine", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "load restored dump") {
		t.Fatalf("Verify error = %v, want it to mention the dump load failure", err)
	}
}

func TestVerifyFailsWhenRowCountsQueryFails(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}},
			{},
			{}, {}, {},
			{},
			{Err: errBoom}, // RowCounts: list databases fails
			{},             // docker rm -f throwaway
			{},             // rm -rf scratch dir
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "postgres:16-alpine", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "count rows") {
		t.Fatalf("Verify error = %v, want it to mention the row-count query failure", err)
	}
}

func TestVerifyFailsOnRowCountMismatch(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "2026-07-18T00-00-00Z\n"}},
			{Result: sshx.Result{Stdout: verifyTestDumpSizeJSONLines}}, // borg list --json-lines (workspace dump size for the free-space preflight)
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}},
			{},
			{Result: sshx.Result{Stdout: "/home\n"}}, // pwd (resolve automationKeyPath to an absolute path)
			{},
			{Result: sshx.Result{Stdout: "deadbeef  /path\n"}},
			{},
			{}, {}, {},
			{},
			{Result: sshx.Result{Stdout: "postgres\n"}},
			{Result: sshx.Result{Stdout: "public.users\n"}},
			{Result: sshx.Result{Stdout: "public.users|999\n"}}, // wrong count
			{},
			{},
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", Image: "postgres:16-alpine", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql", SHA256: "deadbeef", RowCounts: map[string]int64{"postgres.public.users": 5}}}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := Verify(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "row count") {
		t.Fatalf("Verify error = %v, want it to mention a row count mismatch", err)
	}

	st, loadErr := state.Load(d.StateDir, d.ServerID)
	if loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	if st.Verify.EverPassed {
		t.Error("expected Verify.EverPassed to remain false after a row count mismatch")
	}
}

// TestCompareRowCountsCatchesAMissingTable: a table entirely absent
// from the restored database and a table present with zero rows both
// read as 0 through a plain map index — compareRowCounts must tell
// them apart, or a partially-failed restore (a table that silently
// never got created) reads as a pass because the manifest happens to
// expect a nonzero count that a missing key coincidentally can't
// produce... except when the baseline itself is 0, which is exactly
// where the bug lived.
func TestCompareRowCountsCatchesAMissingTable(t *testing.T) {
	dm := state.DatabaseManifest{RowCounts: map[string]int64{"public.empty_table": 0, "public.users": 5}}

	// public.empty_table is missing entirely from got (never restored),
	// but the baseline for it is legitimately 0 — a plain `got[table]`
	// read can't distinguish "missing" from "present with 0 rows".
	got := map[string]int64{"public.users": 5}

	if err := compareRowCounts(dm, got); err == nil {
		t.Fatal("expected compareRowCounts to catch a table missing from the restored database, even when its baseline is 0")
	}
}

func TestCompareRowCountsPassesWhenATableIsPresentWithZeroRows(t *testing.T) {
	dm := state.DatabaseManifest{RowCounts: map[string]int64{"public.empty_table": 0}}
	got := map[string]int64{"public.empty_table": 0}

	if err := compareRowCounts(dm, got); err != nil {
		t.Errorf("compareRowCounts: %v, want a genuinely-empty table (present, 0 rows) to pass", err)
	}
}
