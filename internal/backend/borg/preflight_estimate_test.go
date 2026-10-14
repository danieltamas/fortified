package borg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// Expected totals and thresholds below come from SPEC.md §4, not from
// the production estimate helpers or their constants.
func TestPreflightEstimatePostgresAllDatabases(t *testing.T) {
	for _, mode := range []struct {
		name     string
		strategy discover.DumpStrategy
		password string
	}{
		{"docker-peer", discover.DumpStrategyDockerExec, ""},
		{"docker-password", discover.DumpStrategyDockerExec, "test-password"},
		{"native-peer", discover.DumpStrategyNative, ""},
		{"native-password", discover.DumpStrategyNative, "test-password"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for _, boundary := range []struct {
				available int64
				refuse    bool
			}{
				{5000, true}, // Raw 4800 fits, but 4800 × 1.25 = 6000 does not.
				{5999, true},
				{6000, false},
				{6001, false},
			} {
				t.Run(fmt.Sprint(boundary.available), func(t *testing.T) {
					fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
						{Result: sshx.Result{Stdout: "app\npostgres\nteam's data\n"}},
						{Result: sshx.Result{Stdout: "800\n"}},
						{Result: sshx.Result{Stdout: "1600\n"}},
						{Result: sshx.Result{Stdout: "2400\n"}},
						{Result: sshx.Result{Stdout: fmt.Sprintf("Avail\n%d\n", boundary.available)}},
					}}
					dbs := []discover.DatabaseInstance{{Kind: "postgres", Container: "pg", DumpStrategy: mode.strategy, AuthResolved: true}}
					b := Backend{Runner: fake}
					err := b.FreeSpacePreflight(context.Background(), "/work/backup", dbs, map[string]string{"pg": mode.password}, 0)
					assertEstimateDecision(t, err, boundary.refuse)
					if len(fake.Calls) != 5 {
						t.Fatalf("want list, three per-database estimates, df; got %+v", fake.Calls)
					}
					list := estimateCallText(fake.Calls[0])
					if !strings.Contains(list, "pg_database") || !strings.Contains(list, "NOT datistemplate") {
						t.Errorf("database enumeration must exclude templates: %s", list)
					}
					for i, database := range []string{"app", "postgres", "team's data"} {
						call := fake.Calls[i+1]
						if mode.strategy == discover.DumpStrategyDockerExec && mode.password == "" {
							if call.Cmd != "docker" || estimateArgAfter(call.Args, "-d") != database {
								t.Errorf("want docker psql -d %q, got %+v", database, call)
							}
						} else {
							// Assert shell quoting independently, including an apostrophe
							// and a space in a database name.
							quotedDB := "'" + strings.ReplaceAll(database, "'", "'\\''") + "'"
							if !strings.Contains(strings.Join(call.Args, " "), " -d "+quotedDB+" -tAc ") {
								t.Errorf("want shell -d argument %s, got %+v", quotedDB, call)
							}
							wantCmd := "sh"
							if mode.strategy == discover.DumpStrategyNative && mode.password == "" {
								wantCmd = "su"
							}
							if call.Cmd != wantCmd {
								t.Errorf("query command = %q, want %q", call.Cmd, wantCmd)
							}
						}
						assertPostgresEstimateSQL(t, call)
					}
					if fake.Calls[4].Cmd != "df" {
						t.Errorf("last preflight call must check free space: %+v", fake.Calls[4])
					}
				})
			}
		})
	}
}

func TestPreflightEstimateMariaDBDataOnly(t *testing.T) {
	for _, mode := range []struct {
		name     string
		strategy discover.DumpStrategy
		password string
	}{
		{"docker", discover.DumpStrategyDockerExec, "test-password"},
		{"native-defaults-file", discover.DumpStrategyNative, ""},
		{"native-password", discover.DumpStrategyNative, "test-password"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for _, available := range []int64{4500, 4999, 5000} {
				t.Run(fmt.Sprint(available), func(t *testing.T) {
					fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
						{Result: sshx.Result{Stdout: "4000\n"}},
						{Result: sshx.Result{Stdout: fmt.Sprintf("Avail\n%d\n", available)}},
					}}
					b := Backend{Runner: fake}
					dbs := []discover.DatabaseInstance{{Kind: "mariadb", Container: "mysql", DumpStrategy: mode.strategy, AuthResolved: true}}
					err := b.FreeSpacePreflight(context.Background(), "/work/backup", dbs, map[string]string{"mysql": mode.password}, 0)
					assertEstimateDecision(t, err, available < 5000)
					if len(fake.Calls) != 2 || fake.Calls[1].Cmd != "df" {
						t.Fatalf("want one estimate then df, got %+v", fake.Calls)
					}
					query := strings.ToLower(estimateCallText(fake.Calls[0]))
					if !strings.Contains(query, "sum(data_length)") || !strings.Contains(query, "information_schema.tables") || strings.Contains(query, "index_length") {
						t.Errorf("estimate must sum data_length alone: %s", query)
					}
					if mode.strategy == discover.DumpStrategyNative && strings.Contains(query, "docker") {
						t.Errorf("native estimate must not use docker: %s", query)
					}
				})
			}
		})
	}
}

func TestPreflightEstimateLastRunSkipsQueries(t *testing.T) {
	for _, available := range []int64{1250, 1499, 1500} {
		t.Run(fmt.Sprint(available), func(t *testing.T) {
			fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
				{Result: sshx.Result{Stdout: fmt.Sprintf("Avail\n%d\n", available)}},
			}}
			b := Backend{Runner: fake}
			dbs := []discover.DatabaseInstance{
				{Kind: "postgres", Container: "pg", DumpStrategy: discover.DumpStrategyDockerExec},
				{Kind: "postgres", Container: "postgresql", DumpStrategy: discover.DumpStrategyNative},
				{Kind: "mariadb", Container: "mysql", DumpStrategy: discover.DumpStrategyNative},
			}
			err := b.FreeSpacePreflight(context.Background(), "/work/backup", dbs, nil, 1000)
			assertEstimateDecision(t, err, available < 1500)
			if len(fake.Calls) != 1 || fake.Calls[0].Cmd != "df" {
				t.Fatalf("last-run path must issue only df, got %+v", fake.Calls)
			}
		})
	}
}

func TestPreflightEstimateRefusesBeforeDump(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "app\npostgres\n"}},
		{Result: sshx.Result{Stdout: "2000\n"}},
		{Result: sshx.Result{Stdout: "2000\n"}},
		{Result: sshx.Result{Stdout: "Avail\n4500\n"}},
	}}
	b := Backend{Runner: fake}
	dbs := []discover.DatabaseInstance{{Kind: "postgres", Container: "pg", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
	_, _, err := b.CreateArchive(context.Background(), "/repo/x", "pw", "/identity", "/work/backup", "archive", dbs, nil, nil, nil, 0, nil, nil)
	assertEstimateDecision(t, err, true)
	if len(fake.Calls) != 4 {
		t.Fatalf("insufficient space must stop after estimates and df, got %+v", fake.Calls)
	}
	for _, call := range fake.Calls {
		if call.Class != sshx.ReadOnly || strings.Contains(estimateCallText(call), "pg_dump") {
			t.Errorf("preflight refusal must precede any dump or mutation: %+v", call)
		}
	}
}

func TestPreflightEstimateErrorsStopBeforeDump(t *testing.T) {
	queryFailure := errors.New("estimate query failed")
	for _, tc := range []struct {
		name      string
		responses []sshxtest.Response
	}{
		{"list-error", []sshxtest.Response{{Err: queryFailure}}},
		{"size-error", []sshxtest.Response{{Result: sshx.Result{Stdout: "app\n"}}, {Err: queryFailure}}},
		{"invalid-size", []sshxtest.Response{{Result: sshx.Result{Stdout: "app\n"}}, {Result: sshx.Result{Stdout: "not a size\n"}}}},
		{"second-database-error", []sshxtest.Response{{Result: sshx.Result{Stdout: "app\npostgres\n"}}, {Result: sshx.Result{Stdout: "4000\n"}}, {Err: queryFailure}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &sshxtest.FakeRunner{Responses: tc.responses}
			b := Backend{Runner: fake}
			dbs := []discover.DatabaseInstance{{Kind: "postgres", Container: "pg", DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}}
			_, _, err := b.CreateArchive(context.Background(), "/repo/x", "pw", "/identity", "/work/backup", "archive", dbs, nil, nil, nil, 0, nil, nil)
			if err == nil {
				t.Fatal("an unknown estimate must fail closed")
			}
			if len(fake.Calls) != len(tc.responses) {
				t.Fatalf("must stop at failed estimate, got %+v", fake.Calls)
			}
			for _, call := range fake.Calls {
				if call.Class != sshx.ReadOnly {
					t.Errorf("estimate failure allowed a mutation: %+v", call)
				}
			}
		})
	}
}

func TestPreflightEstimateFractionalRequirementRoundsUp(t *testing.T) {
	// 1001 × 1.25 = 1251.25: 1251 free bytes are insufficient.
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "app\n"}},
		{Result: sshx.Result{Stdout: "1001\n"}},
		{Result: sshx.Result{Stdout: "Avail\n1251\n"}},
	}}
	b := Backend{Runner: fake}
	dbs := []discover.DatabaseInstance{{Kind: "postgres", Container: "pg", DumpStrategy: discover.DumpStrategyDockerExec}}
	assertEstimateDecision(t, b.FreeSpacePreflight(context.Background(), "/work/backup", dbs, nil, 0), true)
}

func assertEstimateDecision(t *testing.T, err error, refuse bool) {
	t.Helper()
	if refuse {
		if err == nil || !strings.Contains(err.Error(), "insufficient free space") {
			t.Fatalf("want insufficient-space refusal, got %v", err)
		}
	} else if err != nil {
		t.Fatalf("space meets the spec requirement, got %v", err)
	}
}

func estimateArgAfter(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func estimateCallText(call sshxtest.Call) string {
	return call.Cmd + " " + strings.Join(call.Args, " ")
}

func assertPostgresEstimateSQL(t *testing.T, call sshxtest.Call) {
	t.Helper()
	query := estimateArgAfter(call.Args, "-tAc")
	if query == "" {
		// Undo POSIX apostrophe escaping to inspect SQL in sh/su scripts.
		// Assert the quoted literals separately below so an unquoted
		// SQL predicate cannot pass merely because its words occur.
		script := strings.Join(call.Args, " ")
		for _, literal := range []string{"r", "pg_catalog", "information_schema"} {
			if !strings.Contains(script, "'\\''"+literal+"'\\''") {
				t.Errorf("SQL literal %q lost shell quoting: %+v", literal, call)
			}
		}
		query = strings.ReplaceAll(script, "'\\''", "'")
	}
	query = strings.ToLower(query)
	for _, want := range []string{"sum(pg_table_size(", "pg_class", "pg_namespace", "relkind = 'r'", "not in ('pg_catalog','information_schema')"} {
		if !strings.Contains(query, want) {
			t.Errorf("table-data SQL missing %q: %s", want, query)
		}
	}
	for _, forbidden := range []string{"pg_database_size", "pg_indexes_size", "pg_total_relation_size", "index_length"} {
		if strings.Contains(query, forbidden) {
			t.Errorf("table-data estimate includes forbidden size %q: %s", forbidden, query)
		}
	}
}
