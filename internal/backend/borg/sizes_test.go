package borg

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestPostgresDatabaseSizesParsesEachRow(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "app|1048576\nanalytics|2097152\n"}},
		},
	}
	b := Backend{Runner: fake}

	sizes, err := b.PostgresDatabaseSizes(context.Background(), "psql", "", "")
	if err != nil {
		t.Fatalf("PostgresDatabaseSizes: %v", err)
	}
	if sizes["app"] != 1048576 || sizes["analytics"] != 2097152 || len(sizes) != 2 {
		t.Errorf("sizes = %v, want {app:1048576, analytics:2097152}", sizes)
	}

	call := fake.Calls[0]
	if call.Cmd != "docker" || !strings.Contains(strings.Join(call.Args, " "), "psql -tAc") {
		t.Errorf("cmd/args = %q %v, want a docker exec ... psql -tAc invocation", call.Cmd, call.Args)
	}
	if call.Class != sshx.ReadOnly {
		t.Errorf("class = %v, want ReadOnly", call.Class)
	}
}

// TestPostgresDatabaseSizesWithPasswordUsesTCPAndPGPASSWORD proves a
// container whose peer auth doesn't work (resolvedAuth non-empty)
// still gets a size breakdown, via the same TCP+PGPASSWORD path
// dumpPostgres uses — the exact gap ("no password supplied") that
// blocked a real backup's free-space preflight check outright.
func TestPostgresDatabaseSizesWithPasswordUsesTCPAndPGPASSWORD(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "app|1048576\n"}},
		},
	}
	b := Backend{Runner: fake}

	sizes, err := b.PostgresDatabaseSizes(context.Background(), "psql", "hunter2", "")
	if err != nil {
		t.Fatalf("PostgresDatabaseSizes: %v", err)
	}
	if sizes["app"] != 1048576 {
		t.Errorf("sizes = %v, want app=1048576", sizes)
	}

	call := fake.Calls[0]
	if call.Cmd != "sh" || !strings.Contains(call.Args[1], "-h 127.0.0.1 -U 'postgres'") {
		t.Errorf("call = %+v, want a TCP loopback psql invocation", call)
	}
	if strings.Contains(call.Args[1], "hunter2") {
		t.Fatalf("the literal password must never appear in the script text, got %q", call.Args[1])
	}
	if len(call.Env) != 1 || call.Env[0] != "PGPASSWORD=hunter2" {
		t.Errorf("call env = %v, want [PGPASSWORD=hunter2]", call.Env)
	}
}

func TestPostgresDatabaseSizesFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.PostgresDatabaseSizes(context.Background(), "psql", "", ""); err == nil {
		t.Fatal("expected PostgresDatabaseSizes to propagate the runner error")
	}
}

func TestMariaDBSchemaSizesExcludesSystemSchemas(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "app\t1048576\ninformation_schema\t4096\nmysql\t8192\nperformance_schema\t2048\nsys\t1024\n"}},
		},
	}
	b := Backend{Runner: fake}

	sizes, err := b.MariaDBSchemaSizes(context.Background(), "mysql", "resolved-password")
	if err != nil {
		t.Fatalf("MariaDBSchemaSizes: %v", err)
	}
	if len(sizes) != 1 || sizes["app"] != 1048576 {
		t.Errorf("sizes = %v, want only {app:1048576} — system schemas must be excluded", sizes)
	}
}

func TestMariaDBSchemaSizesFailurePropagates(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errBoom}}}
	b := Backend{Runner: fake}
	if _, err := b.MariaDBSchemaSizes(context.Background(), "mysql", "resolved-password"); err == nil {
		t.Fatal("expected MariaDBSchemaSizes to propagate the runner error")
	}
}
