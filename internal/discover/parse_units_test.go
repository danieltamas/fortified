package discover

import (
	"context"
	"errors"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

func TestCommandMissingVariants(t *testing.T) {
	cases := []struct {
		name string
		r    sshx.Result
		want bool
	}{
		{"exit127", sshx.Result{ExitCode: 127}, true},
		{"stdout text", sshx.Result{Stdout: "bash: line 1: zpool: command not found"}, true},
		{"stderr text", sshx.Result{Stderr: "sh: btrfs: No such file or directory"}, true},
		{"present", sshx.Result{Stdout: "some real output", ExitCode: 0}, false},
	}
	for _, c := range cases {
		if got := commandMissing(c.r); got != c.want {
			t.Errorf("%s: commandMissing = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRequiredAuthEnvVar(t *testing.T) {
	if requiredAuthEnvVar("postgres") != "" {
		t.Error("postgres should need no required auth env var (peer auth)")
	}
	if requiredAuthEnvVar("mariadb") != "MYSQL_ROOT_PASSWORD" {
		t.Errorf("mariadb requiredAuthEnvVar = %q, want MYSQL_ROOT_PASSWORD", requiredAuthEnvVar("mariadb"))
	}
}

func TestHasEnvVar(t *testing.T) {
	env := []string{"FOO=1", "MYSQL_ROOT_PASSWORD=x"}
	if !hasEnvVar(env, "MYSQL_ROOT_PASSWORD") {
		t.Error("expected MYSQL_ROOT_PASSWORD to be found")
	}
	if hasEnvVar(env, "MISSING") {
		t.Error("expected MISSING to not be found")
	}
	if hasEnvVar(env, "") {
		t.Error("an empty required var name means no auth is required, not a match")
	}
}

func TestSplitAddrPort(t *testing.T) {
	cases := []struct {
		field    string
		wantAddr string
		wantPort int
		wantOK   bool
	}{
		{"127.0.0.1:9008", "127.0.0.1", 9008, true},
		{"[::]:443", "[::]", 443, true},
		{"127.0.0.53%lo:53", "127.0.0.53%lo", 53, true},
		{"no-colon-here", "", 0, false},
		{"host:not-a-port", "", 0, false},
	}
	for _, c := range cases {
		addr, port, ok := splitAddrPort(c.field)
		if addr != c.wantAddr || port != c.wantPort || ok != c.wantOK {
			t.Errorf("splitAddrPort(%q) = (%q, %d, %v), want (%q, %d, %v)", c.field, addr, port, ok, c.wantAddr, c.wantPort, c.wantOK)
		}
	}
}

func TestContainerForPort(t *testing.T) {
	containers := []Container{{Name: "psql", Ports: "127.0.0.1:5432->5432/tcp"}}
	if got := containerForPort(containers, 5432); got != "psql" {
		t.Errorf("containerForPort(5432) = %q, want psql", got)
	}
	if got := containerForPort(containers, 9999); got != "" {
		t.Errorf("containerForPort(9999) = %q, want empty", got)
	}
}

func TestParsePrerequisitesMissingBoth(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdBorgVersion] = sshx.Result{Stdout: "bash: line 1: borg: command not found"}
	cap.Results[cmdDockerVersion] = sshx.Result{Stdout: "bash: line 1: docker: command not found"}

	p := parsePrerequisites(cap)
	if p.BorgInstalled || p.DockerInstalled {
		t.Errorf("expected both prerequisites to be false, got %+v", p)
	}
}

func TestResolveEgressIPSafelyNilAndError(t *testing.T) {
	if got := resolveEgressIPSafely(context.Background(), nil); got != "" {
		t.Errorf("nil resolver should return empty, got %q", got)
	}
	failing := func(context.Context) (string, error) { return "", errors.New("boom") }
	if got := resolveEgressIPSafely(context.Background(), failing); got != "" {
		t.Errorf("failing resolver should return empty, got %q", got)
	}
	ok := func(context.Context) (string, error) { return "203.0.113.5", nil }
	if got := resolveEgressIPSafely(context.Background(), ok); got != "203.0.113.5" {
		t.Errorf("resolveEgressIPSafely = %q, want 203.0.113.5", got)
	}
}
