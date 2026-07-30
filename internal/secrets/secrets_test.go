package secrets

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestSecretsEnvResolution(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_SECRET", "hunter2")
	r := Resolver{Runner: &sshxtest.FakeRunner{}}

	got, err := r.Resolve(context.Background(), "env://FORTIFIED_TEST_SECRET")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Resolve = %q, want hunter2", got)
	}
}

func TestSecretsEnvResolutionMissing(t *testing.T) {
	if err := os.Unsetenv("FORTIFIED_TEST_SECRET_MISSING"); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
	r := Resolver{Runner: &sshxtest.FakeRunner{}}

	if _, err := r.Resolve(context.Background(), "env://FORTIFIED_TEST_SECRET_MISSING"); err == nil {
		t.Fatal("expected an error resolving an unset env var, got nil")
	}
}

func TestSecretsInfisicalArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{{Result: sshx.Result{Stdout: "s3cr3t\n"}}},
	}
	r := Resolver{Runner: fake}

	got, err := r.Resolve(context.Background(), "secret://fortified/host-2-example/borg-passphrase")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("Resolve = %q, want s3cr3t (trailing newline trimmed)", got)
	}

	if len(fake.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(fake.Calls))
	}
	call := fake.Calls[0]
	if call.Class != sshx.ReadOnly {
		t.Errorf("class = %v, want ReadOnly", call.Class)
	}
	if call.Cmd != "infisical" {
		t.Errorf("cmd = %q, want infisical", call.Cmd)
	}
	wantArgs := []string{"secrets", "get", "borg-passphrase", "--plain", "--path", "/fortified/host-2-example"}
	if strings.Join(call.Args, "|") != strings.Join(wantArgs, "|") {
		t.Errorf("args = %v, want %v", call.Args, wantArgs)
	}
}

func TestSecretsInvalidRef(t *testing.T) {
	r := Resolver{Runner: &sshxtest.FakeRunner{}}
	if _, err := r.Resolve(context.Background(), "plaintext-not-a-ref"); err == nil {
		t.Fatal("expected an error for a non-ref value, got nil")
	}
}

func TestSecretsNeverLogged(t *testing.T) {
	const sentinel = "sentinel-mariadb-root-password"

	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: sentinel + "\n"}},
		},
	}
	r := Resolver{Runner: fake}

	got, err := r.Resolve(context.Background(), "secret://fortified/host-2-example/mariadb-root")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != sentinel {
		t.Fatalf("Resolve = %q, want %q", got, sentinel)
	}

	// A later, unrelated failure must not have picked up the sentinel
	// from anywhere — its error text must not contain it.
	_, err2 := r.Resolve(context.Background(), "env://FORTIFIED_TEST_SECRET_MISSING_2")
	if err2 == nil {
		t.Fatal("expected an error for an unset env var")
	}
	if strings.Contains(err2.Error(), sentinel) {
		t.Fatalf("unrelated error leaked the sentinel secret: %v", err2)
	}

	// The recorded Runner calls (what would be audit-logged) must not
	// contain the secret value either — only argv, never output.
	for _, c := range fake.Calls {
		if strings.Contains(strings.Join(c.Args, " "), sentinel) {
			t.Fatalf("recorded call argv leaked the sentinel secret: %+v", c)
		}
	}
}
