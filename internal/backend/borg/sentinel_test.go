package borg

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/audit"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// TestPassphraseNeverInArgvOrLogs proves the sentinel passphrase
// travels only via RunOptions.Env — never argv — by wrapping the
// FakeRunner in the real audit.Runner (which explicitly never records
// Env) and grepping the resulting audit log after a full InitRepo +
// CreateArchive flow.
func TestPassphraseNeverInArgvOrLogs(t *testing.T) {
	const sentinel = "sentinel-borg-passphrase-do-not-leak"

	path := filepath.Join(t.TempDir(), "host.audit.jsonl")
	writer, err := audit.OpenWriter(path)
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // InitRepo
			{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
			{}, // mkdir
			{}, // dump
			{Result: sshx.Result{Stdout: "deadbeef  psql.sql\n"}}, // sha256sum
			{Result: sshx.Result{Stdout: ""}},                     // list tables (none)
			{},                                                    // writeManifest
			{},                                                    // borg create
			{},                                                    // cleanup
		},
	}
	auditedRunner := audit.Runner{Next: fake, Writer: writer, Command: "backup", InvocationID: "inv-sentinel"}
	b := Backend{Runner: auditedRunner}

	if err := b.InitRepo(context.Background(), "/repo/x", sentinel, "/identity-key"); err != nil {
		t.Fatalf("InitRepo: %v", err)
	}
	if _, _, err := b.CreateArchive(context.Background(), "/repo/x", sentinel, "/identity-key", "/work/x", "2026-07-18", onePostgresDB(), nil, nil, 1000, nil, nil); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	raw, err := os.ReadFile(path) //nolint:gosec // t.TempDir()-derived test fixture, not untrusted input
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if strings.Contains(string(raw), sentinel) {
		t.Fatalf("audit log leaked the sentinel passphrase:\n%s", raw)
	}

	for _, c := range fake.Calls {
		if strings.Contains(strings.Join(c.Args, " "), sentinel) {
			t.Fatalf("recorded call argv leaked the sentinel passphrase: %+v", c)
		}
	}
}
