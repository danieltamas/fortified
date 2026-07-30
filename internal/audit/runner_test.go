package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func openTestWriter(t *testing.T) (*Writer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.audit.jsonl")
	w, err := OpenWriter(path)
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, path
}

func readEntries(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // path is t.TempDir()-derived test fixture, not untrusted input
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("parse audit line %q: %v", scanner.Text(), err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	return entries
}

func TestAuditRecordsEveryCall(t *testing.T) {
	w, path := openTestWriter(t)
	fake := &sshxtest.FakeRunner{}
	r := Runner{Next: fake, Writer: w, Command: "backup", InvocationID: "inv-1"}

	calls := []struct {
		class sshx.Class
		cmd   string
		args  []string
	}{
		{sshx.ReadOnly, "ssh", []string{"-p", "23", "u1@u1.your-storagebox.de", "--", "borg", "info"}},
		{sshx.Mutating, "ssh", []string{"-p", "23", "u1@u1.your-storagebox.de", "--", "borg", "create"}},
		{sshx.ReadOnly, "docker", []string{"inspect", "psql"}},
	}
	for _, c := range calls {
		if _, err := r.Run(context.Background(), c.class, c.cmd, c.args, sshx.RunOptions{}); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}

	entries := readEntries(t, path)
	if len(entries) != len(calls) {
		t.Fatalf("expected %d audit lines, got %d", len(calls), len(entries))
	}
	for i, e := range entries {
		wantArgv := append([]string{calls[i].cmd}, calls[i].args...)
		if strings.Join(e.Argv, " ") != strings.Join(wantArgv, " ") {
			t.Errorf("entry %d argv = %v, want %v", i, e.Argv, wantArgv)
		}
		if e.Class != calls[i].class.String() {
			t.Errorf("entry %d class = %q, want %q", i, e.Class, calls[i].class.String())
		}
		if e.InvocationID != "inv-1" {
			t.Errorf("entry %d invocation id = %q, want inv-1", i, e.InvocationID)
		}
		if e.Command != "backup" {
			t.Errorf("entry %d command = %q, want backup", i, e.Command)
		}
	}
}

func TestAuditNeverContainsSecrets(t *testing.T) {
	const sentinel = "sentinel-borg-passphrase-do-not-leak"

	w, path := openTestWriter(t)
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "ok"}},
		},
	}
	r := Runner{Next: fake, Writer: w, Command: "backup", InvocationID: "inv-2"}

	// The secret travels via the session environment, exactly as
	// SPEC.md §3 requires — never argv, never logged.
	_, err := r.Run(context.Background(), sshx.Mutating, "borg", []string{"create"}, sshx.RunOptions{
		Env: []string{"BORG_PASSPHRASE=" + sentinel},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	raw, rerr := os.ReadFile(path) //nolint:gosec // path is t.TempDir()-derived test fixture, not untrusted input
	if rerr != nil {
		t.Fatalf("read audit log: %v", rerr)
	}
	if strings.Contains(string(raw), sentinel) {
		t.Fatalf("audit log leaked the sentinel secret:\n%s", raw)
	}
}

func TestAuditAppendSurvivesCrash(t *testing.T) {
	w, path := openTestWriter(t)

	if err := w.Append(Entry{Command: "backup", InvocationID: "inv-3", Argv: []string{"borg", "check"}}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Append(Entry{Command: "backup", InvocationID: "inv-3", Argv: []string{"borg", "create"}}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Simulate a crash: close without any special finalization step —
	// Append already synced each line, so nothing further is needed
	// for prior lines to be durable and parseable.
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("expected 2 surviving entries, got %d", len(entries))
	}
	if strings.Join(entries[1].Argv, " ") != "borg create" {
		t.Errorf("second entry argv = %v, want [borg create]", entries[1].Argv)
	}
}
