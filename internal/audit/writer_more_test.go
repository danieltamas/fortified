package audit

import (
	"path/filepath"
	"testing"
)

func TestNewInvocationIDIsUniqueAndNonEmpty(t *testing.T) {
	a, err := NewInvocationID()
	if err != nil {
		t.Fatalf("NewInvocationID: %v", err)
	}
	b, err := NewInvocationID()
	if err != nil {
		t.Fatalf("NewInvocationID: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("NewInvocationID returned an empty id")
	}
	if a == b {
		t.Errorf("two calls returned the same id: %q", a)
	}
}

func TestOpenWriterFailsInMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "server.audit.jsonl")
	if _, err := OpenWriter(path); err == nil {
		t.Fatal("expected an error opening a writer in a nonexistent directory")
	}
}

func TestAppendFailsAfterClose(t *testing.T) {
	w, _ := openTestWriter(t)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Append(Entry{Command: "backup"}); err == nil {
		t.Fatal("expected Append to fail after Close")
	}
}

func TestDigestNonEmptyIsStableAndShort(t *testing.T) {
	d1 := digest("some stderr output")
	d2 := digest("some stderr output")
	if d1 != d2 {
		t.Errorf("digest is not stable: %q vs %q", d1, d2)
	}
	if len(d1) != 16 {
		t.Errorf("digest length = %d, want 16", len(d1))
	}
	if digest("different output") == d1 {
		t.Error("different inputs produced the same digest")
	}
}
