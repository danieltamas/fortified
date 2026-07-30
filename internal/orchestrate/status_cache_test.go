package orchestrate

import (
	"testing"

	"github.com/danieltamas/fortified/internal/backend/borg"
)

func TestStatusCacheRoundTrips(t *testing.T) {
	dir := t.TempDir()
	rep := StatusReport{
		ServerID:        "host-2-example",
		RepoInitialized: true,
		Archives:        []string{"2026-07-20T00-00-00Z"},
		Repo:            &borg.RepoStats{UniqueCompressedSize: 59_000_000_000},
	}

	if err := SaveStatusCache(dir, rep); err != nil {
		t.Fatalf("SaveStatusCache: %v", err)
	}

	got, ok, err := LoadStatusCache(dir, "host-2-example")
	if err != nil {
		t.Fatalf("LoadStatusCache: %v", err)
	}
	if !ok {
		t.Fatal("expected a cache hit")
	}
	if got.Repo == nil || got.Repo.UniqueCompressedSize != 59_000_000_000 {
		t.Errorf("got = %+v, want the saved report round-tripped", got)
	}
}

func TestStatusCacheMissIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	_, ok, err := LoadStatusCache(dir, "never-checked")
	if err != nil {
		t.Fatalf("LoadStatusCache: %v, want no error for a missing cache", err)
	}
	if ok {
		t.Error("ok = true, want false for a server with no cache yet")
	}
}

func TestStatusCacheDoesNotDisturbOtherServers(t *testing.T) {
	dir := t.TempDir()
	if err := SaveStatusCache(dir, StatusReport{ServerID: "a", RepoInitialized: true}); err != nil {
		t.Fatalf("SaveStatusCache(a): %v", err)
	}
	if err := SaveStatusCache(dir, StatusReport{ServerID: "b", RepoInitialized: false}); err != nil {
		t.Fatalf("SaveStatusCache(b): %v", err)
	}

	a, ok, err := LoadStatusCache(dir, "a")
	if err != nil || !ok || !a.RepoInitialized {
		t.Errorf("LoadStatusCache(a) = %+v, %v, %v, want RepoInitialized=true", a, ok, err)
	}
	b, ok, err := LoadStatusCache(dir, "b")
	if err != nil || !ok || b.RepoInitialized {
		t.Errorf("LoadStatusCache(b) = %+v, %v, %v, want RepoInitialized=false", b, ok, err)
	}
}
