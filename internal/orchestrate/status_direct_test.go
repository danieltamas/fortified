package orchestrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// TestStatusDirectHappyPath proves StatusDirect reports repo-level
// facts (archives, latest size, total size) using only d.Provider/
// d.Backend/d.Secrets — no state.Load, no d.Target call of any kind,
// since the entire point is answering "what's backed up" without the
// origin server being reachable at all.
func TestStatusDirectHappyPath(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n2026-07-23T22-13-58Z\n"}}, // borg list
		{Result: sshx.Result{Stdout: archiveInfoJSONForStatusTest}},                   // borg info --json <repo>::<latest>
		{Result: sshx.Result{Stdout: repoInfoJSONForStatusTest}},                      // borg info --json <repo>
	}}
	d := testDeps(t, target)

	rep, err := StatusDirect(context.Background(), d, "/Users/operator/my-copy-of-the-key")
	if err != nil {
		t.Fatalf("StatusDirect: %v", err)
	}

	if !rep.RepoInitialized {
		t.Error("RepoInitialized = false, want true")
	}
	if len(rep.Archives) != 2 || rep.Archives[1] != "2026-07-23T22-13-58Z" {
		t.Errorf("Archives = %v, want the latest sorted last", rep.Archives)
	}
	if rep.LatestArchive == nil || rep.LatestArchive.Name != "archive2" {
		t.Fatalf("LatestArchive = %+v, want archive named archive2", rep.LatestArchive)
	}
	if rep.Repo == nil || rep.Repo.UniqueCompressedSize != 9320606 {
		t.Fatalf("Repo = %+v, want UniqueCompressedSize 9320606", rep.Repo)
	}
	// Nothing target-specific is ever populated — there's no target to
	// ask.
	if len(rep.Databases) != 0 || len(rep.ArchivePathSizes) != 0 {
		t.Errorf("rep = %+v, want no database/archive-path sizes (those need the target)", rep)
	}

	listCall := target.Calls[0]
	if listCall.Cmd != "borg" || listCall.Args[0] != "list" {
		t.Fatalf("call[0] = %q %v, want borg list ...", listCall.Cmd, listCall.Args)
	}
	if !strings.Contains(strings.Join(listCall.Env, " "), "/Users/operator/my-copy-of-the-key") {
		t.Errorf("list call env = %v, want the supplied identity path used (via BORG_RSH), not automationKeyPath", listCall.Env)
	}
}

// TestStatusDirectPropagatesDestinationLookupFailure proves a server
// whose Storage Box subaccount can't be found (e.g. never onboarded,
// or deleted) surfaces that clearly rather than a confusing borg
// error further down.
func TestStatusDirectPropagatesDestinationLookupFailure(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	transport := newFakeTransport(t)
	transport.stub("GET", "/v1/storage_boxes/123", storageBoxGetJSON)
	transport.stub("GET", "/v1/storage_boxes/123/subaccounts", `{"subaccounts":[]}`)
	d := testDepsWithTransport(t, target, transport)

	_, err := StatusDirect(context.Background(), d, "/some/key")
	if err == nil {
		t.Fatal("expected an error when no subaccount exists")
	}
	if len(target.Calls) != 0 {
		t.Errorf("expected zero calls to the (unreachable) target, got %+v", target.Calls)
	}
}

// TestStatusDirectPropagatesBorgFailure proves a real borg-side
// failure (e.g. wrong key, repo gone) is surfaced, not swallowed.
func TestStatusDirectPropagatesBorgFailure(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errBoom},
	}}
	d := testDeps(t, target)

	_, err := StatusDirect(context.Background(), d, "/some/key")
	if err == nil || !errors.Is(err, errBoom) {
		t.Fatalf("StatusDirect error = %v, want it to wrap errBoom", err)
	}
}
