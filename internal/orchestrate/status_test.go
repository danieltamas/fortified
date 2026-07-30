package orchestrate

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

// repoPathForStatusTest is the exact ssh:// target testDeps' fixture
// destination (existingSubaccountJSON, onboard_test.go) resolves to
// via RemoteRepoTarget.
const repoPathForStatusTest = "ssh://u123456-sub9@u123456.your-storagebox.de:23/home/repo"

// TestStatusNotOnboardedIsNotAnError proves an unonboarded server's
// status is a soft "nothing to show yet" (RepoInitialized: false,
// zero everything else), not an error — unlike Backup/Verify, which
// must refuse outright, Status is purely inspective.
func TestStatusNotOnboardedIsNotAnError(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	rep, err := Status(context.Background(), d)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rep.RepoInitialized {
		t.Errorf("RepoInitialized = true, want false for an unonboarded server")
	}
	if rep.LastBackup != nil || len(rep.Archives) != 0 {
		t.Errorf("Status = %+v, want a zero report for an unonboarded server", rep)
	}
	for _, c := range target.Calls {
		if c.Class == sshx.Mutating {
			t.Errorf("expected no mutating calls for an unonboarded server, got %+v", c)
		}
	}
}

func TestStatusHappyPath(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Result: sshx.Result{Stdout: "app|1048576\n"}},                                // docker exec psql psql -tAc: database sizes
			{Result: sshx.Result{Stdout: "2026-07-20T00-00-00Z\n2026-07-23T22-13-58Z\n"}}, // borg list
			{Result: sshx.Result{Stdout: archiveInfoJSONForStatusTest}},                   // borg info --json <repo>::<latest>
			{Result: sshx.Result{Stdout: repoInfoJSONForStatusTest}},                      // borg info --json <repo>
		},
	}
	d := testDeps(t, target)
	manifest := &state.Manifest{Databases: []state.DatabaseManifest{{Container: "psql"}, {Container: "mysql"}}}
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", AuthResolved: true}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, manifest, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	rep, err := Status(context.Background(), d)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	if !rep.RepoInitialized {
		t.Error("RepoInitialized = false, want true")
	}
	if len(rep.Archives) != 2 || rep.Archives[1] != "2026-07-23T22-13-58Z" {
		t.Errorf("Archives = %v, want the latest (sorted last) to be 2026-07-23T22-13-58Z", rep.Archives)
	}
	if len(rep.Databases) != 1 || rep.Databases[0].Container != "psql" || rep.Databases[0].Databases["app"] != 1048576 {
		t.Errorf("Databases = %+v, want one psql entry with app=1048576", rep.Databases)
	}
	if rep.LatestArchive == nil || rep.LatestArchive.Name != "archive2" {
		t.Fatalf("LatestArchive = %+v, want the archive named archive2", rep.LatestArchive)
	}
	if rep.Repo == nil || rep.Repo.UniqueCompressedSize != 9320606 {
		t.Fatalf("Repo = %+v, want UniqueCompressedSize 9320606", rep.Repo)
	}

	// The archive info call must be for the *latest* archive (sorted
	// last: "2026-07-23T22-13-58Z"), never the first one ListArchives
	// happened to return ("2026-07-20T00-00-00Z"). Call 0 is the
	// database size query, so the archive info call is now index 2.
	infoCall := target.Calls[2]
	wantArg := "info|--json|" + repoPathForStatusTest + "::2026-07-23T22-13-58Z"
	gotArg := strings.Join(infoCall.Args, "|")
	if gotArg != wantArg {
		t.Errorf("archive info call args = %q, want %q", gotArg, wantArg)
	}

	// Status must cache its own result — status --all reads this
	// straight off disk instead of contacting every server live.
	cached, ok, err := LoadStatusCache(d.StateDir, d.ServerID)
	if err != nil {
		t.Fatalf("LoadStatusCache: %v", err)
	}
	if !ok {
		t.Fatal("expected Status to have cached its report")
	}
	if cached.Repo == nil || cached.Repo.UniqueCompressedSize != rep.Repo.UniqueCompressedSize {
		t.Errorf("cached = %+v, want it to match the just-returned report", cached)
	}
}

// TestStatusDatabaseSizeFailureDegradesGracefully proves a database
// whose size query fails is silently skipped, not a status-wide
// failure — status is an inspection tool, not a correctness-critical
// operation like backup/verify.
func TestStatusDatabaseSizeFailureDegradesGracefully(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{Err: errBoom},                    // docker exec psql psql -tAc: fails
			{Result: sshx.Result{Stdout: ""}}, // borg list: empty
			{Result: sshx.Result{Stdout: repoInfoJSONForStatusTest}}, // borg info --json <repo> (repo total, always runs)
		},
	}
	d := testDeps(t, target)
	databases := []discover.DatabaseInstance{{Kind: "postgres", Container: "psql", AuthResolved: true}}
	if err := state.Save(d.StateDir, onboardedStateWithManifest(d.ServerID, nil, databases)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	rep, err := Status(context.Background(), d)
	if err != nil {
		t.Fatalf("Status: %v, want it to degrade gracefully instead of failing", err)
	}
	if len(rep.Databases) != 0 {
		t.Errorf("Databases = %+v, want the failing database silently skipped", rep.Databases)
	}
}

const archiveInfoJSONForStatusTest = `{"archives":[{"name":"archive2","start":"2026-07-23T22:13:58.000000","end":"2026-07-23T22:13:58.000000","stats":{"compressed_size":7000215,"deduplicated_size":4319530,"nfiles":1,"original_size":7000000}}],"cache":{"stats":{"total_chunks":13,"total_csize":12000387,"total_size":12000000,"total_unique_chunks":10,"unique_csize":9320606,"unique_size":9320394}}}`

const repoInfoJSONForStatusTest = `{"archives":[],"cache":{"stats":{"total_chunks":13,"total_csize":12000387,"total_size":12000000,"total_unique_chunks":10,"unique_csize":9320606,"unique_size":9320394}}}`
