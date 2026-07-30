//go:build integration

package borg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
)

// TestBorgLifecycleLocal: init → create from a fixture tree → list →
// extract → borg check, against a local t.TempDir() repo. No
// databases involved — this proves the borg plumbing itself, isolated
// from docker.
func TestBorgLifecycleLocal(t *testing.T) {
	requireIntegrationTools(t)
	ctx := context.Background()
	b := Backend{Runner: sshx.ExecRunner{}}
	const passphrase = "test-passphrase-lifecycle"

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := b.InitRepo(ctx, repoDir, passphrase, ""); err != nil {
		t.Fatalf("InitRepo: %v", err)
	}

	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, "hello.txt"), []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	workspaceDir := filepath.Join(t.TempDir(), "workspace")
	archiveID, manifest, err := b.CreateArchive(ctx, repoDir, passphrase, "", workspaceDir, "test-archive",
		nil, nil, []string{fixtureDir}, 1000, nil, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if len(manifest.Databases) != 0 {
		t.Errorf("expected an empty manifest with no databases, got %+v", manifest)
	}

	archives, err := b.ListArchives(ctx, repoDir, passphrase, "")
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 1 || archives[0] != string(archiveID) {
		t.Fatalf("archives = %v, want [%s]", archives, archiveID)
	}

	extractDir := t.TempDir()
	if err := b.RestoreArchive(ctx, repoDir, archiveID, passphrase, "", extractDir); err != nil {
		t.Fatalf("RestoreArchive: %v", err)
	}
	restoredFile := filepath.Join(extractDir, fixtureDir, "hello.txt")
	data, err := os.ReadFile(restoredFile) //nolint:gosec // restoredFile is built from t.TempDir(), not untrusted input
	if err != nil {
		t.Fatalf("read restored file %s: %v", restoredFile, err)
	}
	if string(data) != "hello world" {
		t.Errorf("restored content = %q, want %q", data, "hello world")
	}

	if err := b.Check(ctx, repoDir, passphrase, ""); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// TestAppendOnlyLocalBehavior documents borg 1.2.4's real append-only
// semantics, verified live rather than assumed (an earlier draft of
// this test asserted PLAN.md's literal wording — "deletes don't
// reduce visible archives" — and it's false for plain `borg list`):
// a delete issued while append_only is set DOES remove the archive
// from `borg list` (the manifest is genuinely updated) and returns
// exit 0. What append-only actually buys you, per Hetzner's own docs
// and Borg's docs (NOTES.md), is that the underlying segment data
// isn't erased — recoverable by an operator with repo-level access,
// not something a restricted client can be sure of by listing. The
// one thing this test can assert cleanly and honestly: the repo is
// never left corrupted by a delete attempted under append_only —
// `borg check` (read-only, no confirmation prompt) still passes
// afterward, proving the operation was a clean transaction, not a
// destructive break. Full segment-level non-erasure is Borg/Hetzner's
// documented behavior, not independently re-verified here — doing so
// deterministically would mean asserting on internal segment file
// layout, which is out of scope for this test's purpose.
func TestAppendOnlyLocalBehavior(t *testing.T) {
	requireIntegrationTools(t)
	ctx := context.Background()
	b := Backend{Runner: sshx.ExecRunner{}}
	const passphrase = "test-passphrase-append-only"

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := b.InitRepo(ctx, repoDir, passphrase, ""); err != nil {
		t.Fatalf("InitRepo: %v", err)
	}

	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	workspaceDir := filepath.Join(t.TempDir(), "workspace")
	archiveID, _, err := b.CreateArchive(ctx, repoDir, passphrase, "", workspaceDir, "keep-me", nil, nil, []string{fixtureDir}, 1000, nil, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	if _, err := b.Runner.Run(ctx, sshx.Mutating, "borg", []string{"config", repoDir, "append_only", "1"},
		sshx.RunOptions{Env: []string{"BORG_PASSPHRASE=" + passphrase}}); err != nil {
		t.Fatalf("borg config append_only: %v", err)
	}

	if _, err := b.Runner.Run(ctx, sshx.Mutating, "borg", []string{"delete", repoDir + "::" + string(archiveID)},
		sshx.RunOptions{Env: []string{"BORG_PASSPHRASE=" + passphrase}}); err != nil {
		t.Fatalf("delete under append_only: %v", err)
	}

	if err := b.Check(ctx, repoDir, passphrase, ""); err != nil {
		t.Fatalf("borg check after a delete under append_only: repo left inconsistent: %v", err)
	}
}

// TestPostgresDumpRestoreRoundTrip: seed a real postgres container
// with known rows in the default database AND in a second, real app
// database (proving postgresRowCounts covers every database
// pg_dumpall dumps, not just the connection's own default one — a
// gap a cross-vendor review caught precisely because an earlier
// version of this fixture only ever used the default database), dump
// it via the docker-exec recipe, confirm the manifest's row counts
// match both seeds, restore the dump into a *fresh* container, and
// confirm its row counts match the manifest.
func TestPostgresDumpRestoreRoundTrip(t *testing.T) {
	requireIntegrationTools(t)
	ctx := context.Background()
	runner := sshx.ExecRunner{}
	b := Backend{Runner: runner}
	const seedRows = 5
	const appDBName = "appdb"
	const appDBRows = 8

	source := testContainerName(t) + "-pg-source"
	startContainer(t, runner, "postgres:16-alpine", source,
		[]string{"POSTGRES_PASSWORD=test", "POSTGRES_HOST_AUTH_METHOD=trust"},
		[]string{"exec", "-u", "postgres", source, "psql", "-c", "SELECT 1"})
	seedPostgres(t, runner, source, seedRows)
	seedPostgresDatabase(t, runner, source, appDBName, appDBRows)

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := b.InitRepo(ctx, repoDir, "pw", ""); err != nil {
		t.Fatalf("InitRepo: %v", err)
	}
	workspaceDir := filepath.Join(t.TempDir(), "workspace")
	archiveID, manifest, err := b.CreateArchive(ctx, repoDir, "pw", "", workspaceDir, "pg-roundtrip",
		[]discover.DatabaseInstance{postgresRecipe(source)}, nil, nil, 0, nil, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if len(manifest.Databases) != 1 || manifest.Databases[0].RowCounts["postgres.public.widgets"] != seedRows {
		t.Fatalf("manifest = %+v, want RowCounts[postgres.public.widgets]=%d", manifest, seedRows)
	}
	if manifest.Databases[0].RowCounts[appDBName+".public.widgets"] != appDBRows {
		t.Fatalf("manifest = %+v, want RowCounts[%s.public.widgets]=%d — the non-default app database's rows are missing from verification",
			manifest, appDBName+".public.widgets", appDBRows)
	}

	extractDir := t.TempDir()
	if err := b.RestoreArchive(ctx, repoDir, archiveID, "pw", "", extractDir); err != nil {
		t.Fatalf("RestoreArchive: %v", err)
	}
	dumpFile := filepath.Join(extractDir, workspaceDir, source+".sql")
	dumpData, err := os.ReadFile(dumpFile) //nolint:gosec // dumpFile is built from t.TempDir() paths, not untrusted input
	if err != nil {
		t.Fatalf("read restored dump %s: %v", dumpFile, err)
	}

	fresh := testContainerName(t) + "-pg-fresh"
	startContainer(t, runner, "postgres:16-alpine", fresh,
		[]string{"POSTGRES_PASSWORD=test", "POSTGRES_HOST_AUTH_METHOD=trust"},
		[]string{"exec", "-u", "postgres", fresh, "psql", "-c", "SELECT 1"})
	if _, err := runner.Run(ctx, sshx.Mutating, "docker", []string{"exec", "-i", "-u", "postgres", fresh, "psql"},
		sshx.RunOptions{Stdin: string(dumpData), Timeout: 60 * time.Second}); err != nil {
		t.Fatalf("load dump into fresh container: %v", err)
	}

	freshCounts, err := b.postgresRowCounts(ctx, fresh, "", "")
	if err != nil {
		t.Fatalf("count rows in fresh container: %v", err)
	}
	for _, key := range []string{"postgres.public.widgets", appDBName + ".public.widgets"} {
		if freshCounts[key] != manifest.Databases[0].RowCounts[key] {
			t.Errorf("fresh container %s = %d, want %d (the manifest's baseline)",
				key, freshCounts[key], manifest.Databases[0].RowCounts[key])
		}
	}
}

// TestMariaDBDumpRestoreRoundTrip: the same proof as
// TestPostgresDumpRestoreRoundTrip, for mariadb.
func TestMariaDBDumpRestoreRoundTrip(t *testing.T) {
	requireIntegrationTools(t)
	ctx := context.Background()
	runner := sshx.ExecRunner{}
	b := Backend{Runner: runner}
	const seedRows = 5
	const rootPassword = "test-root-password"

	source := testContainerName(t) + "-maria-source"
	startContainer(t, runner, "mariadb:10.4", source,
		[]string{"MYSQL_ROOT_PASSWORD=" + rootPassword},
		[]string{"exec", "-e", "MYSQL_PWD=" + rootPassword, source, "mysql", "-u", "root", "-e", "SELECT 1"})
	seedMariaDB(t, runner, source, rootPassword, seedRows)

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := b.InitRepo(ctx, repoDir, "pw", ""); err != nil {
		t.Fatalf("InitRepo: %v", err)
	}
	workspaceDir := filepath.Join(t.TempDir(), "workspace")
	archiveID, manifest, err := b.CreateArchive(ctx, repoDir, "pw", "", workspaceDir, "maria-roundtrip",
		[]discover.DatabaseInstance{mariaDBRecipe(source)}, nil, nil, 0, nil, nil)
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if len(manifest.Databases) != 1 || manifest.Databases[0].RowCounts["appdb.widgets"] != seedRows {
		t.Fatalf("manifest = %+v, want RowCounts[appdb.widgets]=%d", manifest, seedRows)
	}

	extractDir := t.TempDir()
	if err := b.RestoreArchive(ctx, repoDir, archiveID, "pw", "", extractDir); err != nil {
		t.Fatalf("RestoreArchive: %v", err)
	}
	dumpFile := filepath.Join(extractDir, workspaceDir, source+".sql")
	dumpData, err := os.ReadFile(dumpFile) //nolint:gosec // dumpFile is built from t.TempDir() paths, not untrusted input
	if err != nil {
		t.Fatalf("read restored dump %s: %v", dumpFile, err)
	}

	fresh := testContainerName(t) + "-maria-fresh"
	startContainer(t, runner, "mariadb:10.4", fresh,
		[]string{"MYSQL_ROOT_PASSWORD=" + rootPassword},
		[]string{"exec", "-e", "MYSQL_PWD=" + rootPassword, fresh, "mysql", "-u", "root", "-e", "SELECT 1"})
	if _, err := runner.Run(ctx, sshx.Mutating, "docker", []string{"exec", "-i", "-e", "MYSQL_PWD=" + rootPassword, fresh, "mysql", "-u", "root"},
		sshx.RunOptions{Stdin: string(dumpData), Timeout: 60 * time.Second}); err != nil {
		t.Fatalf("load dump into fresh container: %v", err)
	}

	freshCounts, err := b.mariaDBRowCounts(ctx, fresh, rootPassword)
	if err != nil {
		t.Fatalf("count rows in fresh container: %v", err)
	}
	if freshCounts["appdb.widgets"] != manifest.Databases[0].RowCounts["appdb.widgets"] {
		t.Errorf("fresh container row count = %d, want %d (the manifest's baseline)",
			freshCounts["appdb.widgets"], manifest.Databases[0].RowCounts["appdb.widgets"])
	}
}
