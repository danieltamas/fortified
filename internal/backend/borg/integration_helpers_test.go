//go:build integration

package borg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
)

// requireIntegrationTools skips with a loud message if borg or docker
// aren't on PATH — the phase gate requires these tests to actually
// run (TESTING.md), not just compile, but CI environments without
// them shouldn't hard-fail.
func requireIntegrationTools(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("borg"); err != nil {
		t.Skip("borg not found on PATH — install it to run this integration test (see TESTING.md)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found on PATH — install it to run this integration test (see TESTING.md)")
	}
}

// startContainer runs a detached container and registers its removal
// via t.Cleanup, waiting until it reports healthy readiness via
// readyCmd (retried — the engine images take a moment to accept
// connections after the process starts).
func startContainer(t *testing.T, runner sshx.Runner, image, name string, env []string, readyArgs []string) {
	t.Helper()
	ctx := context.Background()

	args := []string{"run", "-d", "--name", name}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, image)
	if _, err := runner.Run(ctx, sshx.Mutating, "docker", args, sshx.RunOptions{Timeout: 60 * time.Second}); err != nil {
		t.Fatalf("start container %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(context.Background(), sshx.Mutating, "docker", []string{"rm", "-f", name}, sshx.RunOptions{Timeout: 30 * time.Second})
	})

	// Postgres and MariaDB's official images both run a temporary,
	// internal server during first-time initialization before
	// restarting as the real one — a single successful readyArgs call
	// can hit that transient instance and then the socket disappears
	// during the restart. Debounce: require 3 consecutive successes,
	// not just one, before trusting it.
	deadline := time.Now().Add(30 * time.Second)
	consecutiveSuccesses := 0
	for {
		if _, err := runner.Run(ctx, sshx.ReadOnly, "docker", readyArgs, sshx.RunOptions{}); err == nil {
			consecutiveSuccesses++
			if consecutiveSuccesses >= 3 {
				return
			}
		} else {
			consecutiveSuccesses = 0
		}
		if time.Now().After(deadline) {
			t.Fatalf("container %s never became stably ready (readyArgs=%v)", name, readyArgs)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func testContainerName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("fortified-it-%d-%d", os.Getpid(), time.Now().UnixNano())
}

func seedPostgres(t *testing.T, runner sshx.Runner, container string, rows int) {
	t.Helper()
	script := fmt.Sprintf(
		`docker exec -u postgres %s psql -c "CREATE TABLE widgets (id serial primary key, name text)"`, container)
	if _, err := runner.Run(context.Background(), sshx.Mutating, "sh", []string{"-c", script}, sshx.RunOptions{}); err != nil {
		t.Fatalf("create table: %v", err)
	}
	insert := fmt.Sprintf(
		`docker exec -u postgres %s psql -c "INSERT INTO widgets (name) SELECT 'widget-' || g FROM generate_series(1,%d) g"`,
		container, rows)
	if _, err := runner.Run(context.Background(), sshx.Mutating, "sh", []string{"-c", insert}, sshx.RunOptions{}); err != nil {
		t.Fatalf("seed rows: %v", err)
	}
}

// seedPostgresDatabase creates a second database (dbName, distinct
// from the container's default "postgres" database seedPostgres uses)
// with its own widgets table — proof that postgresRowCounts covers
// every database pg_dumpall dumps, not just the default connection's
// own database (the exact gap a cross-vendor review caught: the
// original fixture only ever created its table in the default
// database, which is why the gap went undetected).
func seedPostgresDatabase(t *testing.T, runner sshx.Runner, container, dbName string, rows int) {
	t.Helper()
	createDB := fmt.Sprintf(`docker exec -u postgres %s psql -c "CREATE DATABASE %s"`, container, dbName)
	if _, err := runner.Run(context.Background(), sshx.Mutating, "sh", []string{"-c", createDB}, sshx.RunOptions{}); err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}
	createTable := fmt.Sprintf(
		`docker exec -u postgres %s psql -d %s -c "CREATE TABLE widgets (id serial primary key, name text)"`, container, dbName)
	if _, err := runner.Run(context.Background(), sshx.Mutating, "sh", []string{"-c", createTable}, sshx.RunOptions{}); err != nil {
		t.Fatalf("create table in %s: %v", dbName, err)
	}
	insert := fmt.Sprintf(
		`docker exec -u postgres %s psql -d %s -c "INSERT INTO widgets (name) SELECT 'widget-' || g FROM generate_series(1,%d) g"`,
		container, dbName, rows)
	if _, err := runner.Run(context.Background(), sshx.Mutating, "sh", []string{"-c", insert}, sshx.RunOptions{}); err != nil {
		t.Fatalf("seed rows in %s: %v", dbName, err)
	}
}

func seedMariaDB(t *testing.T, runner sshx.Runner, container, password string, rows int) {
	t.Helper()
	create := fmt.Sprintf(
		`docker exec -e MYSQL_PWD="$MYSQL_PWD" %s mysql -u root -e "CREATE DATABASE IF NOT EXISTS appdb; CREATE TABLE appdb.widgets (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64))"`,
		container)
	if _, err := runner.Run(context.Background(), sshx.Mutating, "sh", []string{"-c", create}, sshx.RunOptions{Env: []string{"MYSQL_PWD=" + password}}); err != nil {
		t.Fatalf("create table: %v", err)
	}
	for i := 0; i < rows; i++ {
		insert := fmt.Sprintf(
			`docker exec -e MYSQL_PWD="$MYSQL_PWD" %s mysql -u root -e "INSERT INTO appdb.widgets (name) VALUES ('widget-%d')"`,
			container, i)
		if _, err := runner.Run(context.Background(), sshx.Mutating, "sh", []string{"-c", insert}, sshx.RunOptions{Env: []string{"MYSQL_PWD=" + password}}); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
}

func postgresRecipe(container string) discover.DatabaseInstance {
	return discover.DatabaseInstance{Kind: "postgres", Container: container, DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}
}

func mariaDBRecipe(container string) discover.DatabaseInstance {
	return discover.DatabaseInstance{Kind: "mariadb", Container: container, DumpStrategy: discover.DumpStrategyDockerExec, AuthResolved: true}
}
