package discover

import (
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

// TestClassifyNativeDatabasesDetectsPostgres proves an active native
// postgresql systemd service is classified as a DatabaseInstance with
// DumpStrategyNative — verified live against a real server (49GB of
// postgres data) that was entirely invisible to Docker-only discovery.
func TestClassifyNativeDatabasesDetectsPostgres(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativePostgresActive] = sshx.Result{Stdout: "active\n"}
	cap.Results[cmdNativePostgresAuthProbe] = sshx.Result{ExitCode: 0, Stdout: "1\n"}

	databases := classifyNativeDatabases(cap)
	if len(databases) != 1 {
		t.Fatalf("got %d databases, want 1: %+v", len(databases), databases)
	}
	db := databases[0]
	if db.Kind != "postgres" || db.DumpStrategy != DumpStrategyNative || !db.AuthResolved {
		t.Errorf("db = %+v, want kind=postgres dump_strategy=native auth_resolved=true", db)
	}
}

// TestClassifyNativeDatabasesPostgresAuthUnresolved proves AuthResolved
// follows the live peer-auth probe, not mere service presence —
// mirroring the Docker postgres path's own live-probe discipline.
func TestClassifyNativeDatabasesPostgresAuthUnresolved(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativePostgresActive] = sshx.Result{Stdout: "active\n"}
	cap.Results[cmdNativePostgresAuthProbe] = sshx.Result{ExitCode: 2, Stderr: "FATAL: Peer authentication failed"}

	databases := classifyNativeDatabases(cap)
	if len(databases) != 1 || databases[0].AuthResolved {
		t.Fatalf("databases = %+v, want one entry with auth_resolved=false", databases)
	}
}

// TestClassifyNativeDatabasesDedupsMySQLAndMariaDB proves mysql.service
// and mariadb.service being simultaneously "active" (verified live:
// Debian/Ubuntu's mariadb-server package provides both as aliases for
// one underlying server) never produces two DatabaseInstances.
func TestClassifyNativeDatabasesDedupsMySQLAndMariaDB(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativeMySQLActive] = sshx.Result{Stdout: "active\n"}
	cap.Results[cmdNativeMariaDBActive] = sshx.Result{Stdout: "active\n"}
	cap.Results[cmdNativeMySQLDebianCnf] = sshx.Result{Stdout: "yes\n"}

	databases := classifyNativeDatabases(cap)
	if len(databases) != 1 {
		t.Fatalf("got %d databases, want exactly 1 (never double-counted): %+v", len(databases), databases)
	}
	db := databases[0]
	if db.Kind != "mariadb" || db.DumpStrategy != DumpStrategyNative || !db.AuthResolved {
		t.Errorf("db = %+v, want kind=mariadb dump_strategy=native auth_resolved=true", db)
	}
}

// TestClassifyNativeDatabasesMySQLAuthUnresolvedWithoutDebianCnf proves
// a missing/unreadable debian.cnf (a non-Debian distro, or a hardened
// environment) reports auth_resolved=false rather than assuming the
// standard credential is there.
func TestClassifyNativeDatabasesMySQLAuthUnresolvedWithoutDebianCnf(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativeMySQLActive] = sshx.Result{Stdout: "active\n"}
	cap.Results[cmdNativeMySQLDebianCnf] = sshx.Result{Stdout: ""}

	databases := classifyNativeDatabases(cap)
	if len(databases) != 1 || databases[0].AuthResolved {
		t.Fatalf("databases = %+v, want one entry with auth_resolved=false", databases)
	}
}

// TestClassifyNativeDatabasesNoneWhenInactive proves a server with no
// native database services (the common case: everything's in Docker,
// or genuinely no database at all) produces zero native instances.
func TestClassifyNativeDatabasesNoneWhenInactive(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativePostgresActive] = sshx.Result{Stdout: "inactive\n", ExitCode: 3}
	cap.Results[cmdNativeMySQLActive] = sshx.Result{Stdout: "inactive\n", ExitCode: 3}
	cap.Results[cmdNativeMariaDBActive] = sshx.Result{Stdout: "inactive\n", ExitCode: 3}

	if databases := classifyNativeDatabases(cap); len(databases) != 0 {
		t.Errorf("databases = %+v, want none", databases)
	}
}

// TestClassifyNativeDatabasesDetectsFailedUnit is a regression guard
// for a real gap found by cross-vendor review: systemdUnitPresent used
// to compare Stdout against the literal string "active" only, so a
// crashed native postgres — systemctl is-active reports "failed", not
// "active", for a unit it definitely knows about — read identically to
// "never installed" and was silently dropped from discover's results,
// reintroducing the exact silent-data-loss class this whole feature
// was built to fix. "failed" (and "activating"/"deactivating"/
// "reloading") must still classify as a native database so the crash
// surfaces loudly at backup time instead.
func TestClassifyNativeDatabasesDetectsFailedUnit(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativePostgresActive] = sshx.Result{Stdout: "failed\n", ExitCode: 3}

	databases := classifyNativeDatabases(cap)
	if len(databases) != 1 || databases[0].Kind != "postgres" {
		t.Fatalf("databases = %+v, want one postgres entry even though the unit is currently failed, not active", databases)
	}
}

// TestClassifyNativeDatabasesNoneWhenSystemctlMissing proves a
// non-systemd distro (systemctl itself absent) degrades to "no native
// databases" rather than erroring the whole discover run.
func TestClassifyNativeDatabasesNoneWhenSystemctlMissing(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativePostgresActive] = sshx.Result{ExitCode: 127, Stderr: "systemctl: command not found"}

	if databases := classifyNativeDatabases(cap); len(databases) != 0 {
		t.Errorf("databases = %+v, want none", databases)
	}
}

// TestClassifyNativeDatabasesSetsPostgresImage proves a classified
// native postgres DatabaseInstance gets a real, usable Docker image —
// verify unconditionally needs one to spin up a throwaway
// restore-and-compare container, and a native install has no image of
// its own the way a Docker container does (a real gap found by
// cross-vendor review: without this, verify tried `docker run` with an
// empty image and could never pass for a native database).
func TestClassifyNativeDatabasesSetsPostgresImage(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdNativePostgresActive] = sshx.Result{Stdout: "active\n"}
	cap.Results[cmdNativePostgresAuthProbe] = sshx.Result{ExitCode: 0}
	cap.Results[cmdNativePostgresVersion] = sshx.Result{Stdout: "psql (PostgreSQL) 15.4 (Debian 15.4-1.pgdg120+1)\n"}

	databases := classifyNativeDatabases(cap)
	if len(databases) != 1 || databases[0].Image != "postgres:15-bookworm" {
		t.Fatalf("databases = %+v, want Image=postgres:15-bookworm", databases)
	}
}

// TestClassifyNativeDatabasesSetsMySQLImage proves the same for
// mysql/mariadb, and that the version string's own content (not the
// systemd unit name probed) decides which of the two images is used.
func TestClassifyNativeDatabasesSetsMySQLImage(t *testing.T) {
	cases := []struct {
		name          string
		versionStdout string
		want          string
	}{
		{"mariadb", "mysql  Ver 15.1 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)\n", "mariadb:10"},
		{"oracle mysql", "mysql  Ver 8.0.35 for Linux on x86_64 (MySQL Community Server - GPL)\n", "mysql:8"},
		{"unparseable falls back", "some unexpected format\n", "mariadb:11"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap := newCapture()
			cap.Results[cmdNativeMySQLActive] = sshx.Result{Stdout: "active\n"}
			cap.Results[cmdNativeMySQLVersion] = sshx.Result{Stdout: tc.versionStdout}

			databases := classifyNativeDatabases(cap)
			if len(databases) != 1 || databases[0].Image != tc.want {
				t.Fatalf("databases = %+v, want Image=%s", databases, tc.want)
			}
		})
	}
}

// TestNativeVerifyImageFallsBackWhenProbeMissingOrUnparseable proves a
// version probe that never ran (an older Capture, or Inspect skipped
// it) or produces an unrecognized format degrades to a sensible
// default rather than blocking classification — matching this
// package's established "best-effort, never blocks the real result"
// pattern (e.g. cockroachDatabaseSize's own doc comment).
func TestNativeVerifyImageFallsBackWhenProbeMissingOrUnparseable(t *testing.T) {
	if got := nativePostgresVerifyImage(newCapture()); got != "postgres:16-bookworm" {
		t.Errorf("nativePostgresVerifyImage with no probe = %q, want the fallback", got)
	}
	if got := nativeMySQLVerifyImage(newCapture()); got != "mariadb:11" {
		t.Errorf("nativeMySQLVerifyImage with no probe = %q, want the fallback", got)
	}

	cap := newCapture()
	cap.Results[cmdNativePostgresVersion] = sshx.Result{Stdout: "not a version string at all\n"}
	if got := nativePostgresVerifyImage(cap); got != "postgres:16-bookworm" {
		t.Errorf("nativePostgresVerifyImage with unparseable output = %q, want the fallback", got)
	}
}
