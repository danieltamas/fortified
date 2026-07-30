package discover

import (
	"regexp"
	"strings"
)

// classifyNativeDatabases detects postgres/mysql/mariadb installed as
// a regular OS package (a systemd service), not inside Docker —
// verified live against two real production servers running
// 49GB/8.3GB of postgres/mysql data entirely invisible to fortified's
// Docker-only discovery (one of them didn't even have docker
// installed), with zero backup coverage despite the servers otherwise
// being fully onboarded and "backed up". mysql and mariadb are probed
// as two candidate systemd unit names for the same engine — verified
// live that Debian/Ubuntu's mariadb-server package provides both
// mysql.service and mariadb.service as aliases for one underlying
// server — and are never double-counted into two instances.
func classifyNativeDatabases(cap *Capture) []DatabaseInstance {
	var databases []DatabaseInstance

	if systemdUnitPresent(cap, cmdNativePostgresActive) {
		authResolved := false
		if r, ok := cap.get(cmdNativePostgresAuthProbe); ok {
			authResolved = r.ExitCode == 0
		}
		databases = append(databases, DatabaseInstance{
			Kind:         "postgres",
			Container:    "postgresql",
			Image:        nativePostgresVerifyImage(cap),
			DumpStrategy: DumpStrategyNative,
			AuthResolved: authResolved,
		})
	}

	if systemdUnitPresent(cap, cmdNativeMySQLActive) || systemdUnitPresent(cap, cmdNativeMariaDBActive) {
		authResolved := false
		if r, ok := cap.get(cmdNativeMySQLDebianCnf); ok {
			authResolved = strings.TrimSpace(r.Stdout) == "yes"
		}
		databases = append(databases, DatabaseInstance{
			Kind:         "mariadb",
			Container:    "mysql",
			Image:        nativeMySQLVerifyImage(cap),
			DumpStrategy: DumpStrategyNative,
			AuthResolved: authResolved,
		})
	}

	return databases
}

var (
	nativePostgresVersionRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)`)
	nativeMariaDBVersionRe  = regexp.MustCompile(`Distrib\s+(\d+)\.`)
	nativeMySQLVersionRe    = regexp.MustCompile(`Ver\s+(\d+)\.`)
)

// nativePostgresVerifyImage picks the Docker image `verify` should use
// for a native postgres's throwaway restore-and-compare container —
// verify's own dump/reload roundtrip doesn't need an exact version
// match (pg_dumpall output is designed to be forward-compatible SQL),
// so the probed major version is enough. A probe that's absent or
// fails to parse (an unusual `psql --version` format, or no native
// postgres at all) falls back to a recent, well-known default rather
// than blocking verification of an otherwise perfectly-good backup
// over a version-string quirk.
func nativePostgresVerifyImage(cap *Capture) string {
	const fallback = "postgres:16-bookworm"
	r, ok := cap.get(cmdNativePostgresVersion)
	if !ok || commandMissing(r) {
		return fallback
	}
	m := nativePostgresVersionRe.FindStringSubmatch(r.Stdout)
	if m == nil {
		return fallback
	}
	return "postgres:" + m[1] + "-bookworm"
}

// nativeMySQLVerifyImage mirrors nativePostgresVerifyImage for
// mysql/mariadb — mysql --version's own output text reveals which of
// the two it actually is ("MariaDB" appears literally in MariaDB's
// version string, never in Oracle MySQL's), so the throwaway
// container uses the same real engine, not just any SQL-compatible
// stand-in.
func nativeMySQLVerifyImage(cap *Capture) string {
	const fallback = "mariadb:11"
	r, ok := cap.get(cmdNativeMySQLVersion)
	if !ok || commandMissing(r) {
		return fallback
	}
	if strings.Contains(r.Stdout, "MariaDB") {
		if m := nativeMariaDBVersionRe.FindStringSubmatch(r.Stdout); m != nil {
			return "mariadb:" + m[1]
		}
		return fallback
	}
	if m := nativeMySQLVersionRe.FindStringSubmatch(r.Stdout); m != nil {
		return "mysql:" + m[1]
	}
	return fallback
}

// systemdUnitPresent reports whether `systemctl is-active <unit>`
// proves the unit exists at all — "active" is the common case, but
// "failed"/"activating"/"deactivating"/"reloading" are just as much
// proof the unit is installed (systemctl can only report those for a
// unit it actually knows about) and must still be classified as a
// native database, not silently dropped: a crashed native postgres
// reading identically to "never installed" would reintroduce the
// exact silent-data-loss class this whole feature was built to fix
// (see this file's own doc comment on the two production servers with
// data invisible to Docker-only discovery) — the crash then surfaces
// loudly at backup/dump time instead, a real actionable error rather
// than a discover-time silence. Only "inactive" is treated as absent:
// is-active alone can't distinguish "never installed" from
// "installed, deliberately stopped", so this keeps the existing,
// documented simplification for that one genuinely ambiguous case. A
// missing systemctl binary (a non-systemd distro) reads as absent too,
// same treatment as every other optional tool this package probes for.
func systemdUnitPresent(cap *Capture, key commandKey) bool {
	r, ok := cap.get(key)
	if !ok || commandMissing(r) {
		return false
	}
	state := strings.TrimSpace(r.Stdout)
	return state != "" && state != "inactive"
}
