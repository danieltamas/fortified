package discover

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

var update = flag.Bool("update", false, "update golden files")

// TestDiscoverGolden is the single most important test in this
// package: real captured output from host-2-example (PLAN.md Phase 2
// step 1 — docker inspect fixtures are hand-redacted synthetic copies
// of the real shape, never the real container env values) parsed into
// the exact expected structured report.
func TestDiscoverGolden(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))

	report, err := Parse("host-2-example", cap, "203.0.113.5")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "host-2-example.golden.json")
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath) //nolint:gosec // goldenPath is a fixed testdata path, not untrusted input
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Parse(host-2-example) mismatch (-update to refresh):\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestDiscoverFlagsNoLiveSnapshot(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !report.VolumeManager.NoLiveSnapshot() {
		t.Error("host-2-example has no LVM/ZFS/Btrfs; NoLiveSnapshot() should be true")
	}
}

func TestDiscoverClassifiesRealDatabases(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	byContainer := make(map[string]DatabaseInstance)
	for _, d := range report.Databases {
		byContainer[d.Container] = d
	}

	psql, ok := byContainer["psql"]
	if !ok {
		t.Fatal("expected a psql DatabaseInstance")
	}
	if psql.Kind != "postgres" || psql.DumpStrategy != DumpStrategyDockerExec || !psql.AuthResolved {
		t.Errorf("psql = %+v, want kind=postgres dump_strategy=docker-exec auth_resolved=true", psql)
	}

	mysql, ok := byContainer["mysql"]
	if !ok {
		t.Fatal("expected a mysql DatabaseInstance")
	}
	if mysql.Kind != "mariadb" || mysql.DumpStrategy != DumpStrategyDockerExec || !mysql.AuthResolved {
		t.Errorf("mysql = %+v, want kind=mariadb dump_strategy=docker-exec auth_resolved=true", mysql)
	}
}

// TestDiscoverPostgresAuthResolvedReflectsLiveProbe proves a postgres
// container's AuthResolved is no longer unconditionally true — it
// follows inspect.go's live peer-auth probe: a container whose
// pg_hba.conf requires a password even locally (verified live: this
// exact gap produced "no password supplied" mid-backup, discovered
// only after onboarding, since the old code assumed postgres always
// needs no credential at all) must come back AuthResolved=false, so
// config.Load requires an explicit auth_ref instead of silently
// producing a config that will fail at backup time.
func TestDiscoverPostgresAuthResolvedReflectsLiveProbe(t *testing.T) {
	psqlInspect := `[{"Config":{"Image":"postgres:17-bookworm","Env":[]},"Mounts":[],"NetworkSettings":{"Networks":{},"Ports":{}}}]`

	cases := []struct {
		name        string
		probeResult *sshx.Result // nil means the probe never ran (key absent)
		want        bool
	}{
		{"probe succeeds", &sshx.Result{ExitCode: 0, Stdout: "1\n"}, true},
		{"probe fails (password required)", &sshx.Result{ExitCode: 2, Stderr: "fe_sendauth: no password supplied"}, false},
		{"probe never ran", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			containers := []Container{{Name: "psql", Image: "postgres:17-bookworm"}}
			cap := newCapture()
			cap.Results[dockerInspectKey("psql")] = sshx.Result{Stdout: psqlInspect}
			if tc.probeResult != nil {
				cap.Results[postgresAuthProbeKey("psql")] = *tc.probeResult
			}

			databases, missing, err := classifyDatabases(containers, cap)
			if err != nil {
				t.Fatalf("classifyDatabases: %v", err)
			}
			if len(missing) != 0 {
				t.Fatalf("missing = %v, want none", missing)
			}
			if len(databases) != 1 {
				t.Fatalf("got %d databases, want 1", len(databases))
			}
			if databases[0].AuthResolved != tc.want {
				t.Errorf("AuthResolved = %v, want %v", databases[0].AuthResolved, tc.want)
			}
		})
	}
}

// TestDiscoverClassifiesCustomPostgresUsername proves a postgres
// container started with a non-default POSTGRES_USER is recorded with
// that username — verified live: the official postgres image, given
// POSTGRES_USER=someone-else, replaces the bootstrap superuser
// entirely rather than adding a second role, so there is no "postgres"
// role at all to connect as. A container using the default (no
// POSTGRES_USER, or POSTGRES_USER=postgres) must record an empty
// Username, matching every other server's fixtures unchanged.
func TestDiscoverClassifiesCustomPostgresUsername(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
	}{
		{"custom POSTGRES_USER", `["POSTGRES_USER=paperclip","POSTGRES_PASSWORD=paperclip"]`, "paperclip"},
		{"default (no POSTGRES_USER)", `[]`, ""},
		{"explicit POSTGRES_USER=postgres", `["POSTGRES_USER=postgres"]`, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inspect := `[{"Config":{"Image":"postgres:17-bookworm","Env":` + tc.env + `},"Mounts":[],"NetworkSettings":{"Networks":{},"Ports":{}}}]`
			containers := []Container{{Name: "paperclip-db", Image: "postgres:17-bookworm"}}
			cap := newCapture()
			cap.Results[dockerInspectKey("paperclip-db")] = sshx.Result{Stdout: inspect}
			cap.Results[postgresAuthProbeKey("paperclip-db")] = sshx.Result{ExitCode: 0}

			databases, missing, err := classifyDatabases(containers, cap)
			if err != nil {
				t.Fatalf("classifyDatabases: %v", err)
			}
			if len(missing) != 0 {
				t.Fatalf("missing = %v, want none", missing)
			}
			if len(databases) != 1 {
				t.Fatalf("got %d databases, want 1", len(databases))
			}
			if databases[0].Username != tc.want {
				t.Errorf("Username = %q, want %q", databases[0].Username, tc.want)
			}
		})
	}
}

// TestPostgresProbeUsernameUsesConfiguredUser proves inspect.go's live
// auth probe would request the container's actual database role via
// -U rather than relying on the implicit default — otherwise the
// probe itself fails with "role postgres does not exist" against a
// container like the one above, misreporting AuthResolved=false for a
// container whose real auth is actually fine under its own custom
// role. Empty means "use the implicit default", matching
// DatabaseInstance.Username's own convention.
func TestPostgresProbeUsernameUsesConfiguredUser(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
	}{
		{"custom user", `[{"Config":{"Image":"postgres:17","Env":["POSTGRES_USER=paperclip"]}}]`, "paperclip"},
		{"default user", `[{"Config":{"Image":"postgres:17","Env":[]}}]`, ""},
		{"explicit POSTGRES_USER=postgres", `[{"Config":{"Image":"postgres:17","Env":["POSTGRES_USER=postgres"]}}]`, ""},
		{"unparseable result falls back to default", `not json`, ""},
		{"empty result falls back to default", `[]`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := postgresProbeUsername(sshx.Result{Stdout: tc.stdout})
			if got != tc.want {
				t.Errorf("postgresProbeUsername(%q) = %q, want %q", tc.stdout, got, tc.want)
			}
		})
	}
}

// TestDiscoverClassifiesCockroachDB proves a cockroachdb/cockroach
// image is recognized and its AuthResolved follows the live
// --insecure reachability probe, mirroring postgres's own live-probe
// treatment — fortified only supports an --insecure cluster (verified
// live against a real v19.1.5 cluster); a secure cluster requiring
// client certs isn't supported, and the probe is what tells the two
// apart.
func TestDiscoverClassifiesCockroachDB(t *testing.T) {
	crdbInspect := `[{"Config":{"Image":"cockroachdb/cockroach:v19.1.5","Env":[]},"Mounts":[],"NetworkSettings":{"Networks":{},"Ports":{}}}]`

	cases := []struct {
		name        string
		probeResult *sshx.Result
		want        bool
	}{
		{"probe succeeds (insecure mode)", &sshx.Result{ExitCode: 0, Stdout: "1\n"}, true},
		{"probe fails (secure cluster, not supported)", &sshx.Result{ExitCode: 1, Stderr: "certificate required"}, false},
		{"probe never ran", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			containers := []Container{{Name: "cockroachdb", Image: "cockroachdb/cockroach:v19.1.5"}}
			cap := newCapture()
			cap.Results[dockerInspectKey("cockroachdb")] = sshx.Result{Stdout: crdbInspect}
			if tc.probeResult != nil {
				cap.Results[cockroachAuthProbeKey("cockroachdb")] = *tc.probeResult
			}

			databases, missing, err := classifyDatabases(containers, cap)
			if err != nil {
				t.Fatalf("classifyDatabases: %v", err)
			}
			if len(missing) != 0 {
				t.Fatalf("missing = %v, want none", missing)
			}
			if len(databases) != 1 || databases[0].Kind != "cockroachdb" {
				t.Fatalf("databases = %+v, want one cockroachdb entry", databases)
			}
			if databases[0].AuthResolved != tc.want {
				t.Errorf("AuthResolved = %v, want %v", databases[0].AuthResolved, tc.want)
			}
		})
	}
}

func TestDiscoverNoDBPortsExposedOnRealHost(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(report.Exposure) != 0 {
		t.Errorf("expected no exposure findings (DB ports are 127.0.0.1-only), got %+v", report.Exposure)
	}
}

func TestDiscoverFlagsMissingBorg(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if report.Prerequisites.BorgInstalled {
		t.Error("host-2-example's real capture has no borg installed; BorgInstalled should be false")
	}
	if !report.Prerequisites.DockerInstalled {
		t.Error("expected DockerInstalled to be true")
	}
}

// TestExposureVantagePoint: a DB port bound to 0.0.0.0 whose firewall
// rules already allowlist the control host's own egress IP must be
// reported as unverifiable, never as a clean "not exposed" — a false
// positive from testing from an already-trusted network was a real
// mistake the source playbook made once (SKILL.md Step 0).
func TestExposureVantagePoint(t *testing.T) {
	bindings := []PortBinding{{Address: "0.0.0.0", Port: 5432, Process: "docker-proxy"}}
	firewallText := "-A INPUT -s 203.0.113.5/32 -p tcp --dport 5432 -j ACCEPT\n"

	findings := findExposure(bindings, nil, "203.0.113.5", firewallText)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityUnverifiable {
		t.Errorf("severity = %q, want %q (never a clean pass)", findings[0].Severity, SeverityUnverifiable)
	}
}

func TestExposureFlaggedWhenEgressIPNotAllowlisted(t *testing.T) {
	bindings := []PortBinding{{Address: "0.0.0.0", Port: 5432, Process: "docker-proxy"}}
	findings := findExposure(bindings, nil, "203.0.113.5", "-P INPUT ACCEPT\n")
	if len(findings) != 1 || findings[0].Severity != SeverityExposed {
		t.Fatalf("findings = %+v, want one Severity=exposed", findings)
	}
}

func TestExposureIgnoresLoopbackBindings(t *testing.T) {
	bindings := []PortBinding{{Address: "127.0.0.1", Port: 5432, Process: "docker-proxy"}}
	if findings := findExposure(bindings, nil, "203.0.113.5", ""); len(findings) != 0 {
		t.Errorf("expected no findings for a loopback-only bind, got %+v", findings)
	}
}

// Degraded-input tests: each fixture file individually missing means
// a structured partial report with Incomplete: true, never a zero
// value masquerading as a real finding.
// TestDiscoverKnownStatePathsFoundUniformly proves the well-known
// stateful paths get surfaced regardless of whether the target uses
// docker-compose at all — the exact gap a compose-file-only heuristic
// can't close (see cmdWireguardDir's doc comment). host-2-example's
// own fixture has none of these present, so this test builds a
// synthetic capture instead.
func TestDiscoverKnownStatePathsFoundUniformly(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdWireguardDir] = sshx.Result{Stdout: "/etc/wireguard\n"}
	cap.Results[cmdTailscaleState] = sshx.Result{Stdout: "/var/lib/tailscale\n"}
	cap.Results[cmdSystemdCustomUnits] = sshx.Result{Stdout: "/etc/systemd/system/anaf-relay-bridge.service\n"}
	cap.Results[cmdCrontabs] = sshx.Result{Stdout: "/var/spool/cron/crontabs\n"}
	cap.Results[cmdLetsEncrypt] = sshx.Result{Stdout: "/etc/letsencrypt\n"}
	// Native nginx, ufw, iptables-persistent, ssh, and cloudflared are
	// absent (exit 2, no stdout) — must not be reported as present.
	cap.Results[cmdNativeNginxConf] = sshx.Result{ExitCode: 2}
	cap.Results[cmdUfwPersisted] = sshx.Result{ExitCode: 2}
	cap.Results[cmdIptablesPersistent] = sshx.Result{ExitCode: 2}
	cap.Results[cmdSSHConfig] = sshx.Result{ExitCode: 2}
	cap.Results[cmdCloudflared] = sshx.Result{ExitCode: 2}

	got := parseKnownStatePaths(cap)
	want := []string{"/etc/wireguard", "/var/lib/tailscale", "/var/spool/cron/crontabs", "/etc/letsencrypt", "/etc/systemd/system"}
	if len(got) != len(want) {
		t.Fatalf("parseKnownStatePaths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseKnownStatePaths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestDiscoverFindsBindMountsForNonDatabaseContainers proves a
// container that isn't a recognized database engine (so
// classifyDatabases never looks at it) still contributes its own
// bind-mount source paths as archive candidates — the exact gap
// verified live on a real fleet: dgraph, redis-stack, and others had
// no compose file discover could find, so their real bind mounts were
// invisible to the emitted config even though `docker inspect` had
// been capturing the answer for the (unrelated) database container the
// whole time. Also proves non-bind mounts (named volumes) and
// ephemeral runtime sockets under /var/run are excluded, and duplicate
// sources across containers are deduped.
func TestDiscoverFindsBindMountsForNonDatabaseContainers(t *testing.T) {
	containers := []Container{{Name: "redis-stack", Image: "redis/redis-stack-server:latest"}, {Name: "example-backend", Image: "img-example-backend"}}
	cap := newCapture()
	cap.Results[dockerInspectKey("redis-stack")] = sshx.Result{Stdout: `[{"Config":{"Image":"redis/redis-stack-server:latest","Env":[]},"Mounts":[
		{"Type":"bind","Source":"/home/redis-stack/data","Destination":"/data"},
		{"Type":"bind","Source":"/home/redis-stack/redis.conf","Destination":"/usr/local/etc/redis/redis.conf"},
		{"Type":"volume","Source":"/var/lib/docker/volumes/some-volume/_data","Destination":"/other"}
	],"NetworkSettings":{"Networks":{},"Ports":{}}}]`}
	cap.Results[dockerInspectKey("example-backend")] = sshx.Result{Stdout: `[{"Config":{"Image":"img-example-backend","Env":[]},"Mounts":[
		{"Type":"bind","Source":"/home/example/backend.example.com/web/public_html/public","Destination":"/app/public"},
		{"Type":"bind","Source":"/var/run/nginx-reload.sock","Destination":"/app/nginx-reload.sock"},
		{"Type":"bind","Source":"/home/redis-stack/data","Destination":"/also-here"}
	],"NetworkSettings":{"Networks":{},"Ports":{}}}]`}

	got := parseContainerBindMounts(containers, cap)
	want := []string{
		"/home/example/backend.example.com/web/public_html/public",
		"/home/redis-stack/data",
		"/home/redis-stack/redis.conf",
	}
	if len(got) != len(want) {
		t.Fatalf("parseContainerBindMounts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseContainerBindMounts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestDiscoverSkipsContainersWithNoCapturedInspect proves a container
// discover never got around to inspecting (or whose inspect failed)
// contributes no bind mounts and, unlike a missing database inspect,
// never marks the report Incomplete — this is a soft "one fewer
// suggestion" gap, not a correctness-critical database detection miss.
func TestDiscoverSkipsContainersWithNoCapturedInspect(t *testing.T) {
	containers := []Container{{Name: "never-inspected", Image: "some/image"}}
	cap := newCapture()

	got := parseContainerBindMounts(containers, cap)
	if len(got) != 0 {
		t.Errorf("parseContainerBindMounts = %v, want empty for a container with no captured inspect", got)
	}
}

func TestDiscoverDegradedInputMissingLsblk(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	delete(cap.Results, cmdLsblk)

	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !report.Incomplete {
		t.Error("expected Incomplete=true when lsblk is missing")
	}
	found := false
	for _, r := range report.IncompleteReasons {
		if r == string(cmdLsblk)+" was not captured" {
			found = true
		}
	}
	if !found {
		t.Errorf("IncompleteReasons = %v, want it to mention lsblk", report.IncompleteReasons)
	}
}

func TestDiscoverDegradedInputMissingDockerInspect(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	delete(cap.Results, dockerInspectKey("psql"))

	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !report.Incomplete {
		t.Error("expected Incomplete=true when a classified container's docker inspect is missing")
	}
	for _, d := range report.Databases {
		if d.Container == "psql" {
			t.Errorf("psql should have been skipped, not reported with zero-value fields: %+v", d)
		}
	}
}

func TestDiscoverCompleteWithFullCapture(t *testing.T) {
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if report.Incomplete {
		t.Errorf("expected a complete report from the full fixture, got IncompleteReasons=%v", report.IncompleteReasons)
	}
}

func TestParseDockerPSRejectsMalformedLine(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdDockerPS] = sshx.Result{Stdout: "{not valid json"}
	if _, err := parseDockerPS(cap); err == nil {
		t.Fatal("expected an error parsing a malformed docker ps line")
	}
}
