package discover

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

const psqlInspectJSON = `[{"Config":{"Image":"postgres:17-bookworm","Env":["POSTGRES_PASSWORD=x"]},"Mounts":[],"NetworkSettings":{"Networks":{"lan":{}},"Ports":{}}}]`

// discoverSession opens a real *sshx.Session over fake so Inspect's
// remote argv (built by Session.Run) is exercised exactly as a live
// caller would construct it — Inspect itself no longer opens
// connections (see its doc comment on why session lifecycle now
// belongs to the caller).
func discoverSession(t *testing.T, fake sshx.Runner) *sshx.Session {
	t.Helper()
	session, err := sshx.OpenSession(context.Background(), fake, sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}, "/tmp/fortified-discover-test.sock")
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	return session
}

func TestDiscoverArgv(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // open
			{}, // lsblk
			{}, // pvs
			{}, // vgs
			{}, // lvs
			{}, // zpool list
			{}, // btrfs filesystem show
			{}, // cat /proc/mdstat
			{Result: sshx.Result{Stdout: `{"Names":"psql","Image":"postgres:17-bookworm","State":"running","Ports":"","Labels":""}`}}, // docker ps --format json
			{}, // find compose files
			{}, // ss -tlnp
			{}, // iptables -S
			{}, // nft list ruleset
			{}, // ufw status verbose
			{}, // borg --version
			{}, // docker --version
			{}, // ls -d /etc/wireguard
			{}, // ls -d /var/lib/tailscale
			{}, // ls -d /etc/nginx
			{}, // ls -d /etc/ufw
			{}, // ls -d /etc/iptables
			{}, // find /etc/systemd/system -maxdepth 1 -name *.service
			{}, // ls -d /etc/docker
			{}, // ls -d /root
			{}, // ls -d /var/spool/cron/crontabs
			{}, // ls -d /etc/ssh
			{}, // ls -d /etc/letsencrypt
			{}, // ls -d /etc/cloudflared
			{}, // systemctl is-active postgresql (native)
			{}, // su - postgres -c psql -tAc "SELECT 1" (native postgres auth probe)
			{}, // systemctl is-active mysql (native)
			{}, // systemctl is-active mariadb (native)
			{}, // test -r /etc/mysql/debian.cnf (native mysql creds)
			{}, // su - postgres -c psql --version (native postgres version)
			{}, // mysql --version (native mysql/mariadb version)
			{Result: sshx.Result{Stdout: psqlInspectJSON}}, // docker inspect psql
			{Result: sshx.Result{Stdout: "1\n"}},           // postgres peer-auth probe for psql
		},
	}
	session := discoverSession(t, fake)

	if _, err := Inspect(context.Background(), session, "host-2-example", nil, nil); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if len(fake.Calls) != 37 {
		t.Fatalf("expected 37 calls (open + 34 fixed + 1 docker inspect + 1 postgres auth probe), got %d", len(fake.Calls))
	}

	wantRemoteArgv := [][]string{
		{"lsblk", "-J"},
		{"pvs"},
		{"vgs"},
		{"lvs"},
		{"zpool", "list"},
		{"btrfs", "filesystem", "show"},
		{"cat", "/proc/mdstat"},
		{"docker", "ps", "-a", "--format", "json"},
		{"find", "/", "-maxdepth", "4", "'('", "-iname", "'docker-compose*.y*ml'", "-o", "-iname", "'compose.y*ml'", "')'"},
		{"ss", "-tlnp"},
		{"iptables", "-S"},
		{"nft", "list", "ruleset"},
		{"ufw", "status", "verbose"},
		{"borg", "--version"},
		{"docker", "--version"},
		{"ls", "-d", "/etc/wireguard"},
		{"ls", "-d", "/var/lib/tailscale"},
		{"ls", "-d", "/etc/nginx"},
		{"ls", "-d", "/etc/ufw"},
		{"ls", "-d", "/etc/iptables"},
		{"find", "/etc/systemd/system", "-maxdepth", "1", "-name", "'*.service'"},
		{"ls", "-d", "/etc/docker"},
		{"ls", "-d", "/root"},
		{"ls", "-d", "/var/spool/cron/crontabs"},
		{"ls", "-d", "/etc/ssh"},
		{"ls", "-d", "/etc/letsencrypt"},
		{"ls", "-d", "/etc/cloudflared"},
		{"systemctl", "is-active", "postgresql"},
		{"su", "-", "postgres", "-c", `'psql -tAc "SELECT 1"'`},
		{"systemctl", "is-active", "mysql"},
		{"systemctl", "is-active", "mariadb"},
		{"sh", "-c", "'test -r /etc/mysql/debian.cnf && echo yes'"},
		{"su", "-", "postgres", "-c", "'psql --version'"},
		{"mysql", "--version"},
	}
	for i, want := range wantRemoteArgv {
		call := fake.Calls[i+1] // skip the open call
		if call.Cmd != "ssh" {
			t.Fatalf("call %d cmd = %q, want ssh", i+1, call.Cmd)
		}
		gotRemote := trailingArgsAfterDashDash(call.Args)
		if strings.Join(gotRemote, "|") != strings.Join(want, "|") {
			t.Errorf("call %d remote argv = %v, want %v", i+1, gotRemote, want)
		}
		if call.Class != sshx.ReadOnly {
			t.Errorf("call %d class = %v, want ReadOnly", i+1, call.Class)
		}
	}

	dockerInspectCall := fake.Calls[35]
	if got := trailingArgsAfterDashDash(dockerInspectCall.Args); strings.Join(got, "|") != strings.Join([]string{"docker", "inspect", "psql"}, "|") {
		t.Errorf("docker inspect call remote argv = %v, want [docker inspect psql]", got)
	}

	authProbeCall := fake.Calls[36]
	if got := trailingArgsAfterDashDash(authProbeCall.Args); strings.Join(got, "|") != strings.Join([]string{"docker", "exec", "-u", "postgres", "psql", "psql", "-tAc", "'SELECT 1'"}, "|") {
		t.Errorf("postgres auth probe call remote argv = %v, want docker exec -u postgres psql psql -tAc 'SELECT 1'", got)
	}
}

// TestDiscoverProbesCustomPostgresUsername proves the live auth probe
// requests the container's actual database role via -U when
// POSTGRES_USER overrode the default — verified live against a real
// container (POSTGRES_USER=paperclip): the official postgres image
// never creates a matching OS/container account for it, only the
// database role, so the docker-exec OS user must stay "postgres" (the
// only account that always exists) while -U carries the real role.
func TestDiscoverProbesCustomPostgresUsername(t *testing.T) {
	paperclipInspectJSON := `[{"Config":{"Image":"postgres:17-bookworm","Env":["POSTGRES_USER=paperclip","POSTGRES_PASSWORD=paperclip"]},"Mounts":[],"NetworkSettings":{"Networks":{},"Ports":{}}}]`
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, {}, {}, {}, {}, {}, {}, // open, lsblk, pvs, vgs, lvs, zpool, btrfs
			{}, // cat /proc/mdstat
			{Result: sshx.Result{Stdout: `{"Names":"paperclip-db","Image":"postgres:17-bookworm","State":"running","Ports":"","Labels":""}`}},
			{}, {}, {}, {}, {}, {}, {}, // find compose, ss, iptables, nft, ufw, borg, docker --version
			{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 12 known-state-path checks
			{}, {}, {}, {}, {}, {}, {}, // 7 native-database probes
			{Result: sshx.Result{Stdout: paperclipInspectJSON}}, // docker inspect paperclip-db
			{Result: sshx.Result{Stdout: "1\n"}},                // postgres peer-auth probe
		},
	}
	session := discoverSession(t, fake)

	if _, err := Inspect(context.Background(), session, "ai.example.com", nil, nil); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	authProbeCall := fake.Calls[len(fake.Calls)-1]
	got := trailingArgsAfterDashDash(authProbeCall.Args)
	want := []string{"docker", "exec", "-u", "postgres", "paperclip-db", "psql", "-U", "paperclip", "-tAc", "'SELECT 1'"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("postgres auth probe call remote argv = %v, want %v", got, want)
	}
}

// TestDiscoverInspectsEveryContainerNotJustDatabases proves Inspect
// now runs `docker inspect` for every container docker ps reports, not
// only ones classifyDatabases recognizes as a database engine —
// verified live that a compose-file-only heuristic silently missed
// real bind mounts for non-database containers (dgraph, redis-stack,
// etc.) with no other way to surface them as archive candidates.
func TestDiscoverInspectsEveryContainerNotJustDatabases(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, {}, {}, {}, {}, {}, {}, {}, // open + 7 fixed pre-docker-ps checks
			{Result: sshx.Result{Stdout: `{"Names":"psql","Image":"postgres:17-bookworm","State":"running","Ports":"","Labels":""}
{"Names":"redis-stack","Image":"redis/redis-stack-server:latest","State":"running","Ports":"","Labels":""}`}}, // docker ps --format json
			{}, {}, {}, {}, {}, {}, {}, // find compose + 6 remaining fixed checks
			{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // known-state-path checks
			{}, {}, {}, {}, {}, {}, {}, // 7 native-database probes
			{Result: sshx.Result{Stdout: psqlInspectJSON}}, // docker inspect psql
			{Result: sshx.Result{Stdout: "1\n"}},           // postgres peer-auth probe for psql
			{Result: sshx.Result{Stdout: `[{"Config":{"Image":"redis/redis-stack-server:latest","Env":[]},"Mounts":[{"Type":"bind","Source":"/home/redis-stack/data","Destination":"/data"}],"NetworkSettings":{"Networks":{},"Ports":{}}}]`}}, // docker inspect redis-stack
		},
	}
	session := discoverSession(t, fake)

	report, err := Inspect(context.Background(), session, "host-2-example", nil, nil)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	lastCall := fake.Calls[len(fake.Calls)-1]
	gotRemote := trailingArgsAfterDashDash(lastCall.Args)
	if strings.Join(gotRemote, "|") != strings.Join([]string{"docker", "inspect", "redis-stack"}, "|") {
		t.Errorf("last call remote argv = %v, want [docker inspect redis-stack] (a non-database container must still be inspected)", gotRemote)
	}

	if !contains(report.ContainerBindMounts, "/home/redis-stack/data") {
		t.Errorf("report.ContainerBindMounts = %v, want /home/redis-stack/data from the non-database container's own bind mount", report.ContainerBindMounts)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func trailingArgsAfterDashDash(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[i+1:]
		}
	}
	return nil
}

// TestInspectReportsProgress proves progress gets called as each step
// runs, in order — the fix for discover printing nothing at all while
// it sequentially issues over a dozen SSH round trips.
func TestInspectReportsProgress(t *testing.T) {
	fake := &sshxtest.FakeRunner{
		Responses: []sshxtest.Response{
			{}, // open
			{}, // lsblk
			{}, // pvs
			{}, // vgs
			{}, // lvs
			{}, // zpool list
			{}, // btrfs filesystem show
			{}, // cat /proc/mdstat
			{Result: sshx.Result{Stdout: `{"Names":"psql","Image":"postgres:17-bookworm","State":"running","Ports":"","Labels":""}`}},
			{},                         // find compose files
			{},                         // ss -tlnp
			{},                         // iptables -S
			{},                         // nft list ruleset
			{},                         // ufw status verbose
			{},                         // borg --version
			{},                         // docker --version
			{},                         // ls -d /etc/wireguard
			{},                         // ls -d /var/lib/tailscale
			{},                         // ls -d /etc/nginx
			{},                         // ls -d /etc/ufw
			{},                         // ls -d /etc/iptables
			{},                         // find /etc/systemd/system -maxdepth 1 -name *.service
			{},                         // ls -d /etc/docker
			{},                         // ls -d /root
			{},                         // ls -d /var/spool/cron/crontabs
			{},                         // ls -d /etc/ssh
			{},                         // ls -d /etc/letsencrypt
			{},                         // ls -d /etc/cloudflared
			{}, {}, {}, {}, {}, {}, {}, // 7 native-database probes
			{Result: sshx.Result{Stdout: psqlInspectJSON}}, // docker inspect psql
		},
	}
	session := discoverSession(t, fake)

	var messages []string
	progress := func(msg string) { messages = append(messages, msg) }

	if _, err := Inspect(context.Background(), session, "host-2-example", nil, progress); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	joined := strings.Join(messages, "\n")
	for _, want := range []string{
		"checking block devices (lsblk)...",
		"checking block devices (lsblk): done",
		"checking docker is installed...",
		"inspecting container psql...",
		"resolving egress IP...",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("progress messages = %v, want one containing %q", messages, want)
		}
	}
}

func TestDiscoverIsAllReadOnlyClass(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	session := discoverSession(t, fake)
	if _, err := Inspect(context.Background(), session, "server", nil, nil); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	for i, c := range fake.Calls {
		if c.Class != sshx.ReadOnly {
			t.Errorf("call %d (%v) has class %v, want ReadOnly — discover must never mutate", i, c.Args, c.Class)
		}
	}
}
