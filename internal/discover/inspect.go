package discover

import (
	"context"
	"fmt"
	"time"

	"github.com/danieltamas/fortified/internal/sshx"
)

// readOnlyCommand is one fixed inspection step. Order matters: it's
// what TestDiscoverArgv asserts, and running the read-only checks in
// the same sequence every time is part of SPEC.md §0's determinism
// requirement.
type readOnlyCommand struct {
	key   commandKey
	label string
	cmd   string
	args  []string
}

var readOnlyCommands = []readOnlyCommand{
	{cmdLsblk, "checking block devices (lsblk)", "lsblk", []string{"-J"}},
	{cmdPVs, "checking LVM physical volumes (pvs)", "pvs", nil},
	{cmdVGs, "checking LVM volume groups (vgs)", "vgs", nil},
	{cmdLVs, "checking LVM logical volumes (lvs)", "lvs", nil},
	{cmdZpoolList, "checking ZFS pools (zpool list)", "zpool", []string{"list"}},
	{cmdBtrfsFilesystem, "checking Btrfs filesystems (btrfs filesystem show)", "btrfs", []string{"filesystem", "show"}},
	{cmdProcMdstat, "checking software RAID (/proc/mdstat)", "cat", []string{"/proc/mdstat"}},
	{cmdDockerPS, "listing containers (docker ps)", "docker", []string{"ps", "-a", "--format", "json"}},
	{cmdDockerComposeFiles, "finding docker-compose files", "find", []string{"/", "-maxdepth", "4", "-iname", "docker-compose*.yml"}},
	{cmdSSTlnp, "checking listening sockets (ss -tlnp)", "ss", []string{"-tlnp"}},
	{cmdIptablesS, "checking iptables rules", "iptables", []string{"-S"}},
	{cmdNftRuleset, "checking nftables ruleset", "nft", []string{"list", "ruleset"}},
	{cmdUfwStatus, "checking ufw status", "ufw", []string{"status", "verbose"}},
	{cmdBorgVersion, "checking borg is installed", "borg", []string{"--version"}},
	{cmdDockerVersion, "checking docker is installed", "docker", []string{"--version"}},

	// Fixed, uniform checklist for well-known stateful paths — probed
	// on every server regardless of how it's orchestrated, so archive
	// candidates don't depend on docker-compose being in use at all.
	{cmdWireguardDir, "checking WireGuard config (/etc/wireguard)", "ls", []string{"-d", "/etc/wireguard"}},
	{cmdTailscaleState, "checking Tailscale state (/var/lib/tailscale)", "ls", []string{"-d", "/var/lib/tailscale"}},
	{cmdNativeNginxConf, "checking native nginx config (/etc/nginx)", "ls", []string{"-d", "/etc/nginx"}},
	{cmdUfwPersisted, "checking ufw persisted rules (/etc/ufw)", "ls", []string{"-d", "/etc/ufw"}},
	{cmdIptablesPersistent, "checking iptables-persistent rules (/etc/iptables)", "ls", []string{"-d", "/etc/iptables"}},
	{cmdSystemdCustomUnits, "checking custom systemd units (/etc/systemd/system)", "find", []string{"/etc/systemd/system", "-maxdepth", "1", "-name", "*.service"}},
	{cmdDockerEtcConf, "checking Docker daemon config (/etc/docker)", "ls", []string{"-d", "/etc/docker"}},
	// /root is the single most sensitive path this checklist can
	// surface — dotfiles, GPG keys, password stores, and (verified
	// live) even fortified's own automation private key file can live
	// here. It's still proposed, not silently skipped: every candidate
	// this checklist produces is a proposal for operator review, never
	// auto-accepted (emit_config.go's own contract) — but this is the
	// one entry where that review matters most, so it's called out by
	// name rather than left to blend in with /etc/wireguard et al.
	{cmdRootHome, "checking root home directory (/root)", "ls", []string{"-d", "/root"}},
	// Verified live against real fleet servers (not guessed): root's
	// crontab held genuine operational automation (cert renewal, DB
	// sync jobs, docker/cache cleanup) that would silently vanish after
	// a bare-metal restore; /etc/ssh holds host keys whose loss forces
	// every client to re-trust the restored host; /etc/letsencrypt and
	// /etc/cloudflared hold real, non-regenerable certs/tunnel config.
	// /etc/crontab and /etc/cron.d were checked too and found to be
	// package-installed defaults only (certbot, e2scrub_all, sysstat,
	// popularity-contest) on every server checked — deliberately not
	// added, same reasoning as /usr/src's exclusion.
	{cmdCrontabs, "checking root's crontab (/var/spool/cron/crontabs)", "ls", []string{"-d", "/var/spool/cron/crontabs"}},
	{cmdSSHConfig, "checking SSH host keys and config (/etc/ssh)", "ls", []string{"-d", "/etc/ssh"}},
	{cmdLetsEncrypt, "checking Let's Encrypt certs (/etc/letsencrypt)", "ls", []string{"-d", "/etc/letsencrypt"}},
	{cmdCloudflared, "checking cloudflared config (/etc/cloudflared)", "ls", []string{"-d", "/etc/cloudflared"}},

	// Native (non-Docker) database detection — see capture.go's doc
	// comment on why this exists. Peer auth via `su - postgres` never
	// needs a password when the caller is already root (the SSH login
	// user for every server in the fleet), which is always true unless
	// pg_hba.conf was hardened to require one even for local
	// connections — probed live rather than assumed, same reasoning as
	// the Docker postgres probe above. debian.cnf is the standard
	// Debian/Ubuntu package-maintainer credential (root-readable only)
	// used to authenticate mysql/mariadb administratively without
	// needing any operator-supplied password — verified live against
	// two real servers.
	{cmdNativePostgresActive, "checking native postgres service (systemctl)", "systemctl", []string{"is-active", "postgresql"}},
	{cmdNativePostgresAuthProbe, "checking native postgres peer auth", "su", []string{"-", "postgres", "-c", `psql -tAc "SELECT 1"`}},
	{cmdNativeMySQLActive, "checking native mysql service (systemctl)", "systemctl", []string{"is-active", "mysql"}},
	{cmdNativeMariaDBActive, "checking native mariadb service (systemctl)", "systemctl", []string{"is-active", "mariadb"}},
	{cmdNativeMySQLDebianCnf, "checking native mysql maintenance credentials (/etc/mysql/debian.cnf)", "sh", []string{"-c", "test -r /etc/mysql/debian.cnf && echo yes"}},
	// verify needs a real Docker image to spin up a throwaway
	// restore-and-compare container for a native database (there is no
	// image of its own, unlike a Docker container) — these two probes
	// let it pick one that actually matches what's installed, rather
	// than guessing. Both fail cleanly (non-zero exit / "not found") on
	// a server with no native postgres/mysql at all, same as every
	// other optional-tool probe in this list.
	{cmdNativePostgresVersion, "checking native postgres version", "su", []string{"-", "postgres", "-c", "psql --version"}},
	{cmdNativeMySQLVersion, "checking native mysql/mariadb version", "mysql", []string{"--version"}},
}

// reportStep calls progress (nil-safe, same func(string) convention as
// orchestrate.Deps.Progress) before and after fn, timing it — this is
// what makes every one of discover's dozen-plus sequential SSH round
// trips visible in the CLI instead of a single silent multi-second
// pause (the exact "nothing happens" complaint this exists to fix).
func reportStep(progress func(string), label string, fn func()) {
	if progress == nil {
		fn()
		return
	}
	progress(label + "...")
	start := time.Now()
	fn()
	progress(fmt.Sprintf("%s: done (%s)", label, time.Since(start).Round(time.Millisecond)))
}

// Inspect runs discover's full read-only inspection over runner, then
// parses the results into a Report. runner is expected to already be
// connected — typically an *sshx.Session opened by the caller, itself
// wrapped in audit.Runner (SPEC.md §4) — so Inspect never owns
// connection lifecycle: opening it internally would force any caller
// wanting an audit trail to wrap audit.Runner *underneath* the
// session's own raw runner instead of above the session, which would
// let a future secret-bearing call's session-establishment argv reach
// the audit log unfiltered. The caller opens and closes the
// connection; Inspect only ever calls Run on what it's given. A
// command that fails because the remote tool is absent (e.g. no LVM
// installed) is expected, not fatal — Parse's commandMissing handling
// is what turns that into a finding.
//
// progress, if non-nil, is called with a short label as each step
// starts and finishes — purely a reporting hook, never read back by
// any logic here, so a nil progress (every existing caller before
// this was added) is always safe and changes no behavior.
func Inspect(ctx context.Context, runner sshx.Runner, serverID string, resolveEgressIP EgressIPFunc, progress func(string)) (*Report, error) {
	cap := newCapture()
	for _, c := range readOnlyCommands {
		reportStep(progress, c.label, func() {
			result, _ := runner.Run(ctx, sshx.ReadOnly, c.cmd, c.args, sshx.RunOptions{})
			cap.Results[c.key] = result
		})
	}

	containers, err := parseDockerPS(cap)
	if err != nil {
		return nil, err
	}
	// Every container is inspected, not just recognized database
	// engines: a container's bind mounts are real archive-path
	// candidates regardless of what's running inside it, and limiting
	// this to database images meant any other container's state (e.g.
	// dgraph, redis-stack, or anything else started without a
	// discoverable compose file) was invisible to archivePaths even
	// though `docker inspect` had the answer the whole time — verified
	// live against a real fleet where 5 running containers' bind mounts
	// were silently missing from the emitted config for exactly this
	// reason.
	for _, c := range containers {
		var inspectResult sshx.Result
		reportStep(progress, fmt.Sprintf("inspecting container %s", c.Name), func() {
			inspectResult, _ = runner.Run(ctx, sshx.ReadOnly, "docker", []string{"inspect", c.Name}, sshx.RunOptions{})
			cap.Results[dockerInspectKey(c.Name)] = inspectResult
		})
		// A postgres container's peer/socket auth (the default
		// docker-exec dump path) is only sometimes actually enabled —
		// verified live: a container whose pg_hba.conf requires a
		// password even for local connections fails this exact command
		// at backup time with "no password supplied", after discover had
		// unconditionally assumed it would work. Probing for real here,
		// once, means an operator learns they need auth_ref at discover
		// time, not from a failed production backup.
		//
		// The connecting OS user (docker exec -u) is always "postgres"
		// — verified live: the official postgres image never creates a
		// matching OS/container account for a custom POSTGRES_USER,
		// only the database role, so `docker exec -u <custom-role>`
		// itself fails at the Docker level ("unable to find user").
		// What DOES need to change is which role psql requests: without
		// -U it defaults to a role named after the OS user ("postgres"),
		// which doesn't exist at all once POSTGRES_USER overrode it —
		// verified live this fails with "role postgres does not exist",
		// not an auth failure, and that -U <actual-role> succeeds fine.
		if engineKind(c.Image) == "postgres" {
			args := []string{"exec", "-u", "postgres", c.Name, "psql"}
			if username := postgresProbeUsername(inspectResult); username != "" {
				args = append(args, "-U", username)
			}
			args = append(args, "-tAc", "SELECT 1")
			reportStep(progress, fmt.Sprintf("checking postgres peer auth for %s", c.Name), func() {
				result, _ := runner.Run(ctx, sshx.ReadOnly, "docker", args, sshx.RunOptions{})
				cap.Results[postgresAuthProbeKey(c.Name)] = result
			})
		}
		// fortified only supports a CockroachDB cluster started with
		// --insecure (verified live) — a secure cluster requiring client
		// certs isn't supported, and this probe is what tells the two
		// apart rather than assuming insecure mode.
		if engineKind(c.Image) == "cockroachdb" {
			reportStep(progress, fmt.Sprintf("checking cockroachdb reachability for %s", c.Name), func() {
				result, _ := runner.Run(ctx, sshx.ReadOnly, "docker",
					[]string{"exec", c.Name, "/cockroach/cockroach", "sql", "--insecure", "-e", "SELECT 1"}, sshx.RunOptions{})
				cap.Results[cockroachAuthProbeKey(c.Name)] = result
			})
		}
	}

	var egressIP string
	reportStep(progress, "resolving egress IP", func() {
		egressIP = resolveEgressIPSafely(ctx, resolveEgressIP)
	})
	return Parse(serverID, cap, egressIP)
}

// resolveEgressIPSafely never fails Inspect over an egress-IP lookup
// problem — an unresolved vantage point degrades an exposure finding's
// precision, but must never block discover from running at all.
func resolveEgressIPSafely(ctx context.Context, resolve EgressIPFunc) string {
	if resolve == nil {
		return ""
	}
	ip, err := resolve(ctx)
	if err != nil {
		return ""
	}
	return ip
}
