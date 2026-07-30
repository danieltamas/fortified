package discover

import (
	"strings"

	"github.com/danieltamas/fortified/internal/sshx"
)

// commandKey names one read-only command in a Capture, shared between
// the live Inspect path and golden-file tests reading fixture files —
// both build the same Capture shape and feed it to Parse.
type commandKey string

const (
	cmdLsblk              commandKey = "lsblk"
	cmdPVs                commandKey = "pvs"
	cmdVGs                commandKey = "vgs"
	cmdLVs                commandKey = "lvs"
	cmdZpoolList          commandKey = "zpool_list"
	cmdBtrfsFilesystem    commandKey = "btrfs_filesystem_show"
	cmdProcMdstat         commandKey = "proc_mdstat"
	cmdDockerPS           commandKey = "docker_ps"
	cmdDockerComposeFiles commandKey = "docker_compose_files"
	cmdSSTlnp             commandKey = "ss_tlnp"
	cmdIptablesS          commandKey = "iptables_s"
	cmdNftRuleset         commandKey = "nft_ruleset"
	cmdUfwStatus          commandKey = "ufw_status"
	cmdBorgVersion        commandKey = "borg_version"
	cmdDockerVersion      commandKey = "docker_version"

	// The checks below probe for well-known stateful paths that exist
	// outside any docker-compose project — native (non-containerized)
	// services and VPN state. Unlike cmdDockerComposeFiles, presence
	// here never depends on docker-compose being the target's
	// orchestration mechanism at all, so a server running everything
	// via plain `docker run` or systemd units still gets these
	// candidates surfaced (the exact gap a compose-file-only heuristic
	// can't close — see PROGRESS.md).
	cmdWireguardDir       commandKey = "wireguard_dir"
	cmdTailscaleState     commandKey = "tailscale_state"
	cmdNativeNginxConf    commandKey = "native_nginx_conf"
	cmdUfwPersisted       commandKey = "ufw_persisted"
	cmdIptablesPersistent commandKey = "iptables_persistent"
	cmdSystemdCustomUnits commandKey = "systemd_custom_units"
	cmdDockerEtcConf      commandKey = "docker_etc_conf"
	cmdRootHome           commandKey = "root_home"
	cmdCrontabs           commandKey = "crontabs"
	cmdSSHConfig          commandKey = "ssh_config"
	cmdLetsEncrypt        commandKey = "letsencrypt"
	cmdCloudflared        commandKey = "cloudflared"

	// The checks below detect postgres/mysql/mariadb installed as a
	// regular OS package (a systemd service), not inside Docker —
	// verified live against two real production servers running
	// 49GB/8.3GB of postgres/mysql data entirely invisible to
	// fortified's Docker-only discovery (docker wasn't even installed
	// on one of them), with zero backup coverage despite the servers
	// otherwise being fully onboarded and "backed up".
	cmdNativePostgresActive    commandKey = "native_postgres_active"
	cmdNativePostgresAuthProbe commandKey = "native_postgres_auth_probe"
	cmdNativeMySQLActive       commandKey = "native_mysql_active"
	cmdNativeMariaDBActive     commandKey = "native_mariadb_active"
	cmdNativeMySQLDebianCnf    commandKey = "native_mysql_debian_cnf"
	// The two checks below identify which Docker image `verify` should
	// use for a native database's throwaway restore-and-compare
	// container — a native install has no image of its own the way a
	// Docker container does, and verify unconditionally needs one (see
	// DatabaseInstance.Image's doc comment).
	cmdNativePostgresVersion commandKey = "native_postgres_version"
	cmdNativeMySQLVersion    commandKey = "native_mysql_version"
)

// dockerInspectKey is the Capture key for one container's `docker
// inspect` output.
func dockerInspectKey(container string) commandKey {
	return commandKey("docker_inspect_" + container)
}

// postgresAuthProbeKey is the Capture key for one postgres container's
// live peer-auth probe — see classifyDatabases' doc comment on why
// this can't just be assumed the way it used to be.
func postgresAuthProbeKey(container string) commandKey {
	return commandKey("postgres_auth_probe_" + container)
}

// cockroachAuthProbeKey is the Capture key for one cockroachdb
// container's live --insecure reachability probe.
func cockroachAuthProbeKey(container string) commandKey {
	return commandKey("cockroach_auth_probe_" + container)
}

// Capture holds every raw command result Parse needs, keyed by
// command name (fixed commands) or "docker_inspect_<container>" (one
// per discovered container). Both the live SSH path (inspect.go) and
// golden-file tests build this same shape.
type Capture struct {
	Results map[commandKey]sshx.Result
}

func newCapture() *Capture {
	return &Capture{Results: make(map[commandKey]sshx.Result)}
}

func (c *Capture) get(key commandKey) (sshx.Result, bool) {
	r, ok := c.Results[key]
	return r, ok
}

// commandMissing reports whether a command wasn't available on the
// target — either the remote shell couldn't find it (exit 127) or its
// output says so directly. Real captures over SSH can present either
// shape depending on how the command was invoked.
func commandMissing(r sshx.Result) bool {
	if r.ExitCode == 127 {
		return true
	}
	return containsCommandNotFound(r.Stdout) || containsCommandNotFound(r.Stderr)
}

func containsCommandNotFound(s string) bool {
	return strings.Contains(s, "command not found") || strings.Contains(s, "No such file or directory")
}
