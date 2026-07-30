package discover

import "strings"

// knownStateChecks maps each well-known-path probe to the literal
// path it reports when present — one entry per fixed check in
// inspect.go's readOnlyCommands tail. Keeping the pairing in one place
// means adding a new probe only ever needs a matching entry here.
var knownStateChecks = []struct {
	key  commandKey
	path string
}{
	{cmdWireguardDir, "/etc/wireguard"},
	{cmdTailscaleState, "/var/lib/tailscale"},
	{cmdNativeNginxConf, "/etc/nginx"},
	{cmdUfwPersisted, "/etc/ufw"},
	{cmdIptablesPersistent, "/etc/iptables"},
	{cmdDockerEtcConf, "/etc/docker"},
	{cmdRootHome, "/root"},
	{cmdCrontabs, "/var/spool/cron/crontabs"},
	{cmdSSHConfig, "/etc/ssh"},
	{cmdLetsEncrypt, "/etc/letsencrypt"},
	{cmdCloudflared, "/etc/cloudflared"},
}

// parseKnownStatePaths reports which of the fixed, uniform stateful
// paths actually exist on this target — see cmdWireguardDir's doc
// comment for why these are checked unconditionally rather than
// inferred from docker-compose presence. A path only appears here when
// its check produced real output (hasListing), so an absent tool
// (e.g. no /etc/wireguard at all) is silently omitted, exactly like
// parseVolumeManager's treatment of an unused-but-installed manager.
func parseKnownStatePaths(cap *Capture) []string {
	var paths []string
	for _, c := range knownStateChecks {
		if hasListing(cap, c.key) {
			paths = append(paths, c.path)
		}
	}
	if r, ok := cap.get(cmdSystemdCustomUnits); ok && !commandMissing(r) && strings.TrimSpace(r.Stdout) != "" {
		paths = append(paths, "/etc/systemd/system")
	}
	return paths
}
