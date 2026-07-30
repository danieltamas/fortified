// Package config loads and validates the fleet.yaml config file
// (SPEC.md §7): strict decoding (unknown keys rejected), TODO
// rejection, and rejection of plaintext values where a secret
// reference is expected. See config/schema.md for the field reference.
package config

// Fleet is the top-level fleet.yaml document: one entry per server.
type Fleet struct {
	Servers map[string]Server `yaml:"servers"`
}

// Server is one fleet member's full configuration.
type Server struct {
	SSH              SSH            `yaml:"ssh"`
	Provider         string         `yaml:"provider"`
	Destination      string         `yaml:"destination"`
	Archive          []ArchivePath  `yaml:"archive"`
	Databases        []Database     `yaml:"databases"`
	EncryptionKeyRef string         `yaml:"encryption_key_ref"`
	Retention        *Retention     `yaml:"retention,omitempty"`
	Hetzner          *HetznerConfig `yaml:"hetzner,omitempty"`
	// WorkspaceDir overrides where backup/verify/restore stage database
	// dumps on the target — an absolute path, e.g. an attached volume
	// with real headroom. Empty (the default) stages under the SSH
	// login's own home directory, same as always. Verified live this
	// matters: a large database's SQL-text dump can need meaningfully
	// more scratch space than the root filesystem has free, even when
	// the database itself is a modest size on disk, and a server can
	// have an attached volume sitting unused with plenty of room.
	// Changing this on a server with existing archives means a later
	// `restore --db` against an *older* archive (created under the old
	// workspace path) won't find the right path — this only ever
	// affects future backups, not a retroactive rewrite of past ones.
	WorkspaceDir string `yaml:"workspace_dir,omitempty"`
}

// HetznerConfig is required when Server.Provider is "hetzner": the
// Storage Box main account fortified's Provider needs at setup time to
// install a server's append-only key directly (NOTES.md — the main
// account's own SFTP session, never the subaccount's password), and
// the Hetzner Cloud API token used for subaccount/snapshot-schedule
// management via hcloud-go. Destination (above) is the Storage Box ID
// the operator provisioned once, out of band.
type HetznerConfig struct {
	MainAccount    SSH    `yaml:"main_account"`
	HCloudTokenRef string `yaml:"hcloud_token_ref"`
}

// SSH is how to reach a server's control-host-facing SSH endpoint.
type SSH struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	User string `yaml:"user"`
}

// ArchivePath is a host-level path (and optional glob) to include in
// the archive alongside database dumps — compose files, TLS certs,
// cron, anything not already captured through the database engine.
type ArchivePath struct {
	Path string `yaml:"path"`
	Glob string `yaml:"glob,omitempty"`
}

// Database describes one stateful database container to dump through
// its engine at backup time. AuthRef is only required when discover
// could not resolve credentials automatically (SPEC.md §3).
type Database struct {
	Kind         string `yaml:"kind"`
	Container    string `yaml:"container"`
	DumpStrategy string `yaml:"dump_strategy"`
	AuthRef      string `yaml:"auth_ref,omitempty"`
}

// Retention is prune's keep policy. DefaultRetention applies to any
// server that doesn't override it (PLAN.md §1).
type Retention struct {
	KeepDaily   int `yaml:"keep_daily"`
	KeepWeekly  int `yaml:"keep_weekly"`
	KeepMonthly int `yaml:"keep_monthly"`
}

// DefaultRetention is applied to a server whose config omits
// retention entirely.
var DefaultRetention = Retention{KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 6}
