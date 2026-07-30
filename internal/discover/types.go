// Package discover inspects a target server's real layout over SSH —
// filesystem/volume manager, RAID, Docker inventory, and database
// exposure — before any command is allowed to mutate it. Full
// inspection logic is implemented in Phase 2; this file defines the
// DatabaseInstance schema early (SPEC.md §3) because internal/state
// (Phase 1) records it.
package discover

// DumpStrategy says how backup should dump a DatabaseInstance's data:
// through the container's own client (preferred, reuses its already-
// working auth) or against an exposed TCP port needing an explicit
// credential.
type DumpStrategy string

const (
	DumpStrategyDockerExec DumpStrategy = "docker-exec"
	DumpStrategyTCP        DumpStrategy = "tcp"
	// DumpStrategyNative is a database installed as a regular OS
	// package (a systemd service), not inside Docker — verified live
	// against two real production servers whose postgres/mysql data
	// (49GB/8.3GB) was entirely invisible to Docker-only discovery.
	// Dumped directly on the host (`su - postgres -c pg_dumpall`,
	// `mysqldump --defaults-file=/etc/mysql/debian.cnf`), never via
	// docker exec.
	DumpStrategyNative DumpStrategy = "native"
)

// DatabaseInstance is discover's required output shape for anything it
// classifies as a database (SPEC.md §3). backup consumes this recipe
// verbatim — it must never re-derive a dump command by guessing from
// a container name at backup time.
type DatabaseInstance struct {
	Kind           string       `json:"kind"`
	Container      string       `json:"container"`
	Image          string       `json:"image"`
	Networks       []string     `json:"networks,omitempty"`
	ExposedPorts   []string     `json:"exposed_ports,omitempty"`
	DataMountPaths []string     `json:"data_mount_paths,omitempty"`
	DumpStrategy   DumpStrategy `json:"dump_strategy"`
	AuthResolved   bool         `json:"auth_resolved"`
	AuthRef        string       `json:"auth_ref,omitempty"`
	// Username is the postgres superuser role/OS-user this container
	// was actually initialized with, only ever set when it differs
	// from "postgres" — verified live: the official postgres image,
	// given POSTGRES_USER=something-else, replaces the bootstrap
	// superuser entirely rather than adding a second role, so there is
	// no "postgres" role at all to connect as (peer auth fails with
	// "role postgres does not exist", not a permissions error). Empty
	// means the default "postgres"; only ever meaningful for kind ==
	// "postgres".
	Username string `json:"username,omitempty"`
}
