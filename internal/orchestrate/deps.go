// Package orchestrate wires the tested internals (discover, the
// provider/backend interfaces, config, secrets, state) into the
// actual onboard/backup/verify/enable-snapshots sequences SPEC.md §5
// describes. Every function here takes an already-connected Deps —
// this package never opens an SSH session, resolves a secret from a
// reference, or reads a config file itself — mirroring the shape
// internal/discover's Inspect established: the caller (cmd/fortified)
// owns connection lifecycle, this package only consumes it. That is
// what makes the whole onboard/backup/verify sequence unit-testable
// end to end against a scripted FakeRunner (SPEC.md §8), with no live
// SSH access required.
package orchestrate

import (
	"fmt"
	"io"

	"github.com/danieltamas/fortified/internal/backend/borg"
	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
)

// Deps bundles what every orchestration step needs for one server.
type Deps struct {
	// Target is the runner for the protected server itself — discover,
	// every borg/docker-exec call, the automation keypair's generation,
	// and its post-install append-only verification all run here
	// (SPEC.md §3's execution topology, and the keypair's "generated on
	// the target, never leaves it" isolation rule).
	Target sshx.Runner

	// StorageBox is the runner for the Hetzner Storage Box *main
	// account*'s SFTP calls (the authorized_keys write) — this must run
	// from the control host, since the main account credential must
	// never reach a protected server (NOTES.md).
	StorageBox sshx.Runner

	// Local runs a command on the control host itself, never through
	// the target's SSH session — Prune is the one command that needs
	// this: its --prune-key must never be read from the protected
	// server's filesystem, so borg prune dials the Storage Box directly
	// from here instead of reusing Target's connection (SPEC.md §5's
	// dual-key model; see borg.Backend.Prune's own doc comment).
	Local sshx.Runner

	Provider hetzner.Provider
	Backend  borg.Backend
	Secrets  secrets.Resolver

	StateDir string
	Server   config.Server
	ServerID string

	// Progress, if non-nil, is called with a short human-readable
	// message as each meaningful step starts and finishes — purely a
	// reporting hook, never read back by any orchestration logic, so a
	// nil Progress (the zero value every existing test uses) is always
	// safe and changes no behavior. This is what gives a long-running
	// command (onboard, backup, verify) live feedback instead of going
	// silent until it either succeeds or fails.
	Progress func(msg string)

	// LiveOutput, if non-nil, receives a long-running remote command's
	// own live progress output as it's produced (currently: `borg
	// create --progress --stats`'s stderr) — a raw tee, not parsed.
	// Nil (every existing test) means no live streaming, same as
	// before this field existed.
	LiveOutput io.Writer
}

// reportProgress calls Progress if set, formatting msg first — the one
// place every step-reporting call site goes through, so nil-checking
// isn't repeated everywhere.
func (d Deps) reportProgress(format string, args ...any) {
	if d.Progress == nil {
		return
	}
	d.Progress(fmt.Sprintf(format, args...))
}
