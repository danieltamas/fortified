package sshx

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Session is one multiplexed SSH connection to a Target, reused across
// many Runner calls instead of a fresh handshake per command. discover
// alone issues over a dozen read-only calls per invocation; reconnecting
// for each risks tripping a hardened server's auth-failure threshold
// (observed live against host-2-example during Phase 2 fixture
// capture — this is not a hypothetical).
type Session struct {
	runner      Runner
	target      Target
	controlPath string
}

// controlArgs returns the -o ControlPath=... flag shared by every ssh
// invocation that opens, uses, or closes a given multiplexed socket.
func controlArgs(controlPath string) []string {
	return []string{"-o", "ControlPath=" + controlPath}
}

// destArgs returns the trailing `-p <port> user@host` (or whichever
// subset target actually specifies) shared by every ssh invocation
// against target — see Target's doc comment for why an unspecified
// Port/User is omitted entirely rather than filled with a default.
func destArgs(target Target) []string {
	var args []string
	if target.Port != 0 {
		args = append(args, "-p", strconv.Itoa(target.Port))
	}
	if target.User != "" {
		args = append(args, fmt.Sprintf("%s@%s", target.User, target.Host))
	} else {
		args = append(args, target.Host)
	}
	return args
}

// OpenSession starts the background master connection (ssh -MNf) at
// controlPath. Every Session.Run call afterward reuses it instead of
// renegotiating a new connection.
func OpenSession(ctx context.Context, runner Runner, target Target, controlPath string) (*Session, error) {
	args := append([]string{
		"-MNf",
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=60",
	}, controlArgs(controlPath)...)
	args = append(args, destArgs(target)...)

	if _, err := runner.Run(ctx, ReadOnly, "ssh", args, RunOptions{}); err != nil {
		return nil, fmt.Errorf("sshx: open multiplexed session to %s: %w", target.Host, err)
	}
	return &Session{runner: runner, target: target, controlPath: controlPath}, nil
}

// Run implements Runner: cmd and args are executed on the session's
// target over the existing multiplexed connection. Implementing the
// same interface ExecRunner does means callers like internal/backend/borg
// can be written once and work identically whether their Runner is
// local (Layer 3's local-repo integration tests) or remote over SSH
// (production) — the caller never branches on which.
//
// opts.Env is NOT forwarded by setting it on the local ssh process's
// own environment — vanilla ssh does not forward the client's
// environment to the remote session (that requires SendEnv/AcceptEnv
// on both ends, which we cannot assume any target has configured).
// Instead the assignments are prepended to the remote command line via
// `env` (e.g. `env BORG_PASSPHRASE=... borg create ...`), each
// shell-quoted like any other argument. This is exactly what SPEC.md
// §3 means by "passed via the SSH session's environment" — never
// written to a file on the target. Known trade-off, accepted rather
// than hidden: the value is briefly visible in `ps` output on both
// ends for the life of the command, same as any other CLI tool that
// passes secrets this way; it is never written to disk or logged
// (audit wraps the logical cmd/args, never this internal construction,
// and never includes opts.Env in what it records).
func (s *Session) Run(ctx context.Context, class Class, cmd string, args []string, opts RunOptions) (Result, error) {
	sshArgs := controlArgs(s.controlPath)
	sshArgs = append(sshArgs, destArgs(s.target)...)
	sshArgs = append(sshArgs, "--")

	words := remoteWords(opts.Env, cmd, args)
	if opts.Dir != "" {
		// A working directory needs shell semantics (`cd ... &&`), so
		// the whole logical command becomes one quoted script passed
		// to `sh -c` — same shellQuoteIfNeeded mechanism, just wrapping
		// the entire line instead of each word separately.
		script := "cd " + shellQuoteIfNeeded(opts.Dir) + " && " + joinQuoted(words)
		sshArgs = append(sshArgs, "sh", "-c", shellQuoteIfNeeded(script))
	} else {
		sshArgs = append(sshArgs, quoteWords(words)...)
	}

	localOpts := opts
	localOpts.Env = nil
	localOpts.Dir = ""
	result, err := s.runner.Run(ctx, class, "ssh", sshArgs, localOpts)
	if err != nil {
		// Never propagate err as-is: the underlying Runner (ExecRunner)
		// formats its own error using the args it was given, which for
		// a Session call is sshArgs — and sshArgs embeds opts.Env's
		// assignments as literal words (the only way to deliver them
		// without server-side env forwarding, see above). Echoing err
		// here would put a secret in plain text into whatever the
		// caller logs or prints. Rebuild the message from cmd/args (the
		// caller's own logical command, never secret-bearing) and the
		// exit code/stderr the remote process actually reported.
		return result, fmt.Errorf("%s %v over ssh session: exit %d: %s", cmd, args, result.ExitCode, result.Stderr)
	}
	return result, nil
}

// remoteWords orders the words that make up one logical remote
// command: an `env VAR=val ...` prefix (see Run's doc comment) when
// env vars are needed, then cmd, then args.
func remoteWords(env []string, cmd string, args []string) []string {
	words := make([]string, 0, len(env)+1+len(args))
	if len(env) > 0 {
		words = append(words, "env")
		words = append(words, env...)
	}
	words = append(words, cmd)
	words = append(words, args...)
	return words
}

func quoteWords(words []string) []string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = shellQuoteIfNeeded(w)
	}
	return quoted
}

func joinQuoted(words []string) string {
	return strings.Join(quoteWords(words), " ")
}

var _ Runner = (*Session)(nil)

// shellQuoteIfNeeded returns s unchanged when it contains no character
// the remote shell would treat specially — which is every argument
// discover's fixed commands ever pass, so their asserted argv is
// unaffected. Anything else (e.g. a "docker exec ... > file" shell
// script CreateArchive needs for redirection) is POSIX single-quoted.
//
// This exists because ssh does not preserve argv boundaries for the
// remote command: it joins all trailing arguments with a single space
// before handing them to the remote shell. An argument containing a
// space — like a Go template string — gets silently split into two
// words remotely (this happened in Phase 2: `--format {{json .}}`
// became `--format {{json` plus a stray `.}}`, and docker rejected it).
// Quoting only the arguments that need it keeps that failure mode from
// recurring without changing the wire shape of anything simple.
func shellQuoteIfNeeded(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"$`\\;|&<>(){}*?[]~#") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Close tears down the multiplexed connection (ssh -O exit).
func (s *Session) Close(ctx context.Context) error {
	args := append([]string{"-O", "exit"}, controlArgs(s.controlPath)...)
	args = append(args, destArgs(s.target)...)
	if _, err := s.runner.Run(ctx, ReadOnly, "ssh", args, RunOptions{}); err != nil {
		return fmt.Errorf("sshx: close session to %s: %w", s.target.Host, err)
	}
	return nil
}
