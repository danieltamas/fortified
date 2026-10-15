package sshx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
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
// Nor does it go on the remote command line: argv is readable by any
// user via `ps` on both ends, which is how a BORG_PASSPHRASE leaked
// there. Instead the assignments are written to the remote command's
// stdin, one per line and ended by a blank line, ahead of opts.Stdin;
// a fixed `sh -c` prelude reads and exports them, then execs cmd with
// the rest of stdin. This is what SPEC.md §3 means by "passed via the
// SSH session's environment" — never argv, never a file on the target.
func (s *Session) Run(ctx context.Context, class Class, cmd string, args []string, opts RunOptions) (Result, error) {
	sshArgs := controlArgs(s.controlPath)
	sshArgs = append(sshArgs, destArgs(s.target)...)
	sshArgs = append(sshArgs, "--")

	localOpts := opts
	localOpts.Env = nil
	localOpts.Dir = ""
	if opts.LiveStderr != nil && len(opts.Env) > 0 {
		live := &redactingWriter{w: opts.LiveStderr, env: opts.Env}
		defer live.flush()
		localOpts.LiveStderr = live
	}

	words := append([]string{cmd}, args...)
	switch {
	case len(opts.Env) > 0:
		envLines, err := stdinEnvLines(opts.Env)
		if err != nil {
			return Result{}, fmt.Errorf("%s %v over ssh session: %w", cmd, args, err)
		}
		localOpts.Stdin = envLines + opts.Stdin
		script := stdinEnvPrelude
		if opts.Dir != "" {
			script += "cd " + shellQuoteIfNeeded(opts.Dir) + " && "
		}
		script += `exec "$@"`
		sshArgs = append(sshArgs, "sh", "-c", shellQuoteIfNeeded(script), "sh")
		sshArgs = append(sshArgs, quoteWords(words)...)
	case opts.Dir != "":
		// A working directory needs shell semantics (`cd ... &&`), so
		// the whole logical command becomes one quoted script passed
		// to `sh -c` — same shellQuoteIfNeeded mechanism, just wrapping
		// the entire line instead of each word separately.
		script := "cd " + shellQuoteIfNeeded(opts.Dir) + " && " + joinQuoted(words)
		sshArgs = append(sshArgs, "sh", "-c", shellQuoteIfNeeded(script))
	default:
		sshArgs = append(sshArgs, quoteWords(words)...)
	}

	result, err := s.runner.Run(ctx, class, "ssh", sshArgs, localOpts)
	if err != nil {
		// Never propagate err as-is: the underlying Runner (ExecRunner)
		// formats its own error from sshArgs, the transport-level
		// construction, not the caller's command. Rebuild the message
		// from cmd/args (the caller's own logical command, never
		// secret-bearing) and the exit code/stderr the remote process
		// actually reported.
		// The remote side can still echo a value back (a tool printing
		// its environment, a shell quoting a rejected line), so env
		// values are redacted from stderr before it's returned or wrapped
		// (and from LiveStderr as it streams, above).
		result.Stderr = redactEnvValues(result.Stderr, opts.Env)
		return result, fmt.Errorf("%s %v over ssh session: exit %d: %s", cmd, args, result.ExitCode, result.Stderr)
	}
	return result, nil
}

// stdinEnvPrelude reads NAME=value lines from stdin up to the first
// blank line and exports each one. sh's read builtin consumes a pipe
// one byte at a time, so whatever follows the blank line is left
// intact for the exec'd command. It exits 125 on a line export
// rejects rather than running the command without its environment.
const stdinEnvPrelude = `while IFS= read -r fortified_env && [ -n "$fortified_env" ]; do export "$fortified_env" || exit 125; done; unset fortified_env; `

// stdinEnvPreludeVar is the prelude's own loop variable; an Env entry
// of that name would be overwritten by the next line read.
const stdinEnvPreludeVar = "fortified_env"

// envNamePattern is what `export` accepts as a name. Anything else
// makes export fail and print the whole NAME=value line to stderr.
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// stdinEnvLines renders env for stdinEnvPrelude. A value containing a
// newline can't survive the line protocol and would be truncated, so
// it's refused instead of delivered partially.
func stdinEnvLines(env []string) (string, error) {
	var b strings.Builder
	for i, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || !envNamePattern.MatchString(name) || name == stdinEnvPreludeVar {
			return "", fmt.Errorf("env entry %d is not NAME=value with a valid, non-reserved name", i)
		}
		if strings.ContainsAny(kv, "\n\r") {
			return "", fmt.Errorf("env %s: value contains a newline", name)
		}
		b.WriteString(kv)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.String(), nil
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

// redactEnvValues replaces every non-empty value from env found in s,
// longest first, so a value that contains another is never left
// partly exposed by the shorter one's replacement.
func redactEnvValues(s string, env []string) string {
	var values []string
	for _, kv := range env {
		if _, value, ok := strings.Cut(kv, "="); ok && value != "" {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, value := range values {
		s = strings.ReplaceAll(s, value, "[redacted]")
	}
	return s
}

// redactingWriter applies redactEnvValues to a live stderr stream. It
// holds output back until a line ends (\n, or the \r a progress line
// redraws with), so a value split across two writes is still caught.
type redactingWriter struct {
	w   io.Writer
	env []string
	buf []byte
}

func (r *redactingWriter) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	if end := bytes.LastIndexAny(r.buf, "\r\n"); end >= 0 {
		line := redactEnvValues(string(r.buf[:end+1]), r.env)
		r.buf = append(r.buf[:0], r.buf[end+1:]...)
		if _, err := io.WriteString(r.w, line); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// flush writes whatever trailing output never ended its line.
func (r *redactingWriter) flush() {
	if len(r.buf) > 0 {
		_, _ = io.WriteString(r.w, redactEnvValues(string(r.buf), r.env))
		r.buf = nil
	}
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
