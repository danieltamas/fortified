package sshx_test

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func envStdinSession(t *testing.T, fake sshx.Runner) *sshx.Session {
	t.Helper()
	s, err := sshx.OpenSession(context.Background(), fake, sshx.Target{Host: "test-host"}, "/tmp/env-acceptance.sock")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type liveStderrRunner func(sshx.RunOptions) (sshx.Result, error)

func (run liveStderrRunner) Run(_ context.Context, _ sshx.Class, _ string, _ []string, opts sshx.RunOptions) (sshx.Result, error) {
	if opts.LiveStderr == nil {
		return sshx.Result{}, nil // Opening the multiplexed session.
	}
	return run(opts)
}

func TestSessionEnvLiveStderrRedactsChunks(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			var live bytes.Buffer
			runner := liveStderrRunner(func(opts sshx.RunOptions) (sshx.Result, error) {
				// Like os/exec, finish the stderr copy goroutine before returning.
				done := make(chan struct{})
				go func() {
					defer close(done)
					for _, step := range []struct{ chunk, want string }{
						{"start first-", ""},
						{"secret and second=secret", ""},
						{"\nprogress first-", "start [redacted] and [redacted]\n"},
						{"secret 10%\r", "start [redacted] and [redacted]\nprogress [redacted] 10%\r"},
						{"progress second=secret 20%\r\ntrailing first-", "start [redacted] and [redacted]\nprogress [redacted] 10%\rprogress [redacted] 20%\r\n"},
						{"secret / second=secret", "start [redacted] and [redacted]\nprogress [redacted] 10%\rprogress [redacted] 20%\r\n"},
					} {
						n, err := opts.LiveStderr.Write([]byte(step.chunk))
						if err != nil || n != len(step.chunk) {
							t.Errorf("Write = (%d, %v), want (%d, nil)", n, err, len(step.chunk))
						}
						if got := live.String(); got != step.want {
							t.Errorf("live output = %q, want %q", got, step.want)
						}
					}
				}()
				<-done
				if failed {
					return sshx.Result{ExitCode: 7}, errors.New("command failed")
				}
				return sshx.Result{}, nil
			})
			s := envStdinSession(t, runner)
			_, err := s.Run(context.Background(), sshx.ReadOnly, "command", nil, sshx.RunOptions{
				Env: []string{"FIRST=first-secret", "SECOND=second=secret", "EMPTY="}, LiveStderr: &live,
			})
			if (err != nil) != failed {
				t.Fatalf("Run error = %v, want failure %v", err, failed)
			}
			want := "start [redacted] and [redacted]\nprogress [redacted] 10%\rprogress [redacted] 20%\r\ntrailing [redacted] / [redacted]"
			if got := live.String(); got != want {
				t.Fatalf("final live output = %q, want %q", got, want)
			}
		})
	}
}

func TestSessionWithoutEnvPassesLiveStderrThrough(t *testing.T) {
	var live bytes.Buffer
	runner := liveStderrRunner(func(opts sshx.RunOptions) (sshx.Result, error) {
		if opts.LiveStderr != &live {
			t.Fatal("LiveStderr must be passed through unchanged without Env")
		}
		for _, chunk := range []string{"first-secret", "\rprogress\n", "unterminated"} {
			if _, err := opts.LiveStderr.Write([]byte(chunk)); err != nil {
				t.Fatal(err)
			}
		}
		if live.String() != "first-secret\rprogress\nunterminated" {
			t.Fatal("unbuffered live output changed or was held back")
		}
		return sshx.Result{}, nil
	})
	s := envStdinSession(t, runner)
	if _, err := s.Run(context.Background(), sshx.ReadOnly, "command", nil, sshx.RunOptions{LiveStderr: &live}); err != nil {
		t.Fatal(err)
	}
}

// SSH joins the words after -- for the remote login shell to parse.
func envRemoteLine(t *testing.T, call sshxtest.Call) string {
	t.Helper()
	for i, arg := range call.Args {
		if arg == "--" {
			return strings.Join(call.Args[i+1:], " ")
		}
	}
	t.Fatal("ssh invocation missing --")
	return ""
}

func TestSessionEnvStdinAcceptance(t *testing.T) {
	for _, payload := range []string{"", "input\n\nwith\\bytes\x00and no final newline"} {
		t.Run(map[bool]string{true: "without stdin", false: "with stdin"}[payload == ""], func(t *testing.T) {
			fake := &sshxtest.FakeRunner{}
			s := envStdinSession(t, fake)
			env := []string{"BORG_PASSPHRASE=first-secret", "PGPASSWORD=second-secret", "MYSQL_PWD=third-secret"}
			if _, err := s.Run(context.Background(), sshx.ReadOnly, "cat", nil, sshx.RunOptions{Env: env, Stdin: payload}); err != nil {
				t.Fatal(err)
			}
			if len(fake.Calls) != 2 {
				t.Fatalf("calls = %d, want open and run", len(fake.Calls))
			}
			call := fake.Calls[1]
			if call.Stdin != strings.Join(env, "\n")+"\n\n"+payload {
				t.Fatal("stdin must contain ordered assignments, blank line, then unchanged payload")
			}
			if len(call.Env) != 0 {
				t.Fatal("local ssh received Env")
			}
			for _, arg := range call.Args {
				for _, value := range []string{"first-secret", "second-secret", "third-secret"} {
					if strings.Contains(arg, value) {
						t.Fatal("secret reached argv")
					}
				}
			}
			line := envRemoteLine(t, call)
			if !strings.HasPrefix(line, "sh -c '") || !strings.HasSuffix(line, `exec "$@"' sh cat`) {
				t.Fatalf("unexpected remote command shape: %s", line)
			}
		})
	}
}

func TestSessionEnvRejectsInvalidEntriesBeforeRun(t *testing.T) {
	for _, tc := range []struct{ name, entry, value string }{
		{"no equals", "missing-equals-secret", "missing-equals-secret"},
		{"empty name", "=empty-name-secret", "empty-name-secret"},
		{"hyphen in name", "BAD-NAME=hyphen-secret", "hyphen-secret"},
		{"leading digit", "1X=digit-secret", "digit-secret"},
		{"reserved name", "fortified_env=reserved-secret", "reserved-secret"},
		{"newline", "PGPASSWORD=line-secret\nnext", "line-secret"},
		{"carriage return", "MYSQL_PWD=cr-secret\rnext", "cr-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &sshxtest.FakeRunner{}
			s := envStdinSession(t, fake)
			_, err := s.Run(context.Background(), sshx.ReadOnly, "cat", nil, sshx.RunOptions{Env: []string{"VALID=prior-secret", tc.entry}})
			if err == nil {
				t.Fatal("invalid Env accepted")
			}
			if len(fake.Calls) != 1 {
				t.Fatal("invalid Env invoked runner after session open")
			}
			if strings.Contains(err.Error(), tc.value) || strings.Contains(err.Error(), "prior-secret") {
				t.Fatal("validation error contains an Env value")
			}
		})
	}
}

func TestSessionWithoutEnvPreservesWireShape(t *testing.T) {
	for _, tc := range []struct {
		name, dir string
		words     []string
	}{
		{"plain", "", []string{"printf", "%s", "'two words'"}},
		{"dir only", "/tmp/work", []string{"sh", "-c", "'cd /tmp/work && printf %s '\\''two words'\\'''"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &sshxtest.FakeRunner{}
			s := envStdinSession(t, fake)
			if _, err := s.Run(context.Background(), sshx.ReadOnly, "printf", []string{"%s", "two words"}, sshx.RunOptions{Dir: tc.dir, Stdin: "unchanged"}); err != nil {
				t.Fatal(err)
			}
			call := fake.Calls[1]
			want := append([]string{"-o", "ControlPath=/tmp/env-acceptance.sock", "test-host", "--"}, tc.words...)
			if !reflect.DeepEqual(call.Args, want) || call.Stdin != "unchanged" || len(call.Env) != 0 {
				t.Fatalf("unexpected legacy wire shape: %+v; want argv %v", call, want)
			}
		})
	}
}

func TestSessionEnvPreludeThroughLocalShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	for _, withDir := range []bool{false, true} {
		t.Run(map[bool]string{false: "env", true: "env and dir"}[withDir], func(t *testing.T) {
			fake := &sshxtest.FakeRunner{}
			s := envStdinSession(t, fake)
			value := "  spaces 'quotes' \"double\" $dollar = equals \\backslash ;|"
			payload := "following\n\nstdin\\unchanged\x00last"
			dir := ""
			if withDir {
				dir = t.TempDir()
			}
			script := `printf '%s\n' "$ACCEPTANCE_SECRET" "$ACCEPTANCE_EMPTY"; if [ -n "$1" ]; then [ "$PWD" = "$1" ] || exit 41; fi; cat`
			_, err := s.Run(context.Background(), sshx.ReadOnly, "sh", []string{"-c", script, "sh", dir}, sshx.RunOptions{
				Env: []string{"ACCEPTANCE_SECRET=" + value, "ACCEPTANCE_EMPTY="}, Dir: dir, Stdin: payload,
			})
			if err != nil {
				t.Fatal(err)
			}
			call := fake.Calls[1]
			cmd := exec.CommandContext(context.Background(), "sh", "-c", envRemoteLine(t, call)) //nolint:gosec // executes only the command captured from this test's trusted fixtures to exercise the SSH shell boundary
			// A reader (rather than a file) makes os/exec use a pipe, as SSH does.
			cmd.Stdin = strings.NewReader(call.Stdin)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("remote shell failed: %v: %s", err, out)
			}
			if string(out) != value+"\n\n"+payload {
				t.Fatalf("exported values or remaining stdin changed: %q", out)
			}
		})
	}
}

func TestSessionFailedRunRedactsEnvFromStderrError(t *testing.T) {
	const value = "stderr-secret-sentinel"
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{}, {
		Result: sshx.Result{ExitCode: 7, Stderr: "command rejected " + value}, Err: errors.New("failed " + value),
	}}}
	s := envStdinSession(t, fake)
	result, err := s.Run(context.Background(), sshx.ReadOnly, "false", nil, sshx.RunOptions{Env: []string{"PGPASSWORD=" + value}})
	if err == nil || result.ExitCode != 7 {
		t.Fatal("failed run must preserve exit status and return an error")
	}
	if result.Stderr != "command rejected [redacted]" {
		t.Fatal("returned stderr must redact the Env value and preserve surrounding text")
	}
	if strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "command rejected [redacted]") {
		t.Fatal("failed run error must contain redacted stderr without the Env value")
	}
}
