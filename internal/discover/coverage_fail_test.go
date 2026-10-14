package discover

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

// Match commands rather than response positions so a failure cannot silently
// migrate to docker ps if the scan's ordering changes.
type coverageFailureRunner struct {
	stage  string
	code   int
	err    error
	stderr string
	hit    bool
}

func (r *coverageFailureRunner) Run(_ context.Context, _ sshx.Class, cmd string, args []string, _ sshx.RunOptions) (sshx.Result, error) {
	stage := ""
	if cmd == "docker" && len(args) > 0 {
		stage = "docker " + args[0]
	} else if cmd == "find" && len(args) > 0 {
		stage = "find " + args[0]
	} else if cmd == "ls" {
		stage = "state ls"
	}
	if stage == r.stage && !r.hit {
		r.hit = true
		return sshx.Result{ExitCode: r.code, Stderr: r.stderr}, r.err
	}
	if stage == "docker ps" {
		return sshx.Result{Stdout: `{"Names":"app","Image":"nginx:alpine","State":"running","Labels":""}`}, nil
	}
	if stage == "docker inspect" {
		return sshx.Result{Stdout: `[{"Config":{"Image":"nginx:alpine"},"Mounts":[]}]`}, nil
	}
	return sshx.Result{}, nil
}

func TestCoverageScanNonRemoteFailuresAcceptance(t *testing.T) {
	for _, stage := range []string{"docker ps", "find /", "state ls", "find /etc/systemd/system", "docker inspect"} {
		for _, code := range []int{255, 0, -1} {
			t.Run(fmt.Sprintf("%s/exit_%d", stage, code), func(t *testing.T) {
				runner := &coverageFailureRunner{stage: stage, code: code, err: errors.New("injected connection or client failure")}
				_, err := ScanArchiveCandidates(context.Background(), runner)
				if !runner.hit {
					t.Fatalf("scan never exercised %s", stage)
				}
				if err == nil {
					t.Fatalf("%s error with exit %d must fail the coverage scan", stage, code)
				}
			})
		}
	}
}

func TestCoverageScanOrdinaryRemoteFailuresAcceptance(t *testing.T) {
	for _, tc := range []struct {
		stage     string
		code      int
		wantError bool
	}{
		{"find /", 1, false},
		{"find /etc/systemd/system", 1, false},
		{"state ls", 2, false},
		{"docker ps", 1, true},
		{"docker inspect", 1, true},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			runner := &coverageFailureRunner{stage: tc.stage, code: tc.code, err: errors.New("remote command failed")}
			_, err := ScanArchiveCandidates(context.Background(), runner)
			if !runner.hit {
				t.Fatalf("scan never exercised %s", tc.stage)
			}
			if (err != nil) != tc.wantError {
				t.Fatalf("scan error = %v, wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestCoverageScanDockerAbsentVersusUnavailableAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name      string
		code      int
		stderr    string
		wantError bool
	}{
		{"docker absent", 127, "sh: docker: command not found", false},
		{"docker socket absent", 1, "error during connect: dial unix /var/run/docker.sock: connect: No such file or directory", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &coverageFailureRunner{stage: "docker ps", code: tc.code, stderr: tc.stderr, err: errors.New("remote command failed")}
			_, err := ScanArchiveCandidates(context.Background(), runner)
			if !runner.hit {
				t.Fatal("scan never exercised docker ps")
			}
			if (err != nil) != tc.wantError {
				t.Fatalf("scan error = %v, wantError=%v", err, tc.wantError)
			}
		})
	}
}
