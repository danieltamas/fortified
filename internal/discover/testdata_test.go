package discover

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

// loadCapture builds a Capture from a testdata fixture directory.
// Regular commands are stored as <name>.stdout/.stderr/.exitcode;
// docker inspect fixtures (which never touch git as raw captures —
// see PROGRESS.md) are stored as docker_inspect_<container>.json,
// read whole as stdout with exit code 0.
func loadCapture(t *testing.T, dir string) *Capture {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", dir, err)
	}

	cap := newCapture()
	seen := make(map[string]bool)
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".json"):
			key := commandKey(strings.TrimSuffix(name, ".json"))
			data := readFixture(t, filepath.Join(dir, name))
			cap.Results[key] = sshx.Result{Stdout: data}
		case strings.HasSuffix(name, ".stdout"):
			base := strings.TrimSuffix(name, ".stdout")
			if seen[base] {
				continue
			}
			seen[base] = true
			cap.Results[commandKey(base)] = sshx.Result{
				Stdout:   readFixture(t, filepath.Join(dir, base+".stdout")),
				Stderr:   readFixtureIfExists(filepath.Join(dir, base+".stderr")),
				ExitCode: readExitCode(t, filepath.Join(dir, base+".exitcode")),
			}
		}
	}
	return cap
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is built from a fixed testdata dir listing, not untrusted input
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return string(data)
}

func readFixtureIfExists(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // path is built from a fixed testdata dir listing, not untrusted input
	if err != nil {
		return ""
	}
	return string(data)
}

func readExitCode(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is built from a fixed testdata dir listing, not untrusted input
	if err != nil {
		t.Fatalf("read exitcode %s: %v", path, err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse exitcode %s: %v", path, err)
	}
	return code
}
