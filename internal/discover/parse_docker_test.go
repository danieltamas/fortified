package discover

import (
	"reflect"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

// TestParseComposeFilesDropsLeakedFindStderr reproduces a real find
// against a live WSL2 Ubuntu server: its sshd merged find's own
// "Permission denied" diagnostics (expected, from scanning the whole
// filesystem as a non-root user) into what this command's stdout
// contained, corrupting the compose-file list with a line that isn't
// a path at all. parseComposeFiles must filter these out rather than
// propagate them into an archive: entry.
func TestParseComposeFilesDropsLeakedFindStderr(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdDockerComposeFiles] = sshx.Result{Stdout: "find: ‘/root’: Permission denied\n" +
		"/usr/src/paperclip/docker-compose.yml\n" +
		"find: ‘/lost+found’: Permission denied\n" +
		"/home/vboxuser/twenty/docker-compose.yml\n" +
		"find: ‘/mnt/c/System Volume Information’: Permission denied\n"}

	got := parseComposeFiles(cap)
	want := []string{
		"/usr/src/paperclip/docker-compose.yml",
		"/home/vboxuser/twenty/docker-compose.yml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseComposeFiles = %v, want %v", got, want)
	}
}

func TestParseComposeFilesAcceptsYamlSuffixCaseInsensitively(t *testing.T) {
	cap := newCapture()
	cap.Results[cmdDockerComposeFiles] = sshx.Result{Stdout: "/app/docker-compose.YAML\n/svc/Docker-Compose.Yml\n"}

	got := parseComposeFiles(cap)
	want := []string{"/app/docker-compose.YAML", "/svc/Docker-Compose.Yml"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseComposeFiles = %v, want %v", got, want)
	}
}

func TestParseComposeFilesEmptyWhenCommandMissing(t *testing.T) {
	cap := newCapture()
	if got := parseComposeFiles(cap); got != nil {
		t.Errorf("parseComposeFiles with no captured result = %v, want nil", got)
	}
}
