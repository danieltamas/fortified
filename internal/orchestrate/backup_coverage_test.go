package orchestrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

func TestBackupCoverageAdvisoryAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ps          sshxtest.Response
		wantWarning string
	}{
		{"uncovered compose project", sshxtest.Response{}, "warning: not archived: /srv/new-app"},
		{"malformed scan", sshxtest.Response{Result: sshx.Result{Stdout: "not-json"}}, "warning: archive coverage check failed:"},
		{"transport failure", sshxtest.Response{Err: errors.New("ssh connection lost")}, "warning: archive coverage check failed:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
			responses := []sshxtest.Response{
				{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
				{},    // mkdir
				{},    // manifest
				{},    // borg create
				{},    // workspace cleanup
				tc.ps, // coverage docker ps
				{Result: sshx.Result{Stdout: "/srv/new-app/compose.yaml\n"}}, // compose find
			}
			// Five state checks, custom units, six more state checks.
			responses = append(responses, make([]sshxtest.Response, 12)...)
			target := &sshxtest.FakeRunner{Responses: responses}
			d := testDeps(t, target)
			d.Server.Archive = []config.ArchivePath{{Path: "/srv/existing"}}
			if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
				t.Fatal(err)
			}
			var messages []string
			d.Progress = func(msg string) {
				messages = append(messages, msg)
				if strings.HasPrefix(msg, "warning:") {
					// Advisory output must follow successful state persistence.
					st, err := state.Load(d.StateDir, d.ServerID)
					if err != nil || st.Timestamps.LastBackup == nil || st.LastManifest == nil {
						t.Errorf("warning before saved backup state: state=%+v err=%v", st, err)
					}
				}
			}
			if err := Backup(context.Background(), d); err != nil {
				t.Fatalf("advisory scan must not fail Backup: %v", err)
			}
			found := false
			for _, msg := range messages {
				if strings.HasPrefix(msg, tc.wantWarning) {
					found = true
				}
			}
			if !found {
				t.Errorf("progress = %q, want %q", messages, tc.wantWarning)
			}
			st, err := state.Load(d.StateDir, d.ServerID)
			if err != nil {
				t.Fatal(err)
			}
			if st.Timestamps.LastBackup == nil || st.LastManifest == nil {
				t.Fatal("scan outcome must not erase successful backup state")
			}
			if len(target.Calls) < 6 || target.Calls[3].Cmd != "borg" || target.Calls[3].Args[0] != "create" || target.Calls[5].Cmd != "docker" {
				t.Fatalf("coverage must run after archive creation: %+v", target.Calls)
			}
		})
	}
}

func TestBackupCoverageNilProgressAcceptance(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, {}, {}, {}, {},
		{Result: sshx.Result{Stdout: "not-json"}},
	}}
	d := testDeps(t, target)
	d.Progress = nil
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatal(err)
	}
	if err := Backup(context.Background(), d); err != nil {
		t.Fatalf("nil progress with failed advisory scan: %v", err)
	}
}

func TestBackupForwardsConfiguredExcludesAcceptance(t *testing.T) {
	t.Setenv("FORTIFIED_TEST_PASSPHRASE", "test-passphrase")
	target := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, {}, {}, {}, {},
	}}
	d := testDeps(t, target)
	d.Server.Archive = []config.ArchivePath{{Path: "/srv/pg", Exclude: []string{"/srv/pg/data"}}}
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatal(err)
	}
	if err := Backup(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	args := target.Calls[3].Args
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--exclude" && args[i+1] == "pp:/srv/pg/data" && strings.Contains(args[i+2], "::") {
			return
		}
	}
	t.Fatalf("backup did not forward exclude before archive: %q", args)
}
