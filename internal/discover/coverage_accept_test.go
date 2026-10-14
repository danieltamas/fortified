package discover

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestDatabaseDataDirAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name, image, inspect, want string
	}{
		{"postgres default with config mounts", "postgres:17", `[{"Config":{"Image":"postgres:17"},"Mounts":[{"Type":"bind","Source":"/srv/pg/data","Destination":"/var/lib/postgresql/data"},{"Type":"bind","Source":"/srv/pg/pg_hba.conf","Destination":"/var/lib/postgresql/data/pg_hba.conf"},{"Type":"bind","Source":"/srv/pg/postgresql.conf","Destination":"/var/lib/postgresql/data/postgresql.conf"}]}]`, "/srv/pg/data"},
		{"postgres 18 parent and most specific mount", "postgres:18", `[{"Config":{"Image":"postgres:18","Env":["PGDATA=/var/lib/postgresql/18/docker"]},"Mounts":[{"Type":"bind","Source":"/srv/pg/config","Destination":"/var/lib/postgresql/18/docker/pg_hba.conf"},{"Type":"bind","Source":"/srv/pg/cluster","Destination":"/var/lib/postgresql"},{"Type":"bind","Source":"/srv/broad","Destination":"/var/lib"}]}]`, "/srv/pg/cluster"},
		{"config only is not data", "postgres:17", `[{"Config":{"Image":"postgres:17"},"Mounts":[{"Type":"bind","Source":"/srv/pg/pg_hba.conf","Destination":"/var/lib/postgresql/data/pg_hba.conf"}]}]`, ""},
		{"destination sibling is not parent", "postgres:17", `[{"Config":{"Image":"postgres:17"},"Mounts":[{"Type":"bind","Source":"/srv/unrelated","Destination":"/var/lib/postgresql/dat"}]}]`, ""},
		{"mariadb", "mariadb:11", `[{"Config":{"Image":"mariadb:11"},"Mounts":[{"Type":"bind","Source":"/srv/mysql/data","Destination":"/var/lib/mysql"},{"Type":"bind","Source":"/srv/mysql/my.cnf","Destination":"/etc/mysql/my.cnf"}]}]`, "/srv/mysql/data"},
		{"cockroach", "cockroachdb/cockroach:v25", `[{"Config":{"Image":"cockroachdb/cockroach:v25"},"Mounts":[{"Type":"bind","Source":"/srv/crdb/data","Destination":"/cockroach/cockroach-data"}]}]`, "/srv/crdb/data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cap := newCapture()
			cap.Results[dockerInspectKey("db")] = sshx.Result{Stdout: tc.inspect}
			dbs, missing, err := classifyDatabases([]Container{{Name: "db", Image: tc.image}}, cap)
			if err != nil || len(missing) != 0 || len(dbs) != 1 {
				t.Fatalf("classify = %v, missing %v, err %v", dbs, missing, err)
			}
			if dbs[0].DataDir != tc.want {
				t.Fatalf("DataDir = %q, want %q", dbs[0].DataDir, tc.want)
			}
		})
	}
}

func TestArchiveProposalExcludesDataDirsAcceptance(t *testing.T) {
	report := &Report{
		ComposeFiles:        []string{"/srv/pg/compose.yaml", "/srv/pg/data/nested/compose.yml"},
		Containers:          []Container{{ProjectDir: "/srv/labels"}},
		KnownStatePaths:     []string{"/etc/wireguard"},
		ContainerBindMounts: []string{"/srv/pg/data", "/srv/pg/data/nested", "/srv/pg/pg_hba.conf", "/srv/pg/datax", "/srv/standalone", "/srv/only-data"},
		Databases:           []DatabaseInstance{{DataDir: "/srv/pg/data"}, {DataDir: "/srv/only-data"}},
	}
	want := []config.ArchivePath{{Path: "/etc/wireguard"}, {Path: "/srv/labels"},
		{Path: "/srv/pg", Exclude: []string{"/srv/pg/data"}}, {Path: "/srv/standalone"}}
	if got := archiveCandidates(report); !reflect.DeepEqual(got, want) {
		t.Fatalf("proposal = %+v, want %+v", got, want)
	}
	// Also check the public emitted proposal uses that contract.
	fleet := EmitConfig(report, sshx.Target{Host: "example", Port: 22, User: "root"}, "hetzner", "backup")
	for _, srv := range fleet.Servers {
		if !reflect.DeepEqual(srv.Archive, want) {
			t.Fatalf("emitted archive = %+v, want %+v", srv.Archive, want)
		}
	}
}

func TestUncoveredPathsAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		archive   []config.ArchivePath
		covered   bool
	}{
		{"equal", "/srv/app", []config.ArchivePath{{Path: "/srv/app"}}, true},
		{"parent covers child", "/srv/app/data", []config.ArchivePath{{Path: "/srv/app"}}, true},
		{"sibling prefix", "/srv/appx", []config.ArchivePath{{Path: "/srv/app"}}, false},
		{"glob never covers directory", "/srv/app", []config.ArchivePath{{Path: "/srv", Glob: "*"}}, false},
		{"exclude equal", "/srv/app/data", []config.ArchivePath{{Path: "/srv/app", Exclude: []string{"/srv/app/data"}}}, false},
		{"exclude descendant", "/srv/app/data/nested", []config.ArchivePath{{Path: "/srv/app", Exclude: []string{"/srv/app/data"}}}, false},
		{"exclude sibling", "/srv/app/datax", []config.ArchivePath{{Path: "/srv/app", Exclude: []string{"/srv/app/data"}}}, true},
		{"child does not cover parent", "/srv/app", []config.ArchivePath{{Path: "/srv/app/data"}}, false},
		{"exclude applies across entries", "/srv/app/data", []config.ArchivePath{{Path: "/srv/app", Exclude: []string{"/srv/app/data"}}, {Path: "/srv/app/data"}}, false},
		{"empty archive", "/srv/app", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UncoveredPaths([]config.ArchivePath{{Path: tc.candidate}}, tc.archive)
			if tc.covered && len(got) != 0 {
				t.Fatalf("uncovered = %v, want none", got)
			}
			if !tc.covered && !reflect.DeepEqual(got, []string{tc.candidate}) {
				t.Fatalf("uncovered = %v, want [%s]", got, tc.candidate)
			}
		})
	}
	if got := UncoveredPaths(nil, nil); len(got) != 0 {
		t.Fatalf("nil candidates = %v", got)
	}
}

func TestCoverageScanTransportErrorAcceptance(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: errors.New("ssh connection lost")}}}
	if _, err := ScanArchiveCandidates(context.Background(), fake); err == nil {
		t.Fatal("scan must report transport failure instead of claiming an empty candidate list")
	}
}

func TestCoverageScanCandidatesAndScopeAcceptance(t *testing.T) {
	// Responses follow the existing scan's call order: ps, compose find,
	// five state checks, custom units, six state checks, then inspect.
	ps, err := json.Marshal(map[string]string{"Names": "app", "Image": "nginx:alpine", "Labels": "com.docker.compose.project=app,com.docker.compose.project.working_dir=/srv/label-app"})
	if err != nil {
		t.Fatal(err)
	}
	responses := []sshxtest.Response{
		{Result: sshx.Result{Stdout: string(ps)}},
		{Result: sshx.Result{Stdout: "/srv/compose-app/compose.yaml\n/srv/compose-app/sub/docker-compose.override.yml\n"}},
		{Result: sshx.Result{Stdout: "/etc/wireguard\n"}}, {}, {}, {}, {},
		{Result: sshx.Result{Stdout: "/etc/systemd/system/custom.service\n"}},
		{}, {}, {}, {}, {}, {},
		{Result: sshx.Result{Stdout: `[{"Mounts":[{"Type":"bind","Source":"/srv/bind-app","Destination":"/app"}]}]`}},
	}
	fake := &sshxtest.FakeRunner{Responses: responses}
	got, err := ScanArchiveCandidates(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	want := []config.ArchivePath{{Path: "/etc/systemd/system"}, {Path: "/etc/wireguard"}, {Path: "/srv/bind-app"}, {Path: "/srv/compose-app"}, {Path: "/srv/label-app"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scan = %+v, want %+v", got, want)
	}
	if len(fake.Responses) != 0 {
		t.Fatalf("unconsumed responses: %d", len(fake.Responses))
	}
	for _, call := range fake.Calls {
		if call.Class != sshx.ReadOnly {
			t.Errorf("scan mutates: %+v", call)
		}
		switch call.Cmd {
		case "docker", "find", "ls":
		default:
			t.Errorf("full inspection command in coverage scan: %+v", call)
		}
	}
	wantFind := []string{"/", "-maxdepth", "4", "(", "-iname", "docker-compose*.y*ml", "-o", "-iname", "compose.y*ml", ")"}
	if len(fake.Calls) < 2 || fake.Calls[1].Cmd != "find" || !reflect.DeepEqual(fake.Calls[1].Args, wantFind) {
		t.Fatalf("compose search must use depth 4 and both filename patterns: %+v", fake.Calls)
	}
}

func TestCoverageComposeFindSSHQuotingAcceptance(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	session, err := sshx.OpenSession(context.Background(), fake, sshx.Target{Host: "example", Port: 22, User: "root"}, "/tmp/coverage-acceptance.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close(context.Background()) }()
	if _, err := ScanArchiveCandidates(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	want := []string{"find", "/", "-maxdepth", "4", "'('", "-iname", "'docker-compose*.y*ml'", "-o", "-iname", "'compose.y*ml'", "')'"}
	for _, call := range fake.Calls {
		for i, arg := range call.Args {
			if arg == "find" && i+1 < len(call.Args) && call.Args[i+1] == "/" {
				if !reflect.DeepEqual(call.Args[i:], want) {
					t.Fatalf("remote find argv = %q, want %q (shell must preserve parentheses and patterns)", call.Args[i:], want)
				}
				return
			}
		}
	}
	t.Fatal("coverage scan did not invoke remote compose search")
}

func TestArchiveProposalRootExcludesDataAcceptance(t *testing.T) {
	got := archivePaths([]string{"/compose.yaml"}, nil, nil, []string{"/srv/pg/data"}, []string{"/srv/pg/data"})
	want := []config.ArchivePath{{Path: "/", Exclude: []string{"/srv/pg/data"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("root proposal = %+v, want %+v (data must still be excluded)", got, want)
	}
}
