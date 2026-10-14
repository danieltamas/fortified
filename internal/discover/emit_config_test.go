package discover

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/sshx"
)

func realReport(t *testing.T) *Report {
	t.Helper()
	cap := loadCapture(t, filepath.Join("testdata", "host-2-example"))
	report, err := Parse("host-2-example", cap, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return report
}

func TestEmitConfigTodoBlocksOnboard(t *testing.T) {
	report := realReport(t)
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	fleet := EmitConfig(report, target, "hetzner", "host2-backup")

	yamlBytes, err := RenderYAML(fleet)
	if err != nil {
		t.Fatalf("RenderYAML: %v", err)
	}

	path := filepath.Join(t.TempDir(), "fleet.yaml")
	if err := os.WriteFile(path, yamlBytes, 0o600); err != nil {
		t.Fatalf("write emitted config: %v", err)
	}

	// Unfilled, it must contain TODO and onboard (config.Load) must
	// refuse it.
	if !strings.Contains(string(yamlBytes), "TODO") {
		t.Fatal("expected emitted config to contain at least one TODO placeholder")
	}
	if _, err := config.Load(path); !errors.Is(err, config.ErrUnresolvedTODO) {
		t.Fatalf("config.Load(unfilled emitted config) error = %v, want ErrUnresolvedTODO", err)
	}
}

// TestEmitConfigUnionsKnownStatePaths proves a well-known stateful
// path (e.g. /etc/wireguard) reaches the emitted archive: list
// alongside compose-derived directories, deduped against any overlap.
func TestEmitConfigUnionsKnownStatePaths(t *testing.T) {
	report := realReport(t)
	report.KnownStatePaths = []string{"/etc/wireguard", "/home/docker/mysql"} // second one overlaps a compose dir
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}

	fleet := EmitConfig(report, target, "hetzner", "host2-backup")
	srv := fleet.Servers["host-2-example"]

	var paths []string
	for _, a := range srv.Archive {
		paths = append(paths, a.Path)
	}

	if !slices.Contains(paths, "/etc/wireguard") {
		t.Errorf("archive paths = %v, want /etc/wireguard included", paths)
	}
	seen := make(map[string]int)
	for _, p := range paths {
		seen[p]++
	}
	if seen["/home/docker/mysql"] != 1 {
		t.Errorf("archive paths = %v, want /home/docker/mysql exactly once despite appearing in both sources", paths)
	}
}

// TestEmitConfigUnionsContainerBindMounts proves a container's own
// bind-mount source path (report.ContainerBindMounts, populated from
// docker inspect data no compose-file heuristic would ever find)
// reaches the emitted archive list alongside compose-derived
// directories, deduped against any overlap — mirrors
// TestEmitConfigUnionsKnownStatePaths for the same union in
// archivePaths.
func TestEmitConfigUnionsContainerBindMounts(t *testing.T) {
	report := realReport(t)
	report.ContainerBindMounts = []string{"/home/redis-stack/data", "/home/docker/mysql"} // second one overlaps a compose dir
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}

	fleet := EmitConfig(report, target, "hetzner", "host2-backup")
	srv := fleet.Servers["host-2-example"]

	var paths []string
	for _, a := range srv.Archive {
		paths = append(paths, a.Path)
	}

	if !slices.Contains(paths, "/home/redis-stack/data") {
		t.Errorf("archive paths = %v, want /home/redis-stack/data included", paths)
	}
	seen := make(map[string]int)
	for _, p := range paths {
		seen[p]++
	}
	if seen["/home/docker/mysql"] != 1 {
		t.Errorf("archive paths = %v, want /home/docker/mysql exactly once despite appearing in both sources", paths)
	}
}

// TestArchivePathsDropsPathsAlreadyCoveredByAParent proves a
// container's own bind-mount sources nested inside a directory
// already proposed (via its compose file, a known-state path, or
// another bind mount) are collapsed away rather than listed
// separately — verified live: without this, host-example's emitted
// config listed /home/psql (from its docker-compose.yml) AND
// /home/psql/data, /home/psql/conf.d, /home/psql/pgbouncer/pgbouncer.ini,
// etc. as five more redundant entries the operator would have had to
// manually prune. A genuinely unrelated top-level bind mount
// (/home/redis-stack/data, no compose file of its own) must still
// survive untouched.
func TestArchivePathsDropsPathsAlreadyCoveredByAParent(t *testing.T) {
	composeFiles := []string{"/home/psql/docker-compose.yml"}
	knownStatePaths := []string{"/etc/nginx"}
	bindMounts := []string{
		"/home/psql/data",                    // covered by the /home/psql compose dir
		"/home/psql/pgbouncer/pgbouncer.ini", // also covered, two levels deep
		"/etc/nginx/maps/games.map",          // covered by the /etc/nginx known-state path
		"/home/redis-stack/data",             // NOT covered by anything — must survive
	}

	got := archivePaths(composeFiles, nil, knownStatePaths, bindMounts, nil)

	var paths []string
	for _, p := range got {
		paths = append(paths, p.Path)
	}
	want := []string{"/etc/nginx", "/home/psql", "/home/redis-stack/data"}
	if len(paths) != len(want) {
		t.Fatalf("archivePaths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("archivePaths[%d] = %q, want %q", i, paths[i], want[i])
		}
	}
}

func TestEmitConfigRoundTrip(t *testing.T) {
	report := realReport(t)
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	fleet := EmitConfig(report, target, "hetzner", "host2-backup")

	yamlBytes, err := RenderYAML(fleet)
	if err != nil {
		t.Fatalf("RenderYAML: %v", err)
	}

	// Simulate the operator filling every TODO.
	filled := strings.ReplaceAll(string(yamlBytes), "TODO", "secret://fortified/host-2-example/placeholder")

	path := filepath.Join(t.TempDir(), "fleet.yaml")
	if err := os.WriteFile(path, []byte(filled), 0o600); err != nil {
		t.Fatalf("write filled config: %v", err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load(filled emitted config) failed to round-trip: %v", err)
	}
	srv, ok := loaded.Servers["host-2-example"]
	if !ok {
		t.Fatal("expected a host-2-example entry in the round-tripped config")
	}
	if srv.SSH.Host != "203.0.113.10" || srv.SSH.Port != 15086 || srv.SSH.User != "root" {
		t.Errorf("SSH = %+v, want the target's connection details preserved", srv.SSH)
	}
	if len(srv.Databases) != len(report.Databases) {
		t.Errorf("Databases = %d entries, want %d", len(srv.Databases), len(report.Databases))
	}
}

func testDestination() ResolvedDestination {
	return ResolvedDestination{ //nolint:gosec // HCloudTokenRef below is a secret *reference* (env var name), never a literal credential
		Provider:         "hetzner",
		Destination:      "433593",
		HCloudTokenRef:   "env://HCLOUD_TOKEN",
		MainAccountHost:  "u123456.your-storagebox.de",
		MainAccountUser:  "u123456",
		EncryptionKeyRef: "env://BORG_PASSPHRASE_HOST_2_EXAMPLE",
	}
}

// TestBuildOrMergeServerConfigNewEntry proves a brand-new server (no
// existing entry at all) gets every field filled in from report/dest
// — nothing left as "TODO" the way EmitConfig always does.
func TestBuildOrMergeServerConfigNewEntry(t *testing.T) {
	report := realReport(t)
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	dest := testDestination()

	srv := BuildOrMergeServerConfig(nil, report, target, dest)

	if srv.SSH != (config.SSH{Host: "203.0.113.10", Port: 15086, User: "root"}) {
		t.Errorf("SSH = %+v, want the target's own connection details", srv.SSH)
	}
	if srv.Provider != "hetzner" || srv.Destination != "433593" {
		t.Errorf("Provider/Destination = %q/%q, want hetzner/433593", srv.Provider, srv.Destination)
	}
	if srv.EncryptionKeyRef != dest.EncryptionKeyRef {
		t.Errorf("EncryptionKeyRef = %q, want %q", srv.EncryptionKeyRef, dest.EncryptionKeyRef)
	}
	if len(srv.Archive) == 0 {
		t.Error("expected Archive to be populated from the report")
	}
	if len(srv.Databases) != len(report.Databases) {
		t.Errorf("Databases = %d entries, want %d", len(srv.Databases), len(report.Databases))
	}
	if srv.Hetzner == nil || srv.Hetzner.MainAccount.Host != dest.MainAccountHost || srv.Hetzner.HCloudTokenRef != dest.HCloudTokenRef {
		t.Errorf("Hetzner = %+v, want main_account.host=%q hcloud_token_ref=%q", srv.Hetzner, dest.MainAccountHost, dest.HCloudTokenRef)
	}
}

// TestBuildOrMergeServerConfigPreservesExistingFields proves an
// operator's own hand edits on an already-partially-configured server
// are never overwritten by a re-run of discover — the whole point of
// merge instead of always regenerating from scratch.
func TestBuildOrMergeServerConfigPreservesExistingFields(t *testing.T) {
	report := realReport(t)
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	dest := testDestination()

	existing := &config.Server{
		SSH:              config.SSH{Host: "custom.example.com", Port: 2222, User: "svc"},
		Provider:         "hetzner",
		Destination:      "999999", // operator already picked a different box by hand
		EncryptionKeyRef: "secret://fortified/host-2-example/borg-passphrase",
		Archive:          []config.ArchivePath{{Path: "/custom/only"}},
		Databases:        []config.Database{{Kind: "postgres", Container: "custom-psql", DumpStrategy: "docker-exec"}},
		Hetzner: &config.HetznerConfig{
			MainAccount:    config.SSH{Host: "custom.your-storagebox.de", Port: 23, User: "u999999"},
			HCloudTokenRef: "secret://fortified/hcloud-token",
		},
	}

	srv := BuildOrMergeServerConfig(existing, report, target, dest)

	if srv.SSH != existing.SSH {
		t.Errorf("SSH = %+v, want the existing hand-set value %+v preserved", srv.SSH, existing.SSH)
	}
	if srv.Destination != "999999" {
		t.Errorf("Destination = %q, want the existing hand-set value preserved, not dest's %q", srv.Destination, dest.Destination)
	}
	if srv.EncryptionKeyRef != existing.EncryptionKeyRef {
		t.Errorf("EncryptionKeyRef = %q, want the existing hand-set value preserved", srv.EncryptionKeyRef)
	}
	if len(srv.Archive) != 1 || srv.Archive[0].Path != "/custom/only" {
		t.Errorf("Archive = %+v, want the existing hand-set list preserved untouched", srv.Archive)
	}
	if len(srv.Databases) != 1 || srv.Databases[0].Container != "custom-psql" {
		t.Errorf("Databases = %+v, want the existing hand-set list preserved untouched", srv.Databases)
	}
	if srv.Hetzner.MainAccount.Host != "custom.your-storagebox.de" {
		t.Errorf("Hetzner.MainAccount = %+v, want the existing hand-set value preserved", srv.Hetzner.MainAccount)
	}
}

// TestBuildOrMergeServerConfigFillsOnlyEmptyFields proves a partially
// hand-written entry (SSH set, everything else blank — exactly what
// an operator might sketch out before ever running discover) gets
// only its empty fields filled in, not a wholesale replacement.
func TestBuildOrMergeServerConfigFillsOnlyEmptyFields(t *testing.T) {
	report := realReport(t)
	target := sshx.Target{Host: "203.0.113.10", Port: 15086, User: "root"}
	dest := testDestination()

	existing := &config.Server{
		SSH: config.SSH{Host: "custom.example.com", Port: 2222, User: "svc"},
	}

	srv := BuildOrMergeServerConfig(existing, report, target, dest)

	if srv.SSH != existing.SSH {
		t.Errorf("SSH = %+v, want the existing hand-set value preserved", srv.SSH)
	}
	if srv.Destination != dest.Destination {
		t.Errorf("Destination = %q, want it filled in from dest (%q) since it was empty", srv.Destination, dest.Destination)
	}
	if srv.EncryptionKeyRef != dest.EncryptionKeyRef {
		t.Errorf("EncryptionKeyRef = %q, want it filled in from dest (%q) since it was empty", srv.EncryptionKeyRef, dest.EncryptionKeyRef)
	}
	if len(srv.Archive) == 0 {
		t.Error("expected Archive to be filled in from the report since it was empty")
	}
}
