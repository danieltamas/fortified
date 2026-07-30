package main

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/sshx"
)

func TestDefaultEncryptionKeyRef(t *testing.T) {
	cases := map[string]string{
		"host-2-example":  "env://BORG_PASSPHRASE_HOST_2_EXAMPLE",
		"example-nodejs":  "env://BORG_PASSPHRASE_EXAMPLE_NODEJS",
		"app.example.com": "env://BORG_PASSPHRASE_APP_EXAMPLE_COM",
	}
	for serverID, want := range cases {
		if got := defaultEncryptionKeyRef(serverID); got != want {
			t.Errorf("defaultEncryptionKeyRef(%q) = %q, want %q", serverID, got, want)
		}
	}
}

func fleetWith(servers map[string]config.Server) *config.Fleet {
	return &config.Fleet{Servers: servers}
}

func hetznerServer(destination string) config.Server {
	return config.Server{
		Provider:    "hetzner",
		Destination: destination,
		Hetzner: &config.HetznerConfig{ //nolint:gosec // HCloudTokenRef below is a secret *reference* (env var name), never a literal credential
			MainAccount:    config.SSH{Host: "u123456.your-storagebox.de", Port: 23, User: "u123456"},
			HCloudTokenRef: "env://HCLOUD_TOKEN",
		},
	}
}

func TestSingleExistingDestinationEmptyFleet(t *testing.T) {
	if _, ok := singleExistingDestination(fleetWith(nil)); ok {
		t.Error("expected no destination for an empty fleet")
	}
}

func TestSingleExistingDestinationOneServerReused(t *testing.T) {
	fleet := fleetWith(map[string]config.Server{"a": hetznerServer("433593")})
	dest, ok := singleExistingDestination(fleet)
	if !ok {
		t.Fatal("expected a destination to be found")
	}
	if dest.Destination != "433593" || dest.MainAccountHost != "u123456.your-storagebox.de" || dest.HCloudTokenRef != "env://HCLOUD_TOKEN" {
		t.Errorf("dest = %+v, want the one server's destination reused", dest)
	}
}

func TestSingleExistingDestinationAmbiguousWhenServersDisagree(t *testing.T) {
	fleet := fleetWith(map[string]config.Server{
		"a": hetznerServer("433593"),
		"b": hetznerServer("999999"),
	})
	if _, ok := singleExistingDestination(fleet); ok {
		t.Error("expected no auto-selected destination when servers disagree")
	}
}

func TestExistingHCloudTokenRef(t *testing.T) {
	if got := existingHCloudTokenRef(fleetWith(nil)); got != "" {
		t.Errorf("existingHCloudTokenRef(empty) = %q, want empty", got)
	}
	srv := hetznerServer("433593")
	srv.Hetzner.HCloudTokenRef = "secret://fortified/hcloud-token"
	fleet := fleetWith(map[string]config.Server{"a": srv})
	if got := existingHCloudTokenRef(fleet); got != "secret://fortified/hcloud-token" {
		t.Errorf("existingHCloudTokenRef = %q, want the existing server's ref reused", got)
	}
}

func TestResolveSSHConfigDefaultsUsesAliasForFallbackTarget(t *testing.T) {
	orig := sshConfigResolver
	defer func() { sshConfigResolver = orig }()
	sshConfigResolver = func(alias string) ([]byte, error) {
		if alias != "example-nodejs" {
			t.Errorf("sshConfigResolver called with %q, want example-nodejs", alias)
		}
		return []byte("hostname example-nodejs\nport 2222\nuser svc\n"), nil
	}

	got := resolveSSHConfigDefaults("example-nodejs", sshx.Target{Host: "example-nodejs", Port: 0, User: ""})
	want := sshx.Target{Host: "example-nodejs", Port: 2222, User: "svc"}
	if got != want {
		t.Errorf("resolveSSHConfigDefaults = %+v, want %+v", got, want)
	}
}

func TestResolveSSHConfigDefaultsFallsBackWhenAliasResolutionFails(t *testing.T) {
	orig := sshConfigResolver
	defer func() { sshConfigResolver = orig }()
	sshConfigResolver = func(string) ([]byte, error) { return nil, errBoomSSH }

	got := resolveSSHConfigDefaults("example-nodejs", sshx.Target{Host: "example-nodejs"})
	want := sshx.Target{Host: "example-nodejs", Port: 22, User: "root"}
	if got != want {
		t.Errorf("resolveSSHConfigDefaults = %+v, want the conventional ssh defaults %+v", got, want)
	}
}

func TestResolveSSHConfigDefaultsNeverConsultsAliasForExplicitHost(t *testing.T) {
	orig := sshConfigResolver
	defer func() { sshConfigResolver = orig }()
	sshConfigResolver = func(alias string) ([]byte, error) {
		t.Fatal("sshConfigResolver must not be called for an explicit --host target")
		return nil, nil
	}

	got := resolveSSHConfigDefaults("example-nodejs", sshx.Target{Host: "1.2.3.4"})
	want := sshx.Target{Host: "1.2.3.4", Port: 22, User: "root"}
	if got != want {
		t.Errorf("resolveSSHConfigDefaults = %+v, want %+v", got, want)
	}
}

func TestResolveSSHConfigDefaultsLeavesExplicitValuesAlone(t *testing.T) {
	orig := sshConfigResolver
	defer func() { sshConfigResolver = orig }()
	sshConfigResolver = func(string) ([]byte, error) {
		t.Fatal("sshConfigResolver must not be called when Port/User are both already explicit")
		return nil, nil
	}

	target := sshx.Target{Host: "example-nodejs", Port: 2200, User: "svc"}
	if got := resolveSSHConfigDefaults("example-nodejs", target); got != target {
		t.Errorf("resolveSSHConfigDefaults = %+v, want it left untouched", got)
	}
}

var errBoomSSH = &sshErr{"boom"}

type sshErr struct{ msg string }

func (e *sshErr) Error() string { return e.msg }

// destinationFakeTransport is a minimal Layer-1 http.RoundTripper test
// double for the Hetzner API calls resolveDestination makes — mirrors
// internal/provider/hetzner's own fakeTransport, kept package-local
// since that one is unexported.
type destinationFakeTransport struct {
	t         *testing.T
	responses map[string]string
	calls     []string
}

func newDestinationFakeTransport(t *testing.T) *destinationFakeTransport {
	t.Helper()
	return &destinationFakeTransport{t: t, responses: make(map[string]string)}
}

func (f *destinationFakeTransport) stub(method, path, body string) {
	f.responses[method+" "+path] = body
}

func (f *destinationFakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path
	f.calls = append(f.calls, key)
	body, ok := f.responses[key]
	if !ok {
		f.t.Fatalf("destinationFakeTransport: no stubbed response for %s (calls so far: %v)", key, f.calls)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

const oneBoxJSON = `{"storage_boxes":[{"id":123,"username":"u123456","status":"active","name":"main","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":"u123456.your-storagebox.de","system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"}]}`

const twoBoxJSON = `{"storage_boxes":[` +
	`{"id":123,"username":"u123456","status":"active","name":"main","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":"u123456.your-storagebox.de","system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"},` +
	`{"id":456,"username":"u456789","status":"active","name":"secondary","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":"u456789.your-storagebox.de","system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"}` +
	`]}`

// TestResolveDestinationReusesSingleExistingWithoutAnyHTTPCall proves
// the common case — a fleet that already agrees on one Storage Box —
// never needs HCLOUD_TOKEN resolved or the Hetzner API touched at
// all: verified live against a real "fortified discover" run, which
// failed with "environment variable not set: HCLOUD_TOKEN" for a
// brand-new server even though its destination was already sitting,
// fully resolved, in fleet.yaml.
func TestResolveDestinationReusesSingleExistingWithoutAnyHTTPCall(t *testing.T) {
	if err := os.Unsetenv("HCLOUD_TOKEN"); err != nil { // deliberately unset — must not be needed for this path
		t.Fatalf("os.Unsetenv: %v", err)
	}
	transport := newDestinationFakeTransport(t) // no stubs — any call fails the test
	fleet := fleetWith(map[string]config.Server{"a": hetznerServer("433593")})

	dest, err := resolveDestination(context.Background(), fleet, "", &http.Client{Transport: transport}, bufio.NewScanner(strings.NewReader("")), io.Discard)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if dest.Destination != "433593" {
		t.Errorf("Destination = %q, want the reused 433593", dest.Destination)
	}
	if len(transport.calls) != 0 {
		t.Errorf("expected zero HTTP calls when reusing the fleet's single existing destination, got %v", transport.calls)
	}
}

func TestResolveDestinationAutoSelectsTheOnlyBox(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "test-token")
	transport := newDestinationFakeTransport(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes", oneBoxJSON)

	dest, err := resolveDestination(context.Background(), fleetWith(nil), "", &http.Client{Transport: transport}, bufio.NewScanner(strings.NewReader("")), io.Discard)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if dest.Destination != "123" || dest.MainAccountHost != "u123456.your-storagebox.de" || dest.MainAccountUser != "u123456" {
		t.Errorf("dest = %+v, want the account's only box auto-selected", dest)
	}
}

func TestResolveDestinationPromptsAndAcceptsAMenuNumber(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "test-token")
	transport := newDestinationFakeTransport(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes", twoBoxJSON)

	dest, err := resolveDestination(context.Background(), fleetWith(nil), "", &http.Client{Transport: transport}, bufio.NewScanner(strings.NewReader("2\n")), io.Discard)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if dest.Destination != "456" || dest.MainAccountHost != "u456789.your-storagebox.de" {
		t.Errorf("dest = %+v, want box #2 (id 456) selected", dest)
	}
}

func TestResolveDestinationRejectsNonNumericExplicitDestination(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "test-token")
	transport := newDestinationFakeTransport(t) // no stubs — must fail before any HTTP call

	_, err := resolveDestination(context.Background(), fleetWith(nil), "not-a-number", &http.Client{Transport: transport}, bufio.NewScanner(strings.NewReader("")), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not a valid Storage Box ID") {
		t.Fatalf("resolveDestination error = %v, want it to reject a non-numeric --destination", err)
	}
}

func TestResolveDestinationExplicitFlagFetchesThatBox(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "test-token")
	transport := newDestinationFakeTransport(t)
	const singleBoxGetJSON = `{"storage_box":{"id":123,"username":"u123456","status":"active","name":"main","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":"u123456.your-storagebox.de","system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"}}`
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", singleBoxGetJSON)

	dest, err := resolveDestination(context.Background(), fleetWith(nil), "123", &http.Client{Transport: transport}, bufio.NewScanner(strings.NewReader("")), io.Discard)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if dest.Destination != "123" || dest.MainAccountHost != "u123456.your-storagebox.de" {
		t.Errorf("dest = %+v, want the explicitly requested box fetched and used, skipping any prompt", dest)
	}
}

// TestBuildOrMergeServerConfigIntegratesWithResolvedDestination is a
// light sanity check that discover.ResolvedDestination and
// discover.BuildOrMergeServerConfig (a different package) compose the
// way writeDiscoveredConfig assumes.
func TestBuildOrMergeServerConfigIntegratesWithResolvedDestination(t *testing.T) {
	dest := discover.ResolvedDestination{ //nolint:gosec // HCloudTokenRef below is a secret *reference* (env var name), never a literal credential
		Provider: "hetzner", Destination: "123",
		HCloudTokenRef: "env://HCLOUD_TOKEN", MainAccountHost: "u123456.your-storagebox.de", MainAccountUser: "u123456",
		EncryptionKeyRef: defaultEncryptionKeyRef("example-nodejs"),
	}
	srv := discover.BuildOrMergeServerConfig(nil, &discover.Report{ServerID: "example-nodejs"}, sshx.Target{Host: "example-nodejs", Port: 22, User: "root"}, dest)
	if srv.Destination != "123" || srv.EncryptionKeyRef != "env://BORG_PASSPHRASE_EXAMPLE_NODEJS" {
		t.Errorf("srv = %+v, want destination/encryption_key_ref filled from dest", srv)
	}
	if err := config.Validate(&config.Fleet{Servers: map[string]config.Server{"example-nodejs": srv}}); err != nil {
		t.Errorf("Validate(new entry) = %v, want it fully resolved with no TODOs", err)
	}
}
