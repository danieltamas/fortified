package hetzner

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

const storageBoxGetJSON = `{"storage_box":{"id":123,"username":null,"status":"active","name":"main","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":"u123456.your-storagebox.de","system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"}}`

func newTestProvider(t *testing.T) (Provider, *fakeTransport) {
	t.Helper()
	transport := newFakeTransport(t)
	client := hcloud.NewClient(
		hcloud.WithToken("test-token"),
		hcloud.WithHTTPClient(&http.Client{Transport: transport}),
	)
	return Provider{Client: client, StorageBoxID: 123}, transport
}

// TestRandomPasswordSatisfiesComplexity proves the generated password
// contains all four character classes and is a fixed 32 characters —
// Hetzner's subaccount create endpoint rejected the previous
// lowercase-hex-only password with "invalid input in field password"
// (verified live against a real Storage Box), so this pins the fix
// against silently regressing back to a single-class password.
func TestRandomPasswordSatisfiesComplexity(t *testing.T) {
	pw, err := randomPassword()
	if err != nil {
		t.Fatalf("randomPassword: %v", err)
	}
	if len(pw) != 32 {
		t.Errorf("len(password) = %d, want 32", len(pw))
	}
	for _, class := range passwordClasses {
		if !strings.ContainsAny(pw, class) {
			t.Errorf("password %q missing a character from class %q", pw, class)
		}
	}
}

// TestCreateDestinationIdempotent also pins that Destination.Server
// comes from the *subaccount's own* server field, not the parent box's
// — deliberately different values here (verified live: a subaccount's
// server field really can differ from its box's, e.g.
// "u123456-sub1.your-storagebox.de" vs. "u123456.your-storagebox.de")
// so a regression back to the box's field would fail this assertion
// instead of coincidentally passing.
func TestCreateDestinationIdempotent(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200,
		`{"subaccounts":[{"id":9,"name":"host-2-example","username":"u123456-sub1","home_directory":"backups/host-2-example","server":"u123456-sub1.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)

	dest, err := p.CreateIsolatedDestination(context.Background(), "host-2-example")
	if err != nil {
		t.Fatalf("CreateIsolatedDestination: %v", err)
	}
	if dest.SubaccountID != 9 || dest.Username != "u123456-sub1" || dest.HomeDirectory != "backups/host-2-example" || dest.Server != "u123456-sub1.your-storagebox.de" {
		t.Errorf("dest = %+v, want SubaccountID=9 Username=u123456-sub1 HomeDirectory=backups/host-2-example Server=u123456-sub1.your-storagebox.de (the subaccount's own server field, not the box's)", dest)
	}

	for _, c := range transport.calls {
		if c.Method == http.MethodPost {
			t.Fatalf("expected zero create requests for an already-existing subaccount, got %+v", transport.calls)
		}
	}
}

// TestGetDestinationFindsExisting proves GetDestination (used by every
// command except onboard) returns an already-onboarded destination
// exactly like CreateIsolatedDestination would, with zero create
// requests — it's read-only by construction, not just by convention.
func TestGetDestinationFindsExisting(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200,
		`{"subaccounts":[{"id":9,"name":"host-2-example","username":"u123456-sub1","home_directory":"backups/host-2-example","server":"u123456.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)

	dest, err := p.GetDestination(context.Background(), "host-2-example")
	if err != nil {
		t.Fatalf("GetDestination: %v", err)
	}
	if dest.SubaccountID != 9 || dest.Username != "u123456-sub1" {
		t.Errorf("dest = %+v, want SubaccountID=9 Username=u123456-sub1", dest)
	}
	for _, c := range transport.calls {
		if c.Method != http.MethodGet {
			t.Errorf("expected only GET requests, got %+v", c)
		}
	}
}

// TestGetDestinationRefusesWhenMissing is the fix for a real gap a
// cross-vendor review caught: backup/verify/enable-snapshots calling
// CreateIsolatedDestination meant a subaccount deleted after onboarding
// (manually, or by some other bug) would come back as a fresh, blank
// subaccount instead of a clear "re-run onboard" error — GetDestination
// must never create anything.
func TestGetDestinationRefusesWhenMissing(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200, `{"subaccounts":[]}`)

	_, err := p.GetDestination(context.Background(), "host-2-example")
	if err == nil {
		t.Fatal("expected GetDestination to refuse when no subaccount exists")
	}
	for _, c := range transport.calls {
		if c.Method == http.MethodPost {
			t.Fatalf("expected zero create requests, got %+v", transport.calls)
		}
	}
}

func TestCreateDestinationCreatesWhenMissing(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200, `{"subaccounts":[]}`)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/subaccounts", 201,
		`{"subaccount":{"id":42,"storage_box":123},"action":{"id":1,"status":"success","command":"create_subaccount","progress":100,"started":"2026-01-01T00:00:00Z","finished":"2026-01-01T00:00:01Z","resources":[]}}`)
	// The create response above carries no username (Hetzner populates
	// it only once the action finishes), so CreateIsolatedDestination
	// must re-fetch the subaccount to learn it.
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts/42", 200,
		`{"subaccount":{"id":42,"name":"host-example","username":"u123456-sub42","home_directory":"backups/host-example","server":"u123456-sub42.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}}`)

	dest, err := p.CreateIsolatedDestination(context.Background(), "host-example")
	if err != nil {
		t.Fatalf("CreateIsolatedDestination: %v", err)
	}
	if dest.SubaccountID != 42 || dest.Username != "u123456-sub42" || dest.HomeDirectory != "backups/host-example" || dest.Server != "u123456-sub42.your-storagebox.de" {
		t.Errorf("dest = %+v, want SubaccountID=42 Username=u123456-sub42 HomeDirectory=backups/host-example Server=u123456-sub42.your-storagebox.de (the newly-created subaccount's own server field, not the box's)", dest)
	}

	var createBody string
	for _, c := range transport.calls {
		if c.Method == http.MethodPost {
			createBody = c.Body
		}
	}
	if createBody == "" {
		t.Fatal("expected exactly one create request")
	}
	if !strings.Contains(createBody, `"home_directory":"backups/host-example"`) {
		t.Errorf("create request body = %s, want it to set home_directory", createBody)
	}
	if !strings.Contains(createBody, `"samba_enabled":false`) || !strings.Contains(createBody, `"webdav_enabled":false`) {
		t.Errorf("create request body = %s, want samba/webdav disabled", createBody)
	}
}

// TestCreateDestinationDryRunSkipsCreate proves --dry-run's contract
// (SPEC.md §5): the read-only lookups still run for real (the plan
// depends on knowing whether the subaccount already exists), but the
// create POST never fires, and the returned Destination carries an
// explicit placeholder rather than an invented ID.
func TestCreateDestinationDryRunSkipsCreate(t *testing.T) {
	p, transport := newTestProvider(t)
	p.DryRun = true
	var out bytes.Buffer
	p.Out = &out
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200, `{"subaccounts":[]}`)

	dest, err := p.CreateIsolatedDestination(context.Background(), "host-example")
	if err != nil {
		t.Fatalf("CreateIsolatedDestination: %v", err)
	}
	if dest.Username != "<to-be-created>" {
		t.Errorf("dest.Username = %q, want an explicit placeholder, never an invented value", dest.Username)
	}
	if dest.HomeDirectory != "backups/host-example" {
		t.Errorf("dest.HomeDirectory = %q, want backups/host-example (this is derivable, not invented)", dest.HomeDirectory)
	}
	for _, c := range transport.calls {
		if c.Method == http.MethodPost {
			t.Errorf("expected zero POST requests under dry-run, got %+v", c)
		}
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Errorf("expected a dry-run plan line to be printed, got %q", out.String())
	}
}

// TestCreateDestinationDryRunStillReturnsExistingSubaccount: an
// already-existing subaccount is read-only knowledge, not a mutation
// — dry-run must return it exactly as it would for real.
func TestCreateDestinationDryRunStillReturnsExistingSubaccount(t *testing.T) {
	p, transport := newTestProvider(t)
	p.DryRun = true
	p.Out = &bytes.Buffer{}
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200,
		`{"subaccounts":[{"id":9,"name":"host-2-example","username":"u123456-sub9","home_directory":"backups/host-2-example","server":"u123456.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)

	dest, err := p.CreateIsolatedDestination(context.Background(), "host-2-example")
	if err != nil {
		t.Fatalf("CreateIsolatedDestination: %v", err)
	}
	if dest.SubaccountID != 9 || dest.Username != "u123456-sub9" {
		t.Errorf("dest = %+v, want the real existing subaccount, not a placeholder", dest)
	}
}

func TestEnableSnapshotsDryRunSkipsAPICall(t *testing.T) {
	p, transport := newTestProvider(t)
	p.DryRun = true
	var out bytes.Buffer
	p.Out = &out
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	dest := Destination{SubaccountID: 9, HomeDirectory: "backups/host-2-example"}

	if err := p.EnableSnapshotSchedule(context.Background(), dest, Schedule{MaxSnapshots: 7, Hour: 2}, true); err != nil {
		t.Fatalf("EnableSnapshotSchedule: %v", err)
	}
	for _, c := range transport.calls {
		if c.Method == http.MethodPost {
			t.Errorf("expected zero POST requests under dry-run, got %+v", c)
		}
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Errorf("expected a dry-run plan line to be printed, got %q", out.String())
	}
}

func TestEnableSnapshotsRefusesWithoutVerify(t *testing.T) {
	p, transport := newTestProvider(t)
	dest := Destination{SubaccountID: 9, HomeDirectory: "backups/host-2-example"}

	err := p.EnableSnapshotSchedule(context.Background(), dest, Schedule{MaxSnapshots: 7, Hour: 2}, false)
	if err == nil {
		t.Fatal("expected EnableSnapshotSchedule to refuse without a passing verify")
	}
	if len(transport.calls) != 0 {
		t.Errorf("expected zero HTTP calls when refusing, got %+v", transport.calls)
	}
}

func TestEnableSnapshotsSucceedsWhenVerified(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/actions/enable_snapshot_plan", 201,
		`{"action":{"id":2,"status":"success","command":"enable_snapshot_plan","progress":100,"started":"2026-01-01T00:00:00Z","finished":"2026-01-01T00:00:01Z","resources":[]}}`)

	dest := Destination{SubaccountID: 9, HomeDirectory: "backups/host-2-example"}
	if err := p.EnableSnapshotSchedule(context.Background(), dest, Schedule{MaxSnapshots: 7, Hour: 2}, true); err != nil {
		t.Fatalf("EnableSnapshotSchedule: %v", err)
	}
}

// TestRenameDestinationRenamesNameAndMovesEverything pins three things
// a rename-in-place must get right together: the subaccount's Name
// (what GetSubaccountByName looks it up by), its HomeDirectory
// metadata, and — this is the bug a live rename actually hit —
// change_home_directory alone leaves the real .ssh/authorized_keys and
// repo behind at the old path, since it only repoints the subaccount
// to a brand-new *empty* directory rather than moving anything.
// Without the sftp move below, the very next connection using the
// "renamed" subaccount fails outright with "Permission denied" — no
// authorized_keys exists at its new home at all.
func TestRenameDestinationRenamesNameAndMovesEverything(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200,
		`{"subaccounts":[{"id":9,"name":"n8n.example.net","username":"u123456-sub9","home_directory":"backups/n8n.example.net","server":"u123456-sub9.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)
	transport.stub(http.MethodPut, "/v1/storage_boxes/123/subaccounts/9", 200,
		`{"subaccount":{"id":9,"name":"n8n-wam-app","username":"u123456-sub9","home_directory":"backups/n8n.example.net","server":"u123456-sub9.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}}`)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/subaccounts/9/actions/change_home_directory", 201,
		`{"action":{"id":3,"status":"success","command":"change_home_directory","progress":100,"started":"2026-01-01T00:00:00Z","finished":"2026-01-01T00:00:01Z","resources":[]}}`)
	fake := &sshxtest.FakeRunner{}

	dest, err := p.RenameDestination(context.Background(), fake, testMain(), "n8n.example.net", "n8n-wam-app")
	if err != nil {
		t.Fatalf("RenameDestination: %v", err)
	}
	if dest.SubaccountID != 9 || dest.HomeDirectory != "backups/n8n-wam-app" {
		t.Errorf("dest = %+v, want SubaccountID=9 HomeDirectory=backups/n8n-wam-app (the new name's, not the stale one still in the update response)", dest)
	}

	var renameBody, moveBody string
	for _, c := range transport.calls {
		switch {
		case c.Method == http.MethodPut:
			renameBody = c.Body
		case c.Method == http.MethodPost && strings.Contains(c.Path, "change_home_directory"):
			moveBody = c.Body
		}
	}
	if !strings.Contains(renameBody, `"name":"n8n-wam-app"`) {
		t.Errorf("PUT body = %s, want it to set name to n8n-wam-app", renameBody)
	}
	if !strings.Contains(moveBody, `"home_directory":"backups/n8n-wam-app"`) {
		t.Errorf("change_home_directory body = %s, want home_directory backups/n8n-wam-app", moveBody)
	}

	if len(fake.Calls) != 1 {
		t.Fatalf("expected exactly 1 sftp call to move the actual data, got %d: %+v", len(fake.Calls), fake.Calls)
	}
	move := fake.Calls[0]
	if move.Cmd != "sftp" {
		t.Errorf("cmd = %q, want sftp", move.Cmd)
	}
	if !strings.Contains(move.Stdin, "-rename backups/n8n.example.net/.ssh backups/n8n-wam-app/.ssh") {
		t.Errorf("stdin = %q, want it to move .ssh from the old home to the new one", move.Stdin)
	}
	if !strings.Contains(move.Stdin, "-rename backups/n8n.example.net/repo backups/n8n-wam-app/repo") {
		t.Errorf("stdin = %q, want it to move repo from the old home to the new one", move.Stdin)
	}
}

// TestRenameDestinationStillMovesDataWhenAPIRenameAlreadyHappened is
// the exact recovery shape a live incident hit: a previous run already
// renamed the subaccount at the API level (it no longer exists under
// oldServerID), but its actual data was left behind at oldServerID's
// own deterministic home directory, orphaned. A naive "already
// renamed, nothing to do" idempotency check would leave that data
// stranded forever — this must still attempt the move.
func TestRenameDestinationStillMovesDataWhenAPIRenameAlreadyHappened(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stubByNameParam(http.MethodGet, "/v1/storage_boxes/123/subaccounts", "n8n.example.net", 200, `{"subaccounts":[]}`)
	transport.stubByNameParam(http.MethodGet, "/v1/storage_boxes/123/subaccounts", "n8n-wam-app", 200,
		`{"subaccounts":[{"id":9,"name":"n8n-wam-app","username":"u123456-sub9","home_directory":"backups/n8n-wam-app","server":"u123456-sub9.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)
	fake := &sshxtest.FakeRunner{}

	dest, err := p.RenameDestination(context.Background(), fake, testMain(), "n8n.example.net", "n8n-wam-app")
	if err != nil {
		t.Fatalf("RenameDestination: %v", err)
	}
	if dest.SubaccountID != 9 || dest.HomeDirectory != "backups/n8n-wam-app" {
		t.Errorf("dest = %+v, want the already-renamed subaccount", dest)
	}
	for _, c := range transport.calls {
		if c.Method == http.MethodPut || c.Method == http.MethodPost {
			t.Errorf("expected zero mutating HTTP requests when already renamed at the API level, got %+v", c)
		}
	}
	if len(fake.Calls) != 1 {
		t.Fatalf("expected the data move to still be attempted, got %d sftp calls: %+v", len(fake.Calls), fake.Calls)
	}
	if !strings.Contains(fake.Calls[0].Stdin, "-rename backups/n8n.example.net/.ssh backups/n8n-wam-app/.ssh") {
		t.Errorf("stdin = %q, want it to still move the orphaned data", fake.Calls[0].Stdin)
	}
}

// TestRenameDestinationRefusesWhenNeitherNameExists guards against
// silently doing nothing (and reporting success) for a genuine typo in
// either server ID.
func TestRenameDestinationRefusesWhenNeitherNameExists(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200, `{"subaccounts":[]}`)
	fake := &sshxtest.FakeRunner{}

	_, err := p.RenameDestination(context.Background(), fake, testMain(), "typo-old", "typo-new")
	if err == nil {
		t.Fatal("expected RenameDestination to refuse when neither name has a subaccount")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero sftp calls when refusing, got %+v", fake.Calls)
	}
}

// TestRenameDestinationDryRunSkipsMutation proves --dry-run's contract:
// the read-only lookup still runs for real, but neither the rename,
// the home-directory move, nor the sftp data move ever fires.
func TestRenameDestinationDryRunSkipsMutation(t *testing.T) {
	p, transport := newTestProvider(t)
	p.DryRun = true
	var out bytes.Buffer
	p.Out = &out
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200,
		`{"subaccounts":[{"id":9,"name":"n8n.example.net","username":"u123456-sub9","home_directory":"backups/n8n.example.net","server":"u123456-sub9.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)
	fake := &sshxtest.FakeRunner{}

	dest, err := p.RenameDestination(context.Background(), fake, testMain(), "n8n.example.net", "n8n-wam-app")
	if err != nil {
		t.Fatalf("RenameDestination: %v", err)
	}
	if dest.SubaccountID != 9 {
		t.Errorf("dest.SubaccountID = %d, want the real existing subaccount's ID, not a placeholder", dest.SubaccountID)
	}
	for _, c := range transport.calls {
		if c.Method == http.MethodPut || c.Method == http.MethodPost {
			t.Errorf("expected zero mutating requests under dry-run, got %+v", c)
		}
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero sftp calls under dry-run, got %+v", fake.Calls)
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Errorf("expected a dry-run plan line to be printed, got %q", out.String())
	}
}

// TestRenameDestinationSurfacesDataMoveFailureAfterAPIRenameAlreadyCommitted
// is the gap the shipped change_home_directory bug should have taught
// this code to guard against: the API-level rename (name + home
// directory) has already been committed against Hetzner by the time
// moveHomeDirectoryContents runs, so a network drop mid-sftp-command
// here must not be swallowed — RenameDestination must return an error
// (never a success Destination) so the caller knows the operator-
// facing state (subaccount renamed) and the actual data (still at the
// old path, or only half-moved) have diverged and a retry is required.
// No existing test ever scripted an sftp failure for this call at all.
func TestRenameDestinationSurfacesDataMoveFailureAfterAPIRenameAlreadyCommitted(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200,
		`{"subaccounts":[{"id":9,"name":"n8n.example.net","username":"u123456-sub9","home_directory":"backups/n8n.example.net","server":"u123456-sub9.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)
	transport.stub(http.MethodPut, "/v1/storage_boxes/123/subaccounts/9", 200,
		`{"subaccount":{"id":9,"name":"n8n-wam-app","username":"u123456-sub9","home_directory":"backups/n8n.example.net","server":"u123456-sub9.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}}`)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/subaccounts/9/actions/change_home_directory", 201,
		`{"action":{"id":3,"status":"success","command":"change_home_directory","progress":100,"started":"2026-01-01T00:00:00Z","finished":"2026-01-01T00:00:01Z","resources":[]}}`)
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("ssh_exchange_identification: Connection closed by remote host")}, // network drop mid sftp move
	}}

	_, err := p.RenameDestination(context.Background(), fake, testMain(), "n8n.example.net", "n8n-wam-app")
	if err == nil {
		t.Fatal("expected RenameDestination to return an error when the sftp data move itself fails, not silently report the API-level rename as a full success")
	}
	if !strings.Contains(err.Error(), "move subaccount") {
		t.Errorf("err = %v, want it to explain this was the data-move step that failed (not the API rename, which already succeeded)", err)
	}
}

// TestRenameDestinationSurfacesDataMoveFailureOnRetryAfterAPIRenameAlready
// is the same failure, but hitting the *other* branch: a previous run
// already got the subaccount renamed at the API level (so this run
// takes the "already renamed, just retry the data move" path) and the
// retry's own sftp move fails too — this must not be reported as
// success either.
func TestRenameDestinationSurfacesDataMoveFailureOnRetryAfterAPIRenameAlready(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stubByNameParam(http.MethodGet, "/v1/storage_boxes/123/subaccounts", "n8n.example.net", 200, `{"subaccounts":[]}`)
	transport.stubByNameParam(http.MethodGet, "/v1/storage_boxes/123/subaccounts", "n8n-wam-app", 200,
		`{"subaccounts":[{"id":9,"name":"n8n-wam-app","username":"u123456-sub9","home_directory":"backups/n8n-wam-app","server":"u123456-sub9.your-storagebox.de","access_settings":{"reachable_externally":false,"readonly":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false},"description":"","labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Err: errors.New("ssh_exchange_identification: Connection closed by remote host")},
	}}

	_, err := p.RenameDestination(context.Background(), fake, testMain(), "n8n.example.net", "n8n-wam-app")
	if err == nil {
		t.Fatal("expected RenameDestination to return an error when the retry's own sftp data move fails")
	}
}

func TestListSnapshots(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/snapshots", 200,
		`{"snapshots":[{"id":1,"name":"snap-1","description":"","stats":{"size":0,"size_data":0},"is_automatic":true,"labels":{},"created":"2026-01-01T00:00:00Z","storage_box":123}]}`)

	snapshots, err := p.ListSnapshots(context.Background())
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].Name != "snap-1" || !snapshots[0].IsAutomatic {
		t.Errorf("snapshots = %+v, want one automatic snap-1", snapshots)
	}
}
