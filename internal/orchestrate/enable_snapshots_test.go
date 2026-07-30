package orchestrate

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
	"github.com/danieltamas/fortified/internal/state"
)

func TestEnableSnapshotsRefusesWithoutPassingVerify(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)
	if err := state.Save(d.StateDir, onboardedState(d.ServerID)); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := EnableSnapshots(context.Background(), d, hetzner.Schedule{MaxSnapshots: 7, Hour: 2})
	if err == nil || !strings.Contains(err.Error(), "no passing verify") {
		t.Fatalf("EnableSnapshots error = %v, want it to mention no passing verify", err)
	}
}

func TestEnableSnapshotsFailsWhenDestinationLookupFails(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	transport := newFakeTransport(t)
	transport.stubStatus(http.MethodGet, "/v1/storage_boxes/123", 500, serviceErrorJSON)
	d := testDepsWithTransport(t, target, transport)

	seeded := onboardedState(d.ServerID)
	seeded.Verify.EverPassed = true
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := EnableSnapshots(context.Background(), d, hetzner.Schedule{MaxSnapshots: 7, Hour: 2})
	if err == nil || !strings.Contains(err.Error(), "confirm destination") {
		t.Fatalf("EnableSnapshots error = %v, want it to mention confirming the destination", err)
	}
}

func TestEnableSnapshotsFailsWhenAPICallFails(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	transport := defaultTransport(t)
	transport.stubStatus(http.MethodPost, "/v1/storage_boxes/123/actions/enable_snapshot_plan", 500, serviceErrorJSON)
	d := testDepsWithTransport(t, target, transport)

	seeded := onboardedState(d.ServerID)
	seeded.Verify.EverPassed = true
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	err := EnableSnapshots(context.Background(), d, hetzner.Schedule{MaxSnapshots: 7, Hour: 2})
	if err == nil {
		t.Fatal("expected EnableSnapshots to fail when the API call fails")
	}
}

func TestEnableSnapshotsHappyPath(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	transport := defaultTransport(t)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/actions/enable_snapshot_plan",
		`{"action":{"id":2,"status":"success","command":"enable_snapshot_plan","progress":100,"started":"2026-01-01T00:00:00Z","finished":"2026-01-01T00:00:01Z","resources":[]}}`)
	d := testDepsWithTransport(t, target, transport)

	seeded := onboardedState(d.ServerID)
	seeded.Verify.EverPassed = true
	if err := state.Save(d.StateDir, seeded); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := EnableSnapshots(context.Background(), d, hetzner.Schedule{MaxSnapshots: 7, Hour: 2}); err != nil {
		t.Fatalf("EnableSnapshots: %v", err)
	}
}
