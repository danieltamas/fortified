package orchestrate

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// TestAuditKeysUsesGetDestinationNeverCreates proves AuditKeys never
// brings a subaccount into existence — auditing must be safe to run
// against a server that was never onboarded, unlike onboard's own
// CreateIsolatedDestination.
func TestAuditKeysUsesGetDestinationNeverCreates(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	if _, err := AuditKeys(context.Background(), d); err != nil {
		t.Fatalf("AuditKeys: %v", err)
	}

	for _, c := range d.StorageBox.(*sshxtest.FakeRunner).Calls {
		if c.Class == sshx.Mutating {
			t.Errorf("expected no mutating calls, got %+v", c)
		}
	}
}

func TestAuditKeysFailsClearlyWhenDestinationMissing(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	transport := newFakeTransport(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", `{"subaccounts":[]}`)
	d := testDepsWithTransport(t, target, transport)

	if _, err := AuditKeys(context.Background(), d); err == nil {
		t.Fatal("expected AuditKeys to fail when no subaccount exists")
	}
}

func TestRemoveKeyByCommentRefusesFortifiedOwnKeyThroughOrchestrate(t *testing.T) {
	target := &sshxtest.FakeRunner{}
	d := testDeps(t, target)

	err := RemoveKeyByComment(context.Background(), d, "fortified-host-2-example")
	if err == nil {
		t.Fatal("expected RemoveKeyByComment to refuse removing fortified's own key")
	}
	if !strings.Contains(err.Error(), "lock fortified out") {
		t.Errorf("error = %v, want it to explain the lockout risk", err)
	}
}
