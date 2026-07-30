package audit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestRunSurfacesAuditWriteFailure(t *testing.T) {
	w, _ := openTestWriter(t)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r := Runner{Next: &sshxtest.FakeRunner{}, Writer: w, Command: "backup", InvocationID: "inv-5"}
	if _, err := r.Run(context.Background(), sshx.ReadOnly, "borg", []string{"info"}, sshx.RunOptions{}); err == nil {
		t.Fatal("expected Run to surface the audit write failure once the writer is closed")
	}
}

func TestRunJoinsOperationErrorWithAuditWriteFailure(t *testing.T) {
	w, _ := openTestWriter(t)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	opErr := errors.New("borg exited 1")
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{{Err: opErr}}}
	r := Runner{Next: fake, Writer: w, Command: "backup", InvocationID: "inv-6"}

	_, err := r.Run(context.Background(), sshx.Mutating, "borg", []string{"create"}, sshx.RunOptions{})
	if err == nil {
		t.Fatal("expected a joined error")
	}
	if !errors.Is(err, opErr) {
		t.Errorf("joined error does not wrap the original operation error: %v", err)
	}
}

func TestRoundTripSurfacesAuditWriteFailure(t *testing.T) {
	w, _ := openTestWriter(t)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rt := RoundTripper{
		Next:         stubTransport{resp: &http.Response{StatusCode: 200}},
		Writer:       w,
		Command:      "onboard",
		InvocationID: "inv-7",
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.hetzner.cloud/v1/subaccounts", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("expected RoundTrip to surface the audit write failure once the writer is closed")
	}
}
