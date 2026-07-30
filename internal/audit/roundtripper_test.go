package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
)

type stubTransport struct{ resp *http.Response }

func (s stubTransport) RoundTrip(*http.Request) (*http.Response, error) { return s.resp, nil }

func TestRoundTripperRecordsClassAndStatus(t *testing.T) {
	w, path := openTestWriter(t)
	rt := RoundTripper{
		Next:         stubTransport{resp: &http.Response{StatusCode: 201}},
		Writer:       w,
		Command:      "onboard",
		InvocationID: "inv-4",
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.hetzner.cloud/v1/subaccounts", nil)
	req = WithClass(req, sshx.Mutating)

	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	entries := readEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Class != "mutating" || e.Method != http.MethodPost || e.Status != 201 {
		t.Errorf("entry = %+v, want class=mutating method=POST status=201", e)
	}
}

func TestRoundTripperDefaultsUnclassifiedToMutating(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://api.hetzner.cloud/v1/snapshots", nil)
	if got := classOf(req); got != sshx.Mutating {
		t.Errorf("classOf(unclassified) = %v, want Mutating (fail-safe default)", got)
	}
}
