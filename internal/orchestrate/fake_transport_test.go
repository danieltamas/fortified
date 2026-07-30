package orchestrate

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// serviceErrorJSON is a generic hcloud API error envelope, for tests
// that need CreateIsolatedDestination to genuinely fail.
const serviceErrorJSON = `{"error":{"code":"service_error","message":"something broke"}}`

type stubbedResponse struct {
	status int
	body   string
}

// fakeTransport is a minimal Layer-1 http.RoundTripper double for
// driving hetzner.Provider's hcloud.Client in orchestrate-level tests
// — the same shape as hetzner's own package-private fakeTransport
// (internal/provider/hetzner/fake_transport_test.go), duplicated here
// rather than shared: it's a small, single-purpose test double, not
// worth a new exported package for two call sites.
type fakeTransport struct {
	t         *testing.T
	responses map[string]stubbedResponse
}

func newFakeTransport(t *testing.T) *fakeTransport {
	t.Helper()
	return &fakeTransport{t: t, responses: make(map[string]stubbedResponse)}
}

// stub registers a 200 (or 201 for POST) response. Use stubStatus for
// a non-2xx response.
func (f *fakeTransport) stub(method, path, body string) {
	status := http.StatusOK
	if method == http.MethodPost {
		status = http.StatusCreated
	}
	f.stubStatus(method, path, status, body)
}

func (f *fakeTransport) stubStatus(method, path string, status int, body string) {
	f.responses[method+" "+path] = stubbedResponse{status: status, body: body}
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path
	resp, ok := f.responses[key]
	if !ok {
		f.t.Fatalf("fakeTransport: no stubbed response for %s", key)
	}
	return &http.Response{
		StatusCode: resp.status,
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Header:     make(http.Header),
	}, nil
}
