package hetzner

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// recordedRequest is one HTTP call a fakeTransport observed — used to
// assert the exact method/path/body fortified sent, per SPEC.md §8's
// "assert exact requests" requirement for the injectable RoundTripper.
type recordedRequest struct {
	Method string
	Path   string
	Body   string
}

// stubbedResponse is a canned reply keyed by "METHOD path".
type stubbedResponse struct {
	Status int
	Body   string
}

// fakeTransport is the Layer-1 test double for http.RoundTripper —
// the HTTP twin of sshx.FakeRunner (SPEC.md §3/§8).
type fakeTransport struct {
	t         *testing.T
	responses map[string]stubbedResponse
	calls     []recordedRequest
}

func newFakeTransport(t *testing.T) *fakeTransport {
	t.Helper()
	return &fakeTransport{t: t, responses: make(map[string]stubbedResponse)}
}

func (f *fakeTransport) stub(method, path string, status int, body string) {
	f.responses[method+" "+path] = stubbedResponse{Status: status, Body: body}
}

// stubByNameParam stubs a response keyed by method+path+its "name"
// query param specifically — for the rare case (e.g.
// RenameDestination's two GetSubaccountByName lookups in one test)
// where the same method+path needs different responses depending on
// which name was filtered for, which plain stub can't express. Keying
// on just the "name" value (not the full raw query) sidesteps having
// to predict pagination params/ordering the SDK adds alongside it.
// RoundTrip prefers this exact match when one is registered, falling
// back to the path-only stub otherwise, so this is purely additive and
// never changes any existing plain-stub test's behavior.
func (f *fakeTransport) stubByNameParam(method, path, name string, status int, body string) {
	f.responses[method+" "+path+"?name="+name] = stubbedResponse{Status: status, Body: body}
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyStr string
	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			f.t.Fatalf("read request body: %v", err)
		}
		bodyStr = string(data)
	}
	pathKey := req.Method + " " + req.URL.Path
	nameKey := pathKey + "?name=" + req.URL.Query().Get("name")
	f.calls = append(f.calls, recordedRequest{Method: req.Method, Path: req.URL.Path, Body: bodyStr})

	resp, ok := f.responses[nameKey]
	if !ok {
		resp, ok = f.responses[pathKey]
	}
	if !ok {
		f.t.Fatalf("fakeTransport: no stubbed response for %s (calls so far: %+v)", nameKey, f.calls)
	}
	return &http.Response{
		StatusCode: resp.Status,
		Body:       io.NopCloser(strings.NewReader(resp.Body)),
		Header:     make(http.Header),
	}, nil
}
