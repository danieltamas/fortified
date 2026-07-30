package audit

import (
	"context"
	"net/http"
	"time"

	"github.com/danieltamas/fortified/internal/sshx"
)

type classCtxKey struct{}

// WithClass attaches req's mutating/read-only classification, read
// back by RoundTripper.RoundTrip. There is no safe default classifier
// for an arbitrary HTTP request (a POST-shaped RPC can be read-only,
// a GET-shaped one can mutate), so every caller must attach one
// explicitly — an unclassified request is treated as Mutating, the
// fail-safe direction for --dry-run.
func WithClass(req *http.Request, class sshx.Class) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), classCtxKey{}, class))
}

func classOf(req *http.Request) sshx.Class {
	if c, ok := req.Context().Value(classCtxKey{}).(sshx.Class); ok {
		return c
	}
	return sshx.Mutating
}

// RoundTripper is the HTTP twin of Runner: it wraps a provider's HTTP
// client, recording one Entry per request without ever logging
// request/response bodies (where an API token or secret could live).
type RoundTripper struct {
	Next         http.RoundTripper
	Writer       *Writer
	Command      string
	InvocationID string
}

// RoundTrip implements http.RoundTripper.
func (rt RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := rt.Next.RoundTrip(req)

	entry := Entry{
		Time:         start.UTC().Format(time.RFC3339Nano),
		Command:      rt.Command,
		InvocationID: rt.InvocationID,
		Class:        classOf(req).String(),
		Method:       req.Method,
		URL:          req.URL.Redacted(),
		DurationMS:   time.Since(start).Milliseconds(),
	}
	if resp != nil {
		entry.Status = resp.StatusCode
	}
	if writeErr := rt.Writer.Append(entry); writeErr != nil && err == nil {
		err = writeErr
	}
	return resp, err
}

var _ http.RoundTripper = RoundTripper{}
