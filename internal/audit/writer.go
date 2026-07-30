// Package audit wraps the Runner and http.RoundTripper interception
// points to write an append-only JSONL audit trail per server
// (SPEC.md §4): timestamp, invocation ID, mutating/read-only class,
// exact argv or method+URL, exit/status, stderr digest, duration.
// Secrets cannot appear here by construction: Entry never carries an
// invocation's environment, only its argv.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Entry is one audit-log line.
type Entry struct {
	Time         string   `json:"time"`
	Command      string   `json:"command"`
	InvocationID string   `json:"invocation_id"`
	Class        string   `json:"class"`
	Argv         []string `json:"argv,omitempty"`
	Method       string   `json:"method,omitempty"`
	URL          string   `json:"url,omitempty"`
	ExitCode     int      `json:"exit_code,omitempty"`
	Status       int      `json:"status,omitempty"`
	StderrDigest string   `json:"stderr_digest,omitempty"`
	DurationMS   int64    `json:"duration_ms"`
}

// Writer appends Entry lines to one server's audit log. Every Append
// syncs to disk immediately, so lines written before a crash are
// intact and parseable (SPEC.md §4).
type Writer struct {
	mu sync.Mutex
	f  *os.File
}

// OpenWriter opens (creating if needed) the append-only audit log at
// path.
func OpenWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // path is caller-controlled (state/<server-id>.audit.jsonl), not untrusted input
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Writer{f: f}, nil
}

// Append writes one Entry as a JSON line and syncs it to disk.
func (w *Writer) Append(e Entry) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(data); err != nil {
		return fmt.Errorf("audit: write entry: %w", err)
	}
	return w.f.Sync()
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	return w.f.Close()
}

// NewInvocationID returns a random ID tying together every call one
// fortified invocation makes.
func NewInvocationID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("audit: generate invocation id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
