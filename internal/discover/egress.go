package discover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EgressIPFunc resolves the control host's own current public IP —
// the vantage point discover must reconcile against a target's
// firewall rules before calling a DB/cache port "exposed" (SPEC.md
// §5). RealEgressIP is the production implementation; tests inject a
// stub so they never depend on real network access.
type EgressIPFunc func(ctx context.Context) (string, error)

// egressIPEchoURL is a var (not a const) so tests can point it at a
// local httptest server instead of the real internet.
var egressIPEchoURL = "https://api.ipify.org"

// RealEgressIP asks a public IP-echo service what address this
// process is reaching the internet from.
func RealEgressIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, egressIPEchoURL, nil)
	if err != nil {
		return "", fmt.Errorf("discover: build egress IP request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("discover: resolve egress IP: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", fmt.Errorf("discover: read egress IP response: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}
