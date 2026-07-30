package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealEgressIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.5\n"))
	}))
	defer srv.Close()

	original := egressIPEchoURL
	egressIPEchoURL = srv.URL
	defer func() { egressIPEchoURL = original }()

	ip, err := RealEgressIP(context.Background())
	if err != nil {
		t.Fatalf("RealEgressIP: %v", err)
	}
	if ip != "203.0.113.5" {
		t.Errorf("RealEgressIP = %q, want 203.0.113.5 (trailing newline trimmed)", ip)
	}
}

func TestRealEgressIPRequestFailure(t *testing.T) {
	original := egressIPEchoURL
	egressIPEchoURL = "http://127.0.0.1:1" // nothing listens here
	defer func() { egressIPEchoURL = original }()

	if _, err := RealEgressIP(context.Background()); err == nil {
		t.Fatal("expected an error when the egress IP service is unreachable")
	}
}
