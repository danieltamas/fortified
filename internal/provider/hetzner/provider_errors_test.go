package hetzner

import (
	"context"
	"net/http"
	"testing"
)

const notFoundJSON = `{"error":{"code":"not_found","message":"storage box not found"}}`
const serviceErrorJSON = `{"error":{"code":"service_error","message":"something broke"}}`

func TestCreateDestinationStorageBoxNotFound(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 404, notFoundJSON)

	if _, err := p.CreateIsolatedDestination(context.Background(), "host-2-example"); err == nil {
		t.Fatal("expected an error when the storage box itself is not found")
	}
}

func TestCreateDestinationLookupError(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 500, serviceErrorJSON)

	if _, err := p.CreateIsolatedDestination(context.Background(), "host-2-example"); err == nil {
		t.Fatal("expected an error when the subaccount lookup fails")
	}
}

func TestCreateDestinationCreateError(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/subaccounts", 200, `{"subaccounts":[]}`)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/subaccounts", 500, serviceErrorJSON)

	if _, err := p.CreateIsolatedDestination(context.Background(), "host-example"); err == nil {
		t.Fatal("expected an error when subaccount creation fails")
	}
}

func TestEnableSnapshotsStorageBoxNotFound(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 404, notFoundJSON)

	dest := Destination{SubaccountID: 9}
	if err := p.EnableSnapshotSchedule(context.Background(), dest, Schedule{}, true); err == nil {
		t.Fatal("expected an error when the storage box is not found")
	}
}

func TestEnableSnapshotsAPIError(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodPost, "/v1/storage_boxes/123/actions/enable_snapshot_plan", 500, serviceErrorJSON)

	dest := Destination{SubaccountID: 9}
	if err := p.EnableSnapshotSchedule(context.Background(), dest, Schedule{}, true); err == nil {
		t.Fatal("expected an error when the enable-snapshot-plan API call fails")
	}
}

func TestListSnapshotsStorageBoxNotFound(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 404, notFoundJSON)

	if _, err := p.ListSnapshots(context.Background()); err == nil {
		t.Fatal("expected an error when the storage box is not found")
	}
}

func TestListSnapshotsAPIError(t *testing.T) {
	p, transport := newTestProvider(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123", 200, storageBoxGetJSON)
	transport.stub(http.MethodGet, "/v1/storage_boxes/123/snapshots", 500, serviceErrorJSON)

	if _, err := p.ListSnapshots(context.Background()); err == nil {
		t.Fatal("expected an error when listing snapshots fails")
	}
}
