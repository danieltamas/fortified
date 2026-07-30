package hetzner

import (
	"context"
	"net/http"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

const storageBoxListJSON = `{"storage_boxes":[` +
	`{"id":123,"username":"u123456","status":"active","name":"main","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":"u123456.your-storagebox.de","system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"},` +
	`{"id":456,"username":null,"status":"active","name":"secondary","storage_box_type":{"id":1,"name":"bx11","description":"","subaccounts_limit":10,"size":0,"prices":[]},"location":{"id":1,"name":"fsn1","description":"","country":"DE","city":"Falkenstein","latitude":0,"longitude":0,"network_zone":"eu-central"},"access_settings":{"reachable_externally":false,"samba_enabled":false,"ssh_enabled":true,"webdav_enabled":false,"zfs_enabled":false},"server":null,"system":"","stats":{"size":0,"size_data":0,"size_snapshots":0},"labels":{},"protection":{"delete":false},"snapshot_plan":null,"created":"2026-01-01T00:00:00Z"}` +
	`]}`

func TestListStorageBoxes(t *testing.T) {
	transport := newFakeTransport(t)
	transport.stub(http.MethodGet, "/v1/storage_boxes", http.StatusOK, storageBoxListJSON)
	client := hcloud.NewClient(
		hcloud.WithToken("test-token"),
		hcloud.WithHTTPClient(&http.Client{Transport: transport}),
	)

	got, err := ListStorageBoxes(context.Background(), client)
	if err != nil {
		t.Fatalf("ListStorageBoxes: %v", err)
	}
	want := []StorageBoxSummary{
		{ID: 123, Name: "main", Server: "u123456.your-storagebox.de", Username: "u123456"},
		{ID: 456, Name: "secondary", Server: "", Username: ""},
	}
	if len(got) != len(want) {
		t.Fatalf("ListStorageBoxes = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("box[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
