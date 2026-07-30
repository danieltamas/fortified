package hetzner

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// StorageBoxSummary is one Storage Box on the account — enough to let
// an operator pick a destination for a server that doesn't have one
// configured yet (discover's auto-write path), without needing a
// known box ID up front the way GetDestination/CreateIsolatedDestination
// do.
type StorageBoxSummary struct {
	ID       int64
	Name     string
	Server   string // hostname, e.g. u123456.your-storagebox.de
	Username string // main account login, e.g. u123456
}

// ListStorageBoxes enumerates every Storage Box visible to client's
// token — a plain package-level function, not a Provider method,
// since a Provider is always scoped to one already-known
// StorageBoxID and this exists specifically for the case where that
// ID isn't known yet.
func ListStorageBoxes(ctx context.Context, client *hcloud.Client) ([]StorageBoxSummary, error) {
	boxes, err := client.StorageBox.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("hetzner: list storage boxes: %w", err)
	}
	result := make([]StorageBoxSummary, 0, len(boxes))
	for _, b := range boxes {
		result = append(result, StorageBoxSummary{ID: b.ID, Name: b.Name, Server: b.Server, Username: b.Username})
	}
	return result, nil
}
