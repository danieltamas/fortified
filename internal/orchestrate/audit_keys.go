package orchestrate

import (
	"context"
	"fmt"

	"github.com/danieltamas/fortified/internal/provider/hetzner"
)

// AuditKeys lists every key currently authorized on d.ServerID's
// Storage Box destination — a read-only report, never a decision.
// Fortified can only ever mark *its own* automation key with
// certainty (its "fortified-<server-id>" naming convention); every
// other entry is surfaced for the operator to judge for themselves —
// it might be their own legitimate prune key, which SPEC.md §1
// requires fortified never possess or compare against, so it
// structurally cannot tell "expected extra key" from "unauthorized
// one" on its own. Uses GetDestination, never CreateIsolatedDestination
// — auditing must never bring a subaccount into existence.
func AuditKeys(ctx context.Context, d Deps) ([]hetzner.AuthorizedKeyEntry, error) {
	dest, err := d.Provider.GetDestination(ctx, d.ServerID)
	if err != nil {
		return nil, fmt.Errorf("audit-keys: confirm destination: %w", err)
	}
	entries, err := hetzner.ListAuthorizedKeys(ctx, d.StorageBox, mainAccount(d), dest)
	if err != nil {
		return nil, fmt.Errorf("audit-keys: %w", err)
	}
	return entries, nil
}

// RemoveKeyByComment removes every authorized_keys entry (whichever
// format) whose comment matches comment exactly — the operator must
// name the exact key, reviewed from AuditKeys' own report first.
// There is deliberately no "remove everything unrecognized" mode:
// fortified has no way to distinguish a legitimate prune key from an
// unauthorized one, so a blanket removal could destroy the operator's
// own dual-key setup instead of protecting it.
func RemoveKeyByComment(ctx context.Context, d Deps, comment string) error {
	dest, err := d.Provider.GetDestination(ctx, d.ServerID)
	if err != nil {
		return fmt.Errorf("audit-keys: confirm destination: %w", err)
	}
	if err := hetzner.RemoveAuthorizedKeysByComment(ctx, d.StorageBox, mainAccount(d), dest, comment); err != nil {
		return fmt.Errorf("audit-keys: %w", err)
	}
	return nil
}
