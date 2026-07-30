package orchestrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/state"
)

// shellSingleQuote POSIX single-quotes s for embedding in a shell
// script string this package builds itself — mirrors
// internal/backend/borg's identical helper (a path built from
// Server.WorkspaceDir can contain a space, same reasoning as that
// package's own dump-redirect quoting).
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// confirmDestinationAndPassphrase confirms server's isolated
// destination already exists (GetDestination, never
// CreateIsolatedDestination — only onboard ever brings one into
// existence) and resolves the repo's encryption passphrase — the two
// things every operation that touches an already-onboarded repo needs
// first. Shared by backup/verify/check/status/prune so this isn't
// reimplemented (with subtly different wording) at every call site.
func confirmDestinationAndPassphrase(ctx context.Context, d Deps, st *state.Server) (dest hetzner.Destination, repoPath, passphrase string, err error) {
	if err := withProgress(d, "confirming destination", func() error {
		var err error
		dest, err = d.Provider.GetDestination(ctx, d.ServerID)
		return err
	}); err != nil {
		return hetzner.Destination{}, "", "", fmt.Errorf("confirm destination: %w", err)
	}
	repoPath = RemoteRepoTarget(dest)

	passphrase, err = d.Secrets.Resolve(ctx, st.Provider.EncryptionKeyRef)
	if err != nil {
		return hetzner.Destination{}, "", "", fmt.Errorf("resolve encryption_key_ref: %w", err)
	}
	return dest, repoPath, passphrase, nil
}
