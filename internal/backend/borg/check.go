package borg

import (
	"context"
	"fmt"

	"github.com/danieltamas/fortified/internal/sshx"
)

// Check runs borg's integrity check against repoPath. SPEC.md §5:
// must run and pass before any Prune.
func (b Backend) Check(ctx context.Context, repoPath, passphrase, identityPath string) error {
	_, err := b.Runner.Run(ctx, sshx.ReadOnly, "borg",
		[]string{"check", repoPath},
		sshx.RunOptions{Env: remoteRepoEnv(passphrase, identityPath), Timeout: sshx.LongRunningTimeout})
	if err != nil {
		return fmt.Errorf("borg: check %s: %w", repoPath, err)
	}
	return nil
}
