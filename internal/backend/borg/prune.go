package borg

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/danieltamas/fortified/internal/sshx"
)

// Prune runs borg prune with retentionPolicy against repoPath, using
// passphrase to unlock the encrypted repo (SPEC.md §3 — every other
// borg operation passes this too; prune is not exempt). pruneKeyPath
// is the one call in the whole tool that takes the unrestricted prune
// key, supplied explicitly every time (SPEC.md §5) — never read from
// the config/state secrets path the automated commands use.
//
// The pruneKeyPath/appendOnlyKeyPath refusal below is a labeling
// safeguard, not a cryptographic one: this Backend has no way to
// inspect or control which SSH key the caller's Runner/Session was
// actually opened with — that's decided once, outside this package,
// when the connection is established. The real dual-key guarantee is
// structural: whatever opens the connection for a Prune call must open
// a *separate* session authenticated with the operator-supplied prune
// key file, never reuse the automation Session backup/verify share.
// This check only catches the caller accidentally passing the same
// path value for both — it cannot catch a caller that passes a
// distinct-looking path while the underlying connection still
// authenticates with the automation key.
func (b Backend) Prune(ctx context.Context, repoPath, passphrase string, policy Policy, pruneKeyPath, appendOnlyKeyPath string) error {
	if pruneKeyPath == "" {
		return fmt.Errorf("borg: prune requires an explicit --prune-key path (SPEC.md §5), never the automation path")
	}
	if appendOnlyKeyPath != "" && filepath.Clean(pruneKeyPath) == filepath.Clean(appendOnlyKeyPath) {
		return fmt.Errorf("borg: refusing to prune using the append-only automation key (%s) — the prune key must be supplied out of band", pruneKeyPath)
	}

	args := []string{
		fmt.Sprintf("--keep-daily=%d", policy.KeepDaily),
		fmt.Sprintf("--keep-weekly=%d", policy.KeepWeekly),
		fmt.Sprintf("--keep-monthly=%d", policy.KeepMonthly),
		repoPath,
	}
	_, err := b.Runner.Run(ctx, sshx.Mutating, "borg", append([]string{"prune"}, args...),
		sshx.RunOptions{Env: remoteRepoEnv(passphrase, pruneKeyPath), Timeout: sshx.LongRunningTimeout})
	if err != nil {
		return fmt.Errorf("borg: prune %s: %w", repoPath, err)
	}
	return nil
}
