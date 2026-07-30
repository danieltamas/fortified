package orchestrate

import (
	"context"
	"fmt"
	"sort"

	"github.com/danieltamas/fortified/internal/backend/borg"
)

// StatusDirect reports a server's repo status by talking to its
// Storage Box directly — it never touches the target server at all.
// This is the one deliberate exception to "every borg operation runs
// on the target, using the target's own automation key" (see Deps'
// doc comment and RemoteRepoTarget): a genuine disaster-recovery check
// needs to answer "what's actually backed up" even when the origin
// server is destroyed, unreachable, or no longer trusted — asking the
// (possibly gone) origin about itself isn't an option.
//
// identityPath is an operator-supplied private key file already
// authorized on that server's Storage Box subaccount — fortified
// never generates, copies, or persists a key for this path. d.Backend
// must be wired to a runner that executes locally (the control host
// itself), not one that proxies through the target's SSH session —
// cmd/fortified's --direct wiring does this by constructing a bare
// borg.Backend{Runner: sshx.ExecRunner{}} rather than going through
// buildDeps' normal target-session wiring.
//
// Unlike Status, this can't report per-database/per-path sizes (those
// come from docker exec/du on the target) — only repo-level facts:
// archives present, the latest one's size, and the whole repo's
// deduplicated size. It also has no local state to consult, so it
// never reads or writes the status cache Status maintains.
func StatusDirect(ctx context.Context, d Deps, identityPath string) (StatusReport, error) {
	dest, err := d.Provider.GetDestination(ctx, d.ServerID)
	if err != nil {
		return StatusReport{}, fmt.Errorf("status --direct: %w", err)
	}
	repoPath := RemoteRepoTarget(dest)

	passphrase, err := d.Secrets.Resolve(ctx, d.Server.EncryptionKeyRef)
	if err != nil {
		return StatusReport{}, fmt.Errorf("status --direct: resolve encryption_key_ref: %w", err)
	}

	rep := StatusReport{ServerID: d.ServerID, RepoInitialized: true}

	archives, err := d.Backend.ListArchives(ctx, repoPath, passphrase, identityPath)
	if err != nil {
		return StatusReport{}, fmt.Errorf("status --direct: list archives: %w", err)
	}
	sort.Strings(archives)
	rep.Archives = archives

	if len(archives) > 0 {
		latest := archives[len(archives)-1]
		stats, err := d.Backend.ArchiveInfo(ctx, repoPath, borg.ArchiveID(latest), passphrase, identityPath)
		if err != nil {
			return StatusReport{}, fmt.Errorf("status --direct: latest archive info: %w", err)
		}
		rep.LatestArchive = &stats
	}

	stats, err := d.Backend.RepoInfo(ctx, repoPath, passphrase, identityPath)
	if err != nil {
		return StatusReport{}, fmt.Errorf("status --direct: repo info: %w", err)
	}
	rep.Repo = &stats

	return rep, nil
}
