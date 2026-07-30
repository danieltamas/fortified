package borg

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/danieltamas/fortified/internal/sshx"
)

// RestoreArchive extracts archiveID into targetPath (an already-empty
// directory the caller is responsible for validating — SPEC.md §5's
// restore command owns the non-empty-path refusal, not this Backend
// call). Decryption uses passphrase resolved from the escrow copy —
// never a copy already present on the target (SKILL.md's key custody
// rule); this Backend has no way to know which copy it was handed,
// so that discipline is the caller's responsibility.
//
// paths, if given, extracts only those archive-relative paths instead
// of the whole archive (`borg extract REPOSITORY::ARCHIVE PATH...`) —
// e.g. `fortified restore --db` pulling out one database's own dump
// file rather than everything the archive contains.
func (b Backend) RestoreArchive(ctx context.Context, repoPath string, archiveID ArchiveID, passphrase, identityPath, targetPath string, paths ...string) error {
	identityPath, err := b.absIdentityPath(ctx, identityPath)
	if err != nil {
		return fmt.Errorf("borg: resolve identity path: %w", err)
	}
	args := append([]string{"extract", fmt.Sprintf("%s::%s", repoPath, archiveID)}, paths...)
	_, err = b.Runner.Run(ctx, sshx.Mutating, "borg", args,
		sshx.RunOptions{
			Env:     remoteRepoEnv(passphrase, identityPath),
			Dir:     targetPath,
			Timeout: sshx.LongRunningTimeout,
		})
	if err != nil {
		return fmt.Errorf("borg: extract %s::%s into %s: %w", repoPath, archiveID, targetPath, err)
	}
	return nil
}

// absIdentityPath resolves a relative identityPath (e.g. the
// automation key's bare filename, staged once at onboard time in
// whatever directory the SSH login shell defaults to) to an absolute
// one. RestoreArchive is the only Backend call that sets Dir on the
// borg invocation itself (borg extract always writes into the current
// directory — there is no destination-path flag), which would
// otherwise silently break BORG_RSH's `-i <relative path>`: ssh
// resolves that path against borg's own cwd at the moment it actually
// opens the file, which by then is targetPath, not wherever the key
// actually lives — verified by tracing sshx.Session.Run's own `cd
// targetPath && env BORG_RSH=... borg extract ...` construction. A
// caller who already knows the identity file's real absolute path
// (or an empty identityPath, meaning "no identity needed" — a local,
// non-ssh:// repo) skips the round trip entirely.
func (b Backend) absIdentityPath(ctx context.Context, identityPath string) (string, error) {
	if identityPath == "" || filepath.IsAbs(identityPath) {
		return identityPath, nil
	}
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "pwd", nil, sshx.RunOptions{})
	if err != nil {
		return "", err
	}
	return filepath.Join(strings.TrimSpace(result.Stdout), identityPath), nil
}

// ListArchives lists the repo's archive names — SPEC.md §5: `restore`
// run without --archive lists archives and exits.
func (b Backend) ListArchives(ctx context.Context, repoPath, passphrase, identityPath string) ([]string, error) {
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "borg",
		[]string{"list", "--short", repoPath},
		sshx.RunOptions{Env: remoteRepoEnv(passphrase, identityPath)})
	if err != nil {
		return nil, fmt.Errorf("borg: list %s: %w", repoPath, err)
	}
	return splitNonEmptyLines(result.Stdout), nil
}
