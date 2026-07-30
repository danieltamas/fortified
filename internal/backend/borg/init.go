package borg

import (
	"context"
	"fmt"

	"github.com/danieltamas/fortified/internal/sshx"
)

// Backend implements the Backend interface against the borg binary.
type Backend struct {
	Runner sshx.Runner
}

// remoteRepoEnv is the environment every borg command needs once
// repoPath is a remote ssh:// URL (see orchestrate.RemoteRepoTarget):
// BORG_PASSPHRASE for the repo itself, and BORG_RSH pinning both which
// identity file borg's *own* internal ssh call uses and its host-key
// policy.
//
// identityPath matters because borg's ssh subprocess — made from
// wherever this Backend's Runner actually executes (the protected
// target server in production, connecting onward to the Storage Box)
// — otherwise falls back to that account's *default* SSH identity
// (an agent's offered keys, ~/.ssh/id_* if any), none of which are
// authorized on the subaccount; only the automation key installed
// there during onboarding is. -o IdentitiesOnly=yes stops it from
// also offering any other identity the default agent/config would
// supply, matching the "too many authentication failures" lesson from
// operating on this same Storage Box by hand earlier in the project
// (PROGRESS.md). Verified live: without -i/-o IdentitiesOnly, InitRepo
// failed with "Permission denied (publickey,password)" despite the
// automation key being correctly installed.
//
// StrictHostKeyChecking=accept-new auto-trusts a host's key the first
// time (still rejects a *changed* one later, unlike disabling
// verification entirely) — needed because that target's own
// known_hosts starts empty; verified live — without it, InitRepo
// failed with "Host key verification failed".
func remoteRepoEnv(passphrase, identityPath string) []string {
	return []string{
		"BORG_PASSPHRASE=" + passphrase,
		"BORG_RSH=ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i " + identityPath,
	}
}

// InitRepo initializes a new encrypted Borg repo at repoPath, using
// identityPath (the automation key's path on the target, see
// orchestrate.automationKeyPath) to authenticate the connection to the
// Storage Box. The passphrase travels via the session environment only
// (BORG_PASSPHRASE) — never argv, never written to a file on the
// target (SPEC.md §3). This is always the very first connection ever
// made to a just-created subaccount, so it uses FirstConnectTimeout
// rather than DefaultTimeout — the caller (onboard's step 5) wraps this
// in sshx.RetryOnTransientConnectionError for the cumulative patience,
// this alone is just a single attempt's budget.
func (b Backend) InitRepo(ctx context.Context, repoPath, passphrase, identityPath string) error {
	_, err := b.Runner.Run(ctx, sshx.Mutating, "borg",
		[]string{"init", "--encryption=repokey-blake2", repoPath},
		sshx.RunOptions{Env: remoteRepoEnv(passphrase, identityPath), Timeout: sshx.FirstConnectTimeout})
	if err != nil {
		return fmt.Errorf("borg: init repo %s: %w", repoPath, err)
	}
	return nil
}
