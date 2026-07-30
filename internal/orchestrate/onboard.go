package orchestrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/state"
)

// automationKeyPath is the automation keypair's filename on the
// target, relative to the SSH login's home directory — a flat name
// (no subdirectory) so onboard never needs a remote mkdir before
// ssh-keygen can write it.
const automationKeyPath = "fortified-automation-key"

// initRepoRetryAttempts and initRepoRetryDelay are vars, not consts,
// so tests can shrink the delay — the defaults are real-world-
// appropriate (waiting out a just-created subaccount's routing/DNS
// propagation, observed live to take upward of 45s), not test-
// appropriate. 12 attempts at 8s apart budgets ~90s of retrying.
var (
	initRepoRetryAttempts = 12
	initRepoRetryDelay    = 8 * time.Second
)

// OnboardOptions carries onboard's operator-supplied inputs that
// aren't "how to reach this server" (Deps) — kept separate since they
// vary per invocation.
type OnboardOptions struct {
	// EscrowAcknowledged must be true to pass step 5 — SPEC.md §5: the
	// operator must confirm the encryption passphrase has been escrowed
	// before the repo is initialized. There is no default that makes
	// this true; the operator supplies it explicitly every time it's
	// needed (--escrow-acknowledged), never a config field that could
	// silently stay true forever.
	EscrowAcknowledged bool
}

// Onboard runs SPEC.md §5's numbered onboard steps (discover, ensure
// borg is installed, confirm destination, install the automation key,
// init the repo), resuming from state's OnboardState.LastCompletedStep
// on re-run — it never re-creates a subaccount, re-generates a key, or
// re-inits a repo that already exists (SPEC.md §4). Enabling snapshots
// is deliberately not run here — that's verify's job to unlock.
func Onboard(ctx context.Context, d Deps, opts OnboardOptions) error {
	st, err := state.Load(d.StateDir, d.ServerID)
	if err != nil {
		return fmt.Errorf("onboard: load state: %w", err)
	}

	// Fail fast on a misconfigured/unset encryption_key_ref, before any
	// of the slow, real work below (discover, subaccount creation, key
	// install) — verified live: this env var not being set was
	// previously only caught deep in step 5, after already burning ~45s
	// on steps 1-4 (real SSH round trips, a real subaccount, a real key
	// installed on the target) that would all have to be repeated on
	// retry anyway. This resolves the value and discards it — a pure
	// validation check, no different from what step 5 does for real —
	// unless it's cleanly unset and the operator has already asserted
	// escrow responsibility (--escrow-acknowledged), in which case
	// onboard generates one instead of just refusing (see below).
	if _, err := d.Secrets.Resolve(ctx, d.Server.EncryptionKeyRef); err != nil {
		varName, isEnvRef := strings.CutPrefix(d.Server.EncryptionKeyRef, "env://")
		if !isEnvRef || !errors.Is(err, secrets.ErrEnvVarNotSet) || !opts.EscrowAcknowledged {
			return fmt.Errorf("onboard: resolve encryption_key_ref before starting: %w", err)
		}

		// Generate-and-use, not generate-and-print-a-preview: this is
		// the ONE place a passphrase is ever generated, and it's set
		// (os.Setenv) and used immediately in this same process. A
		// separate "preview" path that ran the *next* invocation's own
		// fresh Resolve would generate a *different* random value and
		// silently use that one instead — the operator could copy the
		// wrong passphrase into their password manager and never know
		// it doesn't match what actually encrypted the repo. Only ever
		// reachable with --escrow-acknowledged already asserted, same
		// trust level the flag already carries for a manually-set
		// passphrase (this tool has never verified escrow actually
		// happened either way — it trusts the flag).
		generated, genErr := secrets.GeneratePassphrase()
		if genErr != nil {
			return fmt.Errorf("onboard: %w", genErr)
		}
		if err := os.Setenv(varName, generated); err != nil {
			return fmt.Errorf("onboard: set generated passphrase in environment: %w", err)
		}
		d.reportProgress("%s was not set — generated a new repo encryption passphrase for %s:", d.Server.EncryptionKeyRef, d.ServerID)
		d.reportProgress("  %s", generated)
		d.reportProgress("SAVE THIS NOW in your password manager — it is the only way to ever decrypt this repo.")
		d.reportProgress("Also persist it for future runs (backup/verify/status all need it too), e.g. in your shell profile:")
		d.reportProgress("  export %s=%s", varName, generated)
	}

	if st.Onboard.LastCompletedStep < 1 {
		if err := withProgress(d, "[1/5] discovering server layout", func() error {
			return onboardDiscover(ctx, d, st)
		}); err != nil {
			return recordOnboardFailure(d, st, 1, err)
		}
		if err := advanceOnboard(d, st, 1); err != nil {
			return err
		}
	}

	if st.Onboard.LastCompletedStep < 2 {
		if err := withProgress(d, "[2/5] installing borg if missing", func() error {
			return ensureBorgInstalled(ctx, d.Target)
		}); err != nil {
			return recordOnboardFailure(d, st, 2, err)
		}
		if err := advanceOnboard(d, st, 2); err != nil {
			return err
		}
	}

	var dest hetzner.Destination
	if err := withProgress(d, "[3/5] confirming isolated destination", func() error {
		var err error
		dest, err = d.Provider.CreateIsolatedDestination(ctx, d.ServerID)
		return err
	}); err != nil {
		return recordOnboardFailure(d, st, 3, fmt.Errorf("create/confirm destination: %w", err))
	}
	if st.Onboard.LastCompletedStep < 3 {
		st.Provider.DestinationID = strconv.FormatInt(dest.SubaccountID, 10)
		if err := advanceOnboard(d, st, 3); err != nil {
			return err
		}
	}

	repoPath := RepoPath(dest)

	if st.Onboard.LastCompletedStep < 4 {
		var fingerprint string
		err := withProgress(d, "[4/5] generating and installing the append-only automation key", func() error {
			var err error
			fingerprint, err = onboardInstallKey(ctx, d, dest, repoPath)
			return err
		})
		if err != nil {
			return recordOnboardFailure(d, st, 4, err)
		}
		st.Provider.KeyFingerprint = fingerprint
		if err := advanceOnboard(d, st, 4); err != nil {
			return err
		}
	}

	if st.Onboard.LastCompletedStep < 5 {
		if !opts.EscrowAcknowledged {
			return recordOnboardFailure(d, st, 5, fmt.Errorf(
				"repo encryption passphrase escrow must be acknowledged (--escrow-acknowledged) before the repo is initialized — SKILL.md's key custody rule: a repo whose only passphrase copy lived on the lost server is not a backup"))
		}
		err := withProgress(d, "[5/5] initializing the borg repository", func() error {
			pubKeyLine, err := readAutomationPubKey(ctx, d)
			if err != nil {
				return fmt.Errorf("read automation public key: %w", err)
			}
			if pubKeyLine == "" {
				return fmt.Errorf("read automation public key: empty — step 4 should already have generated it")
			}

			// borg init through a borg serve --append-only connection
			// is a documented borg limitation (github.com/borgbackup/
			// borg issues #2413, #5497) — depending on version it
			// either silently ignores the restriction or, as verified
			// live against this exact Storage Box, hard-fails with
			// "Read-only file system" on repository.create()'s own
			// os.mkdir. Both issues converge on the same fix: lift the
			// restriction for this one operation, then restore it
			// immediately after — never leave the automation key
			// unrestricted longer than init itself takes.
			//
			// AppendOnlyLifted is persisted *before* the lift, not
			// after: if this process is killed anywhere between here
			// and the restore below, the on-disk record must already
			// say "may be unrestricted" — saving it only after the
			// fact would miss exactly the crash window it exists to
			// catch.
			st.Provider.AppendOnlyLifted = true
			if err := state.Save(d.StateDir, st); err != nil {
				return fmt.Errorf("record append-only lift before init: %w", err)
			}
			if err := d.Provider.InstallServerKey(ctx, d.StorageBox, d.Target, hetzner.InstallKeyRequest{
				Main: mainAccount(d), Destination: dest, PublicKey: pubKeyLine, AppendOnly: false,
			}); err != nil {
				return fmt.Errorf("temporarily lift append-only restriction for init: %w", err)
			}

			passphrase, err := d.Secrets.Resolve(ctx, d.Server.EncryptionKeyRef)
			if err != nil {
				return fmt.Errorf("resolve encryption_key_ref: %w", err)
			}
			// A brand-new subaccount's own hostname/route can take well
			// over 15s to become reachable after CreateSubaccount already
			// returned success — verified live across three separate
			// subaccounts: "Could not resolve hostname", "Connection
			// closed by remote host", and (persisting through 5 attempts
			// at 3s apart, ~46s total) "No route to host" — the last one
			// ruled out a client-side IPv6 issue directly (the target had
			// no IPv6 configured at all; IPv4 to the box worked
			// immediately once retried by hand minutes later), pointing
			// at Hetzner's own edge needing longer than the original
			// budget to finish routing a just-created subaccount. This is
			// the very first connection ever made to it, so it's the one
			// InitRepo call worth retrying — with a generous budget, since
			// onboarding a server happens once and a couple of extra
			// minutes of patience here beats a confusing manual retry.
			initErr := sshx.RetryOnTransientConnectionError(ctx, initRepoRetryAttempts, initRepoRetryDelay, func() error {
				return d.Backend.InitRepo(ctx, RemoteRepoTarget(dest), passphrase, automationKeyPath)
			})

			// Restore append-only regardless of whether init succeeded
			// — a failed init must never leave the automation key
			// unrestricted. Retried on a transient connection failure
			// like InitRepo above it: a network blip here must not
			// immediately give up and leave the key unrestricted when
			// trying again stood a real chance of succeeding.
			restoreErr := sshx.RetryOnTransientConnectionError(ctx, initRepoRetryAttempts, initRepoRetryDelay, func() error {
				return d.Provider.InstallServerKey(ctx, d.StorageBox, d.Target, hetzner.InstallKeyRequest{
					Main: mainAccount(d), Destination: dest, PublicKey: pubKeyLine,
					AppendOnly: true, RepoPath: repoPath, VerifyKeyPath: automationKeyPath,
				})
			})
			if restoreErr != nil {
				return fmt.Errorf("restore append-only restriction after init: %w", restoreErr)
			}
			st.Provider.AppendOnlyLifted = false
			if err := state.Save(d.StateDir, st); err != nil {
				return fmt.Errorf("record append-only restriction restored: %w", err)
			}

			// "A repository already exists at <path>." (borg's own
			// message, verified live) means a prior attempt's InitRepo
			// call actually succeeded but this step's state save
			// afterward didn't — that is success to resume from, not a
			// failure to report. Any other InitRepo error is real and
			// must still stop onboard here.
			if initErr != nil && !strings.Contains(initErr.Error(), "already exists") {
				return fmt.Errorf("init repo: %w", initErr)
			}
			return nil
		})
		if err != nil {
			return recordOnboardFailure(d, st, 5, err)
		}
		st.Provider.RepoInitialized = true
		st.Provider.EncryptionKeyRef = d.Server.EncryptionKeyRef
		st.Provider.EscrowAcked = true
		if err := advanceOnboard(d, st, 5); err != nil {
			return err
		}
	}

	return nil
}

// ensureBorgInstalled checks whether borg is already present on
// target and, if not, installs it via whichever supported package
// manager is detected. Installing borg is a plain OS package, not a
// Hetzner-specific concern — there's no reason to make the operator
// SSH in and run this by hand before onboarding (or a drill, which
// reuses this against its own throwaway target) can proceed, and
// nothing about it is destructive or hard to reverse.
func ensureBorgInstalled(ctx context.Context, target sshx.Runner) error {
	if _, err := target.Run(ctx, sshx.ReadOnly, "borg", []string{"--version"}, sshx.RunOptions{}); err == nil {
		return nil
	}

	pkgManager, err := detectPackageManager(ctx, target)
	if err != nil {
		return err
	}
	cmd, args, err := borgInstallCommand(pkgManager)
	if err != nil {
		return err
	}
	_, plainErr := target.Run(ctx, sshx.Mutating, cmd, args, sshx.RunOptions{})
	if plainErr != nil {
		// The SSH login user isn't always root — verified live: a
		// server logging in as a non-root sudoer failed the bare
		// install command outright with a dpkg-lock permission error,
		// unlike the rest of the fleet, which all log in as root.
		// Retry once with non-interactive sudo (`sudo -n`, which
		// refuses to prompt rather than hanging a non-interactive SSH
		// session) before giving up.
		sudoCmd, sudoArgs := sudoNonInteractive(cmd, args)
		if _, sudoErr := target.Run(ctx, sshx.Mutating, sudoCmd, sudoArgs, sshx.RunOptions{}); sudoErr != nil {
			return fmt.Errorf("install borg via %s (plain: %w; sudo -n: %v) — configure passwordless sudo for this SSH user, or install borg manually", pkgManager, plainErr, sudoErr)
		}
	}

	if _, err := target.Run(ctx, sshx.ReadOnly, "borg", []string{"--version"}, sshx.RunOptions{}); err != nil {
		return fmt.Errorf("borg still not found on target after installing via %s: %w", pkgManager, err)
	}
	return nil
}

// sudoNonInteractive prefixes cmd/args with `sudo -n` — -n refuses to
// prompt for a password rather than hanging a non-interactive SSH
// session, so a target without passwordless sudo configured fails
// fast with sudo's own clear "a password is required" instead.
func sudoNonInteractive(cmd string, args []string) (string, []string) {
	return "sudo", append([]string{"-n", cmd}, args...)
}

// detectPackageManager probes for the package managers found across
// self-hosted Docker fleets in practice (Debian/Ubuntu, Fedora/RHEL,
// Alpine) and returns whichever answers first — the same uniform,
// distro-agnostic approach discover already uses for well-known
// stateful paths (PROGRESS.md Phase 5 part 7), rather than assuming
// one distro across the fleet.
func detectPackageManager(ctx context.Context, target sshx.Runner) (string, error) {
	result, err := target.Run(ctx, sshx.ReadOnly, "sh",
		[]string{"-c", "command -v apt-get || command -v dnf || command -v yum || command -v apk"},
		sshx.RunOptions{})
	found := strings.TrimSpace(result.Stdout)
	if err != nil || found == "" {
		return "", fmt.Errorf("no supported package manager found on target (checked apt-get, dnf, yum, apk) — install borg manually")
	}
	return filepath.Base(found), nil
}

// borgInstallCommand returns the install invocation for pkgManager.
// apt-get alone needs a metadata refresh first (a fresh server's apt
// cache is typically empty or stale) and DEBIAN_FRONTEND=noninteractive
// to avoid a debconf prompt hanging a non-interactive SSH session —
// dnf/yum/apk all refresh their own metadata as part of install.
//
// apt-get update's own exit code is deliberately ignored (`|| true`):
// it returns non-zero as soon as *any* configured repo fails to
// refresh, even though every other repo's metadata still updated —
// verified live against a real server whose apt.postgresql.org
// third-party source had dropped its (EOL) distro codename entirely.
// borgbackup ships from Ubuntu/Debian's own repos, unrelated to
// whatever third-party source a database server happens to have
// configured for Postgres itself, so one broken PPA must never block
// an otherwise-unrelated install — if the package genuinely can't be
// found, apt-get install fails on its own with its own clear error.
func borgInstallCommand(pkgManager string) (cmd string, args []string, err error) {
	switch pkgManager {
	case "apt-get":
		return "sh", []string{"-c", "apt-get update || true; DEBIAN_FRONTEND=noninteractive apt-get install -y borgbackup"}, nil
	case "dnf":
		return "dnf", []string{"install", "-y", "borgbackup"}, nil
	case "yum":
		return "yum", []string{"install", "-y", "borgbackup"}, nil
	case "apk":
		return "apk", []string{"add", "--no-cache", "borgbackup"}, nil
	default:
		return "", nil, fmt.Errorf("unsupported package manager %q — install borg manually", pkgManager)
	}
}

// RepoPath is the borg repo's identity *within* the subaccount's own
// jailed home directory — an absolute path *as seen from inside that
// jail*, deliberately not prefixed with dest.HomeDirectory (the
// subaccount's SSH/SFTP session is jailed at HomeDirectory, so from
// inside it HomeDirectory is effectively "/" — repeating it would nest
// the repo one level too deep). This exact string feeds both the
// install-time `borg serve --restrict-to-repository` restriction and,
// wrapped by RemoteRepoTarget, borg's own client-side repo argument —
// the single place this layout is decided, so onboard/backup/verify
// never independently guess at it. It must be a leading-slash absolute
// path, not a bare relative name: verified live against a real Storage
// Box, borg serve's restriction check compares the *resolved* absolute
// path from the incoming ssh:// URL (which a leading "/" after the
// host always produces per Borg's own URL syntax — see
// RemoteRepoTarget) against the configured restriction as a literal
// string.
//
// It must also live under "/home/" specifically: Hetzner's own docs
// (docs.hetzner.com/storage/storage-box/access/access-ssh-rsync-borg/)
// state only "/home/" is writable on a Storage Box, and this was
// verified live — borg init's own os.mkdir failed with "OSError:
// [Errno 30] Read-only file system" at the jail's top level ("/repo")
// regardless of account or append-only state. "/home/" is not a
// subdirectory the operator creates: it's a writable alias Hetzner
// bind-mounts onto the same jail root (verified live — a file written
// to "/home/repo/x" via the subaccount is immediately readable at
// dest.HomeDirectory+"/repo/x" via the main account, same inode), just
// exposed with different write permissions than the bare "/" path.
// Because of that alias, borg init's own os.mkdir succeeds once
// requests are routed through "/home/", so no separate pre-creation
// step is needed — unlike RepoPath, dest.HomeDirectory+"/repo" (no
// "/home") is the physical path the main account would use to reach
// the same directory, since the main account sees the raw filesystem,
// not the subaccount's aliased view.
func RepoPath(dest hetzner.Destination) string {
	return "/home/repo"
}

// RemoteRepoTarget is what borg's own client commands (init, create,
// list, extract) are actually given as their repo argument — an
// ssh:// URL connecting to the subaccount (never the main account,
// never a bare local path) using the automation key already installed
// there. A bare relative path with no ssh:// scheme, which is what
// this codebase used before an earlier fix, is not a remote repo
// reference at all: borg (and every caller here, which runs it via the
// *target server's* own SSH session, per Deps.Target) would silently
// treat it as a path on the target server's own local filesystem,
// never reaching the Storage Box (verified live). RepoPath already
// carries its own leading slash, so this doesn't add a second one —
// an accidental double slash after the host has its own, different
// meaning in Borg's URL syntax (a truly absolute path bypassing the
// jail's own root, rather than absolute-within-the-jail).
func RemoteRepoTarget(dest hetzner.Destination) string {
	return fmt.Sprintf("ssh://%s@%s:23%s", dest.Username, dest.Server, RepoPath(dest))
}

// mainAccount builds the operator's Storage Box main-account login
// from fleet.yaml — used to install and lift/restore the automation
// key (onboardInstallKey, and step 5's temporary lift around init), so
// every caller shares one place this is assembled.
func mainAccount(d Deps) hetzner.MainAccount {
	return hetzner.MainAccount{Target: sshx.Target{
		Host: d.Server.Hetzner.MainAccount.Host,
		Port: d.Server.Hetzner.MainAccount.Port,
		User: d.Server.Hetzner.MainAccount.User,
	}}
}

func onboardDiscover(ctx context.Context, d Deps, st *state.Server) error {
	rep, err := discover.Inspect(ctx, d.Target, d.ServerID, discover.RealEgressIP, d.Progress)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if rep.Incomplete {
		return fmt.Errorf("discover result is incomplete (%s) — refusing to proceed; re-run once the target is fully reachable",
			strings.Join(rep.IncompleteReasons, "; "))
	}
	// Borg's absence is no longer a refusal here — step 2
	// (ensureBorgInstalled) installs it if missing, since that's a
	// plain OS package, not something requiring operator judgment.
	st.Databases = rep.Databases
	return nil
}

// onboardInstallKey generates the automation keypair ON THE TARGET
// (SPEC.md §3: it must never leave the target, so it can't be
// generated on the control host and copied over), installs its public
// half append-only via the main account, and confirms the restriction
// took effect using the same private key from where it lives.
//
// Resumable by construction: if a prior attempt got as far as
// generating the keypair but failed (or its state save failed) before
// step 3 could be recorded complete, a re-run must reuse that same
// key rather than blindly regenerating — InstallServerKey is always
// re-run regardless (idempotent: mergeAuthorizedKeysLine replaces its
// own entry, never duplicates), so re-attempting install/verify with
// the *same* key is exactly what "resume" should mean here.
func onboardInstallKey(ctx context.Context, d Deps, dest hetzner.Destination, repoPath string) (fingerprint string, err error) {
	pubKeyLine, err := readAutomationPubKey(ctx, d)
	if err != nil || pubKeyLine == "" {
		if err := generateAutomationKeypair(ctx, d); err != nil {
			return "", err
		}
		pubKeyLine, err = readAutomationPubKey(ctx, d)
		if err != nil {
			return "", fmt.Errorf("read generated public key: %w", err)
		}
		if pubKeyLine == "" {
			return "", fmt.Errorf("generated public key file was empty")
		}
	}

	fp, err := d.Target.Run(ctx, sshx.ReadOnly, "ssh-keygen", []string{"-lf", automationKeyPath + ".pub"}, sshx.RunOptions{})
	if err != nil {
		return "", fmt.Errorf("fingerprint generated key: %w", err)
	}

	req := hetzner.InstallKeyRequest{
		Main:          mainAccount(d),
		Destination:   dest,
		PublicKey:     pubKeyLine,
		AppendOnly:    true,
		RepoPath:      repoPath,
		VerifyKeyPath: automationKeyPath,
	}
	if err := d.Provider.InstallServerKey(ctx, d.StorageBox, d.Target, req); err != nil {
		return "", err
	}
	return strings.TrimSpace(fp.Stdout), nil
}

// readAutomationPubKey returns the automation key's public half if it
// already exists on the target, or "" if the read failed for any
// reason. It deliberately doesn't distinguish "file doesn't exist yet"
// (the expected case on a fresh onboard) from a genuine read failure
// (e.g. the target is unreachable) — both simply fall through to
// generateAutomationKeypair, which will itself surface a clear error
// if the target really is unreachable.
func readAutomationPubKey(ctx context.Context, d Deps) (string, error) {
	pub, err := d.Target.Run(ctx, sshx.ReadOnly, "cat", []string{automationKeyPath + ".pub"}, sshx.RunOptions{})
	if err != nil {
		return "", nil //nolint:nilerr // absence is the expected, common case here — see doc comment
	}
	return strings.TrimSpace(pub.Stdout), nil
}

// generateAutomationKeypair removes any stale key material first —
// ssh-keygen prompts interactively to overwrite an existing file, which
// would hang or silently abort against a non-interactive session — a
// scenario only reachable if a prior onboard attempt generated a key
// but failed before recording it (SPEC.md §4's resumability).
func generateAutomationKeypair(ctx context.Context, d Deps) error {
	if _, err := d.Target.Run(ctx, sshx.Mutating, "rm",
		[]string{"-f", automationKeyPath, automationKeyPath + ".pub"}, sshx.RunOptions{}); err != nil {
		return fmt.Errorf("clear any stale automation keypair: %w", err)
	}
	if _, err := d.Target.Run(ctx, sshx.Mutating, "ssh-keygen",
		[]string{"-t", "ed25519", "-N", "", "-C", "fortified-" + d.ServerID, "-f", automationKeyPath}, sshx.RunOptions{}); err != nil {
		return fmt.Errorf("generate automation keypair on target: %w", err)
	}
	return nil
}

func advanceOnboard(d Deps, st *state.Server, step int) error {
	st.Onboard.LastCompletedStep = step
	st.Onboard.FailureReason = ""
	if err := state.Save(d.StateDir, st); err != nil {
		return fmt.Errorf("onboard: save state after step %d: %w", step, err)
	}
	return nil
}

func recordOnboardFailure(d Deps, st *state.Server, step int, cause error) error {
	st.Onboard.FailureReason = cause.Error()
	if saveErr := state.Save(d.StateDir, st); saveErr != nil {
		return fmt.Errorf("onboard: step %d: %w (and saving the failure reason also failed: %v)", step, cause, saveErr)
	}
	return fmt.Errorf("onboard: step %d: %w", step, cause)
}
