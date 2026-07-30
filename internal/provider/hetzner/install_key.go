package hetzner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danieltamas/fortified/internal/sshx"
)

// MainAccount is the operator's own Storage Box login — used only at
// setup time, to write a subaccount's authorized_keys directly. It is
// never stored on a protected server (NOTES.md).
type MainAccount struct {
	Target sshx.Target // Host = Storage Box hostname, Port = 22 (SFTP), User = main account username (uXXXXXX)
}

// mainAccountSFTPArgs builds the sftp invocation for main — every
// call site in this file and audit_keys.go shares this so a single
// onboard/audit-keys invocation's several main-account round trips
// (get, put, mkdir, get, put, ...) reuse one multiplexed SSH
// connection instead of each spawning its own from scratch. Without
// this, sftp (a separate client binary from the ssh used for
// Deps.Target's own already-multiplexed Session) authenticates fresh
// on every single call — verified live: onboard step 5's lift/restore
// dance alone triggered 5 separate reconnect/Touch-ID prompts before
// this fix. ControlPersist=60 lets the master connection self-expire
// shortly after the last use rather than lingering indefinitely — this
// package has no session object with an explicit close to hang cleanup
// off, unlike sshx.Session.
func mainAccountSFTPArgs(main MainAccount) []string {
	controlPath := fmt.Sprintf("/tmp/fortified-storagebox-%d-%s.sock", os.Getpid(), main.Target.Host)
	return []string{
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=60",
		"-o", "ControlPath=" + controlPath,
		"-b", "-", "-P", strconv.Itoa(main.Target.Port),
		fmt.Sprintf("%s@%s", main.Target.User, main.Target.Host),
	}
}

// InstallKeyRequest bundles InstallServerKey's inputs (SPEC.md §3's
// InstallServerKey(dest, pubkey, appendOnly), expanded with what the
// verified real mechanism actually needs).
type InstallKeyRequest struct {
	Main        MainAccount
	Destination Destination
	PublicKey   string // full "ssh-ed25519 AAAA... comment" line
	AppendOnly  bool
	RepoPath    string // borg --restrict-to-repository path; required when AppendOnly

	// VerifyKeyPath, when set, is a private key file path InstallServerKey
	// uses to open a connection AS the newly installed key and confirm
	// the append-only restriction actually took effect — SPEC.md §5:
	// "the tool must surface a clear failure if it cannot confirm this,
	// not silently proceed as if protected." Empty skips verification
	// (only ever appropriate for AppendOnly=false). This path must be
	// resolvable by verifyRunner (InstallServerKey's second runner) —
	// in production that's the target server, since SPEC.md §3 requires
	// the automation keypair to be generated on the target and never
	// leave it, so its private key only ever exists there.
	VerifyKeyPath string
}

// InstallServerKey writes dest's authorized_keys directly, as the
// main account (NOTES.md: install-ssh-key cannot attach a forced
// command, so it cannot be used for an append-only key). When
// AppendOnly, the installed entry is prefixed with a forced command
// restricting every session on that key to `borg serve --append-only`
// — Hetzner's Storage Box enforces this server-side, not the client.
//
// Two runners, deliberately not one: mainRunner executes the
// authorized_keys write as the operator's main Storage Box account
// (SPEC.md §3 — that credential lives on the control host, never a
// protected server); verifyRunner executes the post-install
// confirmation AS the newly installed key, which must run from
// wherever VerifyKeyPath's private key actually lives — the target
// server in production, since the automation keypair is generated
// there and never leaves it. Passing the same runner for both is
// fine in tests (a FakeRunner has no real filesystem to care), but
// production wiring must not collapse these into one connection.
func (p Provider) InstallServerKey(ctx context.Context, mainRunner, verifyRunner sshx.Runner, req InstallKeyRequest) error {
	if req.AppendOnly && req.RepoPath == "" {
		return fmt.Errorf("hetzner: AppendOnly key install requires RepoPath")
	}
	line := authorizedKeysLine(req.PublicKey, req.AppendOnly, req.RepoPath)

	if err := writeAuthorizedKeys(ctx, mainRunner, req.Main, req.Destination, line); err != nil {
		return err
	}

	if req.AppendOnly && req.VerifyKeyPath != "" {
		if err := verifyAppendOnly(ctx, verifyRunner, req.Destination, req.VerifyKeyPath); err != nil {
			return fmt.Errorf("hetzner: append-only restriction could not be confirmed for subaccount %d: %w", req.Destination.SubaccountID, err)
		}
	}
	return nil
}

// authorizedKeysLine builds the authorized_keys entry for pubkey. When
// appendOnly, it's prefixed with the forced command that restricts
// every session on this key to `borg serve --append-only` — the
// mechanism Hetzner's Storage Box enforces server-side (NOTES.md).
func authorizedKeysLine(pubkey string, appendOnly bool, repoPath string) string {
	if !appendOnly {
		return pubkey
	}
	return fmt.Sprintf(`command="borg serve --append-only --restrict-to-repository %s",restrict %s`, repoPath, pubkey)
}

// writeAuthorizedKeys merges line into the subaccount's
// .ssh/authorized_keys, connecting as the main account (never the
// subaccount's own password) via sftp in batch mode. This must merge,
// not overwrite: a real deployment installs the append-only automation
// key and, separately, the operator's unrestricted prune key
// (NOTES.md) — a blind overwrite would delete whichever key was
// installed first.
func writeAuthorizedKeys(ctx context.Context, runner sshx.Runner, main MainAccount, dest Destination, line string) error {
	sshDir := dest.HomeDirectory + "/.ssh"
	remoteFile := sshDir + "/authorized_keys"

	existing, err := fetchExistingAuthorizedKeys(ctx, runner, main, remoteFile)
	if err != nil {
		return err
	}
	merged := mergeAuthorizedKeysLine(existing, line)

	tmp, err := os.CreateTemp("", "fortified-authorized-keys-*")
	if err != nil {
		return fmt.Errorf("hetzner: create temp file for authorized_keys: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.WriteString(merged); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hetzner: write temp authorized_keys content: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("hetzner: close temp authorized_keys file: %w", err)
	}

	// "-mkdir" (leading "-") tells sftp batch mode to ignore a failure
	// (the directory may already exist from a prior onboard attempt) —
	// SPEC.md §4: re-running onboard must never fail on already-done work.
	script := fmt.Sprintf("-mkdir %s\nput %s %s\n", sshDir, tmp.Name(), remoteFile)

	if _, err := runner.Run(ctx, sshx.Mutating, "sftp", mainAccountSFTPArgs(main), sshx.RunOptions{Stdin: script}); err != nil {
		return fmt.Errorf("hetzner: write authorized_keys for subaccount %d: %w", dest.SubaccountID, err)
	}
	return nil
}

// fetchExistingAuthorizedKeys downloads remoteFile's current content
// so writeAuthorizedKeys can merge into it. A leading "-" on the sftp
// "get" command tells batch mode to ignore a failure — the file
// legitimately doesn't exist yet on a server's first-ever key install
// — in which case this returns "", nil.
func fetchExistingAuthorizedKeys(ctx context.Context, runner sshx.Runner, main MainAccount, remoteFile string) (string, error) {
	tmp, err := os.CreateTemp("", "fortified-authorized-keys-existing-*")
	if err != nil {
		return "", fmt.Errorf("hetzner: create temp file for existing authorized_keys: %w", err)
	}
	localPath := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(localPath) // sftp get must create it fresh; a stub file would make "does it exist" ambiguous
	defer func() { _ = os.Remove(localPath) }()

	script := fmt.Sprintf("-get %s %s\n", remoteFile, localPath)
	if _, err := runner.Run(ctx, sshx.ReadOnly, "sftp", mainAccountSFTPArgs(main), sshx.RunOptions{Stdin: script}); err != nil {
		return "", fmt.Errorf("hetzner: fetch existing authorized_keys: %w", err)
	}

	data, err := os.ReadFile(localPath) //nolint:gosec // localPath is our own os.CreateTemp path, not untrusted input
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("hetzner: read fetched authorized_keys: %w", err)
	}
	return string(data), nil
}

// mergeAuthorizedKeysLine returns existing with any prior entry for
// the same public key removed, plus newLine appended — so
// reinstalling a key (e.g. to change its append-only restriction)
// replaces its own entry without disturbing unrelated keys (like the
// operator's separately-installed prune key, NOTES.md).
func mergeAuthorizedKeysLine(existing, newLine string) string {
	blob := pubKeyBlob(newLine)
	var kept []string
	for _, l := range strings.Split(existing, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if blob != "" && strings.Contains(l, blob) {
			continue // superseded by newLine
		}
		kept = append(kept, l)
	}
	kept = append(kept, newLine)
	return strings.Join(kept, "\n") + "\n"
}

// pubKeyBlob extracts the base64 key material from an authorized_keys
// line, whether or not it carries a leading command="..." restriction
// or a trailing comment — the blob is what identifies "the same key"
// for merge/replace instead of duplicate-append.
func pubKeyBlob(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") {
			if i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

// verifyAppendOnly confirms the installed key's forced command
// actually took effect: attempting an SFTP session as the subaccount
// (dest.Username@dest.Server) with the new key must be refused (the
// server routes every session on that key to `borg serve`, never the
// sftp subsystem). If SFTP *succeeds*, the restriction did not take
// effect and this returns an error. This must connect to the
// subaccount, not the main account (req.Main.Target) — the forced
// command is installed on the subaccount's authorized_keys, so
// verifying against the main account would always "succeed" and prove
// nothing about the restriction under test.
// appendOnlyVerifyRetryAttempts and appendOnlyVerifyRetryDelay are
// vars, not consts, so tests can shrink the delay — the defaults are
// real-world-appropriate (waiting out a just-created subaccount's
// routing/DNS propagation, observed live to take upward of 45s), not
// test-appropriate. 12 attempts at 8s apart budgets ~90s of retrying.
var (
	appendOnlyVerifyRetryAttempts = 12
	appendOnlyVerifyRetryDelay    = 8 * time.Second
)

func verifyAppendOnly(ctx context.Context, runner sshx.Runner, dest Destination, keyPath string) error {
	args := []string{"-i", keyPath, "-P", "23", "-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", dest.Username, dest.Server)}
	// This is the very first connection ever made to a just-created
	// subaccount's own hostname/route, which can take well over 15s to
	// become reachable after the Hetzner API's CreateSubaccount call
	// already returned success (verified live across three separate
	// subaccounts — see onboard.go's initRepoRetryAttempts doc comment
	// for the full evidence, including ruling out a client-side IPv6
	// issue). Without retrying specifically on that class of failure, a
	// connection-level error here reads exactly like "the forced
	// command refused the session" — a false pass that only surfaces
	// as a real failure later, in InitRepo.
	err := sshx.RetryOnTransientConnectionError(ctx, appendOnlyVerifyRetryAttempts, appendOnlyVerifyRetryDelay, func() error {
		_, runErr := runner.Run(ctx, sshx.ReadOnly, "sftp", args, sshx.RunOptions{Stdin: "ls\n"})
		return runErr
	})
	if err == nil {
		return fmt.Errorf("SFTP access succeeded using the append-only key — the forced command was not applied")
	}
	// A refusal is only proof of the restriction if we actually reached
	// the subaccount and it refused us — verified live, that refusal
	// reads as "permission denied (publickey)" even though the key IS
	// correctly installed (the sftp client's own confusing behavior
	// when the far end speaks borg's protocol instead of SFTP, not a
	// real auth rejection — see TestInstallKeyAppendOnlyConfirmedSucceeds).
	// But if every attempt instead failed at the network layer
	// (IsTransientConnectionError's signatures — DNS, refused, timeout,
	// unreachable — exhausted across the whole retry budget above), we
	// never got far enough to observe the restriction at all: treating
	// that as "confirmed" was the fail-open gap here — a real outage or
	// firewall issue would silently certify a key whose restriction was
	// never actually tested.
	if sshx.IsTransientConnectionError(err) {
		return fmt.Errorf("could not confirm the append-only restriction — every attempt to even reach the subaccount failed (last error: %w)", err)
	}
	return nil
}
