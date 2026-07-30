package hetzner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/danieltamas/fortified/internal/sshx"
)

// AuthorizedKeyEntry is one parsed key from a subaccount's
// authorized_keys file — either a single-line OpenSSH entry (the only
// format port 23/borg honors a forced command= on) or an RFC4716
// block (port 22/SFTP only — NOTES.md). Both are surfaced together
// because both grant real access to what's supposed to be an isolated
// destination; an unrestricted RFC4716 key is arguably the more
// dangerous of the two, since it grants raw file access that bypasses
// borg's own append-only enforcement entirely (that enforcement is
// the forced command on port 23, which has no RFC4716/port-22
// equivalent).
type AuthorizedKeyEntry struct {
	Comment        string `json:"comment"`
	Format         string `json:"format"` // "openssh" or "rfc4716"
	Restricted     bool   `json:"restricted"`
	Command        string `json:"command,omitempty"`
	FortifiedOwned bool   `json:"fortified_owned"`
}

// ListAuthorizedKeys fetches and parses every entry in dest's
// authorized_keys via the main account (read-only) — the first step
// of auditing what actually has access to an isolated destination.
// Fortified can only ever mark *its own* automation key with
// certainty (by its "fortified-<server-id>" naming convention); every
// other entry is surfaced for the operator to judge, never
// auto-classified as "expected" — it might be the operator's own
// legitimate prune key, which fortified must never possess or compare
// against (SPEC.md §1), so it structurally cannot tell that apart
// from a genuinely unauthorized key on its own.
func ListAuthorizedKeys(ctx context.Context, runner sshx.Runner, main MainAccount, dest Destination) ([]AuthorizedKeyEntry, error) {
	remoteFile := dest.HomeDirectory + "/.ssh/authorized_keys"
	existing, err := fetchExistingAuthorizedKeys(ctx, runner, main, remoteFile)
	if err != nil {
		return nil, err
	}
	return parseAuthorizedKeys(existing), nil
}

func parseAuthorizedKeys(content string) []AuthorizedKeyEntry {
	var entries []AuthorizedKeyEntry
	inBlock := false
	blockComment := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "---- BEGIN"):
			inBlock = true
			blockComment = ""
			continue
		case strings.HasPrefix(line, "---- END"):
			if inBlock {
				entries = append(entries, AuthorizedKeyEntry{Comment: blockComment, Format: "rfc4716"})
			}
			inBlock = false
			continue
		case inBlock:
			if strings.HasPrefix(line, "Comment:") {
				blockComment = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "Comment:")), `"`)
			}
			continue
		}

		if pubKeyBlob(line) == "" {
			continue
		}
		entries = append(entries, AuthorizedKeyEntry{
			Comment:    lineComment(line),
			Format:     "openssh",
			Restricted: strings.Contains(line, "command="),
			Command:    extractCommand(line),
		})
	}
	for i := range entries {
		entries[i].FortifiedOwned = strings.HasPrefix(entries[i].Comment, "fortified-")
	}
	return entries
}

// lineComment returns a single-line entry's trailing comment field —
// whatever follows the base64 key blob, if anything. Mirrors
// pubKeyBlob's own field-scan so a preceding command="..." (which
// itself contains spaces strings.Fields will split on) never throws
// off where the blob and comment actually start.
func lineComment(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") {
			if i+2 <= len(fields)-1 {
				return strings.Join(fields[i+2:], " ")
			}
			return ""
		}
	}
	return ""
}

// extractCommand pulls the quoted value out of a command="..." forced
// command, operating on the raw line (not a whitespace split, since
// the command text itself contains spaces).
func extractCommand(line string) string {
	const marker = `command="`
	start := strings.Index(line, marker)
	if start == -1 {
		return ""
	}
	rest := line[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end == -1 {
		return ""
	}
	return rest[:end]
}

// RemoveAuthorizedKeysByComment removes every entry (single-line or
// RFC4716 block) whose comment matches comment exactly, via the main
// account. Refuses outright if comment matches fortified's own
// automation-key naming convention ("fortified-<server-id>") — this
// must never be able to lock fortified out of its own destination.
// Naming the exact comment (never a blanket "remove everything
// unrecognized") is the explicit, named confirmation a destructive
// action requires (SPEC.md §1) — the operator must have already
// reviewed ListAuthorizedKeys' own report and decided this specific
// key doesn't belong.
func RemoveAuthorizedKeysByComment(ctx context.Context, runner sshx.Runner, main MainAccount, dest Destination, comment string) error {
	if strings.HasPrefix(comment, "fortified-") {
		return fmt.Errorf("hetzner: refusing to remove %q — that is fortified's own automation key naming convention; removing it would lock fortified out of its own destination", comment)
	}

	remoteFile := dest.HomeDirectory + "/.ssh/authorized_keys"
	existing, err := fetchExistingAuthorizedKeys(ctx, runner, main, remoteFile)
	if err != nil {
		return err
	}

	kept, removed := stripEntriesByComment(existing, comment)
	if !removed {
		return fmt.Errorf("hetzner: no authorized_keys entry with comment %q found", comment)
	}

	if err := uploadAuthorizedKeys(ctx, runner, main, remoteFile, kept); err != nil {
		return err
	}
	return nil
}

// stripEntriesByComment rebuilds content with every entry (single-line
// or RFC4716 block) whose comment matches comment removed, reporting
// whether anything was actually removed.
func stripEntriesByComment(content, comment string) (kept string, removed bool) {
	var out []string
	var block []string
	inBlock := false
	blockMatches := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "---- BEGIN") {
			inBlock = true
			blockMatches = false
			block = []string{line}
			continue
		}
		if strings.HasPrefix(line, "---- END") {
			block = append(block, line)
			if blockMatches {
				removed = true
			} else {
				out = append(out, block...)
			}
			inBlock = false
			continue
		}
		if inBlock {
			block = append(block, line)
			if strings.HasPrefix(line, "Comment:") {
				got := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "Comment:")), `"`)
				blockMatches = got == comment
			}
			continue
		}
		if lineComment(line) == comment {
			removed = true
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return "", removed
	}
	return strings.Join(out, "\n") + "\n", removed
}

// uploadAuthorizedKeys writes content as dest's whole authorized_keys
// file, via the main account — used for removal, where the caller has
// already computed the exact desired final content (unlike
// writeAuthorizedKeys, which merges one new line into whatever
// already exists).
func uploadAuthorizedKeys(ctx context.Context, runner sshx.Runner, main MainAccount, remoteFile, content string) error {
	tmp, err := os.CreateTemp("", "fortified-authorized-keys-*")
	if err != nil {
		return fmt.Errorf("hetzner: create temp file for authorized_keys: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hetzner: write temp authorized_keys content: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("hetzner: close temp authorized_keys file: %w", err)
	}

	script := fmt.Sprintf("put %s %s\n", tmp.Name(), remoteFile)
	if _, err := runner.Run(ctx, sshx.Mutating, "sftp", mainAccountSFTPArgs(main), sshx.RunOptions{Stdin: script}); err != nil {
		return fmt.Errorf("hetzner: write authorized_keys: %w", err)
	}
	return nil
}
