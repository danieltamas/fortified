package hetzner

import (
	"context"
	"strings"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

// realAuthorizedKeysFixture mirrors exactly what was found live on
// host-2-example's subaccount: a personal key present in both
// RFC4716 (port 22/SFTP) and single-line OpenSSH (unrestricted) form
// — neither installed by fortified — plus fortified's own
// append-only-restricted automation key.
const realAuthorizedKeysFixture = `---- BEGIN SSH2 PUBLIC KEY ----
Comment: "hello@operator.com"
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEv+kLOhK53szn9N8f
iiP2tz2gYufTMph+zK6W5jV0jwf76lj+BTLCBwSuthT10hXWtqLOTKKjFwGn+pCvJpK1Y=
---- END SSH2 PUBLIC KEY ----
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEv+kLOhK53szn9N8fiiP2tz2gYufTMph+zK6W5jV0jwf76lj+BTLCBwSuthT10hXWtqLOTKKjFwGn+pCvJpK1Y= hello@operator.com
command="borg serve --append-only --restrict-to-repository /repo",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJK4Pcv6WnvHd3kVzuxJfhHaIepRbcrlpYjcnuI0JNpv fortified-host-2-example
`

// TestParseAuthorizedKeysRealFixture pins the exact live shape found
// auditing host-2-example's subaccount: three entries (an RFC4716
// block and a duplicate single-line entry for the same personal key,
// neither installed by fortified, plus fortified's own append-only
// automation key) — every field must be parsed correctly for the
// audit report to be trustworthy.
func TestParseAuthorizedKeysRealFixture(t *testing.T) {
	entries := parseAuthorizedKeys(realAuthorizedKeysFixture)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(entries), entries)
	}

	rfc4716 := entries[0]
	if rfc4716.Format != "rfc4716" || rfc4716.Comment != "hello@operator.com" || rfc4716.FortifiedOwned {
		t.Errorf("rfc4716 entry = %+v, want Format=rfc4716 Comment=hello@operator.com FortifiedOwned=false", rfc4716)
	}

	openssh := entries[1]
	if openssh.Format != "openssh" || openssh.Comment != "hello@operator.com" || openssh.Restricted || openssh.FortifiedOwned {
		t.Errorf("openssh entry = %+v, want Format=openssh Comment=hello@operator.com Restricted=false FortifiedOwned=false", openssh)
	}

	automation := entries[2]
	if !automation.Restricted || automation.Command != "borg serve --append-only --restrict-to-repository /repo" || !automation.FortifiedOwned {
		t.Errorf("automation entry = %+v, want Restricted=true Command matching, FortifiedOwned=true", automation)
	}
	if automation.Comment != "fortified-host-2-example" {
		t.Errorf("automation entry comment = %q, want fortified-host-2-example", automation.Comment)
	}
}

// TestStripEntriesByCommentRemovesBothFormats proves removal strips
// *every* entry matching the comment — both the RFC4716 block and the
// single-line duplicate — in one pass, since both grant real access
// under the same human-meaningful identity, and leaves the unrelated
// fortified entry untouched.
func TestStripEntriesByCommentRemovesBothFormats(t *testing.T) {
	kept, removed := stripEntriesByComment(realAuthorizedKeysFixture, "hello@operator.com")
	if !removed {
		t.Fatal("expected stripEntriesByComment to report removal")
	}
	if strings.Contains(kept, "hello@operator.com") {
		t.Errorf("kept content still mentions the removed comment: %q", kept)
	}
	if !strings.Contains(kept, "fortified-host-2-example") {
		t.Errorf("kept content lost the unrelated fortified key: %q", kept)
	}
}

func TestStripEntriesByCommentReportsNotFound(t *testing.T) {
	_, removed := stripEntriesByComment(realAuthorizedKeysFixture, "nonexistent@example.com")
	if removed {
		t.Error("expected removed=false when the comment matches nothing")
	}
}

// TestRemoveAuthorizedKeysByCommentRefusesFortifiedOwnKey is the
// critical safety guarantee: this command must never be able to lock
// fortified out of its own destination. The refusal must happen
// before ever fetching/mutating anything remote — proven here by a
// bare FakeRunner with zero scripted responses still working, since a
// real fetch attempt would need one.
func TestRemoveAuthorizedKeysByCommentRefusesFortifiedOwnKey(t *testing.T) {
	fake := &sshxtest.FakeRunner{}
	err := RemoveAuthorizedKeysByComment(context.Background(), fake, testMain(), testDest(), "fortified-host-2-example")
	if err == nil {
		t.Fatal("expected RemoveAuthorizedKeysByComment to refuse removing fortified's own automation key")
	}
	if !strings.Contains(err.Error(), "lock fortified out") {
		t.Errorf("error = %v, want it to explain the lockout risk", err)
	}
	if len(fake.Calls) != 0 {
		t.Errorf("expected zero remote calls before the safety check, got %+v", fake.Calls)
	}
}
