// Package hetzner implements the Provider interface (SPEC.md §3)
// against Hetzner Storage Box: subaccount creation, append-only key
// installation, and snapshot-schedule management. See NOTES.md for
// the research this implementation is built on — in particular, key
// installation uses direct authorized_keys provisioning by the main
// account, not the install-ssh-key protocol command, because
// install-ssh-key cannot attach the forced command append-only
// enforcement depends on (verified against current Hetzner docs and
// the hcloud-go source, not assumed).
package hetzner

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/danieltamas/fortified/internal/sshx"
)

// Provider implements the backup-destination Provider interface
// against Hetzner Storage Box. All HTTP goes through Client's
// configured http.Client — set its Transport to an audit.RoundTripper
// in production so every call is recorded (SPEC.md §4). One Storage
// Box is provisioned once by the operator; subaccounts (one per
// protected server, SKILL.md's isolation rule) are what this Provider
// creates and manages.
//
// DryRun and Out implement SPEC.md §5's --dry-run semantics for the
// two methods that mutate (CreateIsolatedDestination's create path,
// EnableSnapshotSchedule): unlike sshx.Runner calls, hcloud-go builds
// its own HTTP requests internally, so there's no per-call
// classification seam to hook from outside — the mutating branch has
// to be skipped here, at the one place that knows it's about to
// happen, printing to Out instead of faking an HTTP response (a faked
// response risks handing the caller invented values — e.g. a
// subaccount ID that was never really assigned — which SPEC.md §5
// explicitly forbids: only explicit placeholders, never invented
// data). Read-only lookups (GetByID, GetSubaccountByName) still run
// for real even under DryRun, since the plan legitimately depends on
// their output (does the destination already exist?).
type Provider struct {
	Client       *hcloud.Client
	StorageBoxID int64
	DryRun       bool
	Out          io.Writer
}

// Destination identifies one server's isolated backup destination.
type Destination struct {
	SubaccountID  int64
	Username      string // subaccount login, e.g. u123456-sub1 — distinct from the main account's uXXXXXX
	HomeDirectory string
	Server        string // Storage Box hostname, e.g. u123456.your-storagebox.de
}

// lookupDestination finds serverID's Storage Box subaccount if one
// already exists, returning the box alongside it so a caller that
// goes on to create one doesn't need a second GetByID round trip.
func (p Provider) lookupDestination(ctx context.Context, serverID string) (*hcloud.StorageBoxSubaccount, *hcloud.StorageBox, error) {
	box, _, err := p.Client.StorageBox.GetByID(ctx, p.StorageBoxID)
	if err != nil {
		return nil, nil, fmt.Errorf("hetzner: get storage box %d: %w", p.StorageBoxID, err)
	}
	if box == nil {
		return nil, nil, fmt.Errorf("hetzner: storage box %d not found", p.StorageBoxID)
	}
	existing, _, err := p.Client.StorageBox.GetSubaccountByName(ctx, box, serverID)
	if err != nil {
		return nil, nil, fmt.Errorf("hetzner: look up subaccount %s: %w", serverID, err)
	}
	return existing, box, nil
}

// GetDestination looks up serverID's already-onboarded destination —
// unlike CreateIsolatedDestination, it never creates one. Every
// command except onboard must use this: onboard is the only step that
// should ever bring a new subaccount into existence. A later command
// (backup/verify/enable-snapshots) whose state believes onboarding
// already happened must refuse clearly if the destination is gone,
// rather than silently creating a fresh, un-keyed subaccount with no
// repo and no automation key installed on it and failing much later,
// far more confusingly, at "repo not found".
func (p Provider) GetDestination(ctx context.Context, serverID string) (Destination, error) {
	existing, _, err := p.lookupDestination(ctx, serverID)
	if err != nil {
		return Destination{}, err
	}
	if existing == nil {
		return Destination{}, fmt.Errorf("hetzner: no Storage Box subaccount named %q — it may have been deleted since onboarding; re-run onboard rather than assuming it will recreate itself", serverID)
	}
	return Destination{SubaccountID: existing.ID, Username: existing.Username, HomeDirectory: homeDirectory(serverID), Server: existing.Server}, nil
}

// CreateIsolatedDestination is idempotent: calling it twice for the
// same serverID returns the existing subaccount and issues zero
// create requests the second time (SPEC.md §3). Only onboard should
// call this — every other command uses GetDestination instead (see
// its doc comment for why).
func (p Provider) CreateIsolatedDestination(ctx context.Context, serverID string) (Destination, error) {
	existing, box, err := p.lookupDestination(ctx, serverID)
	if err != nil {
		return Destination{}, err
	}

	home := homeDirectory(serverID)

	if existing != nil {
		return Destination{SubaccountID: existing.ID, Username: existing.Username, HomeDirectory: home, Server: existing.Server}, nil
	}

	if p.DryRun {
		_, _ = fmt.Fprintf(p.Out, "[dry-run] would create Storage Box subaccount %q (home %s)\n", serverID, home)
		// Server is a placeholder too, like Username: a subaccount's own
		// hostname (distinct from the parent box's, per the live API —
		// verified: "u123456.your-storagebox.de" for the box vs.
		// "u123456-sub1.your-storagebox.de" for one of its subaccounts)
		// isn't knowable before creation actually assigns it.
		return Destination{SubaccountID: 0, Username: "<to-be-created>", HomeDirectory: home, Server: "<to-be-created>"}, nil
	}

	password, err := randomPassword()
	if err != nil {
		return Destination{}, fmt.Errorf("hetzner: generate subaccount password: %w", err)
	}

	enabled, disabled := true, false
	result, _, err := p.Client.StorageBox.CreateSubaccount(ctx, box, hcloud.StorageBoxSubaccountCreateOpts{
		Name:          serverID,
		HomeDirectory: home,
		Password:      password,
		AccessSettings: &hcloud.StorageBoxSubaccountCreateOptsAccessSettings{
			SSHEnabled:          &enabled,
			SambaEnabled:        &disabled,
			WebDAVEnabled:       &disabled,
			ReachableExternally: &disabled,
		},
	})
	if err != nil {
		return Destination{}, fmt.Errorf("hetzner: create subaccount %s: %w", serverID, err)
	}
	if result.Action != nil {
		if err := p.Client.Action.WaitFor(ctx, result.Action); err != nil {
			return Destination{}, fmt.Errorf("hetzner: wait for subaccount %s creation: %w", serverID, err)
		}
	}

	// The create response only carries ID/StorageBox — Username isn't
	// populated until the create action finishes — so re-fetch the
	// subaccount to get it.
	created, _, err := p.Client.StorageBox.GetSubaccountByID(ctx, box, result.Subaccount.ID)
	if err != nil {
		return Destination{}, fmt.Errorf("hetzner: fetch created subaccount %d: %w", result.Subaccount.ID, err)
	}
	if created == nil {
		return Destination{}, fmt.Errorf("hetzner: subaccount %d not found immediately after creation", result.Subaccount.ID)
	}

	// password is discarded here, never stored anywhere: the main
	// account writes authorized_keys directly (InstallServerKey), so
	// the subaccount password is never needed again (NOTES.md).
	return Destination{SubaccountID: created.ID, Username: created.Username, HomeDirectory: home, Server: created.Server}, nil
}

// RenameDestination moves oldServerID's Storage Box subaccount to
// newServerID, in place: its Name (what GetSubaccountByName looks
// every other command's serverID up by), its HomeDirectory metadata,
// and — critically — the actual .ssh/authorized_keys and repo that
// live at the old path, which Hetzner's own change-home-directory
// action does NOT carry over on its own (verified live: it repoints
// the subaccount to a brand-new *empty* directory at the new path,
// orphaning everything that was actually there — the very next
// connection then fails outright with "Permission denied", since no
// authorized_keys exists at the new location at all). mainRunner/main
// authenticate as the operator's main Storage Box account, the only
// one with filesystem visibility across every subaccount's directory
// (NOTES.md) — the same account InstallServerKey already uses.
//
// Idempotent, and safe to re-run after a previous run only got as far
// as the API-level rename (oldServerID's subaccount no longer exists,
// but its data was left behind at oldServerID's own deterministic home
// directory): the content move is attempted unconditionally in that
// branch too, using -rename (sftp batch mode's "ignore failure" — a
// not-yet-onboarded server legitimately has no repo yet, and a partial
// retry may have already moved one of the two entries).
func (p Provider) RenameDestination(ctx context.Context, mainRunner sshx.Runner, main MainAccount, oldServerID, newServerID string) (Destination, error) {
	existingOld, _, err := p.lookupDestination(ctx, oldServerID)
	if err != nil {
		return Destination{}, err
	}

	oldHome := homeDirectory(oldServerID)
	newHome := homeDirectory(newServerID)

	if existingOld == nil {
		existingNew, _, err := p.lookupDestination(ctx, newServerID)
		if err != nil {
			return Destination{}, err
		}
		if existingNew == nil {
			return Destination{}, fmt.Errorf("hetzner: no Storage Box subaccount named %q (nor %q) — nothing to rename", oldServerID, newServerID)
		}
		if p.DryRun {
			_, _ = fmt.Fprintf(p.Out, "[dry-run] subaccount already renamed to %q — would still ensure %s's data has moved to %s\n", newServerID, oldHome, newHome)
			return Destination{SubaccountID: existingNew.ID, Username: existingNew.Username, HomeDirectory: newHome, Server: existingNew.Server}, nil
		}
		// A prior attempt may have gotten only as far as the Name
		// rename before dying — HomeDirectory metadata (and therefore
		// the jail the subaccount actually authenticates into) can
		// still be stuck at oldHome even though the subaccount now
		// answers to newServerID. Re-issuing this is itself idempotent
		// (Hetzner accepts setting it to its current value), so this
		// isn't gated on detecting the mismatch first.
		if existingNew.HomeDirectory != newHome {
			if err := p.changeHomeDirectory(ctx, existingNew, newHome); err != nil {
				return Destination{}, err
			}
		}
		if err := moveHomeDirectoryContents(ctx, mainRunner, main, oldHome, newHome); err != nil {
			return Destination{}, fmt.Errorf("hetzner: move subaccount %d's data from %s to %s: %w", existingNew.ID, oldHome, newHome, err)
		}
		return Destination{SubaccountID: existingNew.ID, Username: existingNew.Username, HomeDirectory: newHome, Server: existingNew.Server}, nil
	}

	if p.DryRun {
		_, _ = fmt.Fprintf(p.Out, "[dry-run] would rename Storage Box subaccount %q to %q and move its data (%s -> %s)\n",
			oldServerID, newServerID, oldHome, newHome)
		return Destination{SubaccountID: existingOld.ID, Username: existingOld.Username, HomeDirectory: existingOld.HomeDirectory, Server: existingOld.Server}, nil
	}

	renamed, _, err := p.Client.StorageBox.UpdateSubaccount(ctx, existingOld, hcloud.StorageBoxSubaccountUpdateOpts{Name: newServerID})
	if err != nil {
		return Destination{}, fmt.Errorf("hetzner: rename subaccount %d from %q to %q: %w", existingOld.ID, oldServerID, newServerID, err)
	}

	if err := p.changeHomeDirectory(ctx, renamed, newHome); err != nil {
		return Destination{}, err
	}

	if err := moveHomeDirectoryContents(ctx, mainRunner, main, oldHome, newHome); err != nil {
		return Destination{}, fmt.Errorf("hetzner: move subaccount %d's data from %s to %s: %w", renamed.ID, oldHome, newHome, err)
	}

	return Destination{SubaccountID: renamed.ID, Username: renamed.Username, HomeDirectory: newHome, Server: renamed.Server}, nil
}

// changeHomeDirectory issues the API call that repoints subaccount's
// jail root to newHome, waiting for the resulting action to finish.
// This alone does NOT move any data already there (see
// RenameDestination's doc comment) — moveHomeDirectoryContents handles
// that separately, against the main account.
func (p Provider) changeHomeDirectory(ctx context.Context, subaccount *hcloud.StorageBoxSubaccount, newHome string) error {
	action, _, err := p.Client.StorageBox.ChangeSubaccountHomeDirectory(ctx, subaccount, hcloud.StorageBoxSubaccountChangeHomeDirectoryOpts{HomeDirectory: newHome})
	if err != nil {
		return fmt.Errorf("hetzner: move subaccount %d's home directory to %s: %w", subaccount.ID, newHome, err)
	}
	if action != nil {
		if err := p.Client.Action.WaitFor(ctx, action); err != nil {
			return fmt.Errorf("hetzner: wait for subaccount %d's home directory move: %w", subaccount.ID, err)
		}
	}
	return nil
}

// moveHomeDirectoryContents moves oldHome's .ssh and repo entries into
// newHome (already created, empty, by changeHomeDirectory) via the
// main account, in one batch so both share a single connection. The
// two moves are prefixed with "-" (sftp batch mode's "ignore this
// command's failure") — a not-yet-onboarded server legitimately has no
// repo yet, and a re-run after a partially-completed move must not fail
// just because one of the two entries already moved. But ".ssh" itself
// is not optional for any server this is ever called against (rename
// is documented for an already-onboarded server, which always has its
// automation key installed) — the trailing, unprefixed `ls` makes the
// whole batch fail loudly if authorized_keys isn't reachable at its
// new home afterward, rather than silently reporting success while the
// key that makes the subaccount usable at all stayed orphaned at
// oldHome (verified live: this exact silent failure is what "-rename"
// alone produced before this check existed).
func moveHomeDirectoryContents(ctx context.Context, runner sshx.Runner, main MainAccount, oldHome, newHome string) error {
	script := fmt.Sprintf("-rename %s/.ssh %s/.ssh\n-rename %s/repo %s/repo\nls %s/.ssh/authorized_keys\n",
		oldHome, newHome, oldHome, newHome, newHome)
	if _, err := runner.Run(ctx, sshx.Mutating, "sftp", mainAccountSFTPArgs(main), sshx.RunOptions{Stdin: script}); err != nil {
		return fmt.Errorf("move (or confirm) %s/.ssh -> %s/.ssh: %w", oldHome, newHome, err)
	}
	return nil
}

func homeDirectory(serverID string) string {
	return "backups/" + serverID
}

// passwordClasses are the character classes randomPassword guarantees
// at least one of each of — Hetzner's subaccount password field
// rejects a pure lowercase-hex value with "invalid input in field
// password" (verified live: this is the exact error onboard hit
// against a real Storage Box, not a hypothetical policy). The
// password itself is discarded immediately after subaccount creation
// (see the caller's doc comment) and never needed again, so its exact
// composition only has to satisfy Hetzner's validation, not be
// memorable or typeable.
var passwordClasses = []string{
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"abcdefghijklmnopqrstuvwxyz",
	"0123456789",
	"!@#$%^&*-_=+",
}

func randomPassword() (string, error) {
	const length = 32
	all := strings.Join(passwordClasses, "")

	chars := make([]byte, length)
	for i, class := range passwordClasses {
		c, err := randomChar(class)
		if err != nil {
			return "", err
		}
		chars[i] = c
	}
	for i := len(passwordClasses); i < length; i++ {
		c, err := randomChar(all)
		if err != nil {
			return "", err
		}
		chars[i] = c
	}

	for i := len(chars) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("hetzner: shuffle password: %w", err)
		}
		chars[i], chars[j.Int64()] = chars[j.Int64()], chars[i]
	}
	return string(chars), nil
}

func randomChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, fmt.Errorf("hetzner: generate random password character: %w", err)
	}
	return charset[n.Int64()], nil
}

// Schedule is a Storage Box snapshot schedule.
type Schedule struct {
	MaxSnapshots int
	Minute       int
	Hour         int
}

// EnableSnapshotSchedule turns on the destination's native snapshot
// schedule. It refuses unless verified is true — SPEC.md §4 requires
// that verify has passed at least once for this server before
// snapshots (the immutability backstop) are enabled, so this can
// never protect a still-unproven backup.
func (p Provider) EnableSnapshotSchedule(ctx context.Context, dest Destination, schedule Schedule, verified bool) error {
	if !verified {
		return fmt.Errorf("hetzner: refusing to enable snapshots for subaccount %d: no passing verify recorded yet", dest.SubaccountID)
	}

	box, _, err := p.Client.StorageBox.GetByID(ctx, p.StorageBoxID)
	if err != nil {
		return fmt.Errorf("hetzner: get storage box %d: %w", p.StorageBoxID, err)
	}
	if box == nil {
		return fmt.Errorf("hetzner: storage box %d not found", p.StorageBoxID)
	}

	if p.DryRun {
		_, _ = fmt.Fprintf(p.Out, "[dry-run] would enable snapshot plan on storage box %d (max=%d, %02d:%02d UTC)\n",
			p.StorageBoxID, schedule.MaxSnapshots, schedule.Hour, schedule.Minute)
		return nil
	}

	action, _, err := p.Client.StorageBox.EnableSnapshotPlan(ctx, box, hcloud.StorageBoxEnableSnapshotPlanOpts{
		MaxSnapshots: schedule.MaxSnapshots,
		Minute:       schedule.Minute,
		Hour:         schedule.Hour,
	})
	if err != nil {
		return fmt.Errorf("hetzner: enable snapshot plan: %w", err)
	}
	if action != nil {
		if err := p.Client.Action.WaitFor(ctx, action); err != nil {
			return fmt.Errorf("hetzner: wait for snapshot plan to enable: %w", err)
		}
	}
	return nil
}

// Snapshot is one point-in-time Storage Box snapshot.
type Snapshot struct {
	ID          int64
	Name        string
	IsAutomatic bool
}

// ListSnapshots lists the destination's Storage Box's snapshots.
// Snapshots are box-wide, not scoped to one subaccount (SPEC.md §6).
func (p Provider) ListSnapshots(ctx context.Context) ([]Snapshot, error) {
	box, _, err := p.Client.StorageBox.GetByID(ctx, p.StorageBoxID)
	if err != nil {
		return nil, fmt.Errorf("hetzner: get storage box %d: %w", p.StorageBoxID, err)
	}
	if box == nil {
		return nil, fmt.Errorf("hetzner: storage box %d not found", p.StorageBoxID)
	}

	snapshots, _, err := p.Client.StorageBox.ListSnapshots(ctx, box, hcloud.StorageBoxSnapshotListOpts{})
	if err != nil {
		return nil, fmt.Errorf("hetzner: list snapshots: %w", err)
	}

	result := make([]Snapshot, 0, len(snapshots))
	for _, s := range snapshots {
		result = append(result, Snapshot{ID: s.ID, Name: s.Name, IsAutomatic: s.IsAutomatic})
	}
	return result, nil
}
