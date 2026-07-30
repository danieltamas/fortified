package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"unicode"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/danieltamas/fortified/internal/config"
	"github.com/danieltamas/fortified/internal/discover"
	"github.com/danieltamas/fortified/internal/provider/hetzner"
	"github.com/danieltamas/fortified/internal/secrets"
	"github.com/danieltamas/fortified/internal/sshx"
)

// defaultEncryptionKeyRef proposes an env:// ref name for a new
// server, matching the naming convention already used by hand
// throughout fleet.yaml (e.g. env://BORG_PASSPHRASE_HOST_2_EXAMPLE
// for "host-2-example") — the operator still has to actually set the
// env var (or run onboard --escrow-acknowledged, which offers to
// generate one), but the ref name itself needs no typing.
func defaultEncryptionKeyRef(serverID string) string {
	var b strings.Builder
	for _, r := range serverID {
		switch r {
		case '-', '.', '_':
			b.WriteByte('_')
		default:
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return "env://BORG_PASSPHRASE_" + b.String()
}

// existingHCloudTokenRef returns the hcloud_token_ref already used by
// some other configured server, if any — reused as the default for a
// new server rather than asking the operator to type it again, since
// a fleet almost always shares one Hetzner account.
func existingHCloudTokenRef(fleet *config.Fleet) string {
	for _, srv := range fleet.Servers {
		if srv.Hetzner != nil && srv.Hetzner.HCloudTokenRef != "" {
			return srv.Hetzner.HCloudTokenRef
		}
	}
	return ""
}

// singleExistingDestination returns the one Storage Box every already-
// configured server agrees on, if there's exactly one distinct
// destination in use across the whole fleet — the common case (one
// operator, one Storage Box) where a brand-new server's destination
// never needs asking about at all.
func singleExistingDestination(fleet *config.Fleet) (discover.ResolvedDestination, bool) {
	var found *discover.ResolvedDestination
	for _, srv := range fleet.Servers {
		if srv.Provider != "hetzner" || srv.Hetzner == nil || srv.Destination == "" {
			continue
		}
		if found != nil && found.Destination != srv.Destination {
			return discover.ResolvedDestination{}, false // ambiguous — more than one box in use
		}
		found = &discover.ResolvedDestination{
			Provider:        srv.Provider,
			Destination:     srv.Destination,
			HCloudTokenRef:  srv.Hetzner.HCloudTokenRef,
			MainAccountHost: srv.Hetzner.MainAccount.Host,
			MainAccountUser: srv.Hetzner.MainAccount.User,
		}
	}
	if found == nil {
		return discover.ResolvedDestination{}, false
	}
	return *found, true
}

// resolveDestination figures out which Hetzner Storage Box a new
// server's backups should land on. It never asks when the answer is
// already unambiguous (an explicit --destination, or every other
// configured server already agreeing on one box); otherwise it
// fetches the account's real Storage Boxes and prompts — a numbered
// menu, plus the option to type a different box ID directly — instead
// of requiring the operator to already know and type a numeric ID
// blind. httpClient is injectable so tests can point the Hetzner API
// calls at a fake transport instead of the network; production always
// passes http.DefaultClient.
func resolveDestination(ctx context.Context, fleet *config.Fleet, explicitDestination string, httpClient *http.Client, in *bufio.Scanner, out io.Writer) (discover.ResolvedDestination, error) {
	// Checked before ever touching the Hetzner API or resolving a
	// token: the common case (a fleet that already agrees on one box)
	// needs neither — verified live, this used to demand HCLOUD_TOKEN
	// even when the answer was already sitting in fleet.yaml.
	if explicitDestination == "" {
		if dest, ok := singleExistingDestination(fleet); ok {
			_, _ = fmt.Fprintf(out, "reusing Storage Box %s (%s) — already used by the rest of the fleet\n", dest.Destination, dest.MainAccountHost)
			return dest, nil
		}
	}

	tokenRef := existingHCloudTokenRef(fleet)
	if tokenRef == "" {
		tokenRef = "env://HCLOUD_TOKEN" //nolint:gosec // this is a secret *reference* (env var name), never a literal credential
	}
	resolver := secrets.Resolver{Runner: sshx.ExecRunner{}}
	token, err := resolver.Resolve(ctx, tokenRef)
	if err != nil {
		return discover.ResolvedDestination{}, fmt.Errorf("resolve %s to talk to the Hetzner API: %w", tokenRef, err)
	}
	client := hcloud.NewClient(hcloud.WithToken(token), hcloud.WithHTTPClient(httpClient))

	asDestination := func(b hetzner.StorageBoxSummary) discover.ResolvedDestination {
		return discover.ResolvedDestination{
			Provider: "hetzner", Destination: strconv.FormatInt(b.ID, 10),
			HCloudTokenRef: tokenRef, MainAccountHost: b.Server, MainAccountUser: b.Username,
		}
	}

	if explicitDestination != "" {
		id, convErr := strconv.ParseInt(explicitDestination, 10, 64)
		if convErr != nil {
			return discover.ResolvedDestination{}, fmt.Errorf("--destination %q is not a valid Storage Box ID: %w", explicitDestination, convErr)
		}
		box, _, err := client.StorageBox.GetByID(ctx, id)
		if err != nil {
			return discover.ResolvedDestination{}, fmt.Errorf("hetzner: get storage box %d: %w", id, err)
		}
		if box == nil {
			return discover.ResolvedDestination{}, fmt.Errorf("hetzner: storage box %d not found", id)
		}
		return asDestination(hetzner.StorageBoxSummary{ID: box.ID, Server: box.Server, Username: box.Username}), nil
	}

	boxes, err := hetzner.ListStorageBoxes(ctx, client)
	if err != nil {
		return discover.ResolvedDestination{}, err
	}
	if len(boxes) == 0 {
		return discover.ResolvedDestination{}, fmt.Errorf("no Storage Boxes found on this Hetzner account — create one first, then re-run discover")
	}
	if len(boxes) == 1 {
		_, _ = fmt.Fprintf(out, "using the only Storage Box on this account: %d (%s)\n", boxes[0].ID, boxes[0].Server)
		return asDestination(boxes[0]), nil
	}

	_, _ = fmt.Fprintln(out, "multiple Storage Boxes found on this account — pick one:")
	for i, b := range boxes {
		_, _ = fmt.Fprintf(out, "  [%d] %d  %-20s %s\n", i+1, b.ID, b.Name, b.Server)
	}
	_, _ = fmt.Fprint(out, "enter a number from the list above, or type a Storage Box ID directly: ")
	if !in.Scan() {
		return discover.ResolvedDestination{}, fmt.Errorf("no destination selected")
	}
	choice := strings.TrimSpace(in.Text())

	if n, convErr := strconv.Atoi(choice); convErr == nil && n >= 1 && n <= len(boxes) {
		return asDestination(boxes[n-1]), nil
	}

	id, convErr := strconv.ParseInt(choice, 10, 64)
	if convErr != nil {
		return discover.ResolvedDestination{}, fmt.Errorf("%q is neither a menu number nor a Storage Box ID", choice)
	}
	box, _, err := client.StorageBox.GetByID(ctx, id)
	if err != nil {
		return discover.ResolvedDestination{}, fmt.Errorf("hetzner: get storage box %d: %w", id, err)
	}
	if box == nil {
		return discover.ResolvedDestination{}, fmt.Errorf("hetzner: storage box %d not found", id)
	}
	return asDestination(hetzner.StorageBoxSummary{ID: box.ID, Server: box.Server, Username: box.Username}), nil
}

// sshConfigResolver runs `ssh -G <alias>` and returns its stdout —
// overridable in tests, since exec.Command has no fake to inject.
var sshConfigResolver = func(alias string) ([]byte, error) {
	return exec.Command("ssh", "-G", alias).Output() //nolint:gosec // alias is the operator's own server-id argument, run through the operator's own ssh client
}

// resolveSSHConfigDefaults fills in whatever of target's Port/User
// isn't already explicit by asking the local ssh client to resolve
// serverID's own ~/.ssh/config Host alias — needed only when discover
// is about to persist target into fleet.yaml, which (unlike one
// ad-hoc `ssh <host>` invocation, where an alias's Port/User apply
// implicitly) always needs concrete values written down. Falls back
// to ssh's own conventional defaults (port 22, user root) rather than
// failing outright — a wrong default is a one-line hand-edit; a hard
// failure here would hide the discover report that already succeeded.
func resolveSSHConfigDefaults(serverID string, target sshx.Target) sshx.Target {
	resolved := target
	if resolved.Host == serverID && (resolved.Port == 0 || resolved.User == "") {
		if out, err := sshConfigResolver(serverID); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
				if !ok {
					continue
				}
				switch key {
				case "port":
					if resolved.Port == 0 {
						if p, convErr := strconv.Atoi(value); convErr == nil {
							resolved.Port = p
						}
					}
				case "user":
					if resolved.User == "" {
						resolved.User = value
					}
				}
			}
		}
	}
	if resolved.Port == 0 {
		resolved.Port = 22
	}
	if resolved.User == "" {
		resolved.User = "root"
	}
	return resolved
}
