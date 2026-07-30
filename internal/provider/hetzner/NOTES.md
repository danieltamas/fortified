# Hetzner Storage Box research notes (append-only enforcement + Go SDK coverage)

Research date / access date for all URLs below: **2026-07-18**.

---

## Question 1 — Can we install an SSH key with a forced command (`borg serve --append-only`) on a Storage Box?

**Answer: YES, but only via direct `authorized_keys` file provisioning — NOT via Console, `hcloud` CLI, Cloud API, or `install-ssh-key`.** The restriction, once installed, is enforced by Hetzner's server-side SSH service on port 23, not by the client. Qualified positive — see caveats, especially password auth.

### What the supported management surfaces offer (and don't)

1. **`install-ssh-key`** — Hetzner's documented helper (`cat key.pub | ssh -p23 uXXXXX@... install-ssh-key`) installs a **plain, unrestricted** key. No mechanism to attach options.
   Hetzner's SSH-key docs page ("How-To: Add SSH keys", last updated 2025-06-25) documents exactly three methods — `install-ssh-key`, manual upload to `.ssh/authorized_keys` via port 23, and RFC4716-format upload via port 22/SFTP — and mentions **no** Console/API method and **no** `command=`/`restrict` options. It does confirm "This also works in subaccounts."
   Source: https://docs.hetzner.com/storage/storage-box/backup-space-ssh-keys/

2. **Cloud API (`api.hetzner.com`, the current post-Robot product)** — Storage Boxes moved from Robot to the unified Console/Cloud API; the Robot Webservice endpoints were deprecated 2025-06-25 and removed 2025-07-30.
   The current API accepts SSH keys **only as plain public-key strings at Storage Box creation time** (`POST /storage_boxes`, `ssh_keys` array). There are **no** endpoints to add/manage SSH keys after creation, **no** SSH-key fields at all on subaccounts, and **no** key-options/forced-command support anywhere in the API. The API changelog contains no SSH-key-management entries.
   Sources: https://docs.hetzner.cloud/changelog · https://docs.hetzner.cloud/reference/hetzner (Storage Box sections) · confirmed against the official Go SDK types, which mirror the API: `StorageBoxCreateOpts.SSHKeys []*SSHKey` ("Only the value of SSHKey.PublicKey is provided to the API") and `StorageBoxSubaccountCreateOpts` (no key fields) in https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/storage_box.go and https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/storage_box_subaccount.go

3. **Console UI** — subaccount settings expose only access toggles (SSH/Samba/WebDAV/external reachability/read-only) and home directory; no key options. (Mirrored in the API's `access_settings`.)

### The path that DOES work: direct `authorized_keys` provisioning

The Storage Box account owner can write arbitrary content to `<home>/.ssh/authorized_keys` (upload via SCP/SFTP — this is Hetzner's own documented method #2/#3 above). That file may contain an entry of the form:

```
command="borg serve --append-only --restrict-to-repository <repo-path>",restrict ssh-ed25519 AAAA... fortified-automation
```

- Hetzner's Borg/SSH access docs (last updated 2025-04-03) explicitly state that Borg **append-only mode is supported** ("only allows the creation of new archives, but denies the deletion of old archives") and defer to the official BorgBackup documentation for configuration — and Borg's documented mechanism for remote append-only enforcement is precisely the forced command on the server-side `authorized_keys` entry.
  Sources: https://docs.hetzner.com/storage/storage-box/access/access-ssh-rsync-borg/ · https://borgbackup.readthedocs.io/en/stable/usage/notes.html (append-only mode)
- The Storage Box runs **two distinct SSH services**: port 22 (SFTP-only, reads only RFC4716-format key entries) and port 23 (restricted shell + Borg/rsync, reads only single-line OpenSSH-format entries). **Port 23 honors the `command=` option in `authorized_keys`.**
  Source (third-party, actively maintained gist, last active 2026-05-02): https://gist.github.com/mildsunrise/743b17d376c4d416aee238034edbbe36
- The same pattern is documented as the standard way to get append-only on Hetzner by the BorgBackupServer project ("edit `~/.ssh/authorized_keys` over SSH/SFTP and prefix your key with `command=\"borg serve --append-only --restrict-to-path /home\"`").
  Source: https://github.com/marcpope/borgbackupserver/discussions/147

**Why this is genuinely server-enforced for the dual-key model:** once the automation key's entry carries `command=`, every SSH session authenticated with that key runs only `borg serve --append-only` — including SFTP attempts on port 23, so the key **cannot rewrite its own `authorized_keys`**. And because the entry exists only in OpenSSH single-line format, the key is unusable on port 22 (which reads only RFC4716 entries). The compromised client cannot "unset a flag"; the restriction lives on Hetzner's side.

### Ambiguities and caveats (explicit)

1. **Not explicitly documented first-party.** No official Hetzner page shows a `command=` example. Hetzner's docs assert append-only support and point at Borg's docs (whose mechanism is the forced command); the `command=`-honored-on-port-23 claim rests on the third-party sources above plus widespread community use. The 2023 fluix.one restic post used the same technique but did not document verifying enforcement (https://fluix.one/blog/hetzner-restic-append-only/). → **Implementation must include a verification step**: after installing the restricted key, connect with it and assert (a) SFTP/shell access is refused, (b) `borg serve` is what answers.
2. **Password authentication cannot be disabled** on Storage Box accounts/subaccounts (per the gist above; consistent with the API, which *requires* a password at subaccount creation and offers no disable flag — `StorageBoxSubaccountCreateOpts.Password`, `ResetSubaccountPassword`). **The subaccount password must never be stored on a protected server**, or an attacker can SFTP in with it and strip the forced command. Fortified should generate a random password at setup and discard it immediately — the password is never needed operationally, because the main account can write the subaccount's `authorized_keys` directly (see next section).
3. **Disable Samba/WebDAV/external reachability** on the backup subaccount (`access_settings`) — otherwise the filesystem (including `.ssh/authorized_keys`) is reachable outside SSH entirely.
4. **Whether the `restrict` option (no-pty etc.) is honored** on Hetzner's custom sshd is unconfirmed; `command=` is the load-bearing part. Include `restrict` anyway (harmless if ignored) but don't rely on it.
5. **Borg append-only semantics:** deletions attempted over an append-only connection are appended to the transaction log rather than hard-refused with an error in all cases; recovery is via transaction rollback. See https://borgbackup.readthedocs.io/en/stable/usage/notes.html. Hetzner snapshot plans (API-managed, not deletable via the subaccount's SSH) are a good second layer.

### Main-account write access to subaccount home directories (confirmed — no subaccount password needed)

Follow-up question: can the MAIN account write a subaccount's `authorized_keys` directly, avoiding any use of the subaccount password? **Confirmed yes, first-party.** Hetzner's Storage Box overview docs (last updated 2025-06-25) state:

> "The main user has complete access to all directories — including all sub-account directories."
> "Each sub-account requires its own `authorized_keys` file in the sub-account's directory."

Source: https://docs.hetzner.com/storage/storage-box/general/ (accessed 2026-07-18)

Mechanics:

- A subaccount's home is just a directory inside the main Storage Box filesystem, set at creation via the `home_directory` field (e.g. `backups/server1`; API `POST /storage_boxes/{id}/subaccounts`, SDK `StorageBoxSubaccountCreateOpts.HomeDirectory`). The subaccount is jailed to it; the main account sees it at that same path relative to the main account's root.
- **Path pattern from the main account:** `/<home_directory>/.ssh/authorized_keys` — i.e. the `home_directory` value you chose at creation, **not** `/<subaccount-username>/...`. Example: home_directory `backups/server1` → main account writes `/backups/server1/.ssh/authorized_keys`.
- **Port:** either works for the main account's write — SFTP on port 22 or SCP/SFTP on port 23 (the main account's own key must be installed in the matching format for whichever port it uses). Port choice matters only for which key entries the *subaccount's* SSH auth later reads: the automation key entry must be OpenSSH single-line format so it is valid only on port 23 (where Borg runs and `command=` is honored).
- Minor caveat: the docs say "complete access" without spelling out "write" verbatim, but the same page requires an `authorized_keys` file to be placed in each sub-account directory and the sub-account read-only toggle is described as limiting *sub-account users* only — main-user write access is the clear reading. Confidence: high; verify empirically at setup time (the write itself is the test).

This removes the subaccount password from the workflow entirely: generate a random password at creation (API requires one), never persist it, and do the `authorized_keys` write as the main account.

### Setup procedure fortified must implement (summary)

1. Create subaccount via Cloud API (`POST /storage_boxes/{id}/subaccounts`) with SSH enabled, Samba/WebDAV/external off, random password (required by API; discarded immediately, never stored anywhere).
2. Using **operator/main-account credentials** (setup-time only, never stored on protected servers), write `/<home_directory>/.ssh/authorized_keys` from the main account's own SFTP/SCP session (no subaccount login involved), containing:
   - the automation key prefixed with `command="borg serve --append-only --restrict-to-repository <path>",restrict` (OpenSSH single-line format → port 23 only);
   - optionally the operator's unrestricted prune key as a second, unprefixed entry.
3. Verify enforcement with the automation key (SFTP refused; borg serve answers; archive creation works).
4. Enable snapshot plan via API as an independent recovery layer.

---

## Question 2 — Go SDK coverage of Storage Box on the unified Cloud API

**Answer: YES — the official `github.com/hetznercloud/hcloud-go/v2` covers everything fortified needs from the API, and it is no longer experimental.** Verified against actual source on `main`, not just docs.

- **v2.28.0 (2025-10-21)** added Storage Box API support, marked experimental (phase expected to end 2025-11-21). **v2.35.0 (2026-01-15)** added subaccount `name` (and split `GetSubaccount` / `GetSubaccountByUsername`). **v2.36.0** declared "Storage Box support no longer experimental" (GA).
  Source: https://github.com/hetznercloud/hcloud-go/blob/main/CHANGELOG.md
- **Verified method surface** (from https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/zz_storage_box_client_iface.go):
  - **Storage Box:** Get/List/All, Create, Update, Delete, Folders, ChangeProtection, ChangeType, ResetPassword, UpdateAccessSettings.
  - **Subaccounts (full CRUD):** CreateSubaccount, UpdateSubaccount, DeleteSubaccount, Get/List/All variants, ResetSubaccountPassword, UpdateSubaccountAccessSettings, ChangeSubaccountHomeDirectory.
  - **Snapshots:** CreateSnapshot, UpdateSnapshot, DeleteSnapshot, Get/List/All variants, RollbackSnapshot.
  - **Snapshot plans:** EnableSnapshotPlan (`StorageBoxEnableSnapshotPlanOpts`: MaxSnapshots, Minute, Hour, DayOfWeek, DayOfMonth), DisableSnapshotPlan; the active plan is readable on the StorageBox object.
- **What's missing (SDK *and* underlying API):** any post-creation SSH-key management, any subaccount SSH-key management, any key options/forced commands. `SSHKeys` exists only on `StorageBoxCreateOpts` as plain public-key strings. This is an API gap, not an SDK gap — **no raw REST calls will fix it**; `authorized_keys` provisioning must be done over SFTP/SSH by fortified itself (which is required anyway for the forced command, per Question 1).
  Sources: https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/storage_box.go · https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/storage_box_subaccount.go · https://pkg.go.dev/github.com/hetznercloud/hcloud-go/v2/hcloud

No hand-rolled REST needed for subaccount CRUD or snapshot schedules; use `hcloud-go/v2` ≥ v2.36.0.
