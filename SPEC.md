# fortified — deterministic backup & disaster-recovery CLI

> Working name: "fortified" — fits "one fortified outpost per server" per the fleet-backup-playbook skill's
> theme. Rename freely; nothing below depends on the name.

## 0. Why this exists (read before building anything)

The operator runs a growing fleet of bare-metal/self-hosted servers — Docker
containers and native/systemd-installed databases alike (Hetzner today;
other providers later — a second batch of servers is next, bigger footprint, not yet touched).
None of them currently have a working, verified backup. The method for doing this correctly
was worked out by hand, once, against a real fleet (two Hetzner boxes, `host-2-example` and
`host-example`) and is written down at `~/agent-os/skills/fleet-backup-playbook/SKILL.md` —
**read that file first.** This tool exists to turn that manual method into something
that takes minutes per server instead of an hour of careful, error-prone SSH archaeology,
and that behaves the same way every time.

**The one requirement that overrides all others: determinism.** The operator was explicit —
this tool exists specifically so backing up any server is fast *and* predictable. Every design
decision below is in service of that. If a feature would make behavior depend on interactive
judgment calls at runtime (a wizard, a TUI with branching screens, an LLM improvising shell
commands against production), it's the wrong shape for this tool, no matter how convenient it
seems. Push judgment calls into `discover`'s output and the operator's config file, not into
runtime interactivity.

This spec went through two rounds of adversarial review (independent Claude- and GPT-family
passes) specifically hunting for places a fresh implementer would have to guess. §4 (state &
locking) and the `DatabaseInstance` schema in §3 exist because of that review — they weren't in
the first draft, and their absence would have meant real ambiguity, not just missing polish.

## 1. Non-negotiables

1. **Single static binary.** No runtime dependency drift, ever — a compiled Go binary has no
   equivalent of the "wrong Python interpreter on PATH breaks a script" failure mode. Go, not
   Rust: this tool's job is orchestrating `ssh`/`borg`/`pg_dump`/`mysqldump` and calling a REST
   API, and the bottleneck is always the network or those external tools, never the
   orchestrator's language — Rust's real advantages don't pay for themselves here.
2. **Orchestrate proven tools, don't reimplement them.** Shell out to `ssh`, `borg`,
   `pg_dump`/`pg_dumpall`, `mysqldump` as subprocesses. Do not write a Go SSH client or reimplement
   Borg's repository format. This is a safety-critical tool; the risk of a subtly-wrong
   from-scratch reimplementation of a backup protocol is not worth whatever elegance a native
   Go SSH/Borg library might offer. Check exit codes and stderr from every subprocess call —
   never assume success from the absence of an error.
3. **Idempotent by construction.** Every command must be safe to re-run — resuming from
   whatever state was actually reached, not from scratch, and not by silently duplicating
   remote resources. §4 defines exactly what state that requires and how re-runs use it.
4. **Dual-key discipline is structural, not a convention someone has to remember.** The tool
   must never possess or request the unrestricted prune key as part of any routine command.
   `prune` (or `check` immediately before a prune) is the ONE command class that requires the
   operator to supply that key explicitly, out of band (e.g. a flag pointing at a path, or
   stdin) — never read from the same config/secrets path the automated commands use. If this
   boundary blurs, the entire point of the append-only design is defeated. See SKILL.md's
   "Backup mechanism: dual-key, not one" section for why.
5. **Secrets never touch the config file in plaintext**, and never get logged. Reference
   secrets by name; resolve them at runtime from environment variables or an external secrets
   manager (Infisical is this operator's existing tool of choice across other projects — support
   it as the first integration, but don't hard-require it; env-var resolution must always work
   as a fallback with no external dependency).
6. **Nothing destructive runs without an explicit, named confirmation.** `prune`, `forget`,
   anything that deletes a snapshot, anything that overwrites a target during a restore — all of
   these require either an interactive y/N (default: abort) or an explicit `--yes-i-mean-it`
   style flag for scripted use. No destructive action should ever be a plausible accidental
   keystroke away.
7. **A discovery step before any mutation, always.** Never assume a target's layout — LVM/ZFS/
   Btrfs vs. plain filesystem, RAID, what's actually running, what's genuinely stateful — see
   SKILL.md Step 0. `onboard` must run (or require having already run) `discover` first and
   refuse to proceed past a failed/incomplete discovery.

## 2. Goals / non-goals for v1

**Goals:**
- Onboard a new bare-metal server to Hetzner Storage Box backups in minutes, correctly, every
  time — including generating its config, not just consuming a hand-written one (§5's
  `discover --emit-config`).
- Make "did the backup job actually run, and would it actually restore" a fact the tool can
  report on demand — not a belief.
- Be the thing a cron job calls nightly, and the thing that pages someone (via exit code /
  a hook the operator wires to their own alerting) when a job fails or silently stops running.
- Be extensible to a second backup-destination provider later without a rewrite — but do not
  build that second provider now. One real provider (Hetzner), one real backend tool (Borg),
  built correctly, beats a speculative abstraction with only one implementation exercising it.

**Non-goals for v1 (explicitly deferred, don't build):**
- Multi-provider support beyond Hetzner. Design the `Provider` interface so it's *possible*
  later (see §6), but ship only the Hetzner implementation.
- restic support. Borg is the chosen mechanism (Hetzner's own docs give it first-party,
  server-enforced append-only support; restic's equivalent needs extra backend-specific
  scaffolding — see SKILL.md's `references/hetzner.md`). Don't build a backend abstraction for
  a tool with only one backend; add it if/when a second one is genuinely needed.
- A TUI. See §0 — determinism and speed point toward a plain, scriptable CLI, not screens and
  interactive state. A live multi-server status *dashboard* is a legitimate future feature (a
  read-only view, not part of the mutating onboarding flow) — revisit post-v1, don't build now.
- The conversational/agent-chat control layer described in §9. Real, wanted, explicitly out of
  scope for v1 — build the deterministic core first; the chat layer is a client of that core, not
  a replacement for it.

None of the above should leak into v1's interfaces "just in case." The `Provider`/`Backend`
split in §3 exists because two concrete things (Hetzner, Borg) already need that boundary drawn
today — not because a third provider or backend might exist someday. If you find yourself adding
a method, config field, or abstraction layer that only a *future* non-goal would use, cut it.

## 3. Architecture overview

`fortified` runs on a single always-on **control host** that the operator designates (their own
workstation, or a small always-on box) — it is never installed on the servers it protects. All
target interaction happens over SSH from the control host outward (`internal/sshx`). This is
why locking and state (§4) are local to the control host: they'd be meaningless split across
targets, and cron on the control host is what actually calls `backup` nightly.

**Execution topology, made explicit:** `fortified` itself runs only on the control host, but `borg`
and the database dump commands execute **on the target server** (invoked over SSH), pushing to the
Storage Box with that server's own append-only key — the key is generated on the target and never
leaves it (SKILL.md's isolation rule), so the archive-creating process must run where the key lives.
That makes `borg` (and working `docker exec` access to each database container) a runtime
prerequisite **on every target**, not on the control host — §1's single-static-binary guarantee
covers `fortified` only. `discover` must record tool presence and versions on the target
(`borg --version`, `docker --version`), and `onboard` must refuse to proceed if `borg` is missing,
telling the operator what to install — never installing it silently as a side effect. Any secret a
target-side invocation needs (e.g. `BORG_PASSPHRASE`) is resolved on the control host and passed
per-invocation via the SSH session's environment — never written to a file on the target, and
never on the remote command line, where `ps` on either host would show it: the assignments travel
on the remote command's stdin and a fixed `sh -c` prelude exports them before exec'ing the command.

```
cmd/fortified/        - main package, cobra command tree
internal/discover/    - target inspection (filesystem, RAID, docker, exposure)
internal/provider/    - Provider interface + hetzner/ implementation
internal/backend/     - backup-mechanism interface + borg/ implementation
internal/config/      - fleet config file load/validate
internal/secrets/     - secret resolution (env var, Infisical)
internal/sshx/        - thin wrapper around exec'ing the system `ssh`/`scp` binaries
internal/state/       - per-server state record + locking (§4)
internal/report/      - structured output (table + --json) shared by all commands
```

**`Provider` interface** (backup *destination*, e.g. Hetzner Storage Box):
- `CreateIsolatedDestination(serverID string) (Destination, error)` — subaccount/account +
  confined path, per SKILL.md's per-server isolation rule. Must be idempotent: calling it twice
  for the same `serverID` returns the existing destination, never creates a second one.
- `InstallServerKey(dest Destination, pubkey string, appendOnly bool) error`
- `EnableSnapshotSchedule(dest Destination, schedule Schedule) error` — the tool must refuse
  this call until `verify` has passed at least once for that server (tracked in state, §4) —
  not just discourage it.
- `ListSnapshots(dest Destination) ([]Snapshot, error)`

**`Backend` interface** (backup *mechanism*, e.g. Borg):
- `InitRepo(dest Destination, encryptionKeyRef string) error`
- `CreateArchive(dest Destination, sourcePaths []string) (ArchiveID, error)`
- `RestoreArchive(archiveID ArchiveID, targetPath string) error`
- `Check(dest Destination) error` — integrity check, must run and pass before any `Prune`.
- `Prune(dest Destination, retentionPolicy Policy, pruneKeyRef string) error` — the one call
  that takes the unrestricted key reference; never callable with the append-only key.

Keep both interfaces narrow. Resist adding methods "for completeness" — every method here maps
to a real step from the playbook; don't add ones that don't.

**Both interfaces' underlying command execution (SSH calls, `borg` invocations) must go through
an injectable runner** (`type Runner interface { Run(cmd string, args []string) (stdout, stderr
string, exitCode int, err error) }` or equivalent) rather than calling `os/exec` directly inline.
This is what makes §8's testing strategy possible at all — without it, nothing in this tool is
unit-testable without live SSH access to a real server.

**`DatabaseInstance` — discover's required output shape for anything it classifies as a
database.** This is the fix for the biggest gap the review round found: "Postgres exists" is not
enough for `backup` to construct a correct dump command. For each stateful database container,
`discover` must report:
- `Kind` (postgres/mariadb/…), `Container` (name + image), `Networks`, `ExposedPorts`
- `DataMountPaths` — bind-mounted paths to exclude from any raw file archiving (never dump these
  directly; they exist so `backup` knows what NOT to touch)
- `DumpStrategy` — how to actually dump it: `docker exec` into the container (preferred: uses the
  container's own client + auth, e.g. `docker exec -u postgres <c> pg_dumpall` relies on
  Postgres peer auth already working inside the container) vs. an exposed TCP port needing an
  explicit credential
- `AuthResolved bool` + `AuthRef string` — whether discover found usable auth automatically
  (e.g. read `MYSQL_ROOT_PASSWORD` from the container's env via `docker inspect`) or whether the
  operator must supply an `auth_ref` in config pointing at a secret (§7). **Say this plainly: for
  nonstandard setups, some manual config will remain — the tool should minimize it, not pretend
  it never happens.**
`backup` consumes this recorded recipe; it must never re-derive a dump command by guessing from
a container name at backup time.

## 4. State & locking

Every server has a local state record on the control host (e.g.
`~/.config/fortified/state/<server-id>.json`, exact format is an implementation detail, the
*contents* are not):

- Provider destination ID, installed key fingerprint, repo-init status, encryption key ref,
  the `DatabaseInstance` list discover last produced, last successful onboarding step, and (if
  the last attempt failed) the failure reason.
- Whether `verify` has ever passed for this server — the fact that gates `enable-snapshots`.
- Timestamps: last `backup`, last passing `verify`, last `check`, last `drill`. This is exactly
  what `status` (§5) reads to answer "is this fleet actually protected" in one command.

**Re-running `onboard` resumes from the first incomplete step**, using this record — it never
silently re-creates a subaccount, re-generates a key, or re-inits a repo that already exists.
It never rotates keys/passphrases or deletes remote resources automatically; if that's ever
needed, that's a separate, explicitly-destructive command, not a side effect of retrying.

**Locking**: every command that touches a server's state record or its Borg repo
(`onboard`/`backup`/`verify`/`restore`/`check`/`prune`/`drill`/`enable-snapshots`) takes an exclusive
advisory lock (e.g. `flock` on a per-server lock file next to the state record) before doing
anything. A second invocation while one is held fails fast with who's holding it and since when
— it does not queue or block by default (an optional `--wait` may block instead, for scripted
use). Borg's own internal repo lock is a backstop, not the mechanism this tool relies on — the
whole point is to fail loudly *before* two commands (a cron `backup` and a manual `verify`, say)
even reach Borg. `status` is read-only and exempt from this lock.

**`backup`'s own internal ordering, made explicit**: stage every configured database's dump into
a temp workspace first, checking each dump subprocess's exit code as it completes. Only if
*every* dump succeeds does `backup` create the Borg archive; if any dump fails, delete the temp
workspace, create no archive, and exit non-zero. A partial archive that looks complete is worse
than a run that visibly failed — never let a half-successful backup masquerade as a good one.

The temp workspace lives **on the target** (that's where the dumps and the borg key are — §3's
topology), which means staging can exhaust a production disk. Before dumping anything, `backup`
must run a free-space pre-flight: required = last successful run's total dump size × 1.5, or, on
a first run, the engine-reported size of the data a dump actually writes × 1.25 — Postgres:
`pg_table_size` of ordinary tables plus `pg_largeobject` in every database (heap + TOAST); MariaDB/MySQL:
`information_schema` `data_length`. Indexes and on-disk bloat are never dumped, so the on-disk
`pg_database_size` overstates a dump (measured: 2.3× a real `pg_dumpall`); dumps are uncompressed
text, so data can also grow (measured: `mysqldump` at 1.20× `data_length`), hence the headroom. If free space is insufficient, fail *before* the first
dump with a message saying how much is needed and where. Streaming dumps straight into borg would
remove the space requirement, but it breaks the all-dumps-succeed-before-archive rule above —
explicitly deferred; do not build it into v1.

As each dump completes, `backup` records a **verification baseline** alongside it: per-table row
counts (queried through the same engine connection the dump used) and a SHA-256 of the dump file,
written to a manifest that ships inside the archive and is also stored in the server's state
record. This is `verify`'s ground truth (§5) — without it, "row counts match" has nothing to
match against.

**The control host's state is itself a single point of failure — acknowledge it, don't hide it.**
For a DR tool, losing the machine that knows the fleet's protection status is an ironic failure
mode. Two rules keep it survivable: (a) the state directory contains only names and facts, never
resolved secret values — enforce this so the operator can safely include `~/.config/fortified/`
in their own backup (a private git repo is fine); (b) everything re-derivable from remote reality
(destination IDs, installed key fingerprints, repo existence) must be reconstructible by
re-running `discover`/`onboard`, which already resume idempotently. Facts that exist only locally
(verify/drill timestamps) die with the control host and must be re-earned by re-running `verify`
— `status` must then show that server as *unverified*, never as unknown-but-probably-fine.

**Audit trail — every action recorded, structurally.** Every subprocess and API call already
flows through §3's injectable `Runner` (and its HTTP equivalent); wrap that single interception
point with an append-only audit log: one JSONL file per server beside the state record
(`state/<server-id>.audit.jsonl`), one line per call — timestamp, fortified command + an
invocation ID tying a run's calls together, the call's declared class (mutating vs. read-only),
exact argv (or HTTP method + URL), exit code/status, stderr digest, duration. Secrets cannot
appear here by construction: they travel via session environment, never argv (§3), and the
audit writer never records env values. Every `Runner` call site must declare its class —
the audit log records it, and `--dry-run` (§5) enforces it. The audit log is included in the
state-dir backup guidance above, and it answers the question `status` doesn't: `status` shows
protection *facts*; the audit log shows *actions* — "what exactly did this tool run against my
infrastructure, and when."

## 5. Command reference (v1)

Every lock-taking command (`onboard`/`backup`/`verify`/`restore`/`check`/`prune`/`drill`/
`enable-snapshots`) accepts **`--dry-run`**: print the exact commands that would execute, run
nothing that mutates. Precise semantics: calls declared read-only (§4's audit classes) may still
execute where computing the plan depends on their output (e.g. checking whether a subaccount
already exists); every call declared mutating is printed instead of run, with values that would
only exist after a real mutation rendered as explicit placeholders (`<generated-keypair>`) —
never invented. Dry-run output is the pre-execution twin of the audit trail (§4): inspect
before, verify after.

```
fortified discover <server> [--emit-config]
```
SSH to the target, run the full Step-0 inspection from SKILL.md (filesystem/volume manager,
RAID, `docker ps -a` + compose files, stateful-vs-reproducible classification via the
`DatabaseInstance` schema in §3, port bindings, firewall rules), plus presence and versions of the
target-side prerequisites (`borg`, `docker`) per §3's execution topology. Never mutates anything. Output:
a structured report (table by default, `--json` for scripting) the operator reviews before
`onboard`. Must explicitly flag when no LVM/ZFS/Btrfs is present (meaning: database backups on
this target MUST go through the DB engine, never raw file copy) and must explicitly flag any
DB/cache port bound to `0.0.0.0`.

`--emit-config` prints a ready-to-review config stanza (§7) inferred from the discovery: archive
paths from found compose files (`docker-compose*.y*ml` and `compose.y*ml`), compose working-dir
labels, bind mounts and well-known state paths. A database engine's own data directory mount is
never proposed: it is listed under `exclude:` of the archive path containing it, so the project's
compose file and engine config are archived while the data the dump covers is not copied raw. A
`DatabaseInstance` entry per detected database with
`auth_ref: TODO` wherever auth couldn't be resolved automatically. `onboard` must refuse to
proceed against a config that still contains an unresolved `TODO` — this is what keeps "minutes
per server" honest: the operator reviews and fills gaps in generated YAML, they don't
hand-transcribe a table into YAML from scratch.

For the exposure check specifically: if `discover` itself tests reachability, it MUST do so
from a vantage point it confirms is not already on the target's own allowlist — reconcile the
tool's own egress IP against whatever firewall rules it can read before reporting an "exposed"
finding. (A false positive from testing from an already-trusted network was a real mistake made
building this spec's source method — see SKILL.md Step 0's last bullet. Don't repeat it in code.)

```
fortified onboard <server> --provider hetzner --destination <storage-box-id>
```
Idempotent, multi-step, resuming from state (§4) on re-run:
1. Require a passing `discover` result (run it if missing, or refuse with a clear message).
2. Create/confirm the isolated destination (subaccount) for this server.
3. Generate an SSH keypair **for this server specifically** (never reuse a key across servers)
   and install it, requesting append-only. Confirm the append-only restriction is actually the
   server-enforced forced-command form, not a cosmetic flag — this needs verifying per-target
   against current provider docs at build time (see §6's open item); the tool must surface a
   clear failure if it cannot confirm this, not silently proceed as if protected.
4. Generate the Borg repo encryption passphrase, init the repo, and **require** the operator
   to confirm it's been escrowed (a config field or explicit flag) before continuing — refuse
   to proceed with a repo whose key custody hasn't been acknowledged. See SKILL.md's "Encryption
   key custody" section — a repo whose only passphrase copy lived on the lost server is not a
   backup.
5. Stop here. Do NOT enable the destination's snapshot schedule yet — that's `verify`'s job to
   unlock (§4).

```
fortified backup <server> | --all
```
Runs the actual archive step per §4's staged-dump-then-archive ordering (including the free-space
pre-flight and baseline manifest defined there), into the Borg repo via the append-only key. This
is what cron calls nightly. After the archive is created, `backup` re-scans the target for the
same archive candidates discover proposes and prints a `warning: not archived: <path>` for each
one the configured `archive:` list doesn't cover (a glob entry covers only what it matches; an
`exclude:` uncovers what it names under every entry, since borg applies
all excludes to the whole run) — a service added after onboard surfaces on the next backup.
The check is advisory: it never changes the backup's result or exit code. `--all` runs every configured server sequentially — per-server locks
still apply, one server's failure never stops the others, and it exits non-zero if *any* server
failed, printing a per-server summary — so one cron entry covers the fleet. Exits non-zero on any failure — this exit
code is the dead-man-switch hook; wire it to whatever alerting the operator already has (a
webhook flag is fine to add, but don't build a notification system into this tool — that's
scope creep, the operator already has infra for this).

```
fortified verify <server>
```
Restores the latest archive into a scratch location **on the target** (same free-space pre-flight
as `backup`), then proves restorability against the baseline manifest recorded at backup time
(§4): first each dump file's SHA-256 must match, then each dump is loaded into a **throwaway
database container** (same image as the source container) and per-table row counts are compared
against the manifest — concrete, not "it didn't error". Decryption must use the passphrase
resolved from `encryption_key_ref` — the escrow path — never a copy already present on the
target: verifying with the wrong copy proves nothing about surviving host loss (SKILL.md's key
custody rule). Recorded in state (§4) as the fact that unlocks `enable-snapshots` — this is the
sequencing discipline from SKILL.md made structural instead of a step someone has to remember to
do in order.

```
fortified restore <server> --archive <id|latest> --into <path> [--db <name>]
```
The runbook's first two recovery tiers (dropped table / bad migration, live corruption on a
trusted box) made runnable — these are the incidents that actually happen most, and without a
named command the operator would be back to hand-run borg archaeology mid-incident, which is
exactly what this tool exists to eliminate. Extracts the named archive — or, with `--db`, just
that database's dump — into `--into` on the target, using the append-only key (restore is a
read). **Non-destructive by construction:** refuses any `--into` path that is non-empty or that
appears in any discovered `DataMountPaths`; swapping restored data into the live service is
deliberately a manual operator action, never a flag. Run without `--archive`, it lists the repo's
archives and exits — no separate list command needed.

```
fortified enable-snapshots <server>
```
Turns on the provider's native snapshot schedule for that server's destination. Refuses if
state (§4) doesn't show a passing `verify`. Deliberately a separate command from `onboard`, not
a flag on it — it happens strictly after proof, never as part of a batch of steps that might
itself be broken.

```
fortified check <server>
```
Runs the backend's integrity check (`borg check` equivalent) against the repo. Should run on a
schedule, always before any `prune`.

```
fortified prune <server> --prune-key <path>
```
The one command in the whole tool that requires the unrestricted key, supplied explicitly,
every time — never cached, never read from the same secrets path as everything else. Runs
`check` first automatically and refuses to prune a repo that just failed integrity check.

```
fortified status [server]
```
Read-only, lock-exempt. One-shot table (or `--json`) across every configured server: last
backup timestamp, last passing `verify`, snapshot schedule state, days since last `check`. The
"fleet status board" from the earlier design conversation — a read-only report, not a live TUI.

```
fortified drill <server> --target <throwaway-host>
```
The full-host-loss recovery tier from SKILL.md, made runnable: rebuilds configs + data onto a
genuinely separate throwaway target, timed, with the timing and pass/fail recorded in state
(§4) — not just printed — so "when did we last actually drill this" is a fact `status` can
surface, not a memory. This is the single most-skipped step in real-world DR; make it a
first-class command, not an afterthought.

## 6. Hetzner provider — what's already verified, what still needs confirming

Full detail lives in `~/agent-os/skills/fleet-backup-playbook/references/hetzner.md` — read it,
don't re-derive it. Summary for this spec's purposes:

- Storage Box is a network file service (SFTP/SSH/Borg/rsync/SMB/WebDAV), never block storage —
  reachable from anywhere with the right credentials, not "attached" to a specific server.
- Subaccounts are the per-server isolation primitive. Manageable via the Hetzner Cloud API
  (`create_subaccount`, `access_settings` with `readonly`/`ssh_enabled`/etc.) — but the API does
  **not** do file transfer; that's still SFTP/SSH/Borg against the subaccount's own hostname.
- **SSH key installation is protocol-level, not API-managed**: `ssh -p23 user@host install-ssh-key`
  with the pubkey piped to stdin. Confirm at build time whether Hetzner's current tooling
  (Console UI, or the extended-SSH command set) exposes a way to request the Borg
  `--append-only` forced-command restriction specifically on that key, vs. only a coarser
  subaccount-level read-only toggle. **This is an open item — do not assume it works a
  particular way; verify against current Hetzner docs/Console at implementation time, and if
  the forced-command form isn't available through any supported path, surface that clearly as
  a real limitation rather than quietly settling for the weaker protection.**
- Snapshot *deletion/management* is Console/API-only, never reachable via the file protocols —
  that's the real immutability property. Snapshot *contents* may be readable via those same
  protocols (a `.zfs/snapshot`-style path) — don't design around an assumption that a
  compromised backup key can't read old history, only that it can't delete it.
- Robot Storage Box management was deprecated in favor of the unified Console/API on
  2025-07-29 — purely an admin-plane fact, doesn't change any of the above. If implementation
  turns up a doc page or SDK that still assumes the old flow, re-verify against current docs.

## 7. Config file

One YAML file, one entry per fleet member. Sketch (finalize exact schema during
implementation — this is intent, not a locked format; `discover --emit-config` is the intended
way most of this actually gets written, not hand-authoring):

```yaml
servers:
  host-2-example:
    ssh: { host: 203.0.113.10, port: 15086, user: root }
    provider: hetzner
    destination: host2-backup      # subaccount name
    archive:
      - path: /home                 # compose files, configs — discover confirms what's real
        glob: "*/docker-compose.yml"
      - path: /etc/letsencrypt
      - path: /home/docker/psql     # compose file, pg_hba.conf, postgresql.conf...
        exclude:                    # ...but not the live data dir the dump covers
          - /home/docker/psql/data
    databases:
      - kind: postgres
        container: psql
        dump_strategy: docker-exec
      - kind: mariadb
        container: mysql
        dump_strategy: docker-exec
        auth_ref: secret://fortified/host-2-example/mariadb-root   # only when discover
                                                                      # couldn't auto-resolve it
    encryption_key_ref: secret://fortified/host-2-example/borg-passphrase
```

`encryption_key_ref`, `auth_ref` fields, and any provider API token are **names**, resolved at
runtime via `internal/secrets` — never a literal value in this file.

## 8. Testing strategy

This is safety-critical software touching production infrastructure; "manually verify against
`host-2-example`" is necessary but not sufficient on its own.

- **Everything that shells out does so through the injectable `Runner` from §3.** Unit tests
  supply a fake runner asserting the exact argv constructed and returning scripted
  stdout/stderr/exit codes — this is what makes `internal/provider/hetzner` and
  `internal/backend/borg` testable without live SSH/Borg access at all.
- **`discover`'s parsing gets golden-file tests**: capture real output once from an actual run
  against `host-2-example` (`lsblk`/`df`/`docker ps -a`/etc. output), commit it as a fixture,
  and assert `discover`'s parser produces the expected structured report from that fixture
  forever after — this catches parsing regressions without needing a live target for every CI
  run.
- **Local integration tests** (still no live Hetzner access) run a real `borg` binary against a
  local filesystem repo, and real Postgres/MariaDB containers via Docker, to exercise
  `internal/backend/borg` and the `DatabaseInstance` dump logic end-to-end.
- **Live Hetzner integration** (real Storage Box, real subaccounts) is opt-in behind an
  environment variable, never required for normal CI — this is what the build order's step 5
  (§9) actually is, run deliberately by a human, not automatically on every commit.

## 9. Later: conversational control layer (explicitly Phase 2, not v1)

The operator wants to eventually talk to a Claude Code / Claude CLI session and have it drive
this tool from natural language, the way some existing dev-loop tools let you chat with an
agent about your running project. When this gets built, the load-bearing design constraint is:

**The chat layer may only ever invoke this tool's own named commands (or, better, this tool
exposed as an MCP server with one tool per command above) — never arbitrary shell/SSH access to
a target server.** The entire reason this CLI exists is to make backup operations deterministic;
a conversational layer that can improvise shell commands against production infra the moment
someone asks it something not covered by a named command would quietly delete that guarantee.
"Chat with an agent about backups" should mean "the agent calls `fortified verify host-2-example`
and reports the structured result back to you in plain language," not "the agent decides what
commands to run." Build the MCP-server wrapper once v1's command set is stable and proven; don't
let the shape of a future chat interface influence the core commands' design now.

## 10. Build order

1. `internal/config` + `internal/secrets` (env-var resolution first, Infisical second) +
   `internal/state` (the record and locking from §4) — every other package needs these, and
   getting the state schema right early avoids retrofitting it once commands depend on it.
2. `internal/discover`, including the `DatabaseInstance` schema and `--emit-config` — read-only,
   no destructive risk, and the thing every other command depends on for its safety checks. Get
   this right and thoroughly tested (golden fixtures, §8) before anything else.
3. `internal/provider/hetzner` — subaccount creation, SSH key install, resolving the
   append-only open item from §6.
4. `internal/backend/borg` — repo init, archive, restore, check, prune (shelling out to the
   `borg` binary), with the injectable-runner unit tests and local-integration tests from §8.
5. Wire `discover` → `onboard` → `backup` → `verify` → `enable-snapshots` end to end against
   `host-2-example` specifically as the first real target — this is a live server with a real,
   currently-unprotected Postgres + MariaDB instance and ~15 unrelated Docker projects; treat it
   as the integration test, not a toy.
6. `restore` / `check` / `prune` / `drill` / `status`.
7. Only after all of the above is proven on `host-2-example`: onboard `host-example`, then
   revisit whether a second provider is actually needed yet (the second batch of servers —
   don't assume they're Hetzner too; run `discover`-equivalent reasoning on them fresh when
   the time comes).

## 11. Project shape

- Go version floor: `go 1.24` (bump if a materially newer stable is out when implementation
  starts — don't pin to an already-old floor out of habit).
- Module path: the actual repo's import path, decided when the repo is created — not a
  placeholder value guessed here.
- CLI framework: `spf13/cobra`, pinned in `go.mod`, mandatory (already implied by §3's tree —
  making it explicit so two implementers don't diverge on basic project shape).
- Build target: `CGO_ENABLED=0 go build -trimpath ./cmd/fortified` — this is what actually makes
  §1's "single static binary" true, not just a description.

## 12. Open questions for whoever picks this up

- Exact mechanism for the Borg append-only forced-command restriction on a Hetzner Storage Box
  subaccount key — confirm directly against current Console/API before writing
  `internal/provider/hetzner`'s key-install path (§6).
- Whether an existing Go Hetzner SDK has caught up with Storage Box's move to the Cloud API, or
  whether `internal/provider/hetzner` needs to hand-roll the handful of REST calls it actually
  needs (subaccount CRUD, snapshot schedule, snapshot list) — check before committing to a
  dependency.
- Final config file schema (§7 is intent, not contract).
- Retention policy defaults (`prune` needs *some* policy to enforce; SKILL.md flags "a retention
  policy tied to RPO" as a gap the original hand-built process never resolved — don't inherit
  that gap silently, pick a sane default and make it overridable per server).
