# fortified-guard

A forced-command SSH restriction for fortified's control-plane
automation key — the hop from your control host *to* each protected
target (running discover's probes, database dumps, `docker exec`,
`borg`, etc.), as distinct from the automation key fortified already
generates *on* each target for its own connection to the Storage Box
(that one is already append-only and narrowly scoped, via Hetzner's
own `command=` mechanism — see the main repo's README).

This key is per-server, not shared across the fleet: a leak on one box
never grants anything on another. It's additive to your existing
personal key on each server — your own interactive login is untouched.

This design assumes the automation key authenticates as the same
privileged user already used for interactive SSH (root, matching this
fleet's servers). A genuinely separate, non-root automation account
would need additional ownership/permission adjustments not covered
here.

## Why two phases

fortified's read-only probes (`lsblk`, `systemctl is-active`, `ls -d
/etc/...`) are simple, fixed strings and trivially safe to allowlist.
But the commands that actually matter — dumping a database, loading
verify's throwaway container — are built as `sh -c "<script>"` on the
control host at runtime, with container names, SQL queries, paths, and
secrets (via `$PGPASSWORD`/`$MYSQL_PWD` shell expansion) interpolated
in, then re-quoted by SSH's own argv-joining. So:

- **Phase 1 (do this now):** install in `audit` mode. Nothing is ever
  blocked — every command is logged and allowed. Run a full
  `discover` → `backup` → `verify` against the target with this key so
  the log fills with the *exact* real command text this key will ever
  need to run.
- **Phase 2 (after you have real logs):** derive `allowed.patterns`
  from that log with `derive-pattern.sh` (see below — do NOT paste raw
  captured lines), flip `mode` to `enforce`, and re-run the same
  discover/backup/verify cycle to confirm nothing regressed before
  trusting it for cron.

## Setup (per server)

On your control host:

```sh
ssh-keygen -t ed25519 -N "" -f ~/.ssh/fortified_automation_<server-id>
```

Copy `fortified-guard.sh`, `install.sh`, and the new `.pub` file to the
target — `install.sh` needs all three present, and reads the pubkey
from wherever you put it:

```sh
scp fortified-guard.sh install.sh ~/.ssh/fortified_automation_<server-id>.pub root@<server-id>:/root/
ssh root@<server-id> 'sh /root/install.sh /root/fortified_automation_<server-id>.pub'
```

It prints an `authorized_keys` line — add it by hand to the right
user's `~/.ssh/authorized_keys` on the target (additive; don't remove
your existing key). Then point a *new* `~/.ssh/config` alias at the new
key (see the main conversation for why it needs to be a new alias, not
a change to your existing `Host <server-id>` block), and update that
server's `ssh.host` in `fleet.yaml` to the new alias.

## Checking the log

```sh
ssh <server-id> 'cat /var/log/fortified-guard.log'
```

Each record is length-prefixed, not one-line-per-command: fortified's
own multi-line commands (CockroachDB's dump preamble, for one) contain
embedded newlines, which would otherwise split one record across
several physical lines — or worse, let a crafted command forge a fake
log entry. A record looks like:

```
2026-07-26T00:00:00Z	ALLOWED(audit,no-match)	len=87
docker exec -u postgres psql pg_dumpall > /fortified-backup-workspace-host/psql.sql
---
```

The header line is `<timestamp>\t<decision>\tlen=<N>`; the next
exactly-N bytes (which may themselves span several physical lines) are
the real command; `---` on its own line is just a human-readable
separator, not part of the framing.

Known secret-bearing env values (`BORG_PASSPHRASE`, `PGPASSWORD`,
`MYSQL_PWD`, `POSTGRES_PASSWORD`, `MYSQL_ROOT_PASSWORD`) are redacted
before anything is written — fortified delivers those by prefixing the
remote command with `env VAR=realvalue ...` rather than relying on
server-side `AcceptEnv`, so the raw command genuinely does carry the
plaintext value; don't disable this redaction.

## Deriving patterns for enforce mode

**Never paste a raw captured command straight into `allowed.patterns`.**
`allowed.patterns` is matched as a shell case-glob (needed so a
pattern can still match a command whose archive timestamp or container
name legitimately changes every run) — but real captured commands
routinely contain `*`, `?`, `[` as *literal* characters (a SQL `LIKE
'%foo%'`-style query, a `find -iname` pattern), which a glob would
instead treat as wildcards, silently permitting more than the one
command you actually captured.

Instead, run the captured command through `derive-pattern.sh`, which
escapes every glob metacharacter — the result matches only that exact
command, byte for byte:

```sh
derive-pattern.sh <<'EOF' >> /etc/fortified-guard/allowed.patterns
docker exec -u postgres psql pg_dumpall > /fortified-backup-workspace-host/psql.sql
EOF
```

Then deliberately re-introduce a wildcard (delete the escaping
backslash `derive-pattern.sh` added) only at the specific token(s) you
know vary run to run — e.g. an archive timestamp or workspace path —
never at a token whose `*`/`?`/`[` came from real command content.

## Flipping to enforce

```sh
ssh <server-id> 'echo enforce > /etc/fortified-guard/mode'
```

Anything other than exactly `audit` or `enforce` in the mode file
fails CLOSED (rejects every command, logs a `config-error` decision) —
a typo never silently reverts to allow-all.

Do this only after `allowed.patterns` covers every command you saw in
the audit log for a full discover+backup+verify cycle. Re-run that
same cycle once more after flipping — a `REJECTED(enforce,...)` line
in the log means a pattern is missing, not that something is actually
wrong.
