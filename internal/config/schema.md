# fleet.yaml schema

One YAML document, `servers:` mapping server ID -> server config
(SPEC.md §7). Default path: `~/.config/fortified/fleet.yaml`, override
with `--config`. Unknown keys anywhere in the document are a hard
error (strict decoding) — this catches typos instead of silently
ignoring them.

```yaml
servers:
  host-2-example:
    ssh:
      host: 203.0.113.10     # required
      port: 15086            # required
      user: root             # required
    provider: hetzner        # required
    destination: host2-backup # required — provider-specific destination id
    archive:
      - path: /home
        glob: "*/docker-compose.yml"   # optional
      - path: /etc/letsencrypt
    databases:
      - kind: postgres
        container: psql
        dump_strategy: docker-exec
      - kind: mariadb
        container: mysql
        dump_strategy: docker-exec
        auth_ref: secret://fortified/host-2-example/mariadb-root  # only when
                                                                     # discover
                                                                     # couldn't
                                                                     # auto-resolve it
    encryption_key_ref: secret://fortified/host-2-example/borg-passphrase  # required
    retention:                # optional — defaults to keep-daily=7,
      keep_daily: 7            # keep-weekly=4, keep-monthly=6 (PLAN.md §1)
      keep_weekly: 4
      keep_monthly: 6
    workspace_dir: /mnt/HC_Volume_21111084  # optional — absolute path to stage
                                              # dumps under instead of the SSH
                                              # login's own home directory; use
                                              # when a database's dump needs more
                                              # scratch space than the root
                                              # filesystem has free
```

## Validation rules

- **Unknown keys** anywhere → hard error (strict YAML decoding).
- **Unresolved `TODO`** anywhere in the document → hard error
  (`ErrUnresolvedTODO`). This is what keeps `discover --emit-config`
  honest: the operator must fill every gap before `onboard` will run.
- **`encryption_key_ref`** is required and must be `env://VAR` or
  `secret://path/name` — never a literal value (`ErrPlaintextSecret`).
- **`databases[].auth_ref`**, when present, must be a reference too.
  It's only required when discover couldn't resolve auth automatically
  (e.g. reading `MYSQL_ROOT_PASSWORD` from the container's own env).
- Missing `ssh.host`/`ssh.port`/`ssh.user`/`provider`/`destination` →
  `ErrMissingField`.

## Secret references

Resolved at runtime by `internal/secrets`, never read from this file
directly:
- `env://VAR` — an environment variable on the control host. Always
  available, no external dependency.
- `secret://path/to/name` — fetched via the Infisical CLI
  (`infisical secrets get name --plain --path /path/to`), relying on
  Infisical's own already-configured project/auth context (a
  `.infisical.json` + `infisical login`, or `INFISICAL_TOKEN` in the
  control host's ambient environment). fortified does not manage
  Infisical project/environment selection itself.
