#!/bin/sh
# fortified-guard — forced SSH command for fortified's control-plane
# automation key. Installed as `command="/usr/local/sbin/fortified-guard"`
# on a dedicated key's authorized_keys line (see install.sh), this
# script runs instead of whatever the client actually requested;
# sshd puts the client's real request in $SSH_ORIGINAL_COMMAND.
#
# Two modes, read from /etc/fortified-guard/mode (bare word):
#   audit   - log every command, allow all of them. Safe to run
#             against production servers: nothing can break, because
#             nothing is ever blocked. This is the mode to run fortified
#             discover/backup/verify under first, so the log fills with
#             the exact real command text this key will ever need.
#   enforce - only allow commands matching a pattern in
#             /etc/fortified-guard/allowed.patterns (one shell case-glob
#             per line, '#'-comments and blank lines ignored). Anything
#             else is rejected.
# A missing mode file defaults to audit (the safe, not-yet-configured
# state). A mode file that EXISTS but holds anything other than
# exactly "audit" or "enforce" (a typo, corruption, a permissions
# problem) fails CLOSED — reject and log a config-error decision —
# never silently falls back to allow-all. A security control that
# fails open on a typo isn't one.
#
# Do NOT hand-build allowed.patterns by copy-pasting raw captured log
# lines: fortified's real commands legitimately contain `*`/`?`/`[`
# (SQL, `find` patterns) that a shell case-glob would treat as
# wildcards, silently widening what's allowed beyond the literal
# command that was captured. Use derive-pattern.sh to escape a
# captured line first, then deliberately re-introduce `*` only at the
# specific token(s) you know vary run to run (an archive timestamp, a
# container name) — see README.md.

MODE_FILE="/etc/fortified-guard/mode"
PATTERNS_FILE="/etc/fortified-guard/allowed.patterns"
LOG_FILE="/var/log/fortified-guard.log"

cmd="${SSH_ORIGINAL_COMMAND:-}"

# --- resolve mode, failing closed on anything unrecognized ---
mode="audit"
if [ -e "$MODE_FILE" ]; then
    if [ ! -r "$MODE_FILE" ]; then
        mode="error"
    else
        raw_mode="$(cat "$MODE_FILE" 2>/dev/null | tr -d '[:space:]')"
        case "$raw_mode" in
            "" | audit) mode="audit" ;;
            enforce) mode="enforce" ;;
            *) mode="error" ;;
        esac
    fi
fi

# --- pattern match — `|| [ -n "$pattern" ]` picks up a final line
#     with no trailing newline, which plain `read` otherwise silently
#     drops ---
matched="no"
if [ -r "$PATTERNS_FILE" ]; then
    while IFS= read -r pattern || [ -n "$pattern" ]; do
        case "$pattern" in
            "" | "#"*) continue ;;
        esac
        case "$cmd" in
            $pattern) matched="yes" ;;
        esac
        [ "$matched" = "yes" ] && break
    done < "$PATTERNS_FILE"
fi

case "$mode" in
    enforce)
        if [ "$matched" = "yes" ]; then
            decision="ALLOWED(enforce,matched)"
        else
            decision="REJECTED(enforce,no-match)"
        fi
        ;;
    audit)
        if [ "$matched" = "yes" ]; then
            decision="ALLOWED(audit,matched)"
        else
            decision="ALLOWED(audit,no-match)"
        fi
        ;;
    *)
        decision="REJECTED(config-error,mode-file-invalid)"
        ;;
esac

# --- redact known secret-bearing env assignments before anything
#     touches disk --- sshx.Session.Run delivers secrets by prefixing
#     the remote command with `env VAR=realvalue ...` rather than
#     relying on server-side AcceptEnv (see internal/sshx/session.go's
#     own doc comment on why) — which means $SSH_ORIGINAL_COMMAND
#     carries the actual plaintext secret for these five variable
#     names, the only ones fortified's Go source ever sets this way.
#     A real bug found by cross-vendor review: logging $cmd verbatim,
#     even in "safe" audit mode, would leak the backup passphrase and
#     every database's root credential to this log file. Best-effort:
#     a value containing a literal single quote is only partially
#     redacted by this regex — the log file stays 0600 as
#     defense in depth regardless.
redact() {
    printf '%s' "$1" | sed -E \
        -e "s/(BORG_PASSPHRASE|PGPASSWORD|MYSQL_PWD|POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD)=('[^']*'|[^ ]*)/\\1=REDACTED/g"
}
cmd_for_log="$(redact "$cmd")"

# --- log length-prefixed, not one-line-per-record --- a real bug
#     found by cross-vendor review: fortified's own multi-line
#     commands (e.g. CockroachDB's dump preamble) contain embedded
#     newlines, which would otherwise split one record across several
#     physical lines and let a crafted command forge a fake log entry
#     that reads as a separate, legitimate ALLOWED line. Framing the
#     payload with its exact byte length makes this impossible: the
#     reader always consumes exactly that many bytes as the command,
#     regardless of what's inside them.
{
    cmd_len=$(printf '%s' "$cmd_for_log" | wc -c | tr -d ' ')
    printf '%s\t%s\tlen=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$decision" "$cmd_len"
    printf '%s' "$cmd_for_log"
    printf '\n---\n'
} >> "$LOG_FILE" 2>/dev/null

case "$decision" in
    ALLOWED*) ;;
    *)
        echo "fortified-guard: rejected (see $LOG_FILE on the target for the exact command)" >&2
        exit 1
        ;;
esac

exec /bin/sh -c "$cmd"
