#!/bin/sh
# derive-pattern.sh — escapes shell glob metacharacters (\ * ? [ ]) in
# a captured command, so pasting the OUTPUT into allowed.patterns is
# an exact-match-only pattern by default: none of it is a live
# wildcard yet, even though allowed.patterns is matched via shell
# case-glob (needed for legitimately-variable tokens like an archive
# timestamp or a container name).
#
# NEVER paste raw captured command text directly into allowed.patterns
# — fortified's real commands legitimately contain *, ?, [ (SQL
# queries, `find` patterns), which a case-glob would treat as
# wildcards, silently permitting more than the single command that was
# actually captured. Run the captured line through this script first,
# then deliberately re-introduce a wildcard (delete the escaping
# backslash) only at the specific token(s) you know vary run to run.
#
# Usage:
#   derive-pattern.sh < captured-line.txt
#   echo 'some command' | derive-pattern.sh
#   derive-pattern.sh path/to/file/holding/one/command

# $(...) strips trailing newlines from whatever the sed pipeline
# produces (which itself may or may not have one, depending on the
# input) — printf then adds back exactly one. Without this, appending
# several derived patterns in sequence via `>>` (the documented
# workflow) silently merges one pattern onto the start of the next
# whenever the input line lacked its own trailing newline — verified
# live: this happened on the very first real test of this script.
escaped=$(
    if [ -n "${1:-}" ] && [ -r "$1" ]; then
        cat "$1"
    else
        cat
    fi | sed -e 's/\\/\\\\/g' -e 's/\*/\\*/g' -e 's/?/\\?/g' -e 's/\[/\\[/g' -e 's/\]/\\]/g'
)
printf '%s\n' "$escaped"
