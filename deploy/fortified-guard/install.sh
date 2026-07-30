#!/bin/sh
# install.sh — installs fortified-guard on ONE target server.
#
# Requires fortified-guard.sh to be present alongside this script (NOT
# just this file piped via stdin — it copies that sibling file, so
# both need to actually be on the target first). Copy both files plus
# the new key's .pub to the target, then run this ON the target as
# root:
#
#   scp fortified-guard.sh install.sh <key>.pub root@target:/root/
#   ssh root@target 'sh /root/install.sh /root/<key>.pub'
#
# Usage: install.sh <path-to-new-key.pub>
#
# What it does:
#   1. Copies fortified-guard.sh to /usr/local/sbin/fortified-guard
#      (0555 — this assumes the automation key authenticates as the
#      same privileged user already used for interactive SSH access,
#      e.g. root, matching how this fleet's servers are configured
#      today. A genuinely separate, non-root automation account would
#      additionally need this file's owning group and the log file
#      below adjusted so that account can execute/append to them.)
#   2. Creates /etc/fortified-guard/ with mode=audit (the safe default)
#   3. Creates /var/log/fortified-guard.log, root-only
#   4. Prints the exact authorized_keys line to append — this script
#      never edits authorized_keys itself: that file is the one place
#      a mistake is genuinely hard to recover from unattended, so
#      adding the line is a deliberate, reviewed, manual step.
#
# This is ADDITIVE: your existing key(s) in authorized_keys are left
# exactly as they are. This only adds a new, separately-scoped key.

set -eu

if [ "$(id -u)" != "0" ]; then
    echo "install.sh: must run as root" >&2
    exit 1
fi

pubkey_path="${1:-}"
if [ -z "$pubkey_path" ] || [ ! -r "$pubkey_path" ]; then
    echo "usage: install.sh <path-to-new-key.pub>" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
guard_src="$script_dir/fortified-guard.sh"
if [ ! -r "$guard_src" ]; then
    echo "install.sh: fortified-guard.sh not found next to this script at $guard_src — copy it to the target alongside install.sh first" >&2
    exit 1
fi

install -o root -g root -m 0555 "$guard_src" /usr/local/sbin/fortified-guard

mkdir -p /etc/fortified-guard
chmod 0755 /etc/fortified-guard
if [ ! -f /etc/fortified-guard/mode ]; then
    echo "audit" > /etc/fortified-guard/mode
    chmod 0644 /etc/fortified-guard/mode
fi
if [ ! -f /etc/fortified-guard/allowed.patterns ]; then
    : > /etc/fortified-guard/allowed.patterns
    chmod 0644 /etc/fortified-guard/allowed.patterns
fi

touch /var/log/fortified-guard.log
chmod 0600 /var/log/fortified-guard.log

echo "Installed. Current mode: $(cat /etc/fortified-guard/mode)"
echo
echo "Add this line to the appropriate authorized_keys file (this"
echo "script does NOT do it for you — review it, then add it by hand):"
echo
printf 'command="/usr/local/sbin/fortified-guard",restrict %s\n' "$(cat "$pubkey_path")"
