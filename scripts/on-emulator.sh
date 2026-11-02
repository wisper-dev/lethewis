#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Cargo's runner for x86_64-linux-android: runs a test binary on the emulator with its arguments
# and the LETHEWIS_* settings, and exits with the binary's status. A guest that died fails it
# instead of holding it forever.
set -euo pipefail

binary=$1
shift
dir=/data/local/tmp/lethewis
timeout 60 adb shell mkdir -p "$dir" >/dev/null
timeout 300 adb push "$binary" "$dir/" >/dev/null

quote() { printf "'%s'" "${1//\'/\'\\\'\'}"; }
command="cd $dir &&"
while IFS='=' read -r name value; do
  command+=" $name=$(quote "$value")"
done < <(env | grep '^LETHEWIS_' || true)
command+=" ./$(basename "$binary")"
for argument in "$@"; do
  command+=" $(quote "$argument")"
done
timeout 1800 adb shell "$command"
