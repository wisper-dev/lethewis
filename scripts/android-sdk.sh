#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Puts the pieces of android/versions.sh into the SDK directory given, with the system image of
# each emulator named after it: each archive downloaded, its SHA-1 and SHA-256 checked, unpacked
# in its place with a stamp of the archive. A place already there is kept if its stamp matches.
set -euo pipefail
shopt -s inherit_errexit

if [ $# -lt 1 ]; then
  echo "usage: android-sdk.sh <sdk directory> [emulator ...]" >&2
  exit 2
fi
sdk=$1
shift
# shellcheck source=android/versions.sh
source "$(git rev-parse --show-toplevel)/android/versions.sh"
stamp=.lethewis-archive

packages=("${ANDROID_PACKAGES[@]}")
for emulator in "$@"; do
  if [ -z "${ANDROID_IMAGES[$emulator]:-}" ]; then
    echo "android-sdk: no emulator $emulator in android/versions.sh" >&2
    exit 2
  fi
  packages+=("${ANDROID_IMAGES[$emulator]}")
done

mkdir -p "$sdk"
# In the SDK, so that a place appears at once, by renaming.
work=$(mktemp -d "$sdk/.unpacking.XXXXXX")
trap 'rm -rf "$work"' EXIT
for package in "${packages[@]}"; do
  IFS='|' read -r place archive sha1 sha256 <<<"$package"
  if [ -d "$sdk/$place" ]; then
    if [ "$(cat "$sdk/$place/$stamp" 2>/dev/null)" != "$archive $sha256" ]; then
      echo "android-sdk: $sdk/$place is not from $archive; remove it to put that in" >&2
      exit 1
    fi
    continue
  fi
  echo "android-sdk: $place"
  curl -fsSL --retry 3 -o "$work/archive.zip" "$ANDROID_REPOSITORY/$archive"
  echo "$sha1  $work/archive.zip" | sha1sum --check --quiet --strict -
  echo "$sha256  $work/archive.zip" | sha256sum --check --quiet --strict -
  rm -rf "$work/unpacked"
  unzip -q "$work/archive.zip" -d "$work/unpacked"
  shopt -s nullglob dotglob
  top=("$work/unpacked"/*)
  shopt -u nullglob dotglob
  if [ ${#top[@]} -ne 1 ] || [ ! -d "${top[0]}" ]; then
    echo "android-sdk: $archive does not hold one directory" >&2
    exit 1
  fi
  echo "$archive $sha256" >"${top[0]}/$stamp"
  mkdir -p "$(dirname "$sdk/$place")"
  mv "${top[0]}" "$sdk/$place"
done
