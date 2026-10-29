#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Prints only=true if HEAD differs only in Markdown no code names from a commit of BASE..HEAD. That
# commit is the newest earlier one that passed every check below and holds BASE; otherwise
# only=false.
#
# Needs REPO, BASE, HEAD and a token for gh; fails on any error of git or the API.
set -euo pipefail

checks=("Tests" "Tests on aarch64 Linux" "Tests on macOS" "Every mutant is caught" "Proofs hold"
  "Advisories, licences, sources")
# The newest run of each check; nothing when one page does not hold them all.
newest='select(.total_count <= 100) | [.check_runs[] | select(.app.slug == "github-actions")]
  | group_by(.name) | map(max_by(.id))[] | "\(.conclusion) \(.name)"'

onto=$(git rev-parse --verify "$BASE^{commit}")
tip=$(git rev-parse --verify "$HEAD^{commit}")

passed() {
  local runs name
  runs=$(gh api "repos/$REPO/commits/$1/check-runs?filter=all&per_page=100" --jq "$newest") || exit 1
  for name in "${checks[@]}"; do
    grep -qxF "success $name" <<<"$runs" || return 1
  done
}

only_text() {
  local changed path status
  changed=$(git diff --name-only --no-renames "$1" "$tip") || exit 1
  while IFS= read -r path; do
    case "$path" in
      *.md) ;;
      *) return 1 ;;
    esac
    status=0
    git grep -qF -e "${path##*/}" "$tip" -- '*.rs' '*.sh' '*.py' || status=$?
    [ "$status" = 1 ] || return 1
  done <<<"$changed"
}

commits=$(git rev-list "$onto..$tip")
for commit in $commits; do
  [ "$commit" != "$tip" ] || continue
  if passed "$commit"; then
    echo "every check passed on $commit" >&2
    if git merge-base --is-ancestor "$onto" "$commit" && only_text "$commit"; then
      echo "only=true"
    else
      echo "only=false"
    fi
    exit 0
  fi
done
echo "only=false"
