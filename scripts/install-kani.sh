#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Installs the pinned Kani: the verifier from crates.io, then its bundle of CBMC and Kani's
# compiler, checked against the digest in scripts/kani-pin.sh.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/kani-pin.sh
source scripts/kani-pin.sh

cargo install kani-verifier --locked --version "$KANI_VERSION"
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
bundle="$dir/kani-${KANI_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
curl -sSLo "$bundle" \
  "https://github.com/model-checking/kani/releases/download/kani-${KANI_VERSION}/${bundle##*/}"
echo "$KANI_BUNDLE_SHA256  $bundle" | sha256sum -c -
cargo kani setup --use-local-bundle "$bundle"
