# shellcheck shell=bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# The pinned Kani. The version fixes the verifier and the CBMC solver, which come in the bundle checked
# against this digest, and the name of Kani's nightly compiler, which rustup installs.
export KANI_VERSION=0.68.0
export KANI_BUNDLE_SHA256=32e2b484d73ede0bbf64a2cf0879c4259422497d8aec4ee67d448de9ae7843d3
