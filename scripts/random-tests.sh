#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Runs the long random tests of the core in the optimised build, with the rounds below divided by
# the optional argument. The seed comes from LETHEWIS_RANDOM_SEED.
set -euo pipefail

divisor=${1:-1}
if ! [[ $divisor =~ ^[1-9][0-9]{0,3}$ ]]; then
  echo "usage: random-tests.sh [divisor of the rounds, 1 to 9999]" >&2
  exit 2
fi
echo "seed: ${LETHEWIS_RANDOM_SEED:-unset, so each test takes its own}"
out=$(mktemp)
trap 'rm -f "$out"' EXIT

run() {
  local rounds=$(($1 / divisor)) count=$2
  shift 2
  echo "== $rounds rounds: $*"
  LETHEWIS_RANDOM_ROUNDS=$rounds cargo test -p lethewis-core --lib --all-features --locked \
    --release -- --ignored --exact "$@" | tee "$out"
  grep -q "^test result: ok\. $count passed" "$out"
}

run 1000000 1 slots::tests::many_random_records_unwrap_as_their_plaintext_says
run 1000000 2 words::tests::many_random_words_are_read_as_the_list_says \
  shares::words::tests::many_random_changes_of_symbols_are_refused
# X-Wing runs in every round, so the rounds are fewer.
run 10000 2 slots::archive::tests::many_random_records_of_archive_keys_load_as_their_layers_say \
  slots::archived::tests::many_random_records_of_an_archive_open_as_their_parts_say
run 100000 1 slots::data::tests::many_random_blocks_open_to_their_data_and_refuse_a_changed_bit
run 10000 1 slots::carry::tests::many_random_exports_open_to_their_data_and_refuse_a_changed_bit
