#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Runs the Kani proofs, each in a Kani run of its own, and judges them.
#
#   prove.sh             runs every proof, two at a time or LETHEWIS_PROOF_JOBS, then judges them
#   prove.sh list        writes the declared proofs and prints their names as a JSON array
#   prove.sh run PROOF   runs one proof; its results go to target/proofs/runs/
#   prove.sh judge       judges the results in target/proofs/runs/ against the declared proofs
#
# The judgement accepts the results only if each file holds the one proof it is named after, all of
# them come from the same tools, the pinned Kani ran, every declared proof ran and succeeded, every
# proof lives in a module `proofs`, has a cover property and reached all of them, every proof checks
# code in this repository, every kani::assert( and kani::cover!( written out in the source is in the
# results, some proof reaches every region that Kani compiled of the code in the modules `proofs`,
# and Kani reported no check in this repository's code as unreachable. Kani itself reports success
# with an unreached cover property, so each check is judged here. Writes the manifest of what was
# proven to target/proofs/manifest.json.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/kani-pin.sh
source scripts/kani-pin.sh

out=target/proofs
runs=$out/runs
results=$out/results.json

placed() {
  local misplaced
  misplaced=$(jq -r '.["standard-harnesses"][]?[]' "$out/declared.json" |
    grep -vE '(^|::)proofs::[^:]+$' || true)
  if [ -n "$misplaced" ]; then
    printf 'prove: a proof outside a module proofs: %s\n' "$misplaced" >&2
    exit 1
  fi
  if [ "$(jq '[.["contract-harnesses"][]?[]] | length' "$out/declared.json")" != 0 ]; then
    echo "prove: proofs for contracts are declared, and this script does not run them" >&2
    exit 1
  fi
}

declare_proofs() {
  mkdir -p "$out"
  rm -f "$out/declared.json"
  cargo kani list --format json >&2
  mv kani-list.json "$out/declared.json"
  placed
}

# Paths inside an artifact refuse a colon, so the path separators of a proof's name become dots in
# the name of its file.
run_file() {
  printf '%s/%s.json' "$runs" "${1//::/.}"
}

run_proof() {
  local proof=$1
  mkdir -p "$runs"
  rm -f "$(run_file "$proof")"
  # Kani names its coverage output by the minute, so proofs that run at once build apart.
  if [ -n "${PROVE_SLOT:-}" ]; then
    export CARGO_TARGET_DIR=$out/slot-$PROVE_SLOT
  fi
  rm -rf "${CARGO_TARGET_DIR:-target}"/kani/*/kanicov_*
  # In a crate without the standard library Kani reports an assert! or unwrap that is never reached
  # as a success; line coverage shows it.
  cargo kani --harness "$proof" --exact --output-format terse --harness-timeout 20m --coverage \
    -Z source-coverage -Z unstable-options --export-json "$(run_file "$proof")"
}

prove_all() {
  rm -rf "$runs"
  declare_proofs
  local failed_runs=0
  jq -r '.["standard-harnesses"][]?[]' "$out/declared.json" |
    xargs -r -d '\n' -n 1 -P "${LETHEWIS_PROOF_JOBS:-2}" --process-slot-var=PROVE_SLOT \
      scripts/prove.sh run || failed_runs=1
  if ((failed_runs != 0)); then
    echo "prove: a proof run failed; the judgement of what ran follows" >&2
    (judge) || true
    rm -f "$out/manifest.json"
    exit 1
  fi
  judge
}

judge() {
  rm -f "$results" "$out/manifest.json" "$out/files" "$out/asserted"
  if [ ! -f "$out/declared.json" ]; then
    echo "prove: no list of declared proofs; prove.sh list writes it" >&2
    exit 1
  fi
  placed
  git -c core.excludesFile=/dev/null ls-files -z --cached --others --exclude-standard >"$out/files"
  # Every kani::assert( and kani::cover!( written out in the source; each must be in the results.
  # checks/ holds workspaces of their own, which Kani does not build.
  local file
  while IFS= read -r -d '' file; do
    [[ $file == *.rs && $file != checks/* && -f $file ]] || continue
    FILE=$file awk '!/^[[:space:]]*\/\// && /kani::(assert\(|cover!\()/ {
      print ENVIRON["FILE"] ":" NR
    }' <"$file"
  done <"$out/files" >"$out/asserted"

  local files=() split fail ran_version declared ran problems ran_cbmc stated_kani stated_cbmc
  if [ -d "$runs" ]; then
    mapfile -d '' files < <(find "$runs" -maxdepth 1 -name '*.json' -print0 | sort -z)
  fi
  # Only the results and the descriptions of the proofs are merged: the summary and the time of a
  # file belong to its own run.
  split=$(jq -rn '
    [inputs | {name: (input_filename | split("/") | last | rtrimstr(".json") | gsub("\\."; "::")),
               run: .}] as $runs
    | ($runs[] | .name as $name | .run.verification_results.results as $r
        | if ($r | length) != 1 then "\($name): \($r | length) results in its file"
          elif $r[0].harness_id != $name then "\($name): its file holds \($r[0].harness_id)"
          else empty end),
      (if ($runs | map(.run.tools) | unique | length) > 1
         then "the runs differ in their tools" else empty end),
      (if ($runs | map(.run.project.workspace_root) | unique | length) > 1
         then "the runs differ in their workspace" else empty end),
      (if ($runs | map(.run.metadata | del(.timestamp)) | unique | length) > 1
         then "the runs differ in their target, build or Kani" else empty end)
  ' "${files[@]}" </dev/null)
  if [ -n "$split" ]; then
    printf 'prove: %s\n' "$split" >&2
    exit 1
  fi
  jq -n '
    [inputs] as $runs
    | {metadata: ($runs[0].metadata // {} | del(.timestamp)),
       project: ($runs[0].project // {}),
       tools: ($runs[0].tools // {}),
       harness_metadata: [$runs[].harness_metadata[]],
       verification_results: {results: [$runs[].verification_results.results[]]}}
  ' "${files[@]}" </dev/null >"$results"

  fail=0
  ran_version=$(jq -r '.tools.kani // "unknown"' "$results")
  if [ "$ran_version" != "$KANI_VERSION" ]; then
    echo "prove: Kani $ran_version ran, but $KANI_VERSION is pinned" >&2
    fail=1
  fi

  declared=$(jq -r '.["standard-harnesses"][]?[]' "$out/declared.json" | sort)
  ran=$(jq -r '.verification_results.results[].harness_id' "$results" | sort)
  if [ -z "$declared" ]; then
    echo "prove: no proof is declared; an empty run proves nothing" >&2
    fail=1
  fi
  if [ "$declared" != "$ran" ]; then
    echo "prove: the proofs that ran differ from the proofs declared" >&2
    diff <(printf '%s\n' "$declared") <(printf '%s\n' "$ran") >&2 || true
    fail=1
  fi

  # Every check is judged by itself, not by a summary: a summary field that disappears in another
  # Kani version would read as zero and pass. A file is ours if git tracks it, or if it is new and
  # neither .gitignore nor .git/info/exclude ignores it: Kani also writes relative paths for its own
  # library and for built-in functions.
  problems=$(jq -r --rawfile names "$out/files" --rawfile asserted "$out/asserted" '
    (.project.workspace_root // "") as $root
    | ($names | split("\u0000") | map(select(. != ""))) as $files
    | def relative: (.location.file // "") as $file
        | if $root != "" and ($file | startswith($root + "/"))
          then $file[($root | length) + 1:] else $file end;
    def ours: relative as $relative | any($files[]; . == $relative);
    def coverage: .category == "code_coverage";
    def region: .description | sub("^.*\\$ - "; "");
    def proof_code: (.function // "") | sub("::<(?!impl ).*$"; "") | test("(^|::)proofs::");
    ["Success", "Failure", "Unreachable", "Satisfied", "Unsatisfiable", "Undetermined"] as $known
    | (.verification_results.results[]
      | .harness_id as $proof
      | [.checks[] | select(coverage | not)] as $checks
      | if .status != "Success" then "\($proof): \(.status)" else empty end,
        if ($checks | length) == 0 then "\($proof): no check at all" else empty end,
        if ([$checks[] | select(.category == "cover")] | length) == 0
          then "\($proof): no cover property" else empty end,
        if ([$checks[] | select(ours)] | length) == 0
          then "\($proof): no check in this repository code" else empty end,
        if ([.checks[] | select(coverage and ours and .function == $proof and .status == "Covered")]
            | length) == 0
          then "\($proof): no line coverage of the proof itself" else empty end,
        (.checks[] | select(coverage)
          | if (.location.file // "") == "" then
              "\($proof): line coverage without a location: \(.description)"
            elif .status != "Covered" and .status != "Uncovered" then
              "\($proof): unknown coverage status \(.status): \(.description)"
            else empty end),
        ($checks[]
          | if (.location.file // "") == "" then
              "\($proof): a check without a location: \(.description)"
            elif (.status as $s | $known | index($s)) == null then
              "\($proof): unknown status \(.status): \(.description)"
            elif .category == "cover" then
              if .status != "Satisfied"
                then "\($proof): cover not reached: \(.description)" else empty end
            elif .status == "Unreachable" and ours then
              "\($proof): never reached, so a proof may hold vacuously:" +
                " \(.location.file):\(.location.line) \(.description)"
            elif .status != "Success" and .status != "Unreachable" then
              "\($proof): \(.status): \(.description)"
            else empty end)),
      ([.verification_results.results[].checks[] | select(coverage and ours and proof_code)]
        | group_by(region)[]
        | select(all(.[]; .status != "Covered"))
        | "no proof reaches \(.[0] | region) in \(.[0].function), so a proof may hold vacuously"),
      (([.verification_results.results[].checks[]
          | select((.category == "assertion" or .category == "cover") and ours)
          | "\(relative):\(.location.line)"] | unique) as $seen
        | ($asserted | split("\n") | map(select(. != "")) | unique) - $seen
        | .[] | "\(.): a Kani assertion or cover property that is not in the run")
  ' "$results")
  if [ -n "$problems" ]; then
    printf 'prove: %s\n' "$problems" >&2
    fail=1
  fi
  # The register states the tool versions for every proven row; they must be the versions that ran.
  ran_cbmc=$(jq -r '.tools.cbmc // "unknown"' "$results" | cut -d' ' -f1)
  stated_kani=$(grep -oE 'Kani v?[0-9][0-9.]*[0-9]' docs/proofs.md | sort -u || true)
  stated_cbmc=$(grep -oE 'CBMC v?[0-9][0-9.]*[0-9]' docs/proofs.md | sort -u || true)
  if [ "$stated_kani" != "Kani $KANI_VERSION" ] || [ "$stated_cbmc" != "CBMC $ran_cbmc" ]; then
    echo "prove: docs/proofs.md names [$(printf '%s' "$stated_kani $stated_cbmc" | tr '\n' ' ')]," \
      "but Kani $KANI_VERSION with CBMC $ran_cbmc ran" >&2
    fail=1
  fi
  ((fail == 0)) || exit 1

  jq '. as $root | {
    target: .metadata.target,
    tools,
    proofs: [.verification_results.results[] as $r | {
      proof: $r.harness_id,
      sources: [$root.harness_metadata[] | select(.pretty_name == $r.harness_id)
        | {crate: .crate_name, file: .source.file, line: .source.start_line}],
      status: $r.status,
      duration_ms: $r.duration_ms,
      covers_reached:
        ([$r.checks[] | select(.category == "cover" and .status == "Satisfied")] | length)
    }]
  }' "$results" >"$out/manifest.json"
  echo "prove: every proof holds; manifest in $out/manifest.json"
}

case "${1:-}" in
  "") prove_all ;;
  list)
    declare_proofs
    jq -c '[.["standard-harnesses"][]?[]]' "$out/declared.json"
    ;;
  run)
    [ $# -eq 2 ] || { echo "usage: prove.sh run PROOF" >&2; exit 2; }
    run_proof "$2"
    ;;
  judge) judge ;;
  *)
    echo "usage: prove.sh [list | run PROOF | judge]" >&2
    exit 2
    ;;
esac
