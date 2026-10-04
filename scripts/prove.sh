#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Runs every Kani proof and accepts the run only if the pinned Kani ran, every declared proof ran
# and succeeded, every proof lives in a module `proofs`, has a cover property and reached all of
# them, every proof checks code in this repository, every kani::assert( and kani::cover!( written
# out in the source is in the run, some proof reaches every region that Kani compiled of the code
# in the modules `proofs`, and Kani reported no check in this repository's code as unreachable.
# Kani itself reports success with an unreached cover property, so each check is judged here.
# Writes the manifest of what was proven to target/proofs/manifest.json.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/kani-pin.sh
source scripts/kani-pin.sh

out=target/proofs
results=$out/results.json
mkdir -p "$out"
rm -f "$out/declared.json" "$results" "$out/manifest.json" "$out/files" "$out/asserted"
git -c core.excludesFile=/dev/null ls-files -z --cached --others --exclude-standard >"$out/files"
# Every kani::assert( and kani::cover!( written out in the source; each must be in the run.
# checks/ holds workspaces of their own, which Kani does not build.
while IFS= read -r -d '' file; do
  [[ $file == *.rs && $file != checks/* && -f $file ]] || continue
  FILE=$file awk '!/^[[:space:]]*\/\// && /kani::(assert\(|cover!\()/ {
    print ENVIRON["FILE"] ":" NR
  }' <"$file"
done <"$out/files" >"$out/asserted"

cargo kani list --format json
mv kani-list.json "$out/declared.json"
misplaced=$(jq -r '.["standard-harnesses"][]?[]' "$out/declared.json" |
  grep -vE '(^|::)proofs::[^:]+$' || true)
if [ -n "$misplaced" ]; then
  printf 'prove: a proof outside a module proofs: %s\n' "$misplaced" >&2
  exit 1
fi

# In a crate without the standard library Kani reports an assert! or unwrap that is never reached as
# a success; line coverage shows it.
rm -rf target/kani/*/kanicov_*
cargo kani --workspace --output-format terse --harness-timeout 30m --coverage -Z source-coverage \
  -Z unstable-options --export-json "$results"

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

# Every check is judged by itself, not by a summary: a summary field that disappears in another Kani
# version would read as zero and pass. A file is ours if git tracks it, or if it is new and neither
# .gitignore nor .git/info/exclude ignores it: Kani also writes relative paths for its own library
# and for built-in functions.
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
            if .status != "Satisfied" then "\($proof): cover not reached: \(.description)" else empty end
          elif .status == "Unreachable" and ours then
            "\($proof): never reached, so a proof may hold vacuously: \(.location.file):\(.location.line) \(.description)"
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
    covers_reached: ([$r.checks[] | select(.category == "cover" and .status == "Satisfied")] | length)
  }]
}' "$results" >"$out/manifest.json"
echo "prove: every proof holds; manifest in $out/manifest.json"
