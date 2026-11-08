#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Runs the Kani proofs, each in a run of its own, and judges every check they report. Kani itself
# reports success with an unreached cover property. Kani builds the crate of a proof and the crates
# it reaches, never another crate of the workspace.
#
#   prove.sh             runs every proof, two at a time or LETHEWIS_PROOF_JOBS, then judges them
#   prove.sh list        writes the declared proofs and prints their names as a JSON array
#   prove.sh run PROOF   runs one proof and judges it by the rules of a proof alone; its results
#                        and peak memory go to target/proofs/runs/
#   prove.sh only PROOF...  runs the proofs named, longest by scripts/proof-times first,
#                        LETHEWIS_PROOF_JOBS at a time. A proof joins others only if their peaks fit
#                        LETHEWIS_PROOF_MEMORY megabytes. scripts/proof-plan.py names them.
#   prove.sh times       updates scripts/proof-times from the results in target/proofs/runs/
#   prove.sh judge       judges target/proofs/runs/ against the declared proofs and writes
#                        target/proofs/manifest.json. With LETHEWIS_PROOF_CRATES, the directories of
#                        crates, only their proofs; the manifest names the others as unchanged since
#                        LETHEWIS_PROOF_BASE, a commit of main.
#   prove.sh agree       compares Kani's own results with a run's reading, on a few proofs
#   prove.sh sources     prints a digest of Kani and of every file but the documents. A run writes
#                        it beside its results if no file changed meanwhile.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/kani-pin.sh
source scripts/kani-pin.sh

out=target/proofs
runs=$out/runs
results=$out/results.json
times=scripts/proof-times

# The rules a proof's results meet by themselves, alone or among all others: `own_problems` gives
# what breaks them. Every check is judged by itself, not by a summary field that another Kani
# version may drop. A file is ours if git lists it, as $names does, since Kani also writes relative
# paths for its own library.
# shellcheck disable=SC2016 # the dollars are jq's
proof_rules='
  (.project.workspace_root // "") as $root
  | ($names | split("\u0000") | map(select(. != ""))) as $files
  | def relative: (.location.file // "") as $file
      | if $root != "" and ($file | startswith($root + "/"))
        then $file[($root | length) + 1:] else $file end;
  def ours: relative as $relative | any($files[]; . == $relative);
  def coverage: .category == "code_coverage";
  ["Success", "Failure", "Unreachable", "Satisfied", "Unsatisfiable", "Undetermined"] as $known
  | def own_problems:
        .harness_id as $proof
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
            else empty end);
'

placed() {
  local misplaced
  if git grep -q 'kani::should_panic' -- '*.rs' ':!checks/'; then
    echo "prove: a proof that must panic, which the reading of the results does not support" >&2
    exit 1
  fi
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

# The crates whose sources hold a proof, as lines "<package> <directory>".
proof_crates() {
  cargo metadata --no-deps --format-version 1 --locked |
    jq -r --arg root "$PWD/" '.packages[]
      | "\(.name) \(.manifest_path | ltrimstr($root) | rtrimstr("/Cargo.toml"))"' |
    while read -r package directory; do
      if grep -rqsF --include='*.rs' 'kani::proof' "$directory/src"; then
        printf '%s %s\n' "$package" "$directory"
      fi
    done
}

declare_proofs() {
  local crates package directory
  mkdir -p "$out"
  rm -f "$out/declared.json" "$out"/declared-*.json
  crates=$(proof_crates)
  [ -n "$crates" ] || { echo "prove: no crate holds a proof" >&2; exit 1; }
  while read -r package directory; do
    # Kani's list takes no package; in the crate's directory it builds that crate alone.
    rm -f "$directory/kani-list.json"
    (cd "$directory" && cargo kani list --format json) >&2
    jq --arg package "$package" '{package: $package} + .' "$directory/kani-list.json" \
      >"$out/declared-$package.json"
    rm "$directory/kani-list.json"
  done <<<"$crates"
  jq -s '{
    "standard-harnesses": (map(.["standard-harnesses"] // {}) | add),
    "contract-harnesses": (map(.["contract-harnesses"] // {}) | add),
    "package-of": ([.[] | .package as $package | .["standard-harnesses"] // {} | .[][]
      | {key: ., value: $package}] | from_entries)
  }' "$out"/declared-*.json >"$out/declared.json"
  placed
}

# Artifact paths refuse a colon, so `::` in a proof's name becomes a dot in its file name.
run_file() {
  printf '%s/%s.json' "$runs" "${1//::/.}"
}

# Runs a command and writes into FILE the peak memory, in megabytes, of its largest process.
peak() {
  python3 -c 'import math, resource, subprocess, sys
status = subprocess.call(sys.argv[2:])
with open(sys.argv[1], "w") as out:
    out.write(f"{math.ceil(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024)}\n")
sys.exit(status)' "$@"
}

# Runs PROOF of PACKAGE in the workspace of MANIFEST and reads its results into FILE.
read_run() {
  local manifest=$1 package=$2 proof=$3 file=$4 started
  rm -f "$file" "$file.part" "${file%.json}.peak"
  started=${EPOCHREALTIME//[^0-9]/}
  # Without the standard library Kani reports a never-reached assert! or unwrap as a success; line
  # coverage shows it.
  peak "${file%.json}.peak" cargo kani --manifest-path "$manifest" -p "$package" \
    --harness "$proof" --exact \
    --output-format old --harness-timeout 10m --coverage -Z source-coverage -Z unstable-options \
    >"${file%.json}.txt" 2>&1 || true
  if ! scripts/cbmc-results.py read "$proof" "${file%.json}.txt" \
    $(((${EPOCHREALTIME//[^0-9]/} - started) / 1000)) >"$file.part"; then
    echo "prove: the results of $proof could not be read" >&2
    return 1
  fi
  mv "$file.part" "$file"
}

sources() {
  {
    cargo kani --version
    git ls-files --cached --others --exclude-standard -- ':!*.md' ':!scripts/proof-times' |
      while IFS= read -r name; do
        if [ -f "$name" ]; then
          printf '%s %s\n' "$(git hash-object -- "$name")" "$name"
        fi
      done
  } | git hash-object --stdin
}

run_proof() {
  local proof=$1 file before problems package
  package=$(jq -r --arg proof "$proof" '.["package-of"][$proof] // ""' "$out/declared.json" \
    2>/dev/null || true)
  if [ -z "$package" ]; then
    echo "prove: $proof is not among the proofs prove.sh list declared" >&2
    return 1
  fi
  file=$(run_file "$proof")
  mkdir -p "$runs"
  rm -f "${file%.json}.sources"
  before=$(sources)
  # Kani names its coverage output by the minute, so proofs that run at once build apart.
  if [ -n "${PROVE_SLOT:-}" ]; then
    export CARGO_TARGET_DIR=$out/slot-$PROVE_SLOT
  fi
  rm -rf "${CARGO_TARGET_DIR:-target}"/kani/*/kanicov_*
  read_run Cargo.toml "$package" "$proof" "$file"
  if [ "$(sources)" = "$before" ]; then
    printf '%s\n' "$before" >"${file%.json}.sources"
  fi
  git -c core.excludesFile=/dev/null ls-files -z --cached --others --exclude-standard \
    >"${file%.json}.files"
  problems=$(jq -r --rawfile names "${file%.json}.files" \
    "$proof_rules"'.verification_results.results[] | own_problems' "$file")
  if [ -n "$problems" ]; then
    printf 'prove: %s\n' "$problems" >&2
    return 1
  fi
}

# Kani's own results against our reading of the same run: a proof with every outcome, and two of
# ours.
agree() {
  local run manifest package proof file
  for run in "checks/kani-reading/Cargo.toml kani-reading proofs::every_outcome" \
    "Cargo.toml lethewis-core keyset::proofs::a_transition_keeps_the_set_whole" \
    "Cargo.toml lethewis-core slots::proofs::creating_slots_wipes_every_key"; do
    read -r manifest package proof <<<"$run"
    file=$PWD/$out/agree/${proof//::/.}
    mkdir -p "$out/agree"
    rm -f "$file.kani.json"
    cargo kani --manifest-path "$manifest" -p "$package" --harness "$proof" --exact \
      --output-format terse \
      --harness-timeout 10m --coverage -Z source-coverage -Z unstable-options \
      --export-json "$file.kani.json" >&2 || true
    [ -f "$file.kani.json" ] || { echo "prove: Kani gave no results for $proof" >&2; exit 1; }
    read_run "$manifest" "$package" "$proof" "$file.read.json"
    scripts/cbmc-results.py agree "$file.kani.json" "$file.read.json" ||
      { echo "prove: Kani's results and their reading differ for $proof" >&2; exit 1; }
    if [ "$proof" = proofs::every_outcome ]; then
      # Every outcome is there to compare, and a check placed in a file other than its function's.
      outcomes=$(jq -r '[.verification_results.results[0].checks[]
        | "\(.category):\(.status)"] | unique | join(" ")' "$file.kani.json")
      for outcome in assertion:Failure assertion:Success assertion:Unreachable cover:Satisfied \
        cover:Unsatisfiable code_coverage:Covered code_coverage:Uncovered; do
        [[ " $outcomes " == *" $outcome "* ]] ||
          { echo "prove: $proof no longer gives $outcome" >&2; exit 1; }
      done
      grep -q '^\[.*\] file [^ ]* line ' "$file.read.txt" ||
        { echo "prove: $proof no longer gives a check placed in another file" >&2; exit 1; }
    fi
    # A run cut short, or missing a line of results, is refused, not read as far as it goes.
    awk '/^\*\* Results:$/ { at = NR } at && NR > at + 10 { exit } { print }' \
      "$file.read.txt" >"$file.cut.txt"
    awk '/^\*\* Results:$/ { at = NR } !(at && /\.code_coverage\.[0-9]+\] / && !lost++) { print }' \
      "$file.read.txt" >"$file.lost.txt"
    for broken in cut lost; do
      if scripts/cbmc-results.py read "$proof" "$file.$broken.txt" 0 >/dev/null 2>&1; then
        echo "prove: the reading accepts a run with its results $broken" >&2
        exit 1
      fi
    done
  done
  echo "prove: Kani's results and their reading agree"
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

prove_only() {
  local jobs=${LETHEWIS_PROOF_JOBS:-2}
  local memory=${LETHEWIS_PROOF_MEMORY:-$((1 << 40))}
  if (($# == 0)); then
    echo "usage: prove.sh only PROOF..." >&2
    exit 2
  fi
  if ! [[ $jobs =~ ^[1-9][0-9]*$ && $memory =~ ^[1-9][0-9]*$ ]]; then
    echo "prove: LETHEWIS_PROOF_JOBS and LETHEWIS_PROOF_MEMORY are positive numbers" >&2
    exit 2
  fi
  rm -rf "$runs"
  declare_proofs
  local problems
  [ -f "$times" ] || { echo "prove: no $times" >&2; exit 1; }
  problems=$(jq -r --rawfile times "$times" '
    ($times | split("\n") | map(select(length > 0))) as $lines
    | ($lines | map(select(test("^[0-9]+ [0-9]+ [^ ]+$")) | split(" ")[2])) as $timed
    | [.["standard-harnesses"][]?[]] as $declared
    | ($lines[] | select(test("^[0-9]+ [0-9]+ [^ ]+$") | not)
        | "  not <seconds> <megabytes> <proof>: \(.)"),
      ($timed | group_by(.)[] | select(length > 1) | "  twice: \(.[0])"),
      (($declared - $timed)[] | "  no line for: \(.)"),
      (($timed - $declared)[] | "  no such proof: \(.)")' "$out/declared.json")
  if [ -n "$problems" ]; then
    printf 'prove: %s, a line "<seconds> <megabytes> <proof>" for each declared proof:\n%s\n' \
      "$times" "$problems" >&2
    exit 1
  fi
  local listed
  local -a ordered
  listed=$(jq -rn --rawfile times "$times" '
    ($times | split("\n") | map(select(length > 0) | split(" ") | {key: .[2], value: .})
      | from_entries) as $line
    | [$ARGS.positional[] | $line[.] // error("prove: no such proof: \(.)")]
    | sort_by([-(.[0] | tonumber), .[2]])[] | "\(.[1]) \(.[2])"' --args "$@")
  mapfile -t ordered <<<"$listed"
  run_within "$jobs" "$memory" "${ordered[@]}"
}

# Runs the proofs of the lines "<megabytes> <proof>", at most JOBS at once. One starts beside others
# only if their peaks fit in MEMORY megabytes; fails if a proof failed.
run_within() {
  local jobs=$1 memory=$2 failed=0 used=0 index size pid running slot started
  shift 2
  local -a pending=("$@") free=()
  local -A size_of=() slot_of=()
  trap 'trap - INT TERM; kill 0' INT TERM
  for ((slot = 0; slot < jobs; slot++)); do
    free+=("$slot")
  done
  while ((${#pending[@]} + ${#size_of[@]} > 0)); do
    started=0
    for index in "${!pending[@]}"; do
      ((${#free[@]} > 0)) || break
      size=${pending[index]%% *}
      if ((${#size_of[@]} == 0 || used + size <= memory)); then
        PROVE_SLOT=${free[0]} scripts/prove.sh run "${pending[index]#* }" &
        size_of[$!]=$size
        slot_of[$!]=${free[0]}
        free=("${free[@]:1}")
        used=$((used + size))
        unset 'pending[index]'
        started=1
        break
      fi
    done
    if ((started == 0)); then
      # wait -n of bash 5.2 at times returns 127 and names no proof when two end at once.
      pid=
      for running in "${!size_of[@]}"; do
        if ! kill -0 "$running" 2>/dev/null; then
          pid=$running
          break
        fi
      done
      if [ -z "$pid" ]; then
        sleep 1
        continue
      fi
      wait "$pid" || failed=1
      used=$((used - size_of[$pid]))
      free+=("${slot_of[$pid]}")
      unset 'size_of[$pid]' 'slot_of[$pid]'
    fi
  done
  trap - INT TERM
  return "$failed"
}

# What the proofs that ran took replaces their own; a proof that did not run keeps its line.
write_times() {
  local kept="" peaks="" result written
  if ! compgen -G "$runs/*.json" >/dev/null; then
    echo "prove: no results in $runs to take the seconds from" >&2
    exit 1
  fi
  [ ! -f "$times" ] || kept=$(<"$times")
  for result in "$runs"/*.json; do
    if [ -f "${result%.json}.peak" ]; then
      peaks+="$(<"${result%.json}.peak") ${result##*/}"$'\n'
    fi
  done
  declare_proofs
  written=$(jq -rn --arg kept "$kept" --arg peaks "$peaks" \
    --slurpfile declared "$out/declared.json" '
    def name: rtrimstr(".json") | gsub("\\."; "::");
    ($kept | split("\n") | map(select(test("^[0-9]+ [0-9]+ [^ ]+$")) | split(" ")
      | {key: .[2], value: {seconds: .[0], megabytes: .[1]}}) | from_entries) as $before
    | ($peaks | split("\n") | map(select(length > 0) | split(" ")
      | {key: (.[1] | name), value: .[0]}) | from_entries) as $peak
    | ([inputs | {
        key: (input_filename | split("/") | last | name),
        value: (.verification_results.results[0].duration_ms / 1000 | round | tostring)
      }] | from_entries) as $ran
    | [$declared[0]["standard-harnesses"][]?[]] | sort[]
    | ($ran[.] // $before[.].seconds) as $seconds | ($peak[.] // $before[.].megabytes) as $megabytes
    | if $seconds == null or $megabytes == null then "- \(.)" else "\($seconds) \($megabytes) \(.)"
      end' "$runs"/*.json)
  grep -v '^- ' <<<"$written" >"$times" || true
  grep '^- ' <<<"$written" | sed 's/^- /prove: no seconds or no peak, so no line, for /' >&2 || true
}

# Whether the file $1 is in a crate whose proofs this judgement covers: every crate, unless
# LETHEWIS_PROOF_CRATES names some.
judged() {
  local crate
  [ -n "${LETHEWIS_PROOF_CRATES:-}" ] || return 0
  for crate in $LETHEWIS_PROOF_CRATES; do
    [[ $1 == "$crate"/* ]] && return 0
  done
  return 1
}

judge() {
  rm -f "$results" "$out/manifest.json" "$out/files" "$out/asserted"
  if [ ! -f "$out/declared.json" ]; then
    echo "prove: no list of declared proofs; prove.sh list writes it" >&2
    exit 1
  fi
  placed
  git -c core.excludesFile=/dev/null ls-files -z --cached --others --exclude-standard >"$out/files"
  # Every kani::assert( and kani::cover!( in the source must be in the results. Kani does not build
  # checks/, which holds workspaces of its own.
  local file
  while IFS= read -r -d '' file; do
    [[ $file == *.rs && $file != checks/* && -f $file ]] || continue
    judged "$file" || continue
    FILE=$file awk '!/^[[:space:]]*\/\// && /kani::(assert\(|cover!\()/ {
      print ENVIRON["FILE"] ":" NR
    }' <"$file"
  done <"$out/files" >"$out/asserted"

  local files=() split fail ran_version declared ran problems ran_cbmc kept
  if [ -d "$runs" ]; then
    mapfile -d '' files < <(find "$runs" -maxdepth 1 -name '*.json' -print0 | sort -z)
  fi
  # Only results and proof descriptions are merged: a file's summary and time belong to its own run.
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
  ran_cbmc=$(jq -r '.tools.cbmc // "unknown"' "$results" | cut -d' ' -f1)
  if [ "$ran_version $ran_cbmc" != "$KANI_VERSION $CBMC_VERSION" ]; then
    echo "prove: Kani $ran_version with CBMC $ran_cbmc ran, but Kani $KANI_VERSION with CBMC" \
      "$CBMC_VERSION is pinned" >&2
    fail=1
  fi
  kept=$(jq -r --arg crates "${LETHEWIS_PROOF_CRATES:-}" '
    ($crates | split(" ") | map(select(. != ""))) as $only
    | [.["standard-harnesses"] | keys[] | split("/src/")[0]] | unique[]
    | select(. as $crate | $only != [] and (any($only[]; . == $crate) | not))' \
    "$out/declared.json")
  if [ -n "$kept" ] && [ -z "${LETHEWIS_PROOF_BASE:-}" ]; then
    echo "prove: LETHEWIS_PROOF_CRATES leaves out crates, but no LETHEWIS_PROOF_BASE names" \
      "the commit of main they are unchanged since" >&2
    fail=1
  fi

  declared=$(jq -r --arg crates "${LETHEWIS_PROOF_CRATES:-}" '
    ($crates | split(" ") | map(select(. != ""))) as $only
    | .["standard-harnesses"] | to_entries[]
    | select(.key as $file
        | $only == [] or any($only[]; . as $crate | $file | startswith($crate + "/")))
    | .value[]' "$out/declared.json" | sort)
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

  problems=$(jq -r --rawfile names "$out/files" --rawfile asserted "$out/asserted" "$proof_rules"'
    def region: .description | sub("^.*\\$ - "; "");
    def proof_code: (.function // "") | sub("::<(?!impl ).*$"; "") | test("(^|::)proofs::");
    (.verification_results.results[] | own_problems),
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
  ((fail == 0)) || exit 1

  jq --arg target "$(rustc -vV | sed -n 's/^host: //p')" --arg kept "$kept" \
    --arg base "${LETHEWIS_PROOF_BASE:-}" --slurpfile declared "$out/declared.json" '
    ($kept | split("\n") | map(select(. != ""))) as $kept
    | {
    target: $target,
    tools,
    unchanged_since_main: (if $kept == [] then null else {crates: $kept, commit: $base} end),
    proofs: [.verification_results.results[] as $r | {
      proof: $r.harness_id,
      sources: [$declared[0]["standard-harnesses"] | to_entries[]
        | select(.value | index($r.harness_id)) | {file: .key}],
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
  only)
    shift
    prove_only "$@"
    ;;
  judge) judge ;;
  times) write_times ;;
  agree) agree ;;
  sources) sources ;;
  *)
    echo "usage: prove.sh [list | run PROOF | only PROOF... | judge | agree | sources | times]" >&2
    exit 2
    ;;
esac
