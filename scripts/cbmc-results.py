#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

"""Reads what one proof printed under `cargo kani --output-format old` into the results Kani gives
with `--export-json`, for scripts/prove.sh to judge, and compares the two.

    cbmc-results.py read PROOF OUTPUT MILLISECONDS > results.json
    cbmc-results.py agree KANI.json READ.json

With --export-json, Kani has CBMC build a trace for every region coverage reaches, which costs
most of the run. The statuses are read here as Kani reads them: a check whose reachability check
holds is unreachable, a cover that fails is satisfied, and a coverage check that fails is covered.
Anything not read in full is a refusal.
"""

import collections
import json
import re
import sys

STATUS = r"(?P<status>SUCCESS|FAILURE|UNKNOWN|ERROR)$"
PROPERTY = re.compile(
    r"\[(?P<id>(?P<function>.*?)\.(?P<class>[a-z][a-z_-]*)\.\d+)\] "
    r"(?:file (?P<file>\S+) )?(?:line (?P<line>\d+) )?(?P<description>.*): " + STATUS,
    re.S,
)
GROUP = re.compile(r"(?:(?P<file>\S+) )?function (?P<function>.+)")
CHECK_ID = re.compile(r"\[(KANI_CHECK_ID_[^\]]+)\] (.*)", re.S)
PLAIN = {"SUCCESS": "Success", "FAILURE": "Failure", "UNKNOWN": "Undetermined"}
COVER = {"SUCCESS": "Unsatisfiable", "FAILURE": "Satisfied", "UNKNOWN": "Undetermined"}
COVERAGE = {"SUCCESS": "Uncovered", "FAILURE": "Covered"}
UNREPORTED = {"sanity_check", "pointer_arithmetic", "pointer_primitives"}
# The checks whose descriptions the judge reads; of the others CBMC and Kani word some differently.
DESCRIBED = {"assertion", "cover", "code_coverage"}


def refuse(reason: str) -> None:
    sys.exit(f"cbmc-results: {reason}")


def one(pattern: str, text: str) -> re.Match[str]:
    found = list(re.finditer(pattern, text, re.M))
    if len(found) != 1:
        refuse(f"{len(found)} lines match {pattern!r}, one expected")
    return found[0]


def properties(text: str) -> list[dict[str, str]]:
    """Every property the results list, each with the file and function of its group."""
    start = one(r"^\*\* Results:$", text).end()
    summary = one(r"^\*\* (\d+) of (\d+) failed \(\d+ iterations?\)$", text)
    one(r"^VERIFICATION (FAILED|SUCCESSFUL)$", text[summary.end():])
    found, group, record = [], None, ""
    for line in text[start:summary.start()].strip("\n").split("\n"):
        if record:
            record += "\n" + line
        elif line.startswith("["):
            record = line
        elif not line:
            group = None
            continue
        else:
            match = GROUP.fullmatch(line)
            if match is None or group is not None:
                refuse(f"not a group of properties: {line!r}")
            group = match
            continue
        match = PROPERTY.fullmatch(record)
        if match is None:
            if group is None and re.match(r"\[[a-z][a-z_-]*\.\d+\] ", record):
                refuse(f"a check without a place in the code, which the judge refuses: {record!r}")
            if re.search(r": " + STATUS, record):
                refuse(f"not a property: {record!r}")
            continue
        record = ""
        if group is None or match["function"] != group["function"]:
            refuse(f"a property outside the group of its function: {match['id']}")
        found.append({**match.groupdict(), "file": match["file"] or group["file"] or ""})
    if record:
        refuse(f"a property without a status: {record!r}")
    failed, total = int(summary[1]), int(summary[2])
    if len(found) != total or sum(p["status"] == "FAILURE" for p in found) != failed:
        refuse(f"{len(found)} properties read, the summary counts {total} with {failed} failed")
    if len({p["id"] for p in found}) != len(found):
        refuse("a property is listed twice")
    return found


def checks(found: list[dict[str, str]]) -> list[dict[str, object]]:
    """The checks Kani reports, with the statuses it gives them."""
    reach = {p["description"]: p["status"] for p in found if p["class"] == "reachability_check"}
    if len(reach) != sum(p["class"] == "reachability_check" for p in found):
        refuse("two reachability checks share an identifier")
    used, out = set(), []
    for p in found:
        if p["status"] == "ERROR":
            refuse(f"{p['id']} ended in an error")
        if p["class"] == "reachability_check":
            continue
        # Kani leaves these out; one that does not hold still fails the proof here.
        if p["class"] in UNREPORTED and p["status"] == "SUCCESS":
            continue
        description, unreachable = p["description"], False
        tagged = CHECK_ID.fullmatch(description)
        if tagged:
            if tagged[1] not in reach:
                refuse(f"{p['id']} names a reachability check that is not there")
            used.add(tagged[1])
            description, unreachable = tagged[2], reach[tagged[1]] == "SUCCESS"
        if p["class"] == "code_coverage":
            if tagged or p["status"] not in COVERAGE:
                refuse(f"a coverage check that Kani does not give: {p['id']}")
            status = COVERAGE[p["status"]]
        elif unreachable:
            # Both have one guard: a check never reached cannot fail, and Kani stops if it does.
            if p["status"] != "SUCCESS":
                refuse(f"{p['id']} is unreachable and yet {p['status']}")
            status = "Unreachable"
        else:
            status = (COVER if p["class"] == "cover" else PLAIN)[p["status"]]
        out.append({
            "id": len(out) + 1,
            "function": p["function"],
            "status": status,
            "description": description,
            "location": {"file": p["file"], "line": p["line"]} if p["line"] else {"file": p["file"]},
            "category": p["class"],
        })
    if used != set(reach):
        refuse(f"reachability checks with no check: {sorted(set(reach) - used)}")
    return out


def read(proof: str, output: str, milliseconds: int) -> None:
    with open(output, encoding="utf-8") as file:
        text = file.read()
    kani = one(r"^Kani Rust Verifier (\S+) \(cargo plugin\)$", text)[1]
    cbmc = one(r"^CBMC version (\S+ \(cbmc-[^)]+\))", text)[1]
    if one(r"^Checking harness (.+)\.\.\.$", text)[1] != proof:
        refuse(f"the output is not of {proof}")
    found = checks(properties(text))
    failed = any(c["status"] in ("Failure", "Undetermined") and c["category"] != "cover"
                 for c in found)
    json.dump({
        "metadata": {"kani_version": kani},
        "project": {},
        "tools": {"kani": kani, "cbmc": cbmc},
        "harness_metadata": [],
        "verification_results": {"results": [{
            "harness_id": proof,
            "status": "Failure" if failed else "Success",
            "duration_ms": milliseconds,
            "checks": found,
        }]},
    }, sys.stdout, indent=1)


def outcome(path: str) -> tuple[str, collections.Counter[tuple[str, ...]]]:
    with open(path, encoding="utf-8") as file:
        results = json.load(file)["verification_results"]["results"]
    if len(results) != 1:
        refuse(f"{path} holds {len(results)} proofs, one expected")
    rows = collections.Counter(
        (c["category"], c["status"], c["description"] if c["category"] in DESCRIBED else "",
         c["location"].get("file", ""), str(c["location"].get("line")), c.get("function", ""))
        for c in results[0]["checks"])
    return results[0]["status"], rows


def agree(kani_json: str, read_json: str) -> None:
    (kani_status, kani_rows), (read_status, read_rows) = outcome(kani_json), outcome(read_json)
    differences = [f"proof {kani_status} by Kani, {read_status} as read"] * (kani_status != read_status)
    differences += [f"only Kani: {row}" for row in (kani_rows - read_rows)]
    differences += [f"only read: {row}" for row in (read_rows - kani_rows)]
    if differences:
        refuse("Kani's results and the reading differ:\n" + "\n".join(differences[:20]))


if __name__ == "__main__":
    match sys.argv[1:]:
        case ["read", proof, output, milliseconds]:
            read(proof, output, int(milliseconds))
        case ["agree", kani, read_json]:
            agree(kani, read_json)
        case _:
            refuse("usage: cbmc-results.py read PROOF OUTPUT MILLISECONDS | agree KANI READ")
