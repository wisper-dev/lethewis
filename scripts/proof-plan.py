#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

"""Which proofs a pull request must run, and in how many parts, each within the budget.

`main` is proven whole: a branch merges only up to date and with every proof holding. Kani builds
the crate of a proof and what it reaches in Cargo.lock, nothing else. The proofs of a crate run when
the changes since BASE, a commit of main, touch any of their inputs: a file of a crate it reaches, a
locked package those crates use, a manifest other than in its lints, Markdown that code names, or
anything that is neither a crate's file nor known to leave the proofs alone, the toolchain, Kani and
these scripts included. Their proofs then go, longest first, to the part with the fewest seconds so
far, into as few parts as keep the slowest part within the budget on a runner slower than the one
that recorded the times.

Every plan also checks that docs/proofs.md states the pinned Kani and CBMC.

Usage:
  proof-plan.py plan BASE   prints crates=, base= and parts= lines for $GITHUB_OUTPUT
  proof-plan.py all         the same for every proof, with no base
  proof-plan.py test        runs the planner's own cases on repositories it makes
"""

import heapq
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath

# A part's job may run 15 minutes.
BUDGET = 900
# Measured on 2026-11-05: 32 s to set up and install Kani, 55 s to build, before the first proof.
OVERHEAD = 90
MARGIN = 60
# The slowest of ten parts on 2026-11-05 took 1.25 times the seconds scripts/proof-times records.
SLOW = 1.4
LIMIT = (BUDGET - OVERHEAD - MARGIN) / SLOW
# As the proof job runs them: two at once, and one beside others only if their peaks fit.
JOBS = int(os.environ.get("LETHEWIS_PROOF_JOBS", "2"))
MEMORY = int(os.environ.get("LETHEWIS_PROOF_MEMORY", "13000"))

# Files no proof reads: documents, the Java layer, and checks and scripts that do not build or run
# the proofs.
IGNORED_PREFIXES = ("docs/", "supply-chain/", "android/", "checks/no-alloc/", "LICENSES/")
IGNORED_FILES = {
    ".cargo/mutants.toml", ".github/workflows/release.yml", "_typos.toml", "clippy.toml",
    "deny.toml", "LICENSE", "rustfmt.toml", "scripts/android-env.sh", "scripts/android-sdk.sh",
    "scripts/android.sh", "scripts/constant-time.py", "scripts/lockfiles-agree.py",
    "scripts/minimal-versions.py", "scripts/on-emulator.sh", "scripts/proof-times",
    "scripts/random-tests.sh", "scripts/supply-chain-rules.py", "scripts/text-only.sh",
}
# Code that names a Markdown file reads it, but this planner, which checks the register itself.
CODE = ("*.rs", "*.sh", "*.py", ":!scripts/proof-plan.py")
REGISTER = "docs/proofs.md"
PIN = "scripts/kani-pin.sh"
WORKFLOW = ".github/workflows/ci.yml"
# What of the workflow the proofs depend on: its settings for every job, and the jobs of the proofs.
PROOF_JOBS = ("proof-plan", "proof-parts", "proofs")
ANCHOR = re.compile(r"(?m)(?::|^\s*-)\s+&[\w-]+(?:\s|$)|<<:")


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True,
                          check=True).stdout


def shown(root: Path, base: str, path: str) -> str | None:
    done = subprocess.run(["git", "show", f"{base}:{path}"], cwd=root, capture_output=True,
                          text=True)
    return done.stdout if done.returncode == 0 else None


def members(root: Path) -> dict[str, str]:
    """The workspace's crates, by name, with their directories."""
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    found = {}
    for directory in manifest["workspace"]["members"]:
        package = tomllib.loads((root / directory / "Cargo.toml").read_text())["package"]
        found[package["name"]] = directory
    return found


def crate_of(path: str, names: dict[str, str]) -> str | None:
    """The crate whose directory holds `path`, the innermost one if they nest."""
    holding = [name for name, directory in names.items() if path.startswith(directory + "/")]
    return max(holding, key=lambda name: len(names[name]), default=None)


def named(root: Path, path: str) -> bool:
    """Whether code at HEAD names the file, as scripts/text-only.sh asks."""
    done = subprocess.run(["git", "grep", "-qF", "-e", PurePosixPath(path).name, "HEAD", "--",
                           *CODE], cwd=root, capture_output=True, text=True)
    if done.returncode not in (0, 1):
        raise SystemExit(f"proof-plan: git grep failed: {done.stderr.strip()}")
    return done.returncode == 0


def locked(text: str | None, name: str) -> frozenset | None:
    """The packages of Cargo.lock that `name` reaches, as resolved: a dependency by its name and
    version, however the lock happens to write it. None when the lock or `name` is not there."""
    if text is None:
        return None
    by_name: dict[str, list[dict]] = {}
    for package in tomllib.loads(text).get("package", []):
        by_name.setdefault(package["name"], []).append(package)
    if name not in by_name:
        return None

    def find(reference: str) -> dict:
        parts = reference.split(" ")
        candidates = [p for p in by_name.get(parts[0], [])
                      if len(parts) == 1 or p["version"] == parts[1]]
        if len(candidates) != 1:
            raise SystemExit(f"proof-plan: Cargo.lock names {reference!r} {len(candidates)} times")
        return candidates[0]

    def key(package: dict) -> str:
        return f"{package['name']} {package['version']}"

    seen: dict[str, tuple] = {}
    pending = [find(name)]
    while pending:
        package = pending.pop()
        if key(package) not in seen:
            dependencies = [find(reference) for reference in package.get("dependencies", [])]
            seen[key(package)] = (key(package), package.get("source"), package.get("checksum"),
                                  tuple(sorted(key(d) for d in dependencies)))
            pending += dependencies
    return frozenset(seen.values())


def reached(text: str, name: str, names: dict[str, str]) -> set[str] | None:
    """The workspace crates `name` reaches in Cargo.lock, itself included, of any kind of
    dependency: a package without a source is a crate of this repository. None when the lock
    lacks `name`."""
    packages = locked(text, name)
    if packages is None:
        return None
    return {key.split(" ")[0] for key, source, _, _ in packages
            if source is None and key.split(" ")[0] in names}


def without_lints(text: str | None) -> dict | None:
    if text is None:
        return None
    manifest = tomllib.loads(text)
    manifest.pop("lints", None)
    manifest.get("workspace", {}).pop("lints", None)
    return manifest


def proof_workflow(text: str | None) -> str | None:
    """The top-level settings of the workflow and its proof jobs; all of it if a job is missing or
    if an anchor lets one job take text from another."""
    if text is None or ANCHOR.search(text):
        return text
    kept, jobs, current = [], {}, None
    for line in text.splitlines():
        if line and not line.startswith(" "):
            current = None if line.startswith("jobs:") else "top"
        elif current != "top" and line.startswith("  ") and not line.startswith("   ") \
                and line.rstrip().endswith(":"):
            current = line.strip().rstrip(":")
        if current == "top":
            kept.append(line)
        elif current is not None:
            jobs.setdefault(current, []).append(line)
    if not all(job in jobs for job in PROOF_JOBS):
        return text
    return "\n".join(kept + [line for job in PROOF_JOBS for line in jobs[job]])


def proof_crates(root: Path, names: dict[str, str]) -> dict[str, list[Path]]:
    """The crates that hold proofs, with the files that do."""
    found = {}
    for name, directory in names.items():
        files = sorted(path for path in (root / directory / "src").rglob("*.rs")
                       if "kani::proof" in path.read_text())
        if files:
            found[name] = files
    return found


def touched(root: Path, base: str) -> set[str] | None:
    """The crates with proofs whose inputs the changes since `base` touch; None for all of them."""
    names = members(root)
    proving = proof_crates(root, names)
    lock = (root / "Cargo.lock").read_text()
    reaching = {name: reached(lock, name, names) for name in proving}
    if any(crates is None for crates in reaching.values()):
        return None
    changed: set[str] = set()
    # A file moved shows as removed and added, so both places count.
    for path in git(root, "diff", "--name-only", "--no-renames", f"{base}...HEAD").splitlines():
        if path.endswith(".md"):
            if not named(root, path):
                continue
        elif path.startswith(IGNORED_PREFIXES) or path in IGNORED_FILES:
            continue
        if path == "Cargo.lock":
            before, after = shown(root, base, path), (root / path).read_text()
            changed |= {name for name in proving if locked(before, name) != locked(after, name)}
            continue
        if path == WORKFLOW:
            after = (root / path).read_text() if (root / path).exists() else None
            if proof_workflow(shown(root, base, path)) == proof_workflow(after):
                continue
        if PurePosixPath(path).name == "Cargo.toml":
            after = (root / path).read_text() if (root / path).exists() else None
            if without_lints(shown(root, base, path)) == without_lints(after):
                continue
        crate = crate_of(path, names)
        if crate is None:
            return None
        changed.add(crate)
    return {name for name in proving if reaching[name] & changed}


def owners(root: Path, times: list[tuple[int, int, str]]) -> dict[str, str]:
    """The crate of each proof scripts/proof-times names, found by its function."""
    names = members(root)
    proving = proof_crates(root, names)
    found = {}
    for _, _, proof in times:
        function = re.compile(rf"\bfn {re.escape(proof.rsplit('::', 1)[-1])}\b")
        crates = [name for name, files in proving.items()
                  if any(function.search(path.read_text()) for path in files)]
        if len(crates) != 1:
            raise SystemExit(f"proof-plan: {proof} is defined in {len(crates)} crates")
        found[proof] = crates[0]
    return found


def makespan(part: list[tuple[int, int, str]]) -> int:
    """How long the proofs of a part take as the proof job runs them, in recorded seconds."""
    pending, running, now, used = list(part), [], 0, 0
    while pending or running:
        index = next((i for i, (_, megabytes, _) in enumerate(pending)
                      if len(running) < JOBS and (not running or used + megabytes <= MEMORY)),
                     None)
        if index is None:
            now, megabytes = heapq.heappop(running)
            used -= megabytes
        else:
            seconds, megabytes, _ = pending.pop(index)
            heapq.heappush(running, (now + seconds, megabytes))
            used += megabytes
    return now


def split(proofs: list[tuple[int, int, str]], count: int) -> list[list[tuple[int, int, str]]]:
    parts: list[list[tuple[int, int, str]]] = [[] for _ in range(count)]
    seconds = [0] * count
    for proof in sorted(proofs, key=lambda p: (-p[0], p[2])):
        least = min(range(count), key=lambda k: (seconds[k], k))
        parts[least].append(proof)
        seconds[least] += proof[0]
    return parts


def partition(proofs: list[tuple[int, int, str]]) -> list[list[tuple[int, int, str]]]:
    """The fewest parts whose slowest stays within the limit."""
    if not proofs:
        return []
    longest = max(proofs)
    if longest[0] > LIMIT:
        raise SystemExit(f"proof-plan: {longest[2]} takes {longest[0]} s, alone past the"
                         f" {LIMIT:.0f} s a part may take; make it cheaper")
    count = max(1, math.ceil(sum(p[0] for p in proofs) / JOBS / LIMIT))
    while max(makespan(part) for part in split(proofs, count)) > LIMIT:
        count += 1
    return split(proofs, count)


def stated(root: Path) -> None:
    """Refuses the register unless it names the pinned Kani and CBMC, and no other version."""
    pin = dict(re.findall(r"(?m)^export (KANI|CBMC)_VERSION=(\S+)$", (root / PIN).read_text()))
    pinned = {f"Kani {pin.get('KANI')}", f"CBMC {pin.get('CBMC')}"}
    found = set(re.findall(r"(?:Kani|CBMC) v?[0-9][0-9.]*[0-9]", (root / REGISTER).read_text()))
    if found != pinned:
        raise SystemExit(f"proof-plan: {REGISTER} names {sorted(found)}, but {PIN} pins"
                         f" {sorted(pinned)}")


def read_times(root: Path) -> list[tuple[int, int, str]]:
    times = []
    for line in (root / "scripts/proof-times").read_text().splitlines():
        seconds, megabytes, proof = line.split(" ")
        times.append((int(seconds), int(megabytes), proof))
    return times


def plan(root: Path, base: str | None) -> list[str]:
    """The plan for the changes since `base`, or for every proof without one."""
    stated(root)
    commit = "" if base is None else git(root, "rev-parse", base).strip()
    crates = None if base is None else touched(root, base)
    names = members(root)
    running = set(proof_crates(root, names)) if crates is None else crates
    times = read_times(root)
    owner = owners(root, times)
    parts = partition([t for t in times if owner[t[2]] in running])
    entries = [{"part": number, "of": len(parts), "proofs": " ".join(sorted(p[2] for p in part))}
               for number, part in enumerate(parts, 1)]
    return [f"crates={' '.join(sorted(names[c] for c in running))}", f"base={commit}",
            f"parts={json.dumps(entries)}"]


def test() -> None:
    """The planner's cases on a workspace of three crates: a proves, b is under a, c is apart."""
    def write(root: Path, files: dict[str, str | None]) -> None:
        for name, text in files.items():
            if text is None:
                (root / name).unlink()
                continue
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)

    def commit(root: Path, message: str) -> None:
        git(root, "add", "-A")
        git(root, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
            "-c", "core.hooksPath=/dev/null", "commit", "-qm", message)

    def crate(name: str, deps: str = "") -> str:
        return f'[package]\nname = "{name}"\n[lints]\nrust = {{}}\n[dependencies]\n{deps}'

    lock = ('[[package]]\nname = "a"\nversion = "0.1.0"\ndependencies = ["b", "x"]\n'
            '[[package]]\nname = "b"\nversion = "0.1.0"\n[[package]]\nname = "c"\nversion = "0.1.0"\n'
            'dependencies = ["y"]\n[[package]]\nname = "x"\nversion = "1.0.0"\n'
            'source = "registry+https://example.org"\n[[package]]\nname = "y"\nversion = "1.0.0"\n'
            'source = "registry+https://example.org"\n')
    workspace = ('[workspace]\nmembers = ["crates/a", "crates/b", "crates/c"]\n'
                 '[workspace.dependencies]\nb = { path = "crates/b" }\n'
                 '[workspace.lints.rust]\n[profile.release]\nlto = true\n')
    start = {
        "Cargo.toml": workspace,
        "Cargo.lock": lock,
        "crates/a/Cargo.toml": crate("a", 'b = { workspace = true }\nx = "1"\n'),
        "crates/a/src/lib.rs": "#[kani::proof]\nfn a_holds() {}\nconst N: &str = \"notes.md\";\n",
        "crates/a/src/more.rs": "#[kani::proof]\nfn a_also_holds() {}\n",
        "crates/b/Cargo.toml": crate("b"),
        "crates/b/src/lib.rs": "",
        "crates/c/Cargo.toml": crate("c", 'y = "1"\n'),
        "crates/c/src/lib.rs": "",
        "scripts/prove.sh": "",
        "scripts/proof-plan.py": "proofs.md\n",
        PIN: "export KANI_VERSION=1.0.0\nexport CBMC_VERSION=2.0.0\n",
        REGISTER: "Kani 1.0.0, CBMC 2.0.0\n",
        WORKFLOW: "on: pull_request\nenv:\n  A: 1\njobs:\n  build:\n    steps:\n      - run: build\n"
                  "  proof-plan:\n    steps:\n      - run: plan\n  proof-parts:\n    steps:\n"
                  "      - run: prove\n  proofs:\n    steps:\n      - run: judge\n",
        "scripts/proof-times": "10 100 a_holds\n",
    }
    anchored = start[WORKFLOW].replace("- run: build", "- &shared\n        run: build").replace(
        "- run: prove", "- *shared")
    cases = [
        ("a file of a crate apart", {"crates/c/src/lib.rs": "fn c() {}\n"}, set()),
        ("a file of the crate itself", {"crates/a/src/lib.rs": "#[kani::proof]\nfn a_holds() {}\n"
                                        "fn more() {}\n"}, {"a"}),
        ("a file of a crate under it, by the workspace's path",
         {"crates/b/src/lib.rs": "fn b() {}\n"}, {"a"}),
        ("a file moved out of the crate", {"crates/a/src/more.rs": None,
                                           "docs/more.rs": start["crates/a/src/more.rs"]}, {"a"}),
        ("a document", {"crates/a/README.md": "words\n", "docs/x.md": "words\n"}, set()),
        ("a document a crate reads", {"crates/a/notes.md": "words\n"}, {"a"}),
        ("a document a script reads", {"docs/notes.md": "words\n",
                                       "scripts/prove.sh": "cat docs/notes.md\n"}, None),
        ("the register, which every plan checks", {REGISTER: "Kani 1.0.0, CBMC 2.0.0, more\n"},
         set()),
        ("the lints of the workspace", {"Cargo.toml": workspace.replace(
            "[workspace.lints.rust]\n", "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n")}, set()),
        ("a profile of the workspace", {"Cargo.toml": workspace.replace(
            "lto = true", "lto = false")}, None),
        ("the lints of a crate under it", {"crates/b/Cargo.toml": crate("b").replace(
            "rust = {}", 'rust = { unsafe_code = "deny" }')}, set()),
        ("a dependency of a crate under it", {"crates/b/Cargo.toml": crate("b", 'z = "1"\n')},
         {"a"}),
        ("a locked package of a crate apart", {"Cargo.lock": lock.replace(
            'name = "y"\nversion = "1.0.0"', 'name = "y"\nversion = "1.0.1"')}, set()),
        ("a second version of a package apart", {"Cargo.lock": lock.replace(
            'dependencies = ["b", "x"]', 'dependencies = ["b", "x 1.0.0"]').replace(
            'dependencies = ["y"]', 'dependencies = ["x 2.0.0", "y"]')
            + '[[package]]\nname = "x"\nversion = "2.0.0"\n'
            'source = "registry+https://example.org"\n'},
         set()),
        ("a lock without the crate", {"Cargo.lock": lock.replace(
            'name = "a"\nversion = "0.1.0"\ndependencies = ["b", "x"]\n', 'name = "q"\n'
            'version = "0.1.0"\n')}, None),
        ("a locked package the crate uses", {"Cargo.lock": lock.replace(
            'name = "x"\nversion = "1.0.0"', 'name = "x"\nversion = "1.0.1"')}, {"a"}),
        ("a proof script", {"scripts/prove.sh": "changed\n"}, None),
        ("a job of the workflow beside the proofs", {WORKFLOW: start[WORKFLOW].replace(
            "run: build", "run: build twice")}, set()),
        ("a job of the proofs", {WORKFLOW: start[WORKFLOW].replace(
            "run: prove", "run: prove twice")}, None),
        ("the settings of every job", {WORKFLOW: start[WORKFLOW].replace("A: 1", "A: 2")}, None),
        ("a job beside the proofs whose anchor a proof job takes", [{WORKFLOW: anchored}, {
            WORKFLOW: anchored.replace("run: build", "run: build twice")}], None),
        ("a file nobody listed", {"rust-toolchain.toml": "[toolchain]\n"}, None),
        ("a file no proof reads", {"scripts/android.sh": "changed\n", "android/A.java": "x\n"},
         set()),
        ("a file of a crate within a crate under it", [{
            "Cargo.toml": workspace.replace('"crates/c"]', '"crates/c", "crates/b/inner"]'),
            "crates/b/inner/Cargo.toml": crate("inner"), "crates/b/inner/src/lib.rs": "",
            "Cargo.lock": lock + '[[package]]\nname = "inner"\nversion = "0.1.0"\n'},
            {"crates/b/inner/src/lib.rs": "fn inner() {}\n"}], set()),
    ]
    failed = []

    Edits = dict[str, str | None]

    def made(edits: Edits | list[Edits]) -> tempfile.TemporaryDirectory:
        """A repository of `start` and a commit of each of `edits`; the plan takes the last."""
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        write(root, start)
        git(root, "init", "-q", "-b", "main")
        commit(root, "start")
        for edit in edits if isinstance(edits, list) else [edits]:
            write(root, edit)
            commit(root, "change")
        return directory

    for name, edits, expected in cases:
        with made(edits) as directory:
            got = touched(Path(directory), "main~1")
            if got != expected:
                failed.append(f"{name}: {got} rather than {expected}")
    more = start["crates/a/src/lib.rs"] + "fn more() {}\n"
    with made({"crates/a/src/lib.rs": more}) as directory:
        root = Path(directory)
        part = '[{"part": 1, "of": 1, "proofs": "a_holds"}]'
        if plan(root, "main~1")[0::2] != ["crates=crates/a", f"parts={part}"]:
            failed.append(f"plan: {plan(root, 'main~1')}")
        if plan(root, None) != ["crates=crates/a", "base=", f"parts={part}"]:
            failed.append(f"plan of every proof: {plan(root, None)}")
        write(root, {"scripts/proof-times": ""})
        if plan(root, None)[0::2] != ["crates=crates/a", "parts=[]"]:
            failed.append("plan: a crate without times left out of every proof")
        write(root, {REGISTER: "Kani 1.0.1, CBMC 2.0.0\n"})
        try:
            plan(root, None)
            failed.append("plan: a register naming another Kani was accepted")
        except SystemExit:
            pass
        write(root, {REGISTER: start[REGISTER], "crates/c/src/lib.rs": "fn a_holds() {}\n"
                     "#[kani::proof]\nfn c_holds() {}\n"})
        try:
            owners(root, [(10, 100, "a_holds")])
            failed.append("owners: a proof named in two crates was given one")
        except SystemExit:
            pass
    if locked(None, "a") is not None or locked(lock, "q") is not None:
        failed.append("locked: a lock or a crate missing gave packages")
    small = [(100, 1000, f"p{i}") for i in range(30)]
    parts, fewer = partition(small), split(small, 2)
    if len(parts) != 3 or max(makespan(part) for part in parts) > LIMIT or max(
            makespan(part) for part in fewer) <= LIMIT:
        failed.append(f"partition: {len(parts)} parts are not the fewest within the limit")
    # Too large to run beside each other: more parts than the seconds alone ask for.
    large = [(300, 8000, f"q{i}") for i in range(4)]
    if len(partition(large)) != 4:
        failed.append(f"partition: {len(partition(large))} parts of proofs that run one at a time")
    if makespan([(100, 8000, "a"), (100, 8000, "b")]) != 200:
        failed.append("makespan: two proofs whose peaks do not fit together ran at once")
    if makespan([(100, 1000, "a"), (100, 1000, "b"), (100, 1000, "c")]) != 200:
        failed.append("makespan: more than two proofs ran at once, or fewer")
    try:
        partition([(int(LIMIT) + 1, 1000, "long")])
        failed.append("partition: a proof longer than a part may take was accepted")
    except SystemExit:
        pass
    if failed:
        raise SystemExit("proof-plan: " + "\n".join(failed))
    print(f"proof-plan: {len(cases) + 10} cases hold")


def main() -> None:
    if sys.argv[1:] == ["test"]:
        test()
    elif sys.argv[1:2] == ["plan"] and len(sys.argv) == 3 or sys.argv[1:] == ["all"]:
        print("\n".join(plan(Path(git(Path.cwd(), "rev-parse", "--show-toplevel").strip()),
                             sys.argv[2] if len(sys.argv) == 3 else None)))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
