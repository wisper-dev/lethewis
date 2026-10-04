#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

"""The lockfile of checks/no-alloc agrees with the main one.

Every package in it, apart from the check itself, appears in the main lockfile with the same
version, source and checksum. In both files, a package comes either from crates.io or from a path,
and a package from a path is a crate of the main workspace, or the check itself in its own file,
built from this repository's own manifest. The two lockfiles are resolved separately, and the
manifests only set lower bounds.
"""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

CHECK = "no-alloc"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def main() -> int:
    root = Path(git("rev-parse", "--show-toplevel"))
    check_manifest = root / "checks" / CHECK / "Cargo.toml"
    main_lock = packages(root / "Cargo.lock")
    check_lock = packages(check_manifest.parent / "Cargo.lock")
    problems: list[str] = []

    # From the lockfiles alone, so the result does not depend on Cargo running.
    both = (("Cargo.lock", main_lock), (f"checks/{CHECK}/Cargo.lock", check_lock))
    for lockfile, entries in both:
        for name, version, source, _ in sorted(entries, key=str):
            if source is not None and source != CRATES_IO:
                problems.append(f"{lockfile} takes {name} {version} from {source}")
    compared = {entry for entry in check_lock if (entry[0], entry[2]) != (CHECK, None)}
    for name, version, source, checksum in sorted(compared - main_lock, key=str):
        problems.append(
            f"checks/{CHECK}/Cargo.lock has {name} {version} ({source or 'path'}, checksum"
            f" {checksum or 'none'}), which Cargo.lock does not; resolve it to the versions in"
            " Cargo.lock"
        )
    if not any(source is not None for _, _, source, _ in compared):
        problems.append(f"checks/{CHECK}/Cargo.lock holds no package from outside the repository")

    try:
        members = path_packages(root / "Cargo.toml", no_deps=True)
        own = {**members, CHECK: str(check_manifest)}
        for lockfile, entries, allowed in (
            ("Cargo.lock", main_lock, set(members)),
            (f"checks/{CHECK}/Cargo.lock", check_lock, set(own)),
        ):
            for name, version, source, _ in sorted(entries, key=str):
                if source is None and name not in allowed:
                    problems.append(f"{lockfile} takes {name} {version} from a path")
        for manifest_of, workspace in ((members, root / "Cargo.toml"), (own, check_manifest)):
            for name, manifest in sorted(path_packages(workspace, no_deps=False).items()):
                expected = manifest_of.get(name)
                if expected is None or Path(manifest).resolve() != Path(expected).resolve():
                    built_by = workspace.relative_to(root)
                    problems.append(f"{built_by} builds {name} from {manifest}, not ours")
    except MetadataFailed as failure:
        problems.append(str(failure))

    for problem in problems:
        print(f"lockfiles-agree: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"lockfiles-agree: {len(compared)} packages match")
    return 0


class MetadataFailed(Exception):
    """Cargo could not read a workspace, so which packages come from a path is unknown."""


def packages(lockfile: Path) -> set[tuple[str, str, str | None, str | None]]:
    entries = tomllib.loads(lockfile.read_text()).get("package", [])
    return {(p["name"], p["version"], p.get("source"), p.get("checksum")) for p in entries}


def path_packages(manifest: Path, no_deps: bool) -> dict[str, str]:
    """Packages built from a path, each with its manifest: the workspace members with `no_deps`."""
    command = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"]
    command += ["--color", "never"]
    command += ["--manifest-path", str(manifest)]
    if no_deps:
        command.append("--no-deps")
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        lines = result.stderr.strip().splitlines() or ["no output"]
        reason = next((line for line in lines if line.startswith("error")), lines[0])
        raise MetadataFailed(f"cargo metadata failed for {manifest}: {reason}")
    return {
        package["name"]: package["manifest_path"]
        for package in json.loads(result.stdout)["packages"]
        if package["source"] is None
    }


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


if __name__ == "__main__":
    sys.exit(main())
