#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

"""The lower bounds in the manifests hold.

On top of the committed lockfile, every direct dependency is set to the lowest version its manifest
allows and nothing else moves; then the review rules must hold and every version in the graph must
have a review record, and only then do the tests build and run. Works on a copy of the files git
tracks or would track, so the committed lockfile is left as it is. Needs the network to fetch the
lower versions.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

LOWER_BOUND = re.compile(r"\^(\d+)\.(\d+)\.(\d+)")


def main() -> int:
    root = Path(run("git", "rev-parse", "--show-toplevel", cwd=Path.cwd()).strip())
    if subprocess.run([str(root / "scripts" / "supply-chain-rules.py")], cwd=root).returncode != 0:
        print("minimal-versions: the review rules do not hold", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as work:
        repo = Path(work) / "repo"
        files = run("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", cwd=root)
        for name in filter(None, files.split("\0")):
            if not (root / name).exists() and not (root / name).is_symlink():
                continue
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / name, target, follow_symlinks=False)
        # A cargo home of its own, so the lower versions are downloaded here rather than into the
        # shared cache.
        os.environ["CARGO_HOME"] = str(Path(work) / "cargo-home")

        metadata = json.loads(
            run("cargo", "metadata", "--format-version", "1", "--locked", "--all-features",
                cwd=repo)
        )
        by_id = {package["id"]: package for package in metadata["packages"]}
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        # One update per locked package; every crate of the workspace declares the same bound.
        targets: dict[tuple[str, str], tuple[int, int, int]] = {}
        for member_id in metadata["workspace_members"]:
            resolved = [by_id[dep["pkg"]] for dep in nodes[member_id]["deps"]]
            for dependency in by_id[member_id]["dependencies"]:
                if dependency["source"] is None:
                    continue
                bound = LOWER_BOUND.fullmatch(dependency["req"])
                if bound is None:
                    print(
                        f"minimal-versions: {dependency['name']} requires '{dependency['req']}';"
                        " a lower bound is written as ^x.y.z",
                        file=sys.stderr,
                    )
                    return 1
                lowest = tuple(int(part) for part in bound.groups())
                current = [
                    package["version"]
                    for package in resolved
                    if package["name"] == dependency["name"]
                    and compatible(lowest, version_of(package["version"]))
                ]
                if len(current) != 1:
                    print(
                        f"minimal-versions: no single locked version of {dependency['name']}"
                        f" matches '{dependency['req']}': {current}",
                        file=sys.stderr,
                    )
                    return 1
                key = (dependency["name"], current[0])
                if targets.get(key, lowest) != lowest:
                    print(
                        f"minimal-versions: {dependency['name']} has two lower bounds,"
                        f" {'.'.join(map(str, targets[key]))} and {'.'.join(map(str, lowest))};"
                        " every crate of the workspace writes the same one",
                        file=sys.stderr,
                    )
                    return 1
                targets[key] = lowest
        for (name, version), lowest in sorted(targets.items()):
            run(
                "cargo", "update", "--package", f"{name}@{version}",
                "--precise", ".".join(map(str, lowest)), cwd=repo,
            )

        for command in (
            ["cargo", "vet", "--locked", "--store-path", "supply-chain",
             "--cache-dir", str(Path(work) / "vet-cache")],
            ["cargo", "test", "--workspace", "--all-features", "--locked"],
        ):
            if subprocess.run(command, cwd=repo, check=False).returncode != 0:
                print(f"minimal-versions: {' '.join(command[:2])} failed", file=sys.stderr)
                return 1
    return 0


def version_of(text: str) -> tuple[int, int, int]:
    core = text.split("+", 1)[0].split("-", 1)[0]
    major, minor, patch = (int(part) for part in core.split("."))
    return major, minor, patch


def compatible(lowest: tuple[int, int, int], version: tuple[int, int, int]) -> bool:
    """Whether a caret requirement at `lowest` admits `version`."""
    if version < lowest:
        return False
    if lowest[0] != 0:
        return version[0] == lowest[0]
    if lowest[1] != 0:
        return version[:2] == lowest[:2]
    return version == lowest


def run(*command: str, cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"minimal-versions: {' '.join(command)} failed")
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
