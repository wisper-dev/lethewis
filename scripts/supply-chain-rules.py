#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

"""What cargo-vet and Cargo allow but this repository does not.

Only what is listed here may appear in the store: a review of our own is the only thing that counts,
never an exemption, an imported review or a trusted publisher; every crate of the workspace asks for
a reading in full, and every locked version of a crate that handles secrets has a record of one.
Nothing in the tree changes where dependencies or the compiler come from, or where cargo-vet looks
for its store. Every crate of the workspace inherits its lints, but the one crate allowed unsafe
code, whose own lints differ from them only there.
"""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

STORE_FILES = ("audits.toml", "config.toml", "imports.lock")
SPDX = ("SPDX-FileCopyrightText:", "SPDX-License-Identifier:")
OWN_CRITERION = "read-in-full"
CONFIG_TABLES = {"cargo-vet", "policy"}
AUDITS_TABLES = {"criteria", "audits"}
MEMBER_POLICY_KEYS = {"criteria", "dev-criteria", "dependency-criteria", "notes"}
THIRD_PARTY_POLICY_KEYS = {"dependency-criteria", "notes"}
AUDIT_KEYS = {"who", "criteria", "version", "delta", "notes", "violation"}
LOWERED = "safe-to-deploy"
DEPENDENCY_CRITERIA = {LOWERED, OWN_CRITERION}
TESTS_ONLY = "safe-to-run"
MEMBER_PREFIX = "lethewis-"
TOOLCHAIN_KEYS = {"channel", "components", "targets", "profile"}
UNSAFE_CRATE = "lethewis-dit"
UNSAFE_LINTS = {
    "rust": {"unsafe_code": "deny", "unsafe_op_in_unsafe_fn": "deny"},
    "clippy": {"multiple_unsafe_ops_per_block": "deny"},
}
# Crates that handle key material: every locked version read in full, never lowered in a policy.
HANDLE_SECRETS = {
    "aead", "aes", "aes-gcm-siv", "block-buffer", "cipher", "cmov", "ctr", "ctutils", "digest",
    "hkdf", "hmac", "hybrid-array", "inout", "polyval", "sha2", "universal-hash", "zeroize",
}


def main() -> int:
    root = Path(git("rev-parse", "--show-toplevel"))
    store = root / "supply-chain"
    # First, and without Cargo: a changed toolchain or configuration can keep Cargo from running.
    problems = build_configuration(root)

    listed = git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--",
                 "supply-chain", cwd=root)
    present = sorted({Path(name).name for name in listed.split("\0") if name})
    expected = sorted([*STORE_FILES, *(name + ".license" for name in STORE_FILES)])
    if present != expected:
        problems.append(f"supply-chain/ holds {present}, expected exactly {expected}")
    for name in STORE_FILES:
        sidecar = store / (name + ".license")
        head = sidecar.read_text().splitlines()[:5] if sidecar.is_file() else []
        for tag in SPDX:
            if not any(tag in line for line in head):
                problems.append(f"supply-chain/{name}.license: no {tag} line")

    def load(name: str) -> dict:
        path = store / name
        if not path.is_file():
            problems.append(f"supply-chain/{name} is missing; cargo vet init creates the store")
            return {}
        return tomllib.loads(path.read_text())

    config = load("config.toml")
    audits = load("audits.toml")
    imports = load("imports.lock")

    for table in sorted(set(config) - CONFIG_TABLES):
        problems.append(f"config.toml: [{table}] is not allowed")
    for table in sorted(set(audits) - AUDITS_TABLES):
        problems.append(f"audits.toml: [{table}] is not allowed")
    if imports:
        problems.append(f"imports.lock: must be empty, holds {sorted(imports)}")

    criteria = audits.get("criteria", {})
    if set(criteria) != {OWN_CRITERION}:
        problems.append(f"audits.toml: the only criterion defined here is {OWN_CRITERION}")
    elif criteria[OWN_CRITERION].get("implies") != "safe-to-deploy":
        problems.append(f"audits.toml: {OWN_CRITERION} must imply safe-to-deploy and nothing else")

    for crate, entries in audits.get("audits", {}).items():
        for entry in entries:
            for key in sorted(set(entry) - AUDIT_KEYS):
                problems.append(f"audits.toml: {crate}: field {key} is not allowed")

    records = audits.get("audits", {})
    for package in tomllib.loads((root / "Cargo.lock").read_text()).get("package", []):
        name, version = package["name"], package["version"]
        if name in HANDLE_SECRETS and version not in read_in_full(records.get(name, [])):
            problems.append(
                f"Cargo.lock: {name} {version} handles secrets"
                " and has no record of a reading in full"
            )

    try:
        workspace = metadata(root)
    except SystemExit as failure:
        for problem in problems:
            print(f"supply-chain-rules: {problem}", file=sys.stderr)
        raise failure
    problems += member_lints(root, workspace)
    members = workspace_members(workspace)
    for member in members:
        if not member.startswith(MEMBER_PREFIX):
            problems.append(f"workspace crate {member}: its name must start with {MEMBER_PREFIX}")
    policies = config.get("policy", {})
    for key, policy in policies.items():
        name = key.split(":", 1)[0]
        allowed = MEMBER_POLICY_KEYS if name in members else THIRD_PARTY_POLICY_KEYS
        for dependency, required in policy.get("dependency-criteria", {}).items():
            if not isinstance(required, str):
                problems.append(
                    f"config.toml: [policy.{key}] gives {dependency} a list;"
                    " write one criterion as a string, as cargo vet fmt does"
                )
            elif dependency in HANDLE_SECRETS and required != OWN_CRITERION:
                problems.append(
                    f"config.toml: [policy.{key}] lowers {dependency}, which handles secrets"
                )
            elif required not in DEPENDENCY_CRITERIA:
                problems.append(
                    f"config.toml: [policy.{key}] sets {dependency} to {required!r};"
                    f" a requirement is lowered only to \"{LOWERED}\""
                )
        if "dev-criteria" in policy and policy["dev-criteria"] != TESTS_ONLY:
            problems.append(
                f"config.toml: [policy.{key}] sets dev-criteria to {policy['dev-criteria']!r};"
                f" only \"{TESTS_ONLY}\" is allowed"
            )
        if name in members and key != name:
            problems.append(
                f"config.toml: [policy.\"{key}\"]: a workspace crate has one policy, by name"
            )
        for field in sorted(set(policy) - allowed):
            problems.append(f"config.toml: [policy.{key}]: field {field} is not allowed")
    for member in members:
        found = policies.get(member, {}).get("criteria")
        if found != OWN_CRITERION:
            problems.append(
                f"config.toml: [policy.{member}] must set criteria = \"{OWN_CRITERION}\","
                f" found {found!r}"
            )

    for problem in problems:
        print(f"supply-chain-rules: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"supply-chain-rules: {len(members)} workspace crates read in full,"
        " only our own reviews count"
    )
    return 0


def build_configuration(root: Path) -> list[str]:
    """Files that would change where dependencies, the compiler or the store come from."""
    problems = []
    listed = git("ls-files", "-z", "--cached", "--others", "--exclude-standard", cwd=root)
    for name in filter(None, listed.split("\0")):
        path = Path(name)
        on_disk = root / path
        if on_disk.is_symlink():
            if on_disk.resolve().is_dir():
                problems.append(f"{name}: a symbolic link to a directory is not allowed")
            continue
        if not on_disk.exists():
            continue
        in_cargo_dir = len(path.parts) >= 2 and path.parts[-2] == ".cargo"
        if in_cargo_dir and path.name in ("config", "config.toml"):
            problems.append(f"{name}: a Cargo configuration file is not allowed in the repository")
        if path.name == "Cargo.toml":
            manifest = tomllib.loads((root / path).read_text())
            for table in ("patch", "replace"):
                if table in manifest:
                    problems.append(f"{name}: [{table}] is not allowed")
            for section in ("workspace", "package"):
                if "vet" in manifest.get(section, {}).get("metadata", {}):
                    problems.append(f"{name}: [{section}.metadata.vet] is not allowed")
        if path.name in ("rust-toolchain", "rust-toolchain.toml"):
            toolchain = tomllib.loads((root / path).read_text()).get("toolchain", {})
            for key in sorted(set(toolchain) - TOOLCHAIN_KEYS):
                problems.append(f"{name}: toolchain field {key} is not allowed")
    return problems


def read_in_full(entries: list[dict]) -> set[str]:
    """Versions with a record of a reading in full: a full one, or deltas leading from one."""
    def criteria(entry: dict) -> set[str]:
        value = entry.get("criteria", [])
        return {value} if isinstance(value, str) else set(value)

    covered = {e["version"] for e in entries if "version" in e and OWN_CRITERION in criteria(e)}
    deltas = []
    for entry in entries:
        if "delta" in entry and OWN_CRITERION in criteria(entry):
            start, _, end = entry["delta"].partition("->")
            deltas.append((start.strip(), end.strip()))
    grown = True
    while grown:
        grown = False
        for start, end in deltas:
            if start in covered and end not in covered:
                covered.add(end)
                grown = True
    return covered


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def member_lints(root: Path, workspace: dict) -> list[str]:
    """Every member of the workspace inherits its lints, but the one allowed unsafe code."""
    problems = []
    shared = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["lints"]
    unsafe_lints = {group: {**lints, **UNSAFE_LINTS.get(group, {})}
                    for group, lints in shared.items()}
    for package in workspace["packages"]:
        manifest = Path(package["manifest_path"])
        lints = tomllib.loads(manifest.read_text()).get("lints")
        name = manifest.relative_to(root)
        if package["name"] == UNSAFE_CRATE:
            if lints != unsafe_lints:
                problems.append(f"{name}: lints must be the workspace's, with unsafe code denied"
                                " rather than forbidden")
        elif lints != {"workspace": True}:
            problems.append(f"{name}: lints must be inherited from the workspace")
    return problems


def metadata(root: Path) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=root, check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit("supply-chain-rules: cargo metadata failed, so the workspace is unknown")
    return json.loads(result.stdout)


def workspace_members(workspace: dict) -> list[str]:
    members = sorted(package["name"] for package in workspace["packages"])
    if not members:
        raise SystemExit("supply-chain-rules: no crate found in the workspace")
    return members


if __name__ == "__main__":
    sys.exit(main())
