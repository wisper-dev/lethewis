# Security policy

## Reporting a vulnerability

Use the private advisory form:
**[open a private report](https://github.com/wisper-dev/lethewis/security/advisories/new)**. The
report stays invisible until a fix is released.

If the form is unavailable to you, write to <hi@alanwisper.com> with "security lethewis" in the
subject.

**Do not open a public issue for a vulnerability,** including a draft or a question about whether
something qualifies.

## Disclosure

You receive a first reply within 14 days. The time needed for a fix is agreed case by case rather
than promised in advance.

The fix is released first. Counting from that release: the advisory with a severity after one week,
the technical details after three.

You may publish your own account at any time. The safe harbour below continues to apply if you do.
If you intend to publish, say so, and the dates are agreed with you.

Credit is given under the name or handle you choose, or withheld at your request.

## Safe harbour

Research conducted in good faith against this library will not be met with legal action, or with a
complaint to your employer or institution, by this project.

Good faith means: your own devices and your own data, no attempt to reach anyone else's, and a
private report before publication.

## Scope

**In scope:** the crates in this repository.

- A key that survives destruction.
- A key that leaves the library in the clear.
- A path that opens two-tier access from a single password.
- A replacement key created without the caller being told.
- A counterexample to any property listed as proven in [docs/proofs.md](docs/proofs.md).

**Out of scope,** as stated in the documentation:

- Recovery of data from a copy of the device taken before a key was destroyed.
- Residue in flash memory readable only by desoldering the chip.
- Any device whose keys are already in memory because it was unlocked after boot.
- Copies of a secret left by a value move, a buffer reallocation, a register, swap or a crash dump.
- Weaknesses in third-party dependencies. Report those to their maintainers, and here as well, so
  the dependency can be pinned or replaced.

The full statement of what is and is not defended: [docs/threat-model.md](docs/threat-model.md).

## Claims

No property is claimed as proven unless [docs/proofs.md](docs/proofs.md) states the tool, its
version, the exact statement, the assumptions, and what is not covered. The phrase "formally
verified" is not used on its own.
