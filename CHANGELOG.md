# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning:
[Cargo's SemVer rules](https://doc.rust-lang.org/cargo/reference/semver.html).

All crates in this workspace share one version number and are released together. A raised minimum
supported Rust version is recorded here, although Cargo treats it as a compatible change.

Nothing is published while the version is below 0.1.0.

## [Unreleased]

### Added

- Workspace with the `lethewis-core` crate.
- Documents: licence, security policy, contribution rules, code of conduct, threat model, proof
  register.
- `lethewis-core`: keys held in slots whose memory the caller provides (`Slot`, `Slots`) and
  referred to by handles (`Handle`). No call returns a key. A key is wiped when it is released, and
  every key is wiped when its `Slots` is created or dropped.
- Dependency: `zeroize` 1.9.0, without default features.
- Builds without the standard library and without a memory allocator.

[Unreleased]: https://github.com/wisper-dev/lethewis/commits/main
