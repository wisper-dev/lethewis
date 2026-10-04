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
- Dependency: `zeroize` 1.9.0 or a later compatible version, without default features.
- Dependencies: `hkdf` 0.13.0 and `sha2` 0.11.0 or later compatible versions, without default
  features and with the `zeroize` feature of `sha2`.
- Builds without the standard library and without a memory allocator.
- Keys of 32 or 64 bytes: `Slots::import32`, `Slots::import64`, and `Slots::generate`, which
  writes a key straight into its slot from the platform's random source, given through the
  `Entropy` trait; the library makes no copy of it. `KeyLength` names the two lengths.
- Proofs with Kani 0.68.0 for the slots: a released key is wiped and its handle refused, creating a
  set wipes the keys left in its memory, a handle from another set is refused, a release advances
  the generation, no call panics unless the caller's random source does. Run on every change; see
  `docs/proofs.md`.
- Proofs with Kani 0.68.0 for the plaintext layout of a key record: parsing accepts exactly the
  bytes building can write, building puts every field at its offset, and each returns what the
  other was given.
- Proof with Kani 0.68.0 that the labels built for two key derivations which differ in key
  length, branch or output length are different.
- Dependency review recorded with cargo-vet in `supply-chain/`: a crate that handles key material is
  read in full, and the continuous integration check fails on a version without a record. See
  `SECURITY.md`.

[Unreleased]: https://github.com/wisper-dev/lethewis/commits/main
