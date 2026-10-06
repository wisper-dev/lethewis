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
  `Entropy` trait; the library's own code makes no copy of it. `KeyLength` names the two lengths.
- Proofs with Kani 0.68.0 for the slots: a released key is wiped and its handle refused, creating a
  set wipes the keys left in its memory, a handle from another set is refused, a release advances
  the generation, no call panics unless the caller's random source does. Run on every change; see
  `docs/proofs.md`.
- Proofs with Kani 0.68.0 for the plaintext layout of a key record: parsing accepts exactly the
  bytes building can write, building puts every field at its offset, and each returns what the
  other was given.
- Proof with Kani 0.68.0 that the labels built for two key derivations which differ in key
  length, branch or output length are different.
- `Purpose`: what a key may be used for, given when the key is loaded and never changed. One purpose
  so far, wrapping other keys. `Slots::import32`, `Slots::import64` and `Slots::generate` take it.
- The identifier of a key is derived from the key when it is loaded and kept in its slot; it is
  wiped with the key. `Error::DerivationFailed` when it cannot be derived.
- A failed import leaves its source as it was.
- The proofs on slots cover the identifier, with a model of the derivation.
- The stack a key derivation used is wiped after it, also when it fails. Loading a key now needs
  8 KiB of stack for that, or 64 KiB when this crate is built without optimisation or with
  `--cfg lethewis_unoptimised`, which a build that optimises this crate but not the hash code it
  calls has to set. Tests read the memory of their own process back, with and without optimisation
  and with the hardware and the software SHA-256, to check that the wipe reaches that depth and that
  no piece of the key, of the extracted key or of the HMAC and SHA-256 states, blocks and message
  schedules is left there.
- Dependencies: `aes-gcm-siv` 0.12.1, `aes` 0.9.3 and `polyval` 0.7.3 or later compatible versions,
  without default features and with their `zeroize` features.
- Proofs with Kani 0.68.0 for the code around the cipher of the key records: a seal that fails, and
  a record that does not open, leave the buffer zero, and a record is refused exactly when the
  cipher rejects it.
- Dependency review recorded with cargo-vet in `supply-chain/`: a crate that handles key material is
  read in full, and the continuous integration check fails on a version without a record. See
  `SECURITY.md`.

[Unreleased]: https://github.com/wisper-dev/lethewis/commits/main
