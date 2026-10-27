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
  referred to by handles (`Handle`). Only `Slots::reveal32` returns a key, and only a key for
  external data; a generation of words writes the words its key derives from. The keys of a set are
  wiped when it is released, and every key is wiped when its `Slots` is created or dropped.
- Dependency: `zeroize` 1.9.0 or a later compatible version, without default features.
- Dependencies: `hkdf` 0.13.0 and `sha2` 0.11.0 or later compatible versions, without default
  features and with the `zeroize` feature of `sha2`.
- Builds without the standard library and without a memory allocator.
- Keys of 32 or 64 bytes: `Slots::import32`, `Slots::import64`, and `Slots::generate`, which
  writes a key straight into its slot from the platform's random source, given through the
  `Entropy` trait. `KeyLength` names the two lengths.
- Proofs with Kani 0.68.0 for the slots: a released set is wiped and its handle refused, after any
  sequence of imports and releases of any length; creating the slots wipes the keys left in their
  memory, a release with a handle from other slots is refused, a release advances the generation, no
  call panics unless the caller's random source does. Run on every change; see `docs/proofs.md`.
- Proof with Kani 0.68.0 that the labels built for two key derivations which differ in purpose,
  input length, branch or output length are different.
- `Purpose`: what a key may be used for, given when the key is loaded and never changed: wrapping
  other keys, or external data. `Slots::import32`, `Slots::import64`, `Slots::generate` and
  `Slots::reveal32` take it.
- The identifier of a key is derived from its bytes and length when it is loaded, whatever its
  purpose, and kept in its slot; it is wiped with the key. `Error::DerivationFailed` when it cannot
  be derived.
- A failed import leaves its source as it was.
- The proofs on slots cover the identifier, with a model of the derivation.
- The stack a key derivation used is wiped after it, also when it fails: 8 KiB, or 64 KiB when this
  crate is built without optimisation or with `--cfg lethewis_unoptimised`, which a build that
  optimises this crate but not the hash code it calls has to set. Loading a key now needs 9 KiB of
  stack, or 68 KiB. Tests read the memory of their own process back, with and without optimisation
  and with the hardware and the software SHA-256, to check that the wipe reaches that depth and that
  no piece of the key, of the extracted key or of the HMAC and SHA-256 states, blocks and message
  schedules is left there.
- Dependencies: `aes-gcm-siv` 0.12.1, `aes` 0.9.3 and `polyval` 0.7.3 or later compatible versions,
  without default features and with their `zeroize` features.
- Key sets: a slot holds a set of up to three keys, each enabled or disabled, one of them the
  primary, with a revision counter. An import or a generation loads a set of one.
- `Slots::wrap` writes the set a handle refers to as one record of `RECORD_LEN` bytes, 261,
  encrypted with AES-256-GCM-SIV under a key derived from the key of the parent set, bound to a
  context of 1 to 255 bytes; `Slots::unwrap` loads it back into a free slot.
- A record holds the set's purpose, the stage of each key, the primary and the revision, and the
  identifier of the parent key.
- New errors: `RecordRejected` for any record that does not open, parse or name the key that opened
  it, `SameKey` for a set wrapped under itself, `InvalidContext` and `CipherFailed`.
- `DuplicateKey`: a key is held in one place only, and a load of a key the slots already hold, or of
  a set that holds one key twice, is refused.
- Dependency: `ctutils` 0.4.5 or a later compatible version, without default features, to compare
  a record's parent identifier, and words with the list, in constant time.
- The stack a wrap or an unwrap used is wiped after it, also when it fails: 24 KiB, or 64 KiB when
  this crate is built without optimisation or with `--cfg lethewis_unoptimised`, which a build that
  optimises this crate but not the hash and cipher code it calls has to set. Wrapping and unwrapping
  need 25 KiB of stack, or 72 KiB. Tests read the memory of their own process back after a wrap and
  an unwrap, with and without optimisation and with the hardware and the software AES, POLYVAL and
  SHA-256, and check the wipe and the stack needed at every level of optimisation.
- `lethewis-dit`: runs work with data-independent timing on, on aarch64 where Linux, Android or
  an Apple system reports the feature, and switches it back off when the work returns or unwinds.
  The core runs each import, generation, wrap and unwrap that way. It is the one crate
  with unsafe code: two instructions that read and write the mode, and the calls that ask the
  system about it.
- Dependency of `lethewis-dit`: `libc` 0.2.190 or a later compatible version, without default
  features, on aarch64 Linux, Android and Apple targets.
- Tests also run on aarch64 Linux and on macOS on Apple silicon, with the hardware and the software
  SHA-256, AES and POLYVAL; on aarch64 Linux they read the stack back after a derivation, a wrap and
  an unwrap, at every level of optimisation.
- Proofs with Kani 0.68.0 for the plaintext layout of a key set, which holds up to three keys, the
  position of the primary and a revision counter, and for the stages of its keys: from any set whose
  primary is enabled, every transition keeps it so, counts one revision and changes only what it
  names, and a transition out of order is refused and changes nothing.
- A test unwraps random records sealed with the real derivation and cipher: random sets, parents,
  keys held elsewhere, contexts, slots and changed bits; a million of them from
  a new seed on every pull request.
- A build step checks that the machine code of the comparison of key identifiers runs straight
  through on x86-64, aarch64, Cortex-M4 and WebAssembly: no branch, no call and no write of the
  program counter but the final return.
- Proofs with Kani 0.68.0 for wrapping and unwrapping, with a model of the cipher. A wrap changes no
  slot and writes the record only when it succeeds. An unwrap tries the key of the parent once and
  keeps the plaintext when it opens the record and names that key.
- A refused unwrap changes no slot, and a decrypted set loads exactly the keys it holds, only when
  none is held already or twice.
- Proofs with Kani 0.68.0 for the code around the cipher of the key records: a seal that fails, and
  a record that does not open, leave the buffer zero, and a record is refused exactly when the
  cipher rejects it.
- Dependency review recorded with cargo-vet in `supply-chain/`: a crate that handles key material is
  read in full, and the continuous integration check fails on a version without a record. See
  `SECURITY.md`.
- The stack a load of a key used is wiped after it, not only the stack of the derivation of its
  identifier.
- Changes of a key set in its slot. `Slots::add32` and `Slots::add_generated` add a key, enabled,
  to the first empty position. `Slots::promote`, `Slots::disable`, `Slots::enable`
  and `Slots::destroy` change the stage of a key. A destroyed key is wiped with its identifier.
- `Position` names the three positions of a set. New errors: `SetFull`, `PrimaryKey`,
  `WrongStage` and `SetExhausted`.
- Proofs with Kani 0.68.0 for the changes of a set in its slot and for additions of a key.
- A proof run reads its results from CBMC's own output. On every run the reading is compared with
  Kani's results on a proof with every outcome, failures among them, and on two of the library's
  proofs. A proof is limited to 10 minutes.
- Epochs. `Slots::new` takes memory for the epoch from the caller (`Epoch`), and the number and
  key of the current epoch. A record is wrapped under a key derived from its parent's key and the
  key of its epoch, whose number it names; a record of another epoch is refused.
- A set changes once in an epoch, and the change is saved by wrapping the set in the next:
  `Slots::begin_epoch`, then `Slots::commit_epoch` or `Slots::abandon_epoch`; no set changes in
  between. The platform switches and erases roots through the `Root` trait, and both calls return
  how surely a root is erased (`Erasure`).
- New errors: `Unsaved`, `EpochChanging`, `NoEpochChange`, `EpochExhausted` and `RootFailed`.
- Proofs with Kani 0.68.0 for the change of epoch and for the refusals of an unsaved set.
- Derivation from a password: `Slots::derive_from_password` derives a 32-byte key for wrapping
  with Argon2id, version 0x13, in one lane, straight into a free slot. It takes its working memory
  from the caller (`MemoryBlock`), wipes the blocks it used whether it succeeds or not, and wipes the
  password when it succeeds.
- `PasswordParams` holds the memory, the passes and a 16-byte salt from the platform's random
  source, kept as `PASSWORD_PARAMS_LEN` bytes, 25. Only memory from 64 MiB to 2 GiB, at least 3
  passes and memory times passes up to 8 GiB are made or read.
- New errors: `InvalidParams`, `InvalidPassword` and `NotEnoughMemory`.
- The stack a derivation from a password used is wiped after it: 32 KiB, or 192 KiB without
  optimisation; it needs 33 KiB of stack, or 196 KiB. Tests read the stack back, and check the key
  against vectors of the reference implementation and against an independent implementation.
- Dependencies: `argon2` 0.6.0 and `blake2` 0.11.0 or later compatible versions, without default
  features and with their `zeroize` features; `base64ct` comes with `argon2`.
- Proofs with Kani 0.68.0 for the parameters of a derivation from a password, read exactly as
  written and made or read only within the bounds, and for the derivation into a slot, with a model
  of Argon2id.
- Twelve words of the English list of BIP 39: `Slots::generate_words` creates a 32-byte key for
  wrapping from 16 random bytes and writes their words (`Words`,
  `WORD_COUNT` words of `WORD_LEN` bytes); `Slots::derive_from_words` derives the same key from the
  words into a free slot and wipes them. The key is HKDF-SHA-256 of the 16 bytes, so it does not
  depend on the list.
- Each word is compared with every word of the list, and a word is chosen by its number reading
  every word, in steps with no branch on the words; a build step checks the machine code of both
  steps on four targets.
- New errors: `UnknownWord` and `InvalidChecksum`.
- Words are read and written with data-independent timing on, where it is offered.
- The stack is wiped after both calls: 8 KiB, or 64 KiB without optimisation; they need 10 KiB of
  stack, or 72 KiB. Tests read the stack back, and check the words against the vectors of the
  reference implementation and the key against an independent implementation.
- Proofs with Kani 0.68.0 for the lookup of a word, the numbers of the words and their checksum,
  the reading of any twelve words, and the derivation and the generation into a slot.
- `lethewis-core` holds the English word list of BIP 39, under the MIT licence.
- A second purpose, `Purpose::ExternalData`: a 32-byte key for an engine outside the library.
  `Slots::reveal32` writes such a key into the caller's buffer, only for a call that names the
  purpose, and wipes the stack after it: 8 KiB, or 64 KiB; it needs 9 KiB of stack, or 68 KiB.
- Only keys for wrapping wrap and unwrap, and each purpose takes its own key lengths, also in a
  record. New errors: `WrongPurpose` and `WrongLength`.
- Proofs with Kani 0.68.0 for the purposes. Wrapping and unwrapping refuse a parent of another
  purpose; loads, additions and records refuse a length the purpose does not take; a load finds a
  key held for another purpose. A reveal writes exactly an enabled key for external data.
- Keys, words and nonces from the platform's source are hedged with the key of the epoch, as RFC
  8937 has it: HKDF-SHA-256 of the bytes drawn and a count of draws, with that key as the salt.
  Within one `Slots`, a broken source alone no longer makes them predictable, and a repeating source
  gives different bytes. Password salts are not hedged.
- Proofs with Kani 0.68.0 that keys, words and nonces are the hedge of the source's bytes, and that
  the count of draws grows once for each draw the source answers.
- A set for wrapping holds one key and never changes: changes of stage and additions refuse it with
  `WrongPurpose`, and a record of one is unwrapped only if it holds a set of one that has never
  changed.
  Proofs with Kani 0.68.0 for both.
- Levels of keys. A key for wrapping from a secret, imported or derived from a password or words,
  is never wrapped and wraps only stored keys for wrapping; a stored one, generated or unlocked,
  wraps only keys for external data. A call at the wrong level fails with `WrongLevel`.
- `Slots::lock` keeps a stored key under a key from a secret as a lock record of
  `LOCK_RECORD_LEN` bytes, 297, in two layers of AES-256-GCM-SIV. The inner one is under a key
  derived from the key from a secret alone, the outer under a key derived from the key of the
  epoch, with its number. `Slots::unlock` loads the stored key back.
- `Slots::carry` moves a lock record into the next epoch during a change, without the key from a
  secret. A lock record not carried opens no more once the change is committed and the old root
  erased; a record of another epoch fails with `StaleRecord`.
- Proofs with Kani 0.68.0 for the levels of loads, wraps, locks, unwraps and unlocks, and for the
  layers of lock records and their carry. Tests against lock records and a carried record computed
  by an independent implementation.
- `Slots::combine` derives one key from a secret from two, the second of 32 bytes as the salt of
  HKDF-SHA-256, and releases both. `Slots::challenge` derives from a key from a secret the
  challenge to a chip, whose answer, combined with that key, makes a key that needs both.
- Proofs with Kani 0.68.0 for combining and for the challenge; tests against an independent
  implementation of HKDF-SHA-256.
- The stack a lock, an unlock or a carry used is wiped after it, also when it fails: 24 KiB, or
  64 KiB without optimisation; after a combination or a challenge, 8 KiB, or 64 KiB. Tests read
  it back after each, and after a refused unlock.
- A test of the hierarchy end to end, through the public interface. A profile key is locked under
  a password with the chip and under words, with keys of chats under it. After a change of epoch, a
  chat not wrapped again and a way in not carried open no more.
- A third purpose, `Purpose::Transfer`: a 32-byte key that carries keys for external data to
  another device or into a backup. It is imported from a secret shared with the other device, or
  derived from the twelve words by `Slots::transfer_from_words`, another key than the one
  `Slots::derive_from_words` gives. It is never generated or revealed, and is stored under a stored
  key for wrapping.
- `Slots::export` writes a set for external data as a record of an export, of `RECORD_LEN` bytes,
  under a key derived from the key for transfers alone, in no epoch; each record is bound to the tag
  of the one before. `Slots::end_export` ends the export with a record of `END_RECORD_LEN` bytes, 28.
- `Slots::receive` loads the records of an export, in order, into free slots; a set received is
  neither revealed, wrapped, exported nor changed until `Slots::end_receive` receives the end. A key
  for transfers carries one export at a time, one way, and an export without records has no end.
  New errors: `Unfinished` and `NoTransfer`.
- Proofs with Kani 0.68.0 for exports, receipts and both ends, and tests against an export and its
  end computed by an independent implementation. The stack is wiped after each call: 24 KiB, or 64
  KiB; they need 25 KiB of stack, or 72 KiB.
- Tests end to end: the keys of chats move to a second device under a shared secret, and a backup
  under the words restores them on a new phone; an export cut short leaves nothing to keep.
- Dependencies: `ml-kem` 0.3.3, `x25519-dalek` 3.0.0, `sha3` 0.12.0 and `shake` 0.1.0 or later
  compatible versions, without default features and with their `zeroize` features and the `hazmat`
  feature of `ml-kem`, for X-Wing, the hybrid of ML-KEM-768 and X25519.
- Three purposes of the archive: `Purpose::Archive`, the seed of an archive key;
  `Purpose::ArchiveWrap`, a stored key of the archive, kept only in lock records, that wraps only
  seeds; and `Purpose::ArchiveSeal`, a key of a chat for its archive, under a stored key for
  wrapping. None is imported or derived from a password or words; no seed is generated.
- Archive keys of X-Wing. `Slots::create_archive_key` writes the record of a new one,
  `ARCHIVE_KEY_RECORD_LEN` bytes, 1529: its seed under a stored key of the archive, and that layer
  with its identifier and public key under the profile's stored key and the key of the epoch.
- `Slots::load_archive_key` loads an archive key and refuses a public key its seed does not give,
  with `Error::PublicKeyMismatch`. `Slots::carry_archive_key` carries its record into the next epoch
  without the stored key of the archive.
- X-Wing gives the known answer of its draft once in a process, before its first use, and the key
  pair of a new archive key has to agree with itself. The stack is wiped after each call on an
  archive key: 96 KiB, or 224 KiB; they need 100 KiB of stack, or 232 KiB.
- Proofs with Kani 0.68.0 for the creation, the load and the carry of an archive key, and tests
  against records computed by an independent implementation, the public key of X-Wing included.
- Records of an archive, `ARCHIVE_RECORD_LEN` bytes, 1180: `Slots::archive` encapsulates to an
  archive key and writes the ciphertext and a check of the shared secret under the key of a chat
  for its archive. `Slots::reseal_archive` moves the record to another key of the chat.
- `Slots::archive` seals the data of the batch into a body of `batch_len` bytes, in chunks of
  64 KiB, under a key derived from the shared secret that never leaves the library; the data never
  pass through the body. A body of another length fails with `Error::WrongLength`, and any failure
  wipes the body. A moved record opens the same body.
- `Slots::open_archive` opens the body into data of `batch_data_len` bytes with the archive key,
  all of it or none: a failure wipes the data. It fails with `Error::WrongArchiveKey` for a record
  of another archive key, with `Error::PublicKeyMismatch` for a batch archived to another public
  key, with `Error::RecordRejected` for a body no batch has, and with `Error::WrongLength` for data
  of another length than the body holds.
- `batch_len` and `batch_data_len` give the length of a body and of the data it holds.
- Archiving and opening a batch need 164 KiB of stack, or 232 KiB, and are followed by a wipe
  160 KiB deep, or 224 KiB.
- `Slots::archive_public_key` reads the public key of an archive key, as `ArchivePublic`, from
  its record under the profile's stored key, for those slots and that epoch only. Proofs with Kani
  0.68.0 for the four calls and for the seal and the opening of a body, and tests against records
  and bodies an independent implementation computes.
- Tests check on every machine, not only on aarch64, that each call starts its derivations,
  Argon2id, ciphers and operations of X-Wing inside the switch of data-independent timing.
- The proofs of wraps, locks, exports, the carries of lock records, the ends of exports and archive
  keys follow each seal and opening: the key, the associated data, and the nonce, first bytes and
  tag a record holds. A failed seal gives `Error::CipherFailed`, as nothing else does but the checks
  of X-Wing.
- Outside the proofs and the tests, the calls seal and open with AES-256-GCM-SIV only and ask
  X-Wing for the known answer of its draft only: a build has nothing else they could be given.
- The tests that read back the stack after the calls on archive keys and on records of an archive
  look for what X-Wing, the cipher and the derivations handle, and find it there without the wipe.
- Tests refuse every changed bit of the records of archive keys and of an archive, and read random
  ones sealed with the real derivations and cipher; ten thousand of each from a new seed on every
  pull request.
- `Purpose::Data`: a key of 32 bytes that encrypts the caller's data in the library and leaves it
  only wrapped. Only the platform's source creates it; it is stored under a stored key for wrapping,
  in a set whose keys change by their stages, and is never exported or revealed.
- Blocks of data: a header of `BLOCK_HEADER_LEN` bytes, a salt and a check that names the key, then
  chunks of up to `CHUNK_LEN` bytes, each followed by a tag of `CHUNK_TAG_LEN`; `block_len` gives
  the length of a block.
- `Slots::begin_seal`, `Slots::seal_chunk` and `Slots::seal_last` write a block under the primary
  key of a set a record of this epoch holds. `Slots::begin_open`, `Slots::open_chunk` and
  `Slots::open_last` read it under the key its header names. `Sealing` and `Opening` follow a block
  between the calls and hold no key.
- A sealed chunk is opened and sealed again to the same tag and ciphertext before its tag is given,
  so that a fault of the cipher in one of these passes fails the seal.
- `Error::KeyDisabled` for a block under a disabled key, and `Error::WrongChunk` for a chunk out of
  the order or the length of its block.
- Proofs with Kani 0.68.0 of the layout of a block for every length, of its beginning, of each
  chunk sealed and opened, and of the cipher on a chunk. Tests against blocks an independent
  implementation computes, every changed bit, blocks cut, reordered and mixed, and random blocks.
- Blocks carried to another device or into a backup: `Slots::begin_export_block`,
  `Slots::export_chunk` and `Slots::export_last` seal each chunk of a block again under a key for
  transfers, as the next element of its export. `Slots::begin_receive_block`, `Slots::receive_into`,
  `Slots::receive_chunk` and `Slots::receive_last` seal it under a new set for data of that
  transfer. No key for data leaves the library; `Exporting`, `Receipt` and `Receiving` hold no key.
- A set of an unfinished transfer begins and reads no block, `Error::Unfinished`; a received block
  goes into no set of another transfer, `Error::NotReceived`.
- Proofs with Kani 0.68.0 of the beginnings, of each chunk carried out and received, and of their
  refusals. Tests against carried blocks an independent implementation computes, every changed bit,
  blocks out of order, dropped and mixed, data-independent timing and the stack.
- A call asks the random source before any step on a secret but hedging earlier nonces and salts.
  Hedges wipe their stack, so a panic of the source leaves no secret; Kani proof, stack test.
- Slots are reached only through a table, which Kani proves for eight slots.

[Unreleased]: https://github.com/wisper-dev/lethewis/commits/main
