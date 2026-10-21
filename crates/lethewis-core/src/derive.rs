// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(kani))]
use hkdf::Hkdf;
#[cfg(not(kani))]
use sha2::Sha256;

use crate::entropy::{Entropy, EntropyError};
use crate::key::{CAPACITY, Key, wipe};
use crate::record::{ID_LEN, Purpose, length_to_byte};
use crate::seal::KEY_LEN as CIPHER_KEY_LEN;
use crate::xwing::{CIPHERTEXT_LEN, RANDOMNESS_LEN};

/// The salt of the derivation of an identifier, and of a key from words.
pub(crate) const SALT: &[u8] = b"lethewis derivation salt v1";
/// The first bytes of every label.
const PREFIX: &[u8; 8] = b"lethewis";
const VERSION: u8 = 1;
/// Prefix (8), version, purpose, key length, output length (2), name length, and a name of up to
/// 16 bytes.
const LABEL_CAPACITY: usize = 30;
/// The part of a label before the name.
const HEAD_LEN: usize = 14;
const KEY_ID: &[u8; 6] = b"key id";
const WRAP_KEY: &[u8; 8] = b"wrap key";
const FROM_WORDS: &[u8; 10] = b"from words";
const HEDGE_KEY: &[u8; 9] = b"hedge key";
const HEDGE_WORDS: &[u8; 11] = b"hedge words";
const HEDGE_NONCE: &[u8; 11] = b"hedge nonce";
const LOCK_KEY: &[u8; 8] = b"lock key";
const EPOCH_LAYER: &[u8; 11] = b"epoch layer";
const COMBINED: &[u8; 12] = b"combined key";
const CHALLENGE: &[u8; 9] = b"challenge";
const EXPORT_KEY: &[u8; 10] = b"export key";
const ARCHIVE_KEY: &[u8; 11] = b"archive key";
const ARCHIVE_LAYER: &[u8; 13] = b"archive layer";
const ARCHIVE_SEED: &[u8; 12] = b"archive seed";
const ARCHIVE_SEAL: &[u8; 12] = b"archive seal";
const HEDGE_ENCAPS: &[u8; 12] = b"hedge encaps";
const ARCHIVE_ENCAPS: &[u8; 14] = b"archive encaps";
const ARCHIVE_DATA: &[u8; 12] = b"archive data";
const ARCHIVE_CHECK: &[u8; 13] = b"archive check";
/// The count of a draw, after the bytes the source gave, in the material a hedge extracts.
const COUNT_LEN: usize = 8;
/// How many bytes twelve words stand for.
pub(crate) const WORDS_ENTROPY_LEN: usize = 16;
/// How many bytes of stack a derivation is followed by a wipe of: at least twice what it uses, as a
/// test measures in each build and with each SHA-256 back end. Without optimisation it uses far
/// more.
#[cfg(all(not(kani), not(lethewis_unoptimised)))]
pub(crate) const STACK_WIPE: usize = 8192;
#[cfg(all(not(kani), lethewis_unoptimised))]
pub(crate) const STACK_WIPE: usize = 65_536;
/// How many bytes of stack a wrap or an unwrap is followed by a wipe of: at least twice what the
/// cipher uses at any level of optimisation, as a test measures in the same way.
#[cfg(all(not(kani), not(lethewis_unoptimised)))]
pub(crate) const CIPHER_STACK_WIPE: usize = 24_576;
#[cfg(all(not(kani), lethewis_unoptimised))]
pub(crate) const CIPHER_STACK_WIPE: usize = 65_536;

/// What a derived value is for. Each branch has a name of its own in the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Branch {
    /// The identifier of a key.
    KeyId,
    /// The key that encrypts the records a wrapping key wraps.
    WrapKey,
    /// A key from the bytes twelve words stand for.
    FromWords,
    /// The bytes of a new key, hedged.
    HedgeKey,
    /// The bytes that new words stand for, hedged.
    HedgeWords,
    /// The nonce of a record, hedged.
    HedgeNonce,
    /// The key that encrypts the records a key from a secret locks, whatever the epoch.
    LockKey,
    /// The key that encrypts the outer layer of the lock records of an epoch.
    EpochLayer,
    /// A key from a secret, from another one and a key as the salt.
    Combined,
    /// The challenge to a chip from a key from a secret.
    Challenge,
    /// The key that encrypts the records of an export, and the record that ends one, under a key
    /// for transfers.
    ExportKey,
    /// The key that encrypts the seed of an archive key under a stored key of the archive, whatever
    /// the epoch.
    ArchiveKey,
    /// The key that encrypts the outer layer of the record of an archive key, under a stored key for
    /// wrapping, in an epoch.
    ArchiveLayer,
    /// The seed of an archive key, from hedged bytes and a stored key of the archive.
    ArchiveSeed,
    /// The key that encrypts the records of an archive under a key of a chat for its archive,
    /// whatever the epoch.
    ArchiveSeal,
    /// The randomness of an encapsulation of X-Wing, hedged.
    HedgeEncaps,
    /// The randomness of an encapsulation, from hedged bytes and a key of a chat for its archive.
    ArchiveEncaps,
    /// The key of a batch, from a shared secret of X-Wing.
    ArchiveData,
    /// The check of a shared secret of X-Wing that a record of an archive holds.
    ArchiveCheck,
}

/// The purpose each branch is derived for.
#[cfg(test)]
pub(crate) const fn purpose_of(branch: Branch) -> Option<Purpose> {
    match branch {
        Branch::WrapKey
        | Branch::FromWords
        | Branch::LockKey
        | Branch::EpochLayer
        | Branch::Combined
        | Branch::ArchiveLayer => Some(Purpose::Wrap),
        Branch::ExportKey => Some(Purpose::Transfer),
        Branch::ArchiveKey => Some(Purpose::ArchiveWrap),
        Branch::ArchiveSeed | Branch::ArchiveData | Branch::ArchiveCheck => Some(Purpose::Archive),
        Branch::ArchiveSeal | Branch::ArchiveEncaps => Some(Purpose::ArchiveSeal),
        Branch::KeyId
        | Branch::HedgeKey
        | Branch::HedgeWords
        | Branch::HedgeNonce
        | Branch::HedgeEncaps
        | Branch::Challenge => None,
    }
}

/// Hedges worked out apart from [`hedge`], for the tests.
#[cfg(test)]
pub(crate) mod direct {
    extern crate std;

    use std::vec::Vec;

    use hkdf::Hkdf;
    use sha2::Sha256;

    /// What a hedge makes of `drawn` under the epoch key `epoch` at `count`, for the use `name`:
    /// HKDF-SHA-256 called directly, with the label written out by hand.
    pub(crate) fn hedged_directly(
        epoch: &[u8; 32],
        count: u64,
        name: &[u8],
        drawn: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let mut material = drawn.to_vec();
        material.extend_from_slice(&count.to_le_bytes());
        let mut info = b"lethewis".to_vec();
        info.extend_from_slice(&[1, 0, u8::try_from(material.len()).unwrap()]);
        info.extend_from_slice(&u16::try_from(length).unwrap().to_le_bytes());
        info.push(u8::try_from(name.len()).unwrap());
        info.extend_from_slice(name);
        let mut out = std::vec![0; length];
        Hkdf::<Sha256>::new(Some(epoch), &material)
            .expand(&info, &mut out)
            .unwrap();
        out
    }
}

/// The derivation could not run: the output asked for is longer than HKDF-SHA-256 gives, 255
/// blocks of 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerivationFailed;

/// The identifier of a key, derived from the key itself. It is wiped when dropped.
#[cfg_attr(any(test, kani), derive(Debug, PartialEq, Eq))]
pub(crate) struct KeyId([u8; ID_LEN]);

impl KeyId {
    pub(crate) const fn empty() -> Self {
        Self([0; ID_LEN])
    }

    pub(crate) fn wipe(&mut self) {
        wipe(&mut self.0);
    }

    /// Takes the identifier out of `source` and wipes `source`.
    pub(crate) fn take(&mut self, source: &mut Self) {
        self.0 = source.0;
        source.wipe();
    }

    pub(crate) const fn bytes(&self) -> [u8; ID_LEN] {
        self.0
    }

    /// Whether both are the identifier of one key, compared in constant time.
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.is(&other.0)
    }

    /// Whether the identifier is `bytes`, compared in constant time. Kept out of line, so that the
    /// check of its machine code finds it.
    #[inline(never)]
    pub(crate) fn is(&self, bytes: &[u8; ID_LEN]) -> bool {
        #[cfg(not(kani))]
        {
            use ctutils::CtEq;
            self.0.ct_eq(bytes).to_bool()
        }
        // The comparison ends in inline assembly, which Kani cannot model.
        #[cfg(kani)]
        {
            model::same_id(&self.0, bytes)
        }
    }
}

impl Drop for KeyId {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Derives the identifier of `key` straight into `id`. The purpose is not part of it: the same
/// bytes have one identifier whatever they serve.
pub(crate) fn derive_key_id(key: &Key, id: &mut KeyId) -> Result<(), DerivationFailed> {
    derive(key, SALT, None, Branch::KeyId, &mut id.0)
}

/// Derives the key that encrypts the records the wrapping key `key` wraps in the epoch whose key is
/// `epoch`.
pub(crate) fn derive_wrap_key(
    key: &Key,
    epoch: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    let salt = epoch.material().ok_or(DerivationFailed)?;
    derive(key, salt, Some(Purpose::Wrap), Branch::WrapKey, out)
}

/// Derives the key that encrypts the records the key from a secret `key` locks, in any epoch.
pub(crate) fn derive_lock_key(
    key: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    derive(key, SALT, Some(Purpose::Wrap), Branch::LockKey, out)
}

/// Derives into `out` the key from a secret that the key from a secret `key` and the key `salt`, as
/// the salt, make together.
pub(crate) fn derive_combined(
    key: &Key,
    salt: &Key,
    out: &mut [u8; 32],
) -> Result<(), DerivationFailed> {
    let salt = salt.material().ok_or(DerivationFailed)?;
    derive(key, salt, Some(Purpose::Wrap), Branch::Combined, out)
}

/// Derives into `out` the challenge to a chip from the key from a secret `key`.
pub(crate) fn derive_challenge(key: &Key, out: &mut [u8; 32]) -> Result<(), DerivationFailed> {
    derive(key, SALT, None, Branch::Challenge, out)
}

/// Derives the key that encrypts the records of an export, and the record that ends one, under the
/// key for transfers `key`, in any epoch.
pub(crate) fn derive_export_key(
    key: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    derive(key, SALT, Some(Purpose::Transfer), Branch::ExportKey, out)
}

/// Derives the key that encrypts the outer layer of the lock records of the epoch whose key is
/// `epoch`.
pub(crate) fn derive_layer_key(
    epoch: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    derive(epoch, SALT, Some(Purpose::Wrap), Branch::EpochLayer, out)
}

/// Derives the key that encrypts the seeds the stored key of the archive `key` wraps, in any epoch.
pub(crate) fn derive_archive_key(
    key: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    derive(
        key,
        SALT,
        Some(Purpose::ArchiveWrap),
        Branch::ArchiveKey,
        out,
    )
}

/// Derives the key that encrypts the outer layer of the records of archive keys under the stored
/// key for wrapping `key` in the epoch whose key is `epoch`.
pub(crate) fn derive_archive_layer_key(
    key: &Key,
    epoch: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    let salt = epoch.material().ok_or(DerivationFailed)?;
    derive(key, salt, Some(Purpose::Wrap), Branch::ArchiveLayer, out)
}

/// Derives the seed of an archive key from `hedged`, bytes of the platform's source hedged with the
/// key of the epoch, as the salt and the stored key of the archive `key`.
pub(crate) fn derive_archive_seed(
    key: &Key,
    hedged: &[u8; 32],
    out: &mut [u8; 32],
) -> Result<(), DerivationFailed> {
    derive(
        key,
        hedged,
        Some(Purpose::Archive),
        Branch::ArchiveSeed,
        out,
    )
}

/// Derives the key that encrypts the records of an archive under the key of a chat for its archive
/// `key`, in any epoch.
pub(crate) fn derive_archive_seal_key(
    key: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    derive(
        key,
        SALT,
        Some(Purpose::ArchiveSeal),
        Branch::ArchiveSeal,
        out,
    )
}

/// Derives the randomness of an encapsulation from `hedged`, bytes of the platform's source hedged
/// with the key of the epoch, as the salt and the key of a chat for its archive `key`.
pub(crate) fn derive_archive_randomness(
    key: &Key,
    hedged: &[u8; RANDOMNESS_LEN],
    out: &mut [u8; RANDOMNESS_LEN],
) -> Result<(), DerivationFailed> {
    derive(
        key,
        hedged,
        Some(Purpose::ArchiveSeal),
        Branch::ArchiveEncaps,
        out,
    )
}

/// Derives the key of a batch from the shared secret of X-Wing `shared`, with the ciphertext it
/// came with as the salt.
pub(crate) fn derive_archive_data(
    shared: &Key,
    ciphertext: &[u8; CIPHERTEXT_LEN],
    out: &mut [u8; 32],
) -> Result<(), DerivationFailed> {
    derive(
        shared,
        ciphertext,
        Some(Purpose::Archive),
        Branch::ArchiveData,
        out,
    )
}

/// Derives into `check` the check of the shared secret of X-Wing `shared` that a record of an
/// archive holds, with the ciphertext it came with as the salt.
pub(crate) fn derive_archive_check(
    shared: &Key,
    ciphertext: &[u8; CIPHERTEXT_LEN],
    check: &mut KeyId,
) -> Result<(), DerivationFailed> {
    derive(
        shared,
        ciphertext,
        Some(Purpose::Archive),
        Branch::ArchiveCheck,
        &mut check.0,
    )
}

/// Fills `out` with the key for `purpose` that the bytes twelve words stand for, `entropy`, derive:
/// HKDF-Extract with the salt of identifiers, then HKDF-Expand with a label of its own, which names
/// the purpose. Then the stack the derivation used is wiped, whether it succeeded or not.
pub(crate) fn derive_from_words(
    entropy: &[u8; WORDS_ENTROPY_LEN],
    purpose: Purpose,
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    #[cfg(test)]
    crate::timing::note();
    let derived = words_on_stack(entropy, purpose, out);
    wipe_stack();
    derived
}

/// The derivation from words itself, in a frame of its own.
#[inline(never)]
fn words_on_stack(
    entropy: &[u8; WORDS_ENTROPY_LEN],
    purpose: Purpose,
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    let length = u8::try_from(WORDS_ENTROPY_LEN).map_err(|_| DerivationFailed)?;
    let (label, used) = label(Some(purpose), length, Branch::FromWords, out.len())?;
    let info = label.get(..used).ok_or(DerivationFailed)?;
    // The model of HKDF fills a 32-byte output from the first 32 bytes of the key.
    #[cfg(kani)]
    let twice = model::twice(entropy);
    #[cfg(kani)]
    let entropy = &twice;
    hkdf(SALT, entropy, info, out)
}

/// Fills `out` with the value of `branch` derived from `key` for `purpose`, or for none. The key
/// goes through HKDF-Extract with `salt`, and HKDF-Expand takes the label. Then the stack the
/// derivation used is wiped, whether it succeeded or not.
pub(crate) fn derive(
    key: &Key,
    salt: &[u8],
    purpose: Option<Purpose>,
    branch: Branch,
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    #[cfg(test)]
    crate::timing::note();
    let derived = derive_on_stack(key, salt, purpose, branch, out);
    wipe_stack();
    derived
}

/// Fills `out` from the bytes the platform's source gave, `drawn`, hedged with the key of the epoch
/// as RFC 8937 has it: HKDF-Extract, with that key as the salt, takes the bytes and then `count`,
/// least significant byte first, and HKDF-Expand takes the label of `branch`. While that key is
/// secret, the output cannot be told from random bytes unless the bytes drawn and the count repeat
/// together, which they do not within one set of slots. Then the stack the hedge used is wiped,
/// whether it succeeded or not.
pub(crate) fn hedge(
    epoch: &Key,
    count: u64,
    branch: Branch,
    drawn: &[u8],
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    #[cfg(test)]
    crate::timing::note();
    let hedged = hedge_on_stack(epoch, count, branch, drawn, out);
    wipe_stack();
    hedged
}

/// The hedge itself, in a frame of its own.
#[inline(never)]
fn hedge_on_stack(
    epoch: &Key,
    count: u64,
    branch: Branch,
    drawn: &[u8],
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    let salt = epoch.material().ok_or(DerivationFailed)?;
    let count = count.to_le_bytes();
    let mut material = [0; CAPACITY + COUNT_LEN];
    // Copies of a length fixed at each arm: under the proofs a copy of a length known only at run
    // time reads stale bytes.
    let placed = match drawn.len() {
        12 => place::<12>(&mut material, drawn, count),
        16 => place::<16>(&mut material, drawn, count),
        32 => place::<32>(&mut material, drawn, count),
        CAPACITY => place::<CAPACITY>(&mut material, drawn, count),
        _ => None,
    };
    let used = placed.ok_or(DerivationFailed)?;
    let length = u8::try_from(used).map_err(|_| DerivationFailed)?;
    let hedged = label(None, length, branch, out.len()).and_then(|(label, label_used)| {
        let info = label.get(..label_used).ok_or(DerivationFailed)?;
        let material = material.get(..used).ok_or(DerivationFailed)?;
        hkdf(salt, material, info, out)
    });
    wipe(&mut material);
    hedged
}

/// Puts the `N` bytes drawn and then the count at the start of `material`, and returns how many
/// bytes that is.
fn place<const N: usize>(
    material: &mut [u8; CAPACITY + COUNT_LEN],
    drawn: &[u8],
    count: [u8; COUNT_LEN],
) -> Option<usize> {
    let drawn = <&[u8; N]>::try_from(drawn).ok()?;
    let (head, rest) = material.split_first_chunk_mut::<N>()?;
    *head = *drawn;
    let (tail, _) = rest.split_first_chunk_mut::<COUNT_LEN>()?;
    *tail = count;
    N.checked_add(COUNT_LEN)
}

/// The platform's source hedged with the key of the epoch: what the source writes goes through
/// [`hedge`] before it reaches the buffer given, under the next count of draws. It remembers
/// whether the hedge failed, so that the failure is told from the source's.
pub(crate) struct Hedged<'h, E: ?Sized> {
    pub(crate) source: &'h mut E,
    pub(crate) epoch: &'h Key,
    pub(crate) drawn: &'h mut u64,
    pub(crate) branch: Branch,
    pub(crate) failed: bool,
}

impl<E: Entropy + ?Sized> Entropy for Hedged<'_, E> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        let mut raw = WipeOnDrop([0; CAPACITY]);
        let drawn = match raw.0.get_mut(..dest.len()) {
            Some(drawn) if matches!(drawn.len(), 12 | 16 | 32 | CAPACITY) => drawn,
            _ => {
                self.failed = true;
                return Err(EntropyError);
            }
        };
        self.source.fill(drawn)?;
        let count = *self.drawn;
        *self.drawn = count.wrapping_add(1);
        hedge(self.epoch, count, self.branch, drawn, dest).map_err(|DerivationFailed| {
            self.failed = true;
            EntropyError
        })
    }
}

/// Wipes the bytes when dropped, so that the wipe also runs when the source panics.
struct WipeOnDrop([u8; CAPACITY]);

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Wipes the stack below the caller's frame, as deep as a derivation reaches.
pub(crate) fn wipe_stack() {
    // The wipe ends in inline assembly, which Kani cannot model.
    #[cfg(not(kani))]
    zeroize::zeroize_stack::<STACK_WIPE>();
}

/// Wipes the stack below the caller's frame, as deep as the cipher reaches.
pub(crate) fn wipe_cipher_stack() {
    #[cfg(not(kani))]
    zeroize::zeroize_stack::<CIPHER_STACK_WIPE>();
}

/// The derivation itself, in a frame of its own: the wipe that follows starts where this frame
/// starts.
#[inline(never)]
fn derive_on_stack(
    key: &Key,
    salt: &[u8],
    purpose: Option<Purpose>,
    branch: Branch,
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    let (label, used) = label(purpose, length_to_byte(key.length()), branch, out.len())?;
    let info = label.get(..used).ok_or(DerivationFailed)?;
    let material = key.material().ok_or(DerivationFailed)?;
    hkdf(salt, material, info, out)
}

#[cfg(not(kani))]
fn hkdf(salt: &[u8], material: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), DerivationFailed> {
    Hkdf::<Sha256>::new(Some(salt), material)
        .expand(info, out)
        .map_err(|_| DerivationFailed)
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "a test computes offsets and the SHA-256 message schedule"
)]
pub(crate) mod stack {
    //! What a derivation leaves on the stack, read back from the memory of this process.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use hkdf::Hkdf;
    use sha2::{Digest, Sha256, block_api::compress256};

    use super::{
        Branch, Hedged, SALT, STACK_WIPE, derive, derive_on_stack, hedge, hedge_on_stack, label,
        purpose_of,
    };
    use crate::entropy::{Entropy, EntropyError};
    use crate::epoch::Epoch;
    use crate::key::{
        Key, KeyLength,
        tests::{Counting, counted},
    };
    use crate::record::Purpose;
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::slots::{Slot, Slots};

    /// A 64-byte key whose bytes appear nowhere else.
    fn key_bytes() -> [u8; 64] {
        core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(37).wrapping_add(11))
    }

    /// The initial state of SHA-256, FIPS 180-4, section 5.3.3.
    const IV: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    /// The round constants of SHA-256, FIPS 180-4, section 4.2.2.
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    /// An HMAC key block: `key` padded with zeros to 64 bytes, each byte combined with `pad` by
    /// exclusive or.
    fn key_block(key: &[u8], pad: u8) -> [u8; 64] {
        core::array::from_fn(|i| key.get(i).copied().unwrap_or(0) ^ pad)
    }

    /// The last block SHA-256 compresses for a message of one 64-byte block and then `tail`,
    /// shorter than 56 bytes: the tail, the end mark and the length in bits.
    fn final_block(tail: &[u8]) -> [u8; 64] {
        let mut block = [0; 64];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 0x80;
        let bits = u64::try_from(64 + tail.len()).unwrap() * 8;
        block[56..].copy_from_slice(&bits.to_be_bytes());
        block
    }

    /// The SHA-256 state after `blocks`, from the initial state.
    pub(crate) fn state_after(blocks: &[[u8; 64]]) -> [u32; 8] {
        let mut state = IV;
        compress256(&mut state, blocks);
        state
    }

    /// The message schedule SHA-256 computes for `block`, FIPS 180-4, section 6.2.2.
    fn schedule(block: &[u8; 64]) -> [u32; 64] {
        let mut w = [0_u32; 64];
        for (word, bytes) in w.iter_mut().zip(block.chunks(4)) {
            *word = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for i in 16..64 {
            let (a, b) = (w[i - 15], w[i - 2]);
            let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ a.wrapping_shr(3);
            let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ b.wrapping_shr(10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        w
    }

    /// Words as they sit in memory on either byte order.
    fn words_forms(words: &[u32]) -> [Vec<u8>; 2] {
        [
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
            words.iter().flat_map(|word| word.to_be_bytes()).collect(),
        ]
    }

    /// A state as it sits in memory: as eight words, and as the halves the SHA instructions of
    /// x86-64 keep it in on the way in, during the rounds and on the way out.
    pub(crate) fn state_forms(state: [u32; 8]) -> Vec<Vec<u8>> {
        let mut forms = Vec::from(words_forms(&state));
        for half in [
            [5, 4, 1, 0],
            [7, 6, 3, 2],
            [1, 0, 3, 2],
            [7, 6, 5, 4],
            [0, 1, 4, 5],
            [6, 7, 2, 3],
        ] {
            forms.extend(words_forms(&half.map(|word| state[word])));
        }
        forms
    }

    /// A hash output as bytes and as the words of the state it came from.
    pub(crate) fn hash_forms(hash: &[u8]) -> Vec<Vec<u8>> {
        let words: Vec<u32> = hash
            .chunks(4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
            .collect();
        let mut forms = std::vec![hash.to_vec()];
        forms.extend(state_forms(words.try_into().unwrap()));
        forms
    }

    /// A block a hash compresses, with its message schedule and the schedule plus the round
    /// constants, as they sit in memory.
    pub(crate) fn block_forms(block: &[u8; 64]) -> Vec<Vec<u8>> {
        let w = schedule(block);
        let with_constants: Vec<u32> = w.iter().zip(K).map(|(w, k)| w.wrapping_add(k)).collect();
        let mut forms = std::vec![block.to_vec()];
        forms.extend(words_forms(&w));
        forms.extend(words_forms(&with_constants));
        forms
    }

    /// The secrets a derivation of `branch` from the first `length` bytes of `key` handles: the
    /// key; in Extract, the state after the key and the inner hash; the extracted key, the HMAC key
    /// blocks made from it and the states after each, from which any value could be derived; in
    /// Expand, the inner hash; the message schedules of every secret block; and the first output
    /// block. Of an identifier, which the caller asks for, the plain bytes past its first byte only
    /// are counted, so that the identifier itself is not.
    pub(crate) fn secrets(
        key: &[u8],
        salt: &[u8],
        length: KeyLength,
        branch: Branch,
    ) -> Vec<Vec<u8>> {
        secrets_of(&key[..length.bytes()], salt, branch)
    }

    /// The same for a derivation of `branch` from the whole of `key`: a key of 16, 32 or 64 bytes,
    /// or the material of a hedge.
    pub(crate) fn secrets_of(key: &[u8], salt: &[u8], branch: Branch) -> Vec<Vec<u8>> {
        secrets_for(key, salt, branch, purpose_of(branch))
    }

    /// The same for a derivation for `purpose`, or for none.
    pub(crate) fn secrets_for(
        key: &[u8],
        salt: &[u8],
        branch: Branch,
        purpose: Option<Purpose>,
    ) -> Vec<Vec<u8>> {
        // A hedge takes the bytes drawn and an 8-byte count, and gives as many bytes as were drawn.
        let out_len = match branch {
            Branch::KeyId | Branch::HedgeWords | Branch::ArchiveCheck => 16,
            Branch::HedgeNonce => 12,
            Branch::HedgeKey | Branch::HedgeEncaps => key.len() - 8,
            Branch::ArchiveEncaps => 64,
            Branch::WrapKey
            | Branch::FromWords
            | Branch::LockKey
            | Branch::EpochLayer
            | Branch::Combined
            | Branch::Challenge
            | Branch::ExportKey
            | Branch::ArchiveKey
            | Branch::ArchiveLayer
            | Branch::ArchiveSeed
            | Branch::ArchiveSeal
            | Branch::ArchiveData => 32,
        };
        let length = u8::try_from(key.len()).unwrap();
        let (label, used) = label(purpose, length, branch, out_len).unwrap();
        let info = &label[..used];
        let (prk, expander) = Hkdf::<Sha256>::extract(Some(salt), key);
        let mut output = [0; 32];
        expander.expand(info, &mut output).unwrap();

        let salt_inner = key_block(salt, 0x36);
        let key_block_of_message: [u8; 64] = if key.len() < 64 {
            final_block(key)
        } else {
            key[..64].try_into().unwrap()
        };
        let extract_inner = Sha256::new()
            .chain_update(salt_inner)
            .chain_update(key)
            .finalize();
        let inner_block = key_block(&prk, 0x36);
        let outer_block = key_block(&prk, 0x5c);
        let expand_inner = Sha256::new()
            .chain_update(inner_block)
            .chain_update(info)
            .chain_update([1])
            .finalize();

        let mut secrets = std::vec![key.to_vec(), output[1..].to_vec()];
        // The salt of a wrap key and of a hedge is the key of an epoch, and that of a combined key a
        // key as well.
        if matches!(
            branch,
            Branch::WrapKey
                | Branch::HedgeKey
                | Branch::HedgeWords
                | Branch::HedgeNonce
                | Branch::Combined
        ) {
            secrets.extend(salt_secrets(salt));
        }
        secrets.extend(hash_forms(&prk));
        // Every form of the output but, for an identifier, the plain one, whose first 16 bytes are
        // the identifier.
        secrets.extend(
            hash_forms(&output)
                .into_iter()
                .enumerate()
                .filter(|&(form, _)| branch != Branch::KeyId || (form != 0 && form != 2))
                .map(|(_, bytes)| bytes),
        );
        secrets.extend(state_forms(state_after(&[
            salt_inner,
            key_block_of_message,
        ])));
        secrets.extend(hash_forms(&extract_inner));
        secrets.extend(state_forms(state_after(&[inner_block])));
        secrets.extend(state_forms(state_after(&[outer_block])));
        secrets.extend(hash_forms(&expand_inner));
        for block in [
            key_block_of_message,
            inner_block,
            outer_block,
            final_block(&extract_inner),
            final_block(&expand_inner),
        ] {
            secrets.extend(block_forms(&block));
        }
        secrets
    }

    /// What HMAC keyed with `salt` works with: the salt, its blocks padded for the inner and the
    /// outer hash, and the state after each.
    pub(crate) fn salt_secrets(salt: &[u8]) -> Vec<Vec<u8>> {
        let mut secrets = std::vec![salt.to_vec()];
        for block in [key_block(salt, 0x36), key_block(salt, 0x5c)] {
            secrets.extend(state_forms(state_after(&[block])));
            secrets.extend(block_forms(&block));
        }
        secrets
    }

    /// The pieces of the secrets of a derivation from the first `length` bytes of `key` that depend
    /// on the key.
    fn pieces(key: &[u8], length: KeyLength) -> Vec<Vec<u8>> {
        let other: [u8; 64] = core::array::from_fn(|i| key[i] ^ 0xff);
        key_dependent(
            &secrets(key, SALT, length, Branch::KeyId),
            &secrets(&other, SALT, length, Branch::KeyId),
        )
    }

    fn loaded_key() -> Key {
        let mut key = Key::empty();
        key.load64(&mut key_bytes());
        key
    }

    /// The test can see residue: the derivation without the wipe leaves some.
    #[test]
    fn a_derivation_without_the_wipe_leaves_residue() {
        let pieces = pieces(&key_bytes(), KeyLength::Bytes64);
        let key = loaded_key();
        let range = below_pad(false, || {
            let mut id = [0; 16];
            derive_on_stack(&key, SALT, None, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn a_derivation_leaves_no_residue() {
        let key = loaded_key();
        assert_clean(&pieces(&key_bytes(), KeyLength::Bytes64), || {
            let mut id = [0; 16];
            derive(&key, SALT, None, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
    }

    /// The key of the epoch these tests run under, with every bit of `flip` flipped in each byte;
    /// its bytes vary, so that the tests look for it.
    pub(crate) fn epoch_bytes(flip: u8) -> [u8; 32] {
        core::array::from_fn(|at| {
            u8::try_from(at)
                .unwrap()
                .wrapping_mul(53)
                .wrapping_add(0x6b)
                ^ flip
        })
    }

    fn hedge_epoch() -> Key {
        let mut key = Key::empty();
        key.load32(&mut epoch_bytes(0));
        key
    }

    /// The pieces of what a hedge of 32 bytes at count 3 works with that depend on those bytes:
    /// the bytes themselves and the secrets of their derivation.
    fn hedge_pieces() -> Vec<Vec<u8>> {
        let material = |drawn: &[u8]| {
            let mut material = drawn.to_vec();
            material.extend_from_slice(&3_u64.to_le_bytes());
            material
        };
        let drawn = key_bytes()[..32].to_vec();
        let other: Vec<u8> = drawn.iter().map(|byte| byte ^ 0xff).collect();
        let mut secrets = secrets_of(&material(&drawn), &epoch_bytes(0), Branch::HedgeKey);
        secrets.push(drawn);
        let mut others = secrets_of(&material(&other), &epoch_bytes(0xff), Branch::HedgeKey);
        others.push(other);
        key_dependent(&secrets, &others)
    }

    /// The test can see residue: a hedge without the wipe leaves some.
    #[test]
    fn a_hedge_without_the_wipe_leaves_residue() {
        let (epoch, drawn) = (hedge_epoch(), key_bytes());
        let mut out = [0; 32];
        let range = below_pad(false, || {
            hedge_on_stack(&epoch, 3, Branch::HedgeKey, &drawn[..32], &mut out).unwrap();
            black_box(&out);
        });
        assert!(residue(range, &hedge_pieces()) > 0);
    }

    /// The bytes drawn and the output are the caller's, above what is read.
    #[test]
    fn a_hedge_leaves_no_residue() {
        let (epoch, drawn) = (hedge_epoch(), key_bytes());
        let mut out = [0; 32];
        assert_clean(&hedge_pieces(), || {
            hedge(&epoch, 3, Branch::HedgeKey, &drawn[..32], &mut out).unwrap();
            black_box(&out);
        });
    }

    /// The bytes a panicking source writes, from a static, so that the source keeps no copy of them
    /// on the stack.
    static PANICKED: [u8; 32] = [
        0x8c, 0x31, 0xe7, 0x05, 0x6a, 0xd2, 0x49, 0xb0, 0x17, 0xfe, 0x63, 0x9a, 0x2d, 0xc4, 0x58,
        0x0b, 0x76, 0xe1, 0x3f, 0xa8, 0x92, 0x14, 0xcd, 0x60, 0xbb, 0x27, 0xf5, 0x4e, 0x81, 0x3a,
        0xdc, 0x99,
    ];

    struct Panicking;

    impl Entropy for Panicking {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&PANICKED[..dest.len()]);
            panic!("the source broke after writing")
        }
    }

    /// A source that panics after writing leaves none of its bytes in the hedge's buffer: the panic
    /// unwinds past a wipe of it. With optimisation the unwinding itself overwrites that place, so
    /// only a build without it can tell.
    #[test]
    fn a_panicking_source_leaves_no_bytes_in_the_hedge() {
        let other: Vec<u8> = PANICKED.iter().map(|byte| byte ^ 0xff).collect();
        let pieces = key_dependent(&[PANICKED.to_vec()], &[other]);
        let epoch = hedge_epoch();
        let mut drawn = 0;
        let mut out = [0; 32];
        assert_clean(&pieces, || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut hedged = Hedged {
                    source: &mut Panicking,
                    epoch: &epoch,
                    drawn: &mut drawn,
                    branch: Branch::HedgeKey,
                    failed: false,
                };
                let _ = hedged.fill(&mut out);
            }));
            assert!(outcome.is_err());
        });
        assert_eq!(drawn, 0, "a draw the source does not answer is not counted");
    }

    /// An output longer than HKDF gives fails after Extract, with the extracted key on the stack.
    #[test]
    fn a_failed_derivation_leaves_no_residue() {
        let pieces = pieces(&key_bytes(), KeyLength::Bytes64);
        let key = loaded_key();
        let unwiped = below_pad(false, || {
            let mut out = [0; 8161];
            assert!(derive_on_stack(&key, SALT, None, Branch::KeyId, &mut out).is_err());
            black_box(&out);
        });
        assert!(residue(unwiped, &pieces) > 0);
        assert_clean(&pieces, || {
            let mut out = [0; 8161];
            assert!(derive(&key, SALT, None, Branch::KeyId, &mut out).is_err());
            black_box(&out);
        });
    }

    #[test]
    fn importing_a_key_leaves_no_residue() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, 1, &mut [9; 32]);
        let mut long = key_bytes();
        assert_clean(&pieces(&key_bytes(), KeyLength::Bytes64), || {
            slots.import64(Purpose::Wrap, &mut long).unwrap();
        });
        let mut short: [u8; 32] = key_bytes()[..32].try_into().unwrap();
        assert_clean(&pieces(&key_bytes(), KeyLength::Bytes32), || {
            slots.import32(Purpose::Wrap, &mut short).unwrap();
        });
    }

    #[test]
    fn adding_a_key_leaves_no_residue() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, 1, &mut [9; 32]);
        let set = slots.import32(Purpose::ExternalData, &mut [3; 32]).unwrap();
        let mut short: [u8; 32] = key_bytes()[..32].try_into().unwrap();
        assert_clean(&pieces(&key_bytes(), KeyLength::Bytes32), || {
            slots.add32(set, &mut short).unwrap();
        });
    }

    #[test]
    fn adding_a_generated_key_leaves_no_residue() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, 1, &mut epoch_bytes(0));
        let set = slots.import32(Purpose::ExternalData, &mut [3; 32]).unwrap();
        for count in [0, 1] {
            assert_clean(&generation_pieces(count, KeyLength::Bytes32), || {
                slots
                    .add_generated(set, KeyLength::Bytes32, &mut Counting)
                    .unwrap();
            });
            slots.settle();
        }
    }

    /// What a generation from `drawn`, the bytes the source gave, at `count` under the epoch key
    /// `epoch` works with: those bytes, the key their hedge gives and the secrets of its
    /// identifier, and the secrets of the hedge itself, the key of the epoch among them.
    fn generation_secrets(drawn: &[u8], count: u64, epoch: &[u8; 32]) -> Vec<Vec<u8>> {
        let key = super::direct::hedged_directly(epoch, count, b"hedge key", drawn, drawn.len());
        let mut found = secrets_of(&key, SALT, Branch::KeyId);
        let mut material = drawn.to_vec();
        material.extend_from_slice(&count.to_le_bytes());
        found.extend(secrets_of(&material, epoch, Branch::HedgeKey));
        found.push(drawn.to_vec());
        found
    }

    /// The pieces of a generation by [`Counting`] under the epoch key of these tests that depend on
    /// the source and on that key.
    fn generation_pieces(count: u64, length: KeyLength) -> Vec<Vec<u8>> {
        let drawn = &counted::<64>()[..length.bytes()];
        let other: Vec<u8> = drawn.iter().map(|byte| byte ^ 0xff).collect();
        key_dependent(
            &generation_secrets(drawn, count, &epoch_bytes(0)),
            &generation_secrets(&other, count, &epoch_bytes(0xff)),
        )
    }

    #[test]
    fn generating_a_key_leaves_no_residue() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, 1, &mut epoch_bytes(0));
        for (count, length) in [(0, KeyLength::Bytes64), (1, KeyLength::Bytes32)] {
            assert_clean(&generation_pieces(count, length), || {
                slots
                    .generate(Purpose::Wrap, length, &mut Counting)
                    .unwrap();
            });
        }
    }

    /// The wipe that follows a derivation reaches as deep as it is meant to.
    #[test]
    fn the_wipe_reaches_its_depth() {
        let key = loaded_key();
        let wiped = depth_changed(|| {
            let mut id = [0; 16];
            derive(&key, SALT, None, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
        assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
    }

    /// The wipe covers more than the derivation uses.
    #[test]
    fn the_wipe_is_deeper_than_the_derivation() {
        let key = loaded_key();
        let used = depth_changed(|| {
            let mut id = [0; 16];
            derive_on_stack(&key, SALT, None, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
        std::println!("a derivation uses {used} bytes of stack");
        assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
        // Not needlessly deep either: a thread that cannot spare the stack would be corrupted. The
        // bound is wide: the path taken here may be lighter than another path in the build.
        assert!(used.saturating_mul(16) >= STACK_WIPE, "{used} bytes used");
    }
}

#[cfg(kani)]
use model::hkdf;

/// What stands in for HKDF-SHA-256 under Kani, and how the proofs read an identifier.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    use super::{DerivationFailed, KeyId, WORDS_ENTROPY_LEN};
    use crate::record::ID_LEN;

    /// Whether the last derivation failed, so a proof can tell a failure of the derivation from one
    /// the code makes up.
    static FAILED: AtomicBool = AtomicBool::new(false);
    /// How many derivations have failed, so a proof can tell whether any of several did.
    static FAILURES: AtomicU8 = AtomicU8::new(0);

    /// HKDF-SHA-256 is beyond Kani. The model fails at will, after writing into `out`, and records
    /// whether it failed; otherwise `out` takes the first bytes of the key, or zeros for a key
    /// shorter than `out`, with the key's length, the label and the first bytes of the salt folded
    /// in, so equal inputs give equal outputs, and the output depends on those bytes, that length,
    /// the label and the salt. Folding every byte of the key would be too slow for the solver; that
    /// HKDF uses the whole key and the output length, the unit tests check.
    pub(super) fn hkdf(
        salt: &[u8],
        material: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), DerivationFailed> {
        let fail: bool = kani::any();
        FAILED.store(fail, Ordering::Relaxed);
        if fail {
            FAILURES.store(
                FAILURES.load(Ordering::Relaxed).saturating_add(1),
                Ordering::Relaxed,
            );
            out.fill(0xa5);
            return Err(DerivationFailed);
        }
        fold(salt, material, info, out);
        Ok(())
    }

    /// The 16 bytes twelve words stand for, given twice: the derivation from words passes them so
    /// to the model, so that both halves of a 32-byte output take every byte.
    pub(crate) fn twice(entropy: &[u8; WORDS_ENTROPY_LEN]) -> [u8; 32] {
        let mut both = [0; 32];
        if let Some((first, second)) = both.split_first_chunk_mut::<WORDS_ENTROPY_LEN>() {
            *first = *entropy;
            second.copy_from_slice(entropy);
        }
        both
    }

    /// Whether the last derivation failed.
    pub(crate) fn failed() -> bool {
        FAILED.load(Ordering::Relaxed)
    }

    /// Whether any derivation has failed.
    pub(crate) fn any_failed() -> bool {
        FAILURES.load(Ordering::Relaxed) != 0
    }

    // Never indexing: a path that never derives would leave a check unreached. Copies have lengths
    // known at each call: Kani 0.68.0 reads stale bytes in a slice copy of unknown length. The
    // lengths derived are folded as numbers: byte by byte costs the proofs many times more.
    pub(crate) fn fold(salt: &[u8], material: &[u8], info: &[u8], out: &mut [u8]) {
        let mut label = [0; 32];
        if let Some(to) = label.get_mut(..info.len()) {
            to.copy_from_slice(info);
        }
        let (low, high) = label
            .split_first_chunk::<16>()
            .map_or((0, 0), |(low, high)| {
                let high = high
                    .first_chunk::<16>()
                    .map_or(0, |high| u128::from_ne_bytes(*high));
                (u128::from_ne_bytes(*low), high)
            });
        let head = |bytes: &[u8; 16]| u128::from_ne_bytes(*bytes);
        let salt_low = salt.first_chunk::<16>().map_or(0, head);
        let salt_high = salt
            .get(16..)
            .and_then(<[u8]>::first_chunk::<16>)
            .map_or(0, head);
        if let Ok(out) = <&mut [u8; 16]>::try_from(&mut *out) {
            let key = material.first_chunk::<16>().map_or(0, head);
            *out = (key ^ low ^ high ^ salt_low).to_ne_bytes();
        } else if let Ok(out) = <&mut [u8; 32]>::try_from(&mut *out) {
            let (first, second) = material
                .first_chunk::<32>()
                .and_then(|key| key.split_first_chunk::<16>())
                .map_or((0, 0), |(first, second)| {
                    (head(first), second.first_chunk::<16>().map_or(0, head))
                });
            if let Some((to_first, to_second)) = out.split_first_chunk_mut::<16>() {
                *to_first = (first ^ low ^ salt_low).to_ne_bytes();
                to_second.copy_from_slice(&(second ^ high ^ salt_high).to_ne_bytes());
            }
        } else if let Ok(out) = <&mut [u8; 64]>::try_from(&mut *out) {
            // Taken apart rather than indexed: a bounds check on a path a proof never takes would be
            // a check it never reaches.
            // A 32-byte key fills the first two lanes, so that it reaches a 64-byte output too.
            let [first, second, third, fourth] = material.first_chunk::<64>().map_or_else(
                || {
                    material.first_chunk::<32>().map_or([0; 4], |key| {
                        let (lanes, _) = key.as_chunks::<16>();
                        core::array::from_fn(|at| lanes.get(at).map_or(0, head))
                    })
                },
                |key| {
                    let (lanes, _) = key.as_chunks::<16>();
                    core::array::from_fn(|at| lanes.get(at).map_or(0, head))
                },
            );
            let folded = [
                first ^ low ^ salt_low,
                second ^ high ^ salt_high,
                third ^ low ^ salt_low,
                fourth ^ high ^ salt_high,
            ];
            for (to, lane) in out.as_chunks_mut::<16>().0.iter_mut().zip(folded) {
                *to = lane.to_ne_bytes();
            }
        } else if let Ok(out) = <&mut [u8; 12]>::try_from(&mut *out) {
            let mut key = [0; 16];
            if let (Some(to), Some(drawn)) = (key.first_chunk_mut::<12>(), material.first_chunk()) {
                *to = *drawn;
            }
            let folded = head(&key) ^ low ^ high ^ salt_low;
            if let Some(folded) = (folded ^ folded.wrapping_shr(96))
                .to_ne_bytes()
                .first_chunk::<12>()
            {
                *out = *folded;
            }
        } else {
            match material.get(..out.len()) {
                Some(head) => out.copy_from_slice(head),
                None => out.fill(0),
            }
            for piece in info.chunks(out.len().max(1)).chain([salt]) {
                for (target, &byte) in out.iter_mut().zip(piece) {
                    *target ^= byte;
                }
            }
        }
        if let Some(first) = out.first_mut() {
            *first ^= u8::try_from(material.len()).unwrap_or(u8::MAX);
        }
    }

    /// What stands in for the constant-time comparison of identifiers. As two numbers: comparing the
    /// arrays whole reads bytes from before the latest write in Kani 0.68.0, and byte by byte costs
    /// many times more.
    pub(crate) fn same_id(a: &[u8; ID_LEN], b: &[u8; ID_LEN]) -> bool {
        u128::from_ne_bytes(*a) == u128::from_ne_bytes(*b)
    }

    pub(crate) const fn id_bytes(id: &KeyId) -> &[u8; ID_LEN] {
        &id.0
    }

    pub(crate) const fn id_from_bytes(bytes: [u8; ID_LEN]) -> KeyId {
        KeyId(bytes)
    }
}

/// The label of one derivation from `length` bytes, and how many of its bytes are used. Every
/// field but the name has a fixed width, and the name, which comes last, is preceded by its length,
/// so two different derivations never share a label. A derivation for no purpose has zero there,
/// which no purpose is.
fn label(
    purpose: Option<Purpose>,
    length: u8,
    branch: Branch,
    out_len: usize,
) -> Result<([u8; LABEL_CAPACITY], usize), DerivationFailed> {
    let [low, high] = u16::try_from(out_len)
        .map_err(|_| DerivationFailed)?
        .to_le_bytes();
    let [p0, p1, p2, p3, p4, p5, p6, p7] = *PREFIX;
    let head = |name_len| {
        [
            p0,
            p1,
            p2,
            p3,
            p4,
            p5,
            p6,
            p7,
            VERSION,
            match purpose {
                Some(purpose) => purpose as u8,
                None => 0,
            },
            length,
            low,
            high,
            name_len,
        ]
    };
    match branch {
        Branch::KeyId => joined(head, KEY_ID),
        Branch::WrapKey => joined(head, WRAP_KEY),
        Branch::FromWords => joined(head, FROM_WORDS),
        Branch::HedgeKey => joined(head, HEDGE_KEY),
        Branch::HedgeWords => joined(head, HEDGE_WORDS),
        Branch::HedgeNonce => joined(head, HEDGE_NONCE),
        Branch::LockKey => joined(head, LOCK_KEY),
        Branch::EpochLayer => joined(head, EPOCH_LAYER),
        Branch::Combined => joined(head, COMBINED),
        Branch::Challenge => joined(head, CHALLENGE),
        Branch::ExportKey => joined(head, EXPORT_KEY),
        Branch::ArchiveKey => joined(head, ARCHIVE_KEY),
        Branch::ArchiveLayer => joined(head, ARCHIVE_LAYER),
        Branch::ArchiveSeed => joined(head, ARCHIVE_SEED),
        Branch::ArchiveSeal => joined(head, ARCHIVE_SEAL),
        Branch::HedgeEncaps => joined(head, HEDGE_ENCAPS),
        Branch::ArchiveEncaps => joined(head, ARCHIVE_ENCAPS),
        Branch::ArchiveData => joined(head, ARCHIVE_DATA),
        Branch::ArchiveCheck => joined(head, ARCHIVE_CHECK),
    }
}

/// A label of `head` and `name`, and how many of its bytes are used.
// Placed at fixed offsets rather than appended piece by piece: under the proofs a piece of a length
// known only at run time costs many times its bytes.
fn joined<const N: usize>(
    head: impl FnOnce(u8) -> [u8; HEAD_LEN],
    name: &[u8; N],
) -> Result<([u8; LABEL_CAPACITY], usize), DerivationFailed> {
    let name_len = u8::try_from(N).map_err(|_| DerivationFailed)?;
    let mut label = [0; LABEL_CAPACITY];
    let (first, rest) = label
        .split_first_chunk_mut::<HEAD_LEN>()
        .ok_or(DerivationFailed)?;
    *first = head(name_len);
    let (second, _) = rest.split_first_chunk_mut::<N>().ok_or(DerivationFailed)?;
    *second = *name;
    Ok((label, HEAD_LEN.checked_add(N).ok_or(DerivationFailed)?))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::{
        ARCHIVE_CHECK, ARCHIVE_DATA, ARCHIVE_ENCAPS, ARCHIVE_KEY, ARCHIVE_LAYER, ARCHIVE_SEAL,
        ARCHIVE_SEED, Branch, CHALLENGE, COMBINED, DerivationFailed, EPOCH_LAYER, EXPORT_KEY,
        FROM_WORDS, HEDGE_ENCAPS, HEDGE_KEY, HEDGE_NONCE, HEDGE_WORDS, Hedged, KEY_ID, KeyId,
        LOCK_KEY, SALT, WRAP_KEY, derive, derive_from_words, derive_key_id, hedge, label,
        purpose_of,
    };
    use crate::entropy::{Entropy, EntropyError};
    use crate::key::{Key, KeyLength};
    use crate::record::Purpose;

    /// Input key material, salt, info, and the expected output in hexadecimal.
    type Case<'a> = (&'a [u8], Option<&'a [u8]>, &'a [u8], &'a str);

    /// RFC 5869, appendix A, test cases 1 to 3: the primitive under the wrapper.
    #[test]
    fn hkdf_sha256_matches_rfc_5869() {
        let ikm22 = [0x0b; 22];
        let salt13: [u8; 13] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let info10: [u8; 10] =
            core::array::from_fn(|i| 0xf0_u8.wrapping_add(u8::try_from(i).unwrap()));
        let ikm80: [u8; 80] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let salt80: [u8; 80] =
            core::array::from_fn(|i| 0x60_u8.wrapping_add(u8::try_from(i).unwrap()));
        let info80: [u8; 80] =
            core::array::from_fn(|i| 0xb0_u8.wrapping_add(u8::try_from(i).unwrap()));
        let cases: [Case<'_>; 3] = [
            (
                &ikm22,
                Some(&salt13),
                &info10,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                &ikm80,
                Some(&salt80),
                &info80,
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac78272\
                 71cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f\
                 1d87",
            ),
            (
                &ikm22,
                Some(&[]),
                &[],
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, expected) in cases {
            let mut okm = [0; 82];
            let okm = &mut okm[..expected.len().checked_div(2).unwrap()];
            Hkdf::<Sha256>::new(salt, ikm).expand(info, okm).unwrap();
            assert_eq!(hex(okm), expected);
        }
    }

    #[test]
    fn the_label_is_laid_out_as_documented() {
        let (bytes, used) = label(None, 32, Branch::KeyId, 16).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 0, 32, 16, 0, 6]);
        expected.extend_from_slice(b"key id");
        assert_eq!(&bytes[..used], &expected[..]);

        let (bytes, used) = label(Some(Purpose::Wrap), 64, Branch::WrapKey, 32).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 1, 64, 32, 0, 8]);
        expected.extend_from_slice(b"wrap key");
        assert_eq!(&bytes[..used], &expected[..]);

        let (bytes, used) = label(Some(Purpose::ExternalData), 32, Branch::WrapKey, 32).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 2, 32, 32, 0, 8]);
        expected.extend_from_slice(b"wrap key");
        assert_eq!(&bytes[..used], &expected[..]);

        let (bytes, used) = label(Some(Purpose::Wrap), 16, Branch::FromWords, 32).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 1, 16, 32, 0, 10]);
        expected.extend_from_slice(b"from words");
        assert_eq!(&bytes[..used], &expected[..]);
    }

    /// Keys of both lengths whose bytes are all different: 0, 1, 2, ...
    fn counted_key(length: KeyLength) -> Key {
        let mut key = Key::empty();
        if length == KeyLength::Bytes32 {
            key.load32(&mut core::array::from_fn(|i| u8::try_from(i).unwrap()));
        } else {
            key.load64(&mut core::array::from_fn(|i| u8::try_from(i).unwrap()));
        }
        key
    }

    /// The wrapper against HKDF called directly with the salt and the label written out by hand,
    /// for both key lengths: the whole key goes in, and the label states its length.
    #[test]
    fn derivation_is_hkdf_with_the_salt_and_the_label() {
        for (length, length_byte) in [(KeyLength::Bytes32, 32_u8), (KeyLength::Bytes64, 64)] {
            let key = counted_key(length);
            let mut ours = [0; 16];
            derive(&key, SALT, None, Branch::KeyId, &mut ours).unwrap();

            let ikm: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
            let ikm = &ikm[..usize::from(length_byte)];
            let mut info = b"lethewis".to_vec();
            info.extend_from_slice(&[1, 0, length_byte, 16, 0, 6]);
            info.extend_from_slice(b"key id");
            let mut direct = [0; 16];
            Hkdf::<Sha256>::new(Some(b"lethewis derivation salt v1"), ikm)
                .expand(&info, &mut direct)
                .unwrap();
            assert_eq!(ours, direct, "{length:?}");
        }
    }

    /// The derivation from words against HKDF called directly with the salt and the label written
    /// out by hand: all 16 bytes go in, and the label states their length.
    #[test]
    fn a_derivation_from_words_is_hkdf_with_the_salt_and_its_label() {
        let entropy: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        for purpose in [Purpose::Wrap, Purpose::Transfer] {
            let mut ours = [0; 32];
            derive_from_words(&entropy, purpose, &mut ours).unwrap();
            let mut info = b"lethewis".to_vec();
            info.extend_from_slice(&[1, purpose as u8, 16, 32, 0, 10]);
            info.extend_from_slice(b"from words");
            let mut direct = [0; 32];
            Hkdf::<Sha256>::new(Some(b"lethewis derivation salt v1"), &entropy)
                .expand(&info, &mut direct)
                .unwrap();
            assert_eq!(ours, direct, "{purpose:?}");
        }
    }

    /// Outputs computed by an independent implementation of HKDF-SHA-256 from the documented salt
    /// and label: they fix the derivation for every key already written.
    #[test]
    fn derivations_match_known_answers() {
        let cases = [
            (
                KeyLength::Bytes32,
                Branch::KeyId,
                "68bb1b8348618f0510f27a95ebd2376e",
            ),
            (
                KeyLength::Bytes32,
                Branch::WrapKey,
                "b888ad072bde93503369146e95a5c4205a7ceff3f8063c2b4f3b6ab61abbb8cb",
            ),
            (
                KeyLength::Bytes64,
                Branch::KeyId,
                "f0bd9ee5de83598fb6cff4f1989a7823",
            ),
            (
                KeyLength::Bytes64,
                Branch::WrapKey,
                "36a276730fac754e12ca4c3b3a6cfdf685d2429d5347438ee3020107dfa668f2",
            ),
            (
                KeyLength::Bytes32,
                Branch::LockKey,
                "23f8b69ca6944ae73ae44d9c658de7c7524a81bbd2b36a9aad152c3b24b19eda",
            ),
            (
                KeyLength::Bytes64,
                Branch::LockKey,
                "45bb3bbe7c6432dbfab90f14d4d8a056eaff60c446ea42b871b1ac36b26bd533",
            ),
            (
                KeyLength::Bytes32,
                Branch::EpochLayer,
                "9703118a50323bc84eff5d6653e209d4822837684a270208b934c0d02da087eb",
            ),
            (
                KeyLength::Bytes32,
                Branch::Challenge,
                "0477373f3a3672a9f939bd9be82544eeccf23ab0b19b091e86b93ebb3ad348de",
            ),
            (
                KeyLength::Bytes32,
                Branch::ExportKey,
                "6aaf2c5908b557f37b9d8f978b7e1562d1ed11fe0140b4b0f141fdd84cc631eb",
            ),
        ];
        for (length, branch, expected) in cases {
            let mut out = [0; 32];
            let out = &mut out[..expected.len().checked_div(2).unwrap()];
            derive(&counted_key(length), SALT, purpose_of(branch), branch, out).unwrap();
            assert_eq!(hex(out), expected, "{length:?} {branch:?}");
        }
    }

    /// A combined key against an independent implementation of HKDF-SHA-256: the key from a
    /// secret, of either length, goes in, with the 32 bytes of the other key as the salt.
    #[test]
    fn a_combined_key_matches_known_answers() {
        let mut salt = Key::empty();
        salt.load32(&mut core::array::from_fn(|i| 64 + u8::try_from(i).unwrap()));
        for (length, expected) in [
            (
                KeyLength::Bytes32,
                "d3bcd5a6261170da7661346c8ee46c257579fd9ba0b4b5bfa08d25c372af1869",
            ),
            (
                KeyLength::Bytes64,
                "2e7a0e4937b3ceb87d5015a733a6c8b30e03778b65d404f57996887d4498e5b1",
            ),
        ] {
            let mut out = [0; 32];
            super::derive_combined(&counted_key(length), &salt, &mut out).unwrap();
            assert_eq!(hex(&out), expected, "{length:?}");
        }
    }

    /// A length no hedge takes fails as a hedge, before the source is asked and with no draw
    /// counted.
    #[test]
    fn a_length_no_hedge_takes_asks_nothing_of_the_source() {
        struct Asked(bool);

        impl Entropy for Asked {
            fn fill(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
                self.0 = true;
                Ok(())
            }
        }

        let epoch = hedge_epoch();
        for length in [0, 8, 20, 33, 65] {
            let (mut source, mut drawn) = (Asked(false), 0);
            let mut hedged = Hedged {
                source: &mut source,
                epoch: &epoch,
                drawn: &mut drawn,
                branch: Branch::HedgeKey,
                failed: false,
            };
            assert!(hedged.fill(&mut std::vec![0; length]).is_err());
            assert!(hedged.failed, "{length} bytes");
            assert!(!source.0 && drawn == 0, "{length} bytes");
        }
    }

    /// The key of an epoch whose bytes are 0x40, 0x41, ... 0x5f.
    fn hedge_epoch() -> Key {
        let mut key = Key::empty();
        key.load32(&mut core::array::from_fn(|i| {
            0x40_u8.wrapping_add(u8::try_from(i).unwrap())
        }));
        key
    }

    /// Hedges computed by an independent implementation of HKDF-SHA-256 from the documented salt,
    /// material and label, for each use and length the library draws.
    #[test]
    fn hedges_match_known_answers() {
        let cases = [
            (
                Branch::HedgeKey,
                32,
                5,
                "e4214206964aa889fb9173f1e5a20087076969a7660f4857e0cfc1343a1294ab",
            ),
            (
                Branch::HedgeKey,
                64,
                0,
                "c7efe2d49ed202b046efad802c86c22d3e47e7509b63fd4808702229057b458a\
                 b529952b1792bff31ec14992d6338c97452ce2990eb2764f9d5148c7059c33ce",
            ),
            (
                Branch::HedgeWords,
                16,
                1,
                "657df1779625afcaef46cc1c9357c837",
            ),
            (Branch::HedgeNonce, 12, 2, "a6ebbfae7d7b819bd43e7836"),
        ];
        for (branch, length, count, expected) in cases {
            let drawn: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
            let mut out = [0; 64];
            hedge(
                &hedge_epoch(),
                count,
                branch,
                &drawn[..length],
                &mut out[..length],
            )
            .unwrap();
            assert_eq!(hex(&out[..length]), expected, "{branch:?}");
        }
    }

    /// A hedge is HKDF with the key of the epoch as the salt, the bytes drawn followed by the count
    /// as the material, and the label written out by hand; another count, use or epoch key gives
    /// another value.
    #[test]
    fn a_hedge_is_hkdf_of_the_bytes_and_the_count_under_the_key_of_the_epoch() {
        let drawn = [7; 32];
        let mut ours = [0; 32];
        hedge(&hedge_epoch(), 9, Branch::HedgeKey, &drawn, &mut ours).unwrap();
        let mut material = drawn.to_vec();
        material.extend_from_slice(&9_u64.to_le_bytes());
        let mut info = b"lethewis".to_vec();
        info.extend_from_slice(&[1, 0, 40, 32, 0, 9]);
        info.extend_from_slice(b"hedge key");
        let salt: [u8; 32] =
            core::array::from_fn(|i| 0x40_u8.wrapping_add(u8::try_from(i).unwrap()));
        let mut direct = [0; 32];
        Hkdf::<Sha256>::new(Some(&salt), &material)
            .expand(&info, &mut direct)
            .unwrap();
        assert_eq!(ours, direct);
        let mut other = [0; 32];
        hedge(&hedge_epoch(), 10, Branch::HedgeKey, &drawn, &mut other).unwrap();
        assert_ne!(other, ours, "another count");
        hedge(&hedge_epoch(), 9, Branch::HedgeWords, &drawn, &mut other).unwrap();
        assert_ne!(other, ours, "another use");
        let mut epoch = Key::empty();
        epoch.load32(&mut [3; 32]);
        hedge(&epoch, 9, Branch::HedgeKey, &drawn, &mut other).unwrap();
        assert_ne!(other, ours, "another key of the epoch");
    }

    #[test]
    fn branches_and_output_lengths_give_unrelated_values() {
        let mut key = Key::empty();
        key.load32(&mut [7; 32]);
        let mut id = [0; 32];
        let mut wrap = [0; 32];
        let mut short = [0; 16];
        derive(&key, SALT, None, Branch::KeyId, &mut id).unwrap();
        derive(&key, SALT, Some(Purpose::Wrap), Branch::WrapKey, &mut wrap).unwrap();
        derive(&key, SALT, None, Branch::KeyId, &mut short).unwrap();
        assert_ne!(id, wrap);
        assert_ne!(id[..16], short);
    }

    /// The label states the key length, and Extract takes the key as a message rather than as an
    /// HMAC key, which would pad a short key with zeros: either keeps a key and its zero-padded
    /// long form apart.
    #[test]
    fn a_short_key_and_its_zero_padded_long_form_differ() {
        let mut short = Key::empty();
        short.load32(&mut [7; 32]);
        let mut padded = [0; 64];
        padded[..32].fill(7);
        let mut long = Key::empty();
        long.load64(&mut padded);
        let mut from_short = [0; 16];
        let mut from_long = [0; 16];
        derive(&short, SALT, None, Branch::KeyId, &mut from_short).unwrap();
        derive(&long, SALT, None, Branch::KeyId, &mut from_long).unwrap();
        assert_ne!(from_short, from_long);
    }

    #[test]
    fn take_moves_the_identifier_and_wipes_the_source() {
        let key = counted_key(KeyLength::Bytes64);
        let mut expected = KeyId::empty();
        derive_key_id(&key, &mut expected).unwrap();
        let mut source = KeyId::empty();
        derive_key_id(&key, &mut source).unwrap();
        let mut target = KeyId::empty();
        target.take(&mut source);
        assert_eq!(target, expected);
        assert_eq!(source, KeyId::empty());
        assert_ne!(target, KeyId::empty());
    }

    #[test]
    fn every_branch_has_a_label() {
        for branch in [
            Branch::KeyId,
            Branch::WrapKey,
            Branch::FromWords,
            Branch::HedgeKey,
            Branch::HedgeWords,
            Branch::HedgeNonce,
            Branch::LockKey,
            Branch::EpochLayer,
            Branch::Combined,
            Branch::Challenge,
            Branch::ExportKey,
            Branch::ArchiveKey,
            Branch::ArchiveLayer,
            Branch::ArchiveSeed,
            Branch::ArchiveSeal,
            Branch::HedgeEncaps,
            Branch::ArchiveEncaps,
            Branch::ArchiveData,
            Branch::ArchiveCheck,
        ] {
            let (_, used) = label(purpose_of(branch), 64, branch, 32).unwrap();
            let name = match branch {
                Branch::KeyId => KEY_ID.len(),
                Branch::WrapKey => WRAP_KEY.len(),
                Branch::FromWords => FROM_WORDS.len(),
                Branch::HedgeKey => HEDGE_KEY.len(),
                Branch::HedgeWords => HEDGE_WORDS.len(),
                Branch::HedgeNonce => HEDGE_NONCE.len(),
                Branch::LockKey => LOCK_KEY.len(),
                Branch::EpochLayer => EPOCH_LAYER.len(),
                Branch::Combined => COMBINED.len(),
                Branch::Challenge => CHALLENGE.len(),
                Branch::ExportKey => EXPORT_KEY.len(),
                Branch::ArchiveKey => ARCHIVE_KEY.len(),
                Branch::ArchiveLayer => ARCHIVE_LAYER.len(),
                Branch::ArchiveSeed => ARCHIVE_SEED.len(),
                Branch::ArchiveSeal => ARCHIVE_SEAL.len(),
                Branch::HedgeEncaps => HEDGE_ENCAPS.len(),
                Branch::ArchiveEncaps => ARCHIVE_ENCAPS.len(),
                Branch::ArchiveData => ARCHIVE_DATA.len(),
                Branch::ArchiveCheck => ARCHIVE_CHECK.len(),
            };
            assert_eq!(used, 14 + name);
        }
    }

    #[test]
    fn a_label_states_any_output_length_of_two_bytes() {
        assert!(label(None, 32, Branch::KeyId, 65_535).is_ok());
        assert!(label(None, 32, Branch::KeyId, 65_536).is_err());
    }

    #[test]
    fn an_output_longer_than_hkdf_gives_is_refused() {
        let key = counted_key(KeyLength::Bytes32);
        assert!(derive(&key, SALT, None, Branch::KeyId, &mut [0; 8160]).is_ok());
        let mut out = [9; 8161];
        assert_eq!(
            derive(&key, SALT, None, Branch::KeyId, &mut out),
            Err(DerivationFailed)
        );
        assert!(out.iter().all(|&byte| byte == 9));
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").unwrap();
            text
        })
    }
}

#[cfg(kani)]
#[coverage(on)]
pub(crate) mod proofs {
    use super::{
        Branch, CIPHER_KEY_LEN, SALT, WORDS_ENTROPY_LEN, label,
        model::{fold, twice},
    };
    use crate::key::KeyLength;
    use crate::record::{ID_LEN, Purpose, length_to_byte};

    /// The identifier the model of HKDF gives for the first `length` bytes of `key`, worked out
    /// from the label alone, without a `Key` and without `derive`: the same for every purpose.
    pub(crate) fn expected_key_id(key: &[u8; 64], length: KeyLength) -> [u8; ID_LEN] {
        let mut id = [0; ID_LEN];
        let _ = label(None, length_to_byte(length), Branch::KeyId, ID_LEN).map(|(label, used)| {
            fold(SALT, &key[..length.bytes()], &label[..used], &mut id);
        });
        id
    }

    /// The key the model of HKDF gives the outer layer of the record of an archive key from the
    /// first `length` bytes of the stored key for wrapping `key` in the epoch whose key is `epoch`,
    /// worked out in the same way.
    pub(crate) fn expected_archive_layer_key(
        key: &[u8; 64],
        length: KeyLength,
        epoch: &[u8; 32],
    ) -> [u8; CIPHER_KEY_LEN] {
        let mut out = [0; CIPHER_KEY_LEN];
        let length_byte = length_to_byte(length);
        let _ = label(
            Some(Purpose::Wrap),
            length_byte,
            Branch::ArchiveLayer,
            CIPHER_KEY_LEN,
        )
        .map(|(label, used)| {
            fold(epoch, &key[..length.bytes()], &label[..used], &mut out);
        });
        out
    }

    /// The key the model of HKDF gives a record's cipher from the first `length` bytes of the
    /// wrapping key `key` in the epoch whose key is `epoch`, worked out in the same way.
    pub(crate) fn expected_wrap_key(
        key: &[u8; 64],
        length: KeyLength,
        epoch: &[u8; 32],
    ) -> [u8; CIPHER_KEY_LEN] {
        let mut out = [0; CIPHER_KEY_LEN];
        let length_byte = length_to_byte(length);
        let _ = label(
            Some(Purpose::Wrap),
            length_byte,
            Branch::WrapKey,
            CIPHER_KEY_LEN,
        )
        .map(|(label, used)| {
            fold(epoch, &key[..length.bytes()], &label[..used], &mut out);
        });
        out
    }

    /// The key the model of HKDF gives the records the key from a secret `key`, of `length`, locks,
    /// worked out in the same way.
    pub(crate) fn expected_lock_key(key: &[u8; 64], length: KeyLength) -> [u8; CIPHER_KEY_LEN] {
        let mut out = [0; CIPHER_KEY_LEN];
        let length_byte = length_to_byte(length);
        let _ = label(
            Some(Purpose::Wrap),
            length_byte,
            Branch::LockKey,
            CIPHER_KEY_LEN,
        )
        .map(|(label, used)| {
            fold(SALT, &key[..length.bytes()], &label[..used], &mut out);
        });
        out
    }

    /// The key from a secret the model of HKDF gives from the first `length` bytes of `key` and the
    /// 32 bytes of `salt`, worked out in the same way.
    pub(crate) fn expected_combined(
        key: &[u8; 64],
        length: KeyLength,
        salt: &[u8; 32],
    ) -> [u8; 32] {
        let mut out = [0; 32];
        let _ = label(
            Some(Purpose::Wrap),
            length_to_byte(length),
            Branch::Combined,
            32,
        )
        .map(|(label, used)| {
            fold(salt, &key[..length.bytes()], &label[..used], &mut out);
        });
        out
    }

    /// The challenge the model of HKDF gives from the first `length` bytes of `key`, worked out in
    /// the same way.
    pub(crate) fn expected_challenge(key: &[u8; 64], length: KeyLength) -> [u8; 32] {
        let mut out = [0; 32];
        let _ = label(None, length_to_byte(length), Branch::Challenge, 32).map(|(label, used)| {
            fold(SALT, &key[..length.bytes()], &label[..used], &mut out);
        });
        out
    }

    /// The key the model of HKDF gives the outer layer of lock records in the epoch whose key is
    /// `epoch`, worked out in the same way.
    pub(crate) fn expected_layer_key(epoch: &[u8; 32]) -> [u8; CIPHER_KEY_LEN] {
        let mut out = [0; CIPHER_KEY_LEN];
        let _ = label(Some(Purpose::Wrap), 32, Branch::EpochLayer, CIPHER_KEY_LEN).map(
            |(label, used)| {
                fold(SALT, epoch, &label[..used], &mut out);
            },
        );
        out
    }

    /// The key the model of HKDF gives the inner layer of the record of an archive key from the
    /// stored key of the archive `key`, worked out in the same way.
    pub(crate) fn expected_archive_key(key: &[u8; 32]) -> [u8; CIPHER_KEY_LEN] {
        let mut out = [0; CIPHER_KEY_LEN];
        let _ = label(
            Some(Purpose::ArchiveWrap),
            32,
            Branch::ArchiveKey,
            CIPHER_KEY_LEN,
        )
        .map(|(label, used)| {
            fold(SALT, key, &label[..used], &mut out);
        });
        out
    }

    /// The key the model of HKDF gives the records of an archive under the key of a chat for its
    /// archive `key`, worked out in the same way.
    pub(crate) fn expected_archive_seal_key(key: &[u8; 32]) -> [u8; CIPHER_KEY_LEN] {
        let mut out = [0; CIPHER_KEY_LEN];
        let _ = label(
            Some(Purpose::ArchiveSeal),
            32,
            Branch::ArchiveSeal,
            CIPHER_KEY_LEN,
        )
        .map(|(label, used)| {
            fold(SALT, key, &label[..used], &mut out);
        });
        out
    }

    /// The randomness of an encapsulation the model of HKDF gives from `hedged` and the key of a
    /// chat for its archive `key`, worked out in the same way.
    pub(crate) fn expected_archive_randomness(key: &[u8; 32], hedged: &[u8; 64]) -> [u8; 64] {
        let mut out = [0; 64];
        let _ = label(Some(Purpose::ArchiveSeal), 32, Branch::ArchiveEncaps, 64).map(
            |(label, used)| {
                fold(hedged, key, &label[..used], &mut out);
            },
        );
        out
    }

    /// The check of a shared secret the model of HKDF gives from `shared` and a ciphertext that
    /// begins with `ciphertext`, as far as the model reads it, worked out in the same way.
    pub(crate) fn expected_archive_check(shared: &[u8; 32], ciphertext: &[u8; 32]) -> [u8; ID_LEN] {
        let mut out = [0; ID_LEN];
        let _ =
            label(Some(Purpose::Archive), 32, Branch::ArchiveCheck, ID_LEN).map(|(label, used)| {
                fold(ciphertext, shared, &label[..used], &mut out);
            });
        out
    }

    /// The key of a batch the model of HKDF gives from the shared secret `shared` and a ciphertext
    /// that begins with `ciphertext`, as far as the model reads it, worked out in the same way.
    pub(crate) fn expected_archive_data(shared: &[u8; 32], ciphertext: &[u8; 32]) -> [u8; 32] {
        let mut out = [0; 32];
        let _ = label(Some(Purpose::Archive), 32, Branch::ArchiveData, 32).map(|(label, used)| {
            fold(ciphertext, shared, &label[..used], &mut out);
        });
        out
    }

    /// The key the model of HKDF gives the records of an export, and the record that ends one,
    /// from the key for transfers `key`, worked out in the same way.
    pub(crate) fn expected_export_key(key: &[u8; 32]) -> [u8; CIPHER_KEY_LEN] {
        let mut out = [0; CIPHER_KEY_LEN];
        let _ = label(
            Some(Purpose::Transfer),
            32,
            Branch::ExportKey,
            CIPHER_KEY_LEN,
        )
        .map(|(label, used)| {
            fold(SALT, key, &label[..used], &mut out);
        });
        out
    }

    /// The key for `purpose` the model of HKDF gives from the bytes twelve words stand for, worked
    /// out in the same way.
    pub(crate) fn expected_words_key(
        bytes: &[u8; WORDS_ENTROPY_LEN],
        purpose: Purpose,
    ) -> [u8; 32] {
        let mut out = [0; 32];
        let length = WORDS_ENTROPY_LEN as u8;
        let _ = label(Some(purpose), length, Branch::FromWords, 32).map(|(label, used)| {
            fold(SALT, &twice(bytes), &label[..used], &mut out);
        });
        out
    }

    fn any_branch() -> Branch {
        match kani::any::<u8>() {
            0 => Branch::KeyId,
            1 => Branch::WrapKey,
            2 => Branch::FromWords,
            3 => Branch::HedgeKey,
            4 => Branch::HedgeWords,
            5 => Branch::HedgeNonce,
            6 => Branch::LockKey,
            7 => Branch::EpochLayer,
            8 => Branch::Combined,
            9 => Branch::Challenge,
            10 => Branch::ExportKey,
            11 => Branch::ArchiveKey,
            12 => Branch::ArchiveLayer,
            13 => Branch::ArchiveSeed,
            14 => Branch::ArchiveSeal,
            15 => Branch::HedgeEncaps,
            16 => Branch::ArchiveEncaps,
            17 => Branch::ArchiveData,
            _ => Branch::ArchiveCheck,
        }
    }

    /// What the model of HKDF gives a hedge of the `N` bytes `drawn` under the epoch key `epoch` at
    /// `count`, for `branch`: the bytes and then the count, eight bytes, least significant first,
    /// as the material, worked out in the same way.
    pub(crate) fn expected_hedge<const N: usize>(
        epoch: &[u8; 32],
        count: u64,
        branch: Branch,
        drawn: &[u8; N],
    ) -> [u8; N] {
        let mut material = [0; 72];
        material[..N].copy_from_slice(drawn);
        material[N..N + 8].copy_from_slice(&count.to_le_bytes());
        let mut out = [0; N];
        let _ = label(None, (N + 8) as u8, branch, N).map(|(label, used)| {
            fold(epoch, &material[..N + 8], &label[..used], &mut out);
        });
        out
    }

    /// Any purpose, or none.
    fn any_purpose() -> Option<Purpose> {
        match kani::any::<u8>() {
            0 => None,
            1 => Some(Purpose::Wrap),
            2 => Some(Purpose::ExternalData),
            3 => Some(Purpose::Transfer),
            4 => Some(Purpose::Archive),
            5 => Some(Purpose::ArchiveWrap),
            _ => Some(Purpose::ArchiveSeal),
        }
    }

    /// Two derivations that differ in anything the label states never share a label.
    #[kani::proof]
    #[kani::unwind(32)]
    fn different_derivations_have_different_labels() {
        let (purpose_a, length_a, branch_a, out_a): (Option<Purpose>, u8, Branch, u16) =
            (any_purpose(), kani::any(), any_branch(), kani::any());
        let (purpose_b, length_b, branch_b, out_b): (Option<Purpose>, u8, Branch, u16) =
            (any_purpose(), kani::any(), any_branch(), kani::any());
        let a = label(purpose_a, length_a, branch_a, usize::from(out_a));
        let b = label(purpose_b, length_b, branch_b, usize::from(out_b));
        kani::assert(
            a.is_ok() && b.is_ok(),
            "a label of an output length that fits in two bytes is always built",
        );
        if let (Ok((bytes_a, used_a)), Ok((bytes_b, used_b))) = (a, b)
            && (purpose_a, length_a, branch_a, out_a) != (purpose_b, length_b, branch_b, out_b)
        {
            kani::assert(
                used_a != used_b || bytes_a[..used_a] != bytes_b[..used_b],
                "different derivations have different labels",
            );
        }
        kani::cover!(
            purpose_a != purpose_b && purpose_a.is_some() && purpose_b.is_some(),
            "two purposes"
        );
        kani::cover!(
            purpose_a.is_none() && purpose_b.is_some() && branch_a == branch_b,
            "a purpose and none"
        );
        kani::cover!(branch_a != branch_b, "two branches");
        kani::cover!(
            length_a != length_b && branch_a == branch_b,
            "two key lengths"
        );
        kani::cover!(
            out_a != out_b && length_a == length_b && branch_a == branch_b,
            "two output lengths"
        );
    }
}
