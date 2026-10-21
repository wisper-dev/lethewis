// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(kani))]
use aes_gcm_siv::{
    Aes256GcmSiv, KeyInit, Nonce,
    aead::{AeadInOut, inout::InOutBuf},
};

use crate::key::wipe;
use crate::record::PLAINTEXT_LEN;

/// The size of the key a record is encrypted with, in bytes.
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

/// Nothing was encrypted: the cipher refused the input, or it gave a known input a wrong answer, so
/// this build or this processor does not compute AES-256-GCM-SIV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SealFailed;

/// The record does not open under this key, nonce and associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rejected;

/// AES-256-GCM-SIV, as the calls of the slots seal and open with it: [`seal`] and [`open`].
pub(crate) struct Aes;

/// An input of the shape of a record, and what AES-256-GCM-SIV makes of it.
struct Known {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: &'static [u8],
    plaintext: [u8; PLAINTEXT_LEN],
    ciphertext: [u8; PLAINTEXT_LEN],
    tag: [u8; TAG_LEN],
}

/// Computed by an implementation of RFC 8452 that shares no code with this one and gives the
/// vectors of its appendices C.2 and C.3.
#[rustfmt::skip]
const KNOWN: Known = Known {
    key: [
        0x03, 0x20, 0x3d, 0x5a, 0x77, 0x94, 0xb1, 0xce, 0xeb, 0x08, 0x25, 0x42,
        0x5f, 0x7c, 0x99, 0xb6, 0xd3, 0xf0, 0x0d, 0x2a, 0x47, 0x64, 0x81, 0x9e,
        0xbb, 0xd8, 0xf5, 0x12, 0x2f, 0x4c, 0x69, 0x86,
    ],
    nonce: [
        0x07, 0x14, 0x21, 0x2e, 0x3b, 0x48, 0x55, 0x62, 0x6f, 0x7c, 0x89, 0x96,
    ],
    aad: b"lethewis self-test v1",
    plaintext: [
        0x05, 0x10, 0x1b, 0x26, 0x31, 0x3c, 0x47, 0x52, 0x5d, 0x68, 0x73, 0x7e,
        0x89, 0x94, 0x9f, 0xaa, 0xb5, 0xc0, 0xcb, 0xd6, 0xe1, 0xec, 0xf7, 0x02,
        0x0d, 0x18, 0x23, 0x2e, 0x39, 0x44, 0x4f, 0x5a, 0x65, 0x70, 0x7b, 0x86,
        0x91, 0x9c, 0xa7, 0xb2, 0xbd, 0xc8, 0xd3, 0xde, 0xe9, 0xf4, 0xff, 0x0a,
        0x15, 0x20, 0x2b, 0x36, 0x41, 0x4c, 0x57, 0x62, 0x6d, 0x78, 0x83, 0x8e,
        0x99, 0xa4, 0xaf, 0xba, 0xc5, 0xd0, 0xdb, 0xe6, 0xf1, 0xfc, 0x07, 0x12,
        0x1d, 0x28, 0x33, 0x3e, 0x49, 0x54, 0x5f, 0x6a, 0x75, 0x80, 0x8b, 0x96,
        0xa1, 0xac, 0xb7, 0xc2, 0xcd, 0xd8, 0xe3, 0xee, 0xf9, 0x04, 0x0f, 0x1a,
        0x25, 0x30, 0x3b, 0x46, 0x51, 0x5c, 0x67, 0x72, 0x7d, 0x88, 0x93, 0x9e,
        0xa9, 0xb4, 0xbf, 0xca, 0xd5, 0xe0, 0xeb, 0xf6, 0x01, 0x0c, 0x17, 0x22,
        0x2d, 0x38, 0x43, 0x4e, 0x59, 0x64, 0x6f, 0x7a, 0x85, 0x90, 0x9b, 0xa6,
        0xb1, 0xbc, 0xc7, 0xd2, 0xdd, 0xe8, 0xf3, 0xfe, 0x09, 0x14, 0x1f, 0x2a,
        0x35, 0x40, 0x4b, 0x56, 0x61, 0x6c, 0x77, 0x82, 0x8d, 0x98, 0xa3, 0xae,
        0xb9, 0xc4, 0xcf, 0xda, 0xe5, 0xf0, 0xfb, 0x06, 0x11, 0x1c, 0x27, 0x32,
        0x3d, 0x48, 0x53, 0x5e, 0x69, 0x74, 0x7f, 0x8a, 0x95, 0xa0, 0xab, 0xb6,
        0xc1, 0xcc, 0xd7, 0xe2, 0xed, 0xf8, 0x03, 0x0e, 0x19, 0x24, 0x2f, 0x3a,
        0x45, 0x50, 0x5b, 0x66, 0x71, 0x7c, 0x87, 0x92, 0x9d, 0xa8, 0xb3, 0xbe,
        0xc9, 0xd4, 0xdf, 0xea, 0xf5, 0x00, 0x0b, 0x16, 0x21, 0x2c, 0x37, 0x42,
        0x4d, 0x58, 0x63, 0x6e, 0x79, 0x84, 0x8f, 0x9a, 0xa5, 0xb0, 0xbb, 0xc6,
        0xd1, 0xdc, 0xe7, 0xf2, 0xfd,
    ],
    ciphertext: [
        0x36, 0x39, 0xf5, 0x1a, 0x6f, 0xc4, 0x50, 0x83, 0xfc, 0x53, 0x31, 0x03,
        0x57, 0x29, 0x29, 0x4f, 0xd5, 0x0e, 0x2f, 0x25, 0xc2, 0x3d, 0xb6, 0xfe,
        0x3b, 0x56, 0x04, 0x61, 0x66, 0x55, 0xa6, 0xb7, 0x52, 0xc4, 0x80, 0x3e,
        0x8c, 0x4a, 0x05, 0xd1, 0x97, 0x1a, 0xdc, 0x29, 0x64, 0x27, 0x51, 0x10,
        0xc4, 0xea, 0x35, 0x2c, 0xaf, 0xd0, 0xdf, 0xa3, 0xcc, 0x18, 0x20, 0x29,
        0x16, 0x7b, 0x64, 0xea, 0x5e, 0x1b, 0xf0, 0x23, 0x16, 0x9a, 0x03, 0x29,
        0x56, 0xa0, 0x61, 0xdf, 0x1f, 0xda, 0xfd, 0xe2, 0x94, 0xdc, 0xa9, 0xe0,
        0x5f, 0x0c, 0xfb, 0xe8, 0x94, 0x24, 0xf3, 0xad, 0x0f, 0xb7, 0x7b, 0x85,
        0x52, 0x86, 0x4f, 0x92, 0xa2, 0xd0, 0x9f, 0x6c, 0x49, 0x18, 0x58, 0xe7,
        0xc1, 0xfb, 0x3b, 0x95, 0xbc, 0xf3, 0xad, 0xf1, 0x44, 0x3f, 0x8d, 0x3e,
        0xb0, 0x92, 0xc3, 0xd2, 0xd3, 0xa9, 0xde, 0x81, 0xce, 0xda, 0xf6, 0xde,
        0x11, 0xef, 0x6b, 0xb6, 0x70, 0x63, 0xaf, 0xce, 0xeb, 0x2d, 0xfd, 0x6b,
        0x27, 0x8a, 0xcb, 0xac, 0x0d, 0x37, 0xc4, 0x79, 0x77, 0x8d, 0xac, 0x58,
        0xb8, 0x19, 0x62, 0xb5, 0x08, 0x53, 0x05, 0x46, 0xc6, 0x11, 0x4f, 0x63,
        0x6f, 0x1d, 0x72, 0x4a, 0x6b, 0x31, 0x1c, 0x03, 0x0d, 0xeb, 0x94, 0x56,
        0x46, 0x67, 0x47, 0x5c, 0xea, 0x73, 0x20, 0xa2, 0x3a, 0x26, 0x55, 0xfa,
        0x71, 0x5e, 0x48, 0xe3, 0xfc, 0xde, 0x5f, 0xaa, 0x9b, 0xcd, 0x42, 0x1a,
        0x73, 0x82, 0x99, 0xb8, 0x50, 0xc0, 0x9c, 0x98, 0x78, 0x49, 0x2f, 0xc8,
        0x7a, 0x64, 0xe7, 0x44, 0x32, 0x46, 0x7c, 0x60, 0xba, 0xc1, 0xb1, 0xa4,
        0xbf, 0x9a, 0xb6, 0xe6, 0x56,
    ],
    tag: [
        0x4a, 0xe8, 0x0c, 0x26, 0xf2, 0xc5, 0xc4, 0x30, 0xdf, 0xfb, 0x43, 0x60,
        0xe0, 0x70, 0xc7, 0xab,
    ],
};

/// Encrypts `buffer` in place with AES-256-GCM-SIV and returns the tag. The cipher first encrypts a
/// known input; if its answer is wrong or the cipher fails, `buffer` is wiped and nothing is
/// encrypted. The cipher runs the same code for every length.
pub(crate) fn seal<const N: usize>(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8; N],
) -> Result<[u8; TAG_LEN], SealFailed> {
    seal_checked(&KNOWN, key, nonce, aad, buffer)
}

fn seal_checked<const N: usize>(
    known: &Known,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8; N],
) -> Result<[u8; TAG_LEN], SealFailed> {
    #[cfg(kani)]
    let given = model::head(buffer);
    let sealed = if answers(known) {
        encrypt(key, nonce, aad, buffer)
    } else {
        Err(SealFailed)
    };
    #[cfg(kani)]
    if let Ok(tag) = &sealed {
        model::keep_seal::<N>(key, nonce, aad, (&given, &model::head(buffer)), tag);
    }
    if sealed.is_err() {
        #[cfg(kani)]
        model::note_seal_failed();
        wipe(buffer);
    }
    sealed
}

/// Whether the cipher gives the known answer.
fn answers(known: &Known) -> bool {
    let mut buffer = known.plaintext;
    encrypt(&known.key, &known.nonce, known.aad, &mut buffer)
        .is_ok_and(|tag| buffer == known.ciphertext && tag == known.tag)
}

/// Decrypts `buffer` in place if `tag` matches it, the key, the nonce and the associated data, and
/// otherwise wipes it.
pub(crate) fn open<const N: usize>(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8; N],
    tag: &[u8; TAG_LEN],
) -> Result<(), Rejected> {
    let opened = decrypt(key, nonce, aad, buffer, tag);
    if opened.is_err() {
        wipe(buffer);
    }
    opened
}

// In place only: with a separate output, a ciphertext that fails the tag would leave its
// decryption there.

#[cfg(not(kani))]
fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], SealFailed> {
    #[cfg(test)]
    crate::timing::note();
    Aes256GcmSiv::new(key.into())
        .encrypt_inout_detached(&Nonce::from(*nonce), aad, InOutBuf::from(buffer))
        .map(Into::into)
        .map_err(|_| SealFailed)
}

#[cfg(not(kani))]
fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Rejected> {
    #[cfg(test)]
    crate::timing::note();
    Aes256GcmSiv::new(key.into())
        .decrypt_inout_detached(
            &Nonce::from(*nonce),
            aad,
            InOutBuf::from(buffer),
            tag.into(),
        )
        .map_err(|_| Rejected)
}

#[cfg(kani)]
use model::{decrypt, encrypt};

/// What stands in for AES-256-GCM-SIV under Kani.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use super::{KEY_LEN, NONCE_LEN, PLAINTEXT_LEN, Rejected, SealFailed, TAG_LEN};

    /// The places the model keeps a seal in: the last seal of the plaintext of a record, or of
    /// nothing, and the last seal of anything longer, a layer; and how many first bytes of their
    /// plaintext and of what they wrote, and of their associated data.
    pub(crate) const RECORD: usize = 0;
    pub(crate) const LAYER: usize = 1;
    const KEPT: usize = 2;
    pub(crate) const HEAD: usize = 32;
    pub(crate) const AAD_HEAD: usize = 23;

    /// What the first seals that succeeded were given and gave, so that a proof can follow them:
    /// the key, the nonce, the associated data at the places a proof reads it, the first bytes of
    /// the plaintext and of what was written, and the tag. Kept in words of eight bytes: a store
    /// per byte multiplies the proofs' work.
    static SEALED: [AtomicBool; KEPT] = [const { AtomicBool::new(false) }; KEPT];
    static KEYS: [[AtomicU64; 4]; KEPT] = [const { [const { AtomicU64::new(0) }; 4] }; KEPT];
    static NONCES: [[AtomicU64; 2]; KEPT] = [const { [const { AtomicU64::new(0) }; 2] }; KEPT];
    static AADS: [[AtomicU64; 3]; KEPT] = [const { [const { AtomicU64::new(0) }; 3] }; KEPT];
    static AAD_LENS: [AtomicUsize; KEPT] = [const { AtomicUsize::new(0) }; KEPT];
    static GIVEN: [[AtomicU64; 4]; KEPT] = [const { [const { AtomicU64::new(0) }; 4] }; KEPT];
    static WRITTEN: [[AtomicU64; 4]; KEPT] = [const { [const { AtomicU64::new(0) }; 4] }; KEPT];
    static TAGS: [[AtomicU64; 2]; KEPT] = [const { [const { AtomicU64::new(0) }; 2] }; KEPT];

    /// What a seal was given and gave: the key, the nonce, the first bytes of the associated data,
    /// zero past its end, and its length, the first bytes of the plaintext and of what was written,
    /// and the tag.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Sealed {
        pub(crate) key: [u8; KEY_LEN],
        pub(crate) nonce: [u8; NONCE_LEN],
        pub(crate) aad: [u8; AAD_HEAD],
        pub(crate) aad_len: usize,
        pub(crate) given: [u8; HEAD],
        pub(crate) written: [u8; HEAD],
        pub(crate) tag: [u8; TAG_LEN],
    }

    /// The first bytes of `buffer`, or zeros for a shorter one.
    pub(super) fn head<const N: usize>(buffer: &[u8; N]) -> [u8; HEAD] {
        buffer.first_chunk::<HEAD>().copied().unwrap_or([0; HEAD])
    }

    /// Keeps what a seal of `N` bytes that succeeded was given and gave, in the place its length
    /// takes: the place is known when the proof is built, so that the model reads and writes no
    /// place the proof has to work out.
    pub(super) fn keep_seal<const N: usize>(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        (given, written): (&[u8; HEAD], &[u8; HEAD]),
        tag: &[u8; TAG_LEN],
    ) {
        let at = if N == PLAINTEXT_LEN || N == 0 {
            RECORD
        } else {
            LAYER
        };
        let aad_head: [u8; AAD_HEAD] =
            core::array::from_fn(|place| aad.get(place).copied().unwrap_or(0));
        if let (
            Some(keys),
            Some(nonces),
            Some(aads),
            Some(length),
            Some(givens),
            Some(writtens),
            Some(tags),
            Some(sealed),
        ) = (
            KEYS.get(at),
            NONCES.get(at),
            AADS.get(at),
            AAD_LENS.get(at),
            GIVEN.get(at),
            WRITTEN.get(at),
            TAGS.get(at),
            SEALED.get(at),
        ) {
            keep(keys, key);
            keep(nonces, nonce);
            keep(aads, &aad_head);
            length.store(aad.len(), Ordering::Relaxed);
            keep(givens, given);
            keep(writtens, written);
            keep(tags, tag);
            sealed.store(true, Ordering::Relaxed);
        }
    }

    /// Whether a seal that succeeded is kept at `at`.
    pub(crate) fn kept_at(at: usize) -> bool {
        SEALED
            .get(at)
            .is_some_and(|sealed| sealed.load(Ordering::Relaxed))
    }

    /// What the last seal that succeeded and is kept at `at` was given and gave.
    pub(crate) fn sealed(at: usize) -> Sealed {
        Sealed {
            key: KEYS.get(at).map_or([0; KEY_LEN], kept),
            nonce: NONCES.get(at).map_or([0; NONCE_LEN], kept),
            aad: AADS.get(at).map_or([0; AAD_HEAD], kept),
            aad_len: AAD_LENS
                .get(at)
                .map_or(0, |length| length.load(Ordering::Relaxed)),
            given: GIVEN.get(at).map_or([0; HEAD], kept),
            written: WRITTEN.get(at).map_or([0; HEAD], kept),
            tag: TAGS.get(at).map_or([0; TAG_LEN], kept),
        }
    }

    /// Keeps `bytes`, at most 32, in `words`, least significant byte first.
    fn keep<const N: usize, const W: usize>(words: &[AtomicU64; W], bytes: &[u8; N]) {
        let mut padded = [0; 32];
        if let Some(to) = padded.get_mut(..N) {
            to.copy_from_slice(bytes);
        }
        for (word, chunk) in words.iter().zip(padded.chunks_exact(8)) {
            let mut eight = [0; 8];
            eight.copy_from_slice(chunk);
            word.store(u64::from_le_bytes(eight), Ordering::Relaxed);
        }
    }

    /// The `N` bytes kept in `words`.
    fn kept<const N: usize, const W: usize>(words: &[AtomicU64; W]) -> [u8; N] {
        let mut padded = [0; 32];
        for (word, chunk) in words.iter().zip(padded.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        let mut bytes = [0; N];
        if let Some(from) = padded.get(..N) {
            bytes.copy_from_slice(from);
        }
        bytes
    }

    /// Whether the last decryption was rejected, so a proof can tell a rejection by the cipher from
    /// one the code makes up.
    static REJECTED: AtomicBool = AtomicBool::new(false);

    /// AES-256-GCM-SIV is beyond Kani. Encryption writes any bytes, then gives any tag or fails. The
    /// buffer is written whole: a write per byte multiplies the proofs' work.
    pub(super) fn encrypt<const N: usize>(
        _: &[u8; KEY_LEN],
        _: &[u8; NONCE_LEN],
        _: &[u8],
        buffer: &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        *buffer = kani::any();
        if kani::any() {
            Ok(kani::any())
        } else {
            Err(SealFailed)
        }
    }

    /// Whether any seal has failed, the check on a known input or the encryption, so that a proof
    /// can tell a success from one the code makes up after a failure.
    static SEAL_FAILED: AtomicBool = AtomicBool::new(false);

    pub(super) fn note_seal_failed() {
        SEAL_FAILED.store(true, Ordering::Relaxed);
    }

    /// Whether any seal has failed.
    pub(crate) fn any_seal_failed() -> bool {
        SEAL_FAILED.load(Ordering::Relaxed)
    }

    /// Decryption writes any bytes, then accepts or rejects at will and records which.
    pub(super) fn decrypt<const N: usize>(
        _: &[u8; KEY_LEN],
        _: &[u8; NONCE_LEN],
        _: &[u8],
        buffer: &mut [u8; N],
        _: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        *buffer = kani::any();
        let rejected: bool = kani::any();
        REJECTED.store(rejected, Ordering::Relaxed);
        if rejected { Err(Rejected) } else { Ok(()) }
    }

    /// Whether the last decryption was rejected.
    pub(crate) fn rejected() -> bool {
        REJECTED.load(Ordering::Relaxed)
    }

    /// Whether `refuse` was asked to decrypt.
    static ASKED: AtomicBool = AtomicBool::new(false);

    /// Rejects every decryption and records that one was asked, so that a proof can show that the
    /// code decrypts nothing.
    pub(crate) fn refuse<const N: usize>(
        _: &[u8; KEY_LEN],
        _: &[u8; NONCE_LEN],
        _: &[u8],
        _: &mut [u8; N],
        _: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        ASKED.store(true, Ordering::Relaxed);
        Err(Rejected)
    }

    /// Whether `refuse` was asked to decrypt.
    pub(crate) fn asked() -> bool {
        ASKED.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "a test decodes hex and picks bits of a tag"
)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{
        KNOWN, Known, PLAINTEXT_LEN, Rejected, SealFailed, TAG_LEN, decrypt, encrypt, open, seal,
        seal_checked,
    };

    /// RFC 8452, appendices C.2 and C.3: key, nonce, associated data, plaintext, and the result,
    /// the ciphertext followed by the tag.
    const RFC_8452: [[&str; 5]; 26] = [
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "",
            "07f5f4169bbf55a8400cd47ea6fd400f",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "0100000000000000",
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "010000000000000000000000",
            "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "0100000000000000000000000000000002000000000000000000000000000000",
            concat!(
                "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027f",
                "e819e63abcd020b006a976397632eb5d",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            concat!(
                "0100000000000000000000000000000002000000000000000000000000000000",
                "03000000000000000000000000000000",
            ),
            concat!(
                "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e3",
                "9cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            concat!(
                "0100000000000000000000000000000002000000000000000000000000000000",
                "0300000000000000000000000000000004000000000000000000000000000000",
            ),
            concat!(
                "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7",
                "e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce",
                "112864c269fc0d9d88c61fa47e39aa08",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "0200000000000000",
            "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "020000000000000000000000",
            "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "02000000000000000000000000000000",
            "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "0200000000000000000000000000000003000000000000000000000000000000",
            concat!(
                "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365",
                "aea1bad12702e1965604374aab96dbbc",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            concat!(
                "0200000000000000000000000000000003000000000000000000000000000000",
                "04000000000000000000000000000000",
            ),
            concat!(
                "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47",
                "fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            concat!(
                "0200000000000000000000000000000003000000000000000000000000000000",
                "0400000000000000000000000000000005000000000000000000000000000000",
            ),
            concat!(
                "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc9",
                "8cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c89",
                "5bde0285037c5de81e5b570a049b62a0",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "010000000000000000000000",
            "02000000",
            "22b3f4cd1835e517741dfddccfa07fa4661b74cf",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "010000000000000000000000000000000200",
            "0300000000000000000000000000000004000000",
            concat!(
                "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59",
                "cabfe307",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "0100000000000000000000000000000002000000",
            "030000000000000000000000000000000400",
            concat!(
                "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc205",
                "6543",
            ),
        ],
        [
            "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
            "e0eaf5284d884a0e77d31646",
            "",
            "",
            "169fbb2fbf389a995f6390af22228a62",
        ],
        [
            "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
            "e4b47801afc0577e34699b9e",
            "4fbdc66f14",
            "671fdd",
            "0eaccb93da9bb81333aee0c785b240d319719d",
        ],
        [
            "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3",
            "2f6d1f0434d8848c1177441f",
            "6787f3ea22c127aaf195",
            "195495860f04",
            "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c",
        ],
        [
            "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0",
            "9f572c614b4745914474e7c7",
            "489c8fde2be2cf97e74e932d4ed87d",
            "c9882e5386fd9f92ec",
            "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2",
        ],
        [
            "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235",
            "5c9e940fea2f582950a70d5a",
            "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
            "1db2316fd568378da107b52b",
            "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5",
        ],
        [
            "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
            "6de71860f762ebfbd08284e4",
            "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
            "21702de0de18baa9c9596291b08466",
            "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd",
        ],
        [
            "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
            "028ec6eb5ea7e298342a94d4",
            "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
            "b202b370ef9768ec6561c4fe6b7e7296fa85",
            concat!(
                "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d",
                "0a49",
            ),
        ],
        [
            "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
            "688089e55540db1872504e1c",
            concat!(
                "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f",
                "167541",
            ),
            "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
            concat!(
                "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1d",
                "ed1a286594",
            ),
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
            concat!(
                "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3ea",
                "ffffffff000000000000000000000000",
            ),
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
            concat!(
                "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff00000000",
                "0000000000000000",
            ),
        ],
    ];

    /// Records sealed under other keys, nonces and associated data, computed by the same
    /// independent implementation as the known answer.
    #[rustfmt::skip]
    const OTHERS: [Known; 2] = [
        Known {
            key: [
                0x11, 0x46, 0x7b, 0xb0, 0xe5, 0x1a, 0x4f, 0x84, 0xb9, 0xee, 0x23, 0x58,
                0x8d, 0xc2, 0xf7, 0x2c, 0x61, 0x96, 0xcb, 0x00, 0x35, 0x6a, 0x9f, 0xd4,
                0x09, 0x3e, 0x73, 0xa8, 0xdd, 0x12, 0x47, 0x7c,
            ],
            nonce: [
                0x09, 0x32, 0x5b, 0x84, 0xad, 0xd6, 0xff, 0x28, 0x51, 0x7a, 0xa3, 0xcc,
            ],
            aad: b"",
            plaintext: [
                0x64, 0x6b, 0x72, 0x79, 0x80, 0x87, 0x8e, 0x95, 0x9c, 0xa3, 0xaa, 0xb1,
                0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb, 0xe2, 0xe9, 0xf0, 0xf7, 0xfe, 0x05,
                0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f, 0x36, 0x3d, 0x44, 0x4b, 0x52, 0x59,
                0x60, 0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98, 0x9f, 0xa6, 0xad,
                0xb4, 0xbb, 0xc2, 0xc9, 0xd0, 0xd7, 0xde, 0xe5, 0xec, 0xf3, 0xfa, 0x01,
                0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
                0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9,
                0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0xef, 0xf6, 0xfd,
                0x04, 0x0b, 0x12, 0x19, 0x20, 0x27, 0x2e, 0x35, 0x3c, 0x43, 0x4a, 0x51,
                0x58, 0x5f, 0x66, 0x6d, 0x74, 0x7b, 0x82, 0x89, 0x90, 0x97, 0x9e, 0xa5,
                0xac, 0xb3, 0xba, 0xc1, 0xc8, 0xcf, 0xd6, 0xdd, 0xe4, 0xeb, 0xf2, 0xf9,
                0x00, 0x07, 0x0e, 0x15, 0x1c, 0x23, 0x2a, 0x31, 0x38, 0x3f, 0x46, 0x4d,
                0x54, 0x5b, 0x62, 0x69, 0x70, 0x77, 0x7e, 0x85, 0x8c, 0x93, 0x9a, 0xa1,
                0xa8, 0xaf, 0xb6, 0xbd, 0xc4, 0xcb, 0xd2, 0xd9, 0xe0, 0xe7, 0xee, 0xf5,
                0xfc, 0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49,
                0x50, 0x57, 0x5e, 0x65, 0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d,
                0xa4, 0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc, 0xe3, 0xea, 0xf1,
                0xf8, 0xff, 0x06, 0x0d, 0x14, 0x1b, 0x22, 0x29, 0x30, 0x37, 0x3e, 0x45,
                0x4c, 0x53, 0x5a, 0x61, 0x68, 0x6f, 0x76, 0x7d, 0x84, 0x8b, 0x92, 0x99,
                0xa0, 0xa7, 0xae, 0xb5, 0xbc,
            ],
            ciphertext: [
                0x6c, 0x9c, 0xad, 0xec, 0xbb, 0x59, 0x8c, 0xdc, 0x10, 0xdc, 0x06, 0xe6,
                0xf3, 0x7a, 0x9d, 0xc2, 0x73, 0x01, 0x11, 0xc0, 0x76, 0x77, 0xaf, 0x07,
                0x98, 0x74, 0x45, 0x64, 0x62, 0xed, 0xd3, 0xaf, 0x13, 0x88, 0x1d, 0x37,
                0x2f, 0x3a, 0xd0, 0xf8, 0x09, 0x85, 0xc9, 0x2a, 0xd0, 0x4b, 0xc4, 0x83,
                0xc6, 0x2e, 0x50, 0xf9, 0x43, 0xcd, 0xe3, 0x6c, 0x71, 0xb2, 0xa6, 0x65,
                0x8b, 0xff, 0x4c, 0x63, 0x07, 0x0a, 0x3d, 0x96, 0x43, 0x94, 0x68, 0x55,
                0x4a, 0xe9, 0x21, 0x5b, 0x83, 0x66, 0x62, 0x45, 0x36, 0x28, 0x1c, 0x4c,
                0x1a, 0xcd, 0xeb, 0xa2, 0x99, 0x7b, 0x84, 0xca, 0xef, 0x85, 0xf1, 0xee,
                0x01, 0x9f, 0x69, 0x63, 0xc3, 0x38, 0xe4, 0x0d, 0xaa, 0x30, 0xa6, 0x6e,
                0x02, 0x2e, 0xff, 0x42, 0x88, 0xb7, 0x4c, 0x35, 0x73, 0x50, 0x37, 0x45,
                0x04, 0x8d, 0x7c, 0x6e, 0x6f, 0xba, 0xef, 0x94, 0x89, 0x5b, 0x84, 0xba,
                0x34, 0xbd, 0x8b, 0x87, 0x6e, 0x54, 0x3e, 0x8a, 0x91, 0x06, 0xbe, 0x88,
                0x09, 0x41, 0x67, 0xf7, 0x88, 0xe3, 0x44, 0x67, 0x6d, 0x22, 0x45, 0x01,
                0xea, 0x00, 0x95, 0xdf, 0xf2, 0x9a, 0x7c, 0xc0, 0x38, 0xcd, 0x42, 0xee,
                0x45, 0xc1, 0x75, 0x64, 0x88, 0x9a, 0x88, 0x16, 0x4b, 0x3f, 0x40, 0xf7,
                0x87, 0x51, 0x51, 0xed, 0x0c, 0xbc, 0x4e, 0xd5, 0xc4, 0x34, 0xb3, 0xdf,
                0xf0, 0x2e, 0x03, 0xde, 0xef, 0x4a, 0xd7, 0x5d, 0x2c, 0x49, 0xea, 0x98,
                0x60, 0x3e, 0x69, 0x7f, 0x5f, 0x7f, 0x12, 0x5e, 0x7a, 0xdc, 0x90, 0x67,
                0xb1, 0x3c, 0x9a, 0xba, 0x7e, 0x8b, 0xa1, 0x12, 0xc4, 0xc3, 0x25, 0xa6,
                0xb7, 0x27, 0x8a, 0xab, 0x7e,
            ],
            tag: [
                0xb9, 0x4a, 0x4f, 0x43, 0x8b, 0x1c, 0x57, 0xdc, 0x58, 0xac, 0xb6, 0x58,
                0xc2, 0xde, 0xb0, 0x1d,
            ],
        },
        Known {
            key: [
                0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea, 0xe7, 0xe4, 0xe1, 0xde,
                0xdb, 0xd8, 0xd5, 0xd2, 0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
                0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
            ],
            nonce: [
                0xc8, 0xcd, 0xd2, 0xd7, 0xdc, 0xe1, 0xe6, 0xeb, 0xf0, 0xf5, 0xfa, 0xff,
            ],
            aad: b"lethewis record context 0123456789abcdef",
            plaintext: [
                0x01, 0x14, 0x27, 0x3a, 0x4d, 0x60, 0x73, 0x86, 0x99, 0xac, 0xbf, 0xd2,
                0xe5, 0xf8, 0x0b, 0x1e, 0x31, 0x44, 0x57, 0x6a, 0x7d, 0x90, 0xa3, 0xb6,
                0xc9, 0xdc, 0xef, 0x02, 0x15, 0x28, 0x3b, 0x4e, 0x61, 0x74, 0x87, 0x9a,
                0xad, 0xc0, 0xd3, 0xe6, 0xf9, 0x0c, 0x1f, 0x32, 0x45, 0x58, 0x6b, 0x7e,
                0x91, 0xa4, 0xb7, 0xca, 0xdd, 0xf0, 0x03, 0x16, 0x29, 0x3c, 0x4f, 0x62,
                0x75, 0x88, 0x9b, 0xae, 0xc1, 0xd4, 0xe7, 0xfa, 0x0d, 0x20, 0x33, 0x46,
                0x59, 0x6c, 0x7f, 0x92, 0xa5, 0xb8, 0xcb, 0xde, 0xf1, 0x04, 0x17, 0x2a,
                0x3d, 0x50, 0x63, 0x76, 0x89, 0x9c, 0xaf, 0xc2, 0xd5, 0xe8, 0xfb, 0x0e,
                0x21, 0x34, 0x47, 0x5a, 0x6d, 0x80, 0x93, 0xa6, 0xb9, 0xcc, 0xdf, 0xf2,
                0x05, 0x18, 0x2b, 0x3e, 0x51, 0x64, 0x77, 0x8a, 0x9d, 0xb0, 0xc3, 0xd6,
                0xe9, 0xfc, 0x0f, 0x22, 0x35, 0x48, 0x5b, 0x6e, 0x81, 0x94, 0xa7, 0xba,
                0xcd, 0xe0, 0xf3, 0x06, 0x19, 0x2c, 0x3f, 0x52, 0x65, 0x78, 0x8b, 0x9e,
                0xb1, 0xc4, 0xd7, 0xea, 0xfd, 0x10, 0x23, 0x36, 0x49, 0x5c, 0x6f, 0x82,
                0x95, 0xa8, 0xbb, 0xce, 0xe1, 0xf4, 0x07, 0x1a, 0x2d, 0x40, 0x53, 0x66,
                0x79, 0x8c, 0x9f, 0xb2, 0xc5, 0xd8, 0xeb, 0xfe, 0x11, 0x24, 0x37, 0x4a,
                0x5d, 0x70, 0x83, 0x96, 0xa9, 0xbc, 0xcf, 0xe2, 0xf5, 0x08, 0x1b, 0x2e,
                0x41, 0x54, 0x67, 0x7a, 0x8d, 0xa0, 0xb3, 0xc6, 0xd9, 0xec, 0xff, 0x12,
                0x25, 0x38, 0x4b, 0x5e, 0x71, 0x84, 0x97, 0xaa, 0xbd, 0xd0, 0xe3, 0xf6,
                0x09, 0x1c, 0x2f, 0x42, 0x55, 0x68, 0x7b, 0x8e, 0xa1, 0xb4, 0xc7, 0xda,
                0xed, 0x00, 0x13, 0x26, 0x39,
            ],
            ciphertext: [
                0xe5, 0x5d, 0x4d, 0x38, 0x98, 0xe9, 0x95, 0x9b, 0xaa, 0x5b, 0xb1, 0x4f,
                0x57, 0xa7, 0x7a, 0x77, 0x10, 0x12, 0xe7, 0x0c, 0xec, 0x10, 0x11, 0x39,
                0x49, 0xd5, 0x73, 0xc8, 0x8c, 0x36, 0xea, 0x9f, 0x89, 0x12, 0xca, 0x41,
                0xa7, 0x59, 0x15, 0x6e, 0xa1, 0x4f, 0x83, 0x38, 0xd9, 0x40, 0xaa, 0x68,
                0xc2, 0xdb, 0x27, 0x89, 0x38, 0xa4, 0xed, 0x1c, 0x93, 0x61, 0x9c, 0xdd,
                0x2d, 0x13, 0xbd, 0x33, 0xe3, 0xfd, 0xea, 0x4b, 0x85, 0xed, 0xf3, 0x30,
                0x3f, 0x2e, 0xf0, 0xd8, 0xb4, 0x15, 0xf1, 0x59, 0x46, 0xb3, 0xea, 0x55,
                0x41, 0xdb, 0xd3, 0x28, 0x72, 0x07, 0xc4, 0x0f, 0x3c, 0x93, 0x1b, 0x2d,
                0x81, 0xc6, 0xcb, 0x40, 0x90, 0x08, 0x5f, 0x23, 0x06, 0x9a, 0x34, 0xbd,
                0x72, 0x24, 0x53, 0x61, 0xba, 0xff, 0xe3, 0x06, 0x91, 0xb5, 0x92, 0xd5,
                0xc9, 0x77, 0xca, 0x2a, 0x43, 0x84, 0x08, 0x4a, 0x27, 0xee, 0x41, 0x5c,
                0x8a, 0x6f, 0x8e, 0xc0, 0x7e, 0xcd, 0xce, 0x62, 0xcc, 0xc3, 0x3c, 0x32,
                0x3f, 0x51, 0xb7, 0xce, 0x97, 0x2c, 0x6b, 0x0a, 0xa3, 0xf9, 0x67, 0x14,
                0xf2, 0xcf, 0x77, 0x29, 0x81, 0x97, 0x82, 0x91, 0x3a, 0xe4, 0xc2, 0x5c,
                0x00, 0x62, 0x7a, 0x21, 0x15, 0x45, 0x5f, 0xb6, 0x92, 0x22, 0x2e, 0xff,
                0x6d, 0x0c, 0x7e, 0x60, 0xcd, 0x84, 0x23, 0x09, 0x83, 0xc8, 0x2b, 0x43,
                0x78, 0x71, 0x89, 0x12, 0x0d, 0x36, 0x8e, 0x07, 0x87, 0x0a, 0x81, 0x32,
                0x95, 0xb9, 0x2d, 0xa7, 0xee, 0x52, 0xc1, 0xce, 0xdc, 0x51, 0x61, 0xf8,
                0x62, 0x42, 0x7e, 0xc9, 0xcb, 0x42, 0x15, 0x5c, 0x5e, 0x2a, 0x3b, 0x4a,
                0xe1, 0x25, 0x87, 0x2d, 0xeb,
            ],
            tag: [
                0x3b, 0xcc, 0x6c, 0x5c, 0x12, 0xcf, 0x51, 0x69, 0xde, 0x2b, 0x5f, 0x08,
                0x25, 0x6b, 0xc2, 0xb6,
            ],
        },
    ];

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(text: &str) -> [u8; N] {
        hex(text).try_into().unwrap()
    }

    #[test]
    fn the_cipher_gives_the_vectors_of_rfc_8452() {
        for [key, nonce, aad, plaintext, result] in RFC_8452 {
            let (key, nonce, aad) = (array(key), array(nonce), hex(aad));
            let mut buffer = hex(plaintext);
            let tag = encrypt(&key, &nonce, &aad, &mut buffer).unwrap();
            assert_eq!([&buffer[..], &tag[..]].concat(), hex(result), "{plaintext}");
            decrypt(&key, &nonce, &aad, &mut buffer, &tag).unwrap();
            assert_eq!(buffer, hex(plaintext));
        }
    }

    #[test]
    fn every_changed_bit_of_a_tag_is_rejected() {
        for [key, nonce, aad, _, result] in RFC_8452 {
            let (key, nonce, aad, result) = (array(key), array(nonce), hex(aad), hex(result));
            let (ciphertext, tag) = result.split_at(result.len() - TAG_LEN);
            for bit in 0..TAG_LEN * 8 {
                let mut tag: [u8; TAG_LEN] = tag.try_into().unwrap();
                tag[bit / 8] ^= 1 << (bit % 8);
                let mut buffer = ciphertext.to_vec();
                assert_eq!(
                    decrypt(&key, &nonce, &aad, &mut buffer, &tag),
                    Err(Rejected)
                );
            }
        }
    }

    #[test]
    fn an_empty_ciphertext_with_a_zero_tag_is_rejected() {
        for aad in [&b""[..], b"any associated data"] {
            assert_eq!(
                decrypt(&KNOWN.key, &KNOWN.nonce, aad, &mut [], &[0; TAG_LEN]),
                Err(Rejected)
            );
        }
    }

    #[test]
    fn a_record_seals_to_the_known_answer_and_opens() {
        let mut buffer = KNOWN.plaintext;
        let tag = seal(&KNOWN.key, &KNOWN.nonce, KNOWN.aad, &mut buffer).unwrap();
        assert_eq!((buffer, tag), (KNOWN.ciphertext, KNOWN.tag));
        open(&KNOWN.key, &KNOWN.nonce, KNOWN.aad, &mut buffer, &tag).unwrap();
        assert_eq!(buffer, KNOWN.plaintext);
    }

    #[test]
    fn records_under_other_keys_seal_and_open() {
        for known in OTHERS {
            let mut buffer = known.plaintext;
            let tag = seal(&known.key, &known.nonce, known.aad, &mut buffer).unwrap();
            assert_eq!((buffer, tag), (known.ciphertext, known.tag));
            open(&known.key, &known.nonce, known.aad, &mut buffer, &tag).unwrap();
            assert_eq!(buffer, known.plaintext);
        }
    }

    /// The known input with one byte of one field changed.
    fn changed(field: usize, at: usize) -> Known {
        let mut known = Known { ..KNOWN };
        match field {
            0 => known.key[at % 32] ^= 1,
            1 => known.nonce[at % 12] ^= 1,
            2 => known.aad = b"lethewis self-test v2",
            3 => known.plaintext[at] ^= 1,
            4 => known.ciphertext[at] ^= 1,
            _ => known.tag[at % TAG_LEN] ^= 1,
        }
        known
    }

    #[test]
    fn a_wrong_answer_fails_the_seal_and_wipes_the_buffer() {
        for field in 0..6 {
            for at in [0, 41, PLAINTEXT_LEN - 1] {
                let mut buffer = KNOWN.plaintext;
                assert_eq!(
                    seal_checked(
                        &changed(field, at),
                        &KNOWN.key,
                        &KNOWN.nonce,
                        KNOWN.aad,
                        &mut buffer
                    ),
                    Err(SealFailed),
                    "field {field}, byte {at}"
                );
                assert_eq!(buffer, [0; PLAINTEXT_LEN]);
            }
        }
    }

    #[test]
    fn a_record_that_does_not_open_is_wiped() {
        for field in 0..6 {
            for at in [0, 41, PLAINTEXT_LEN - 1] {
                let known = changed(field, at);
                let mut buffer = if field == 3 {
                    KNOWN.ciphertext
                } else {
                    known.ciphertext
                };
                if field == 3 {
                    buffer[at] ^= 1;
                }
                assert_eq!(
                    open(&known.key, &known.nonce, known.aad, &mut buffer, &known.tag),
                    Err(Rejected),
                    "field {field}, byte {at}"
                );
                assert_eq!(buffer, [0; PLAINTEXT_LEN]);
            }
        }
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs {
    use super::{model::rejected, open, seal};
    use crate::record::{LAYER_LEN, PLAINTEXT_LEN};

    /// Sealing any `N` bytes: it gives a tag, or fails and leaves the buffer zero. Returns whether it
    /// sealed.
    fn seal_any<const N: usize>() -> bool {
        let mut buffer: [u8; N] = kani::any();
        let aad: [u8; 4] = kani::any();
        let sealed = seal(&kani::any(), &kani::any(), &aad, &mut buffer);
        kani::assert(
            sealed.is_ok() || buffer == [0; N],
            "a failed seal leaves the buffer zero",
        );
        sealed.is_ok()
    }

    /// For any key, nonce, associated data and plaintext of a record or of the outer layer of a lock
    /// record, and whatever the cipher does: sealing either gives a tag, or fails and leaves the
    /// buffer zero.
    #[kani::proof]
    #[kani::unwind(270)]
    fn a_failed_seal_leaves_the_buffer_wiped() {
        let sealed = if kani::any() {
            seal_any::<PLAINTEXT_LEN>()
        } else {
            seal_any::<LAYER_LEN>()
        };
        kani::cover!(sealed, "a record is sealed");
        kani::cover!(!sealed, "a seal fails");
    }

    /// Opening any `N` bytes: it fails exactly when the cipher rejects them, and then leaves the
    /// buffer zero. Returns whether it opened.
    fn open_any<const N: usize>() -> bool {
        let mut buffer: [u8; N] = kani::any();
        let aad: [u8; 4] = kani::any();
        let opened = open(&kani::any(), &kani::any(), &aad, &mut buffer, &kani::any());
        kani::assert(
            opened.is_err() == rejected(),
            "a record is refused exactly when the cipher rejects it",
        );
        kani::assert(
            opened.is_ok() || buffer == [0; N],
            "a refused record leaves the buffer zero",
        );
        opened.is_ok()
    }

    /// For any key, nonce, associated data, tag and encrypted record or outer layer of a lock record,
    /// and whatever the cipher does: opening fails exactly when the cipher rejects it, and then
    /// leaves the buffer zero.
    #[kani::proof]
    #[kani::unwind(270)]
    fn a_rejected_record_leaves_the_buffer_wiped() {
        let opened = if kani::any() {
            open_any::<PLAINTEXT_LEN>()
        } else {
            open_any::<LAYER_LEN>()
        };
        kani::cover!(opened, "a record opens");
        kani::cover!(!opened, "a record is refused");
    }
}
