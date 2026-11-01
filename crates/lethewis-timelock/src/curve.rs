// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! BLS12-381 through blst, and SHA-256: a model of both under Kani.

use crate::network::SIGNATURE_LEN;

/// The length of a group key: a point of G2, compressed.
pub(crate) const KEY_LEN: usize = 96;

/// The domain separation tag of the hash to G1 in the scheme bls-unchained-g1-rfc9380.
#[cfg(not(kani))]
pub(crate) const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

#[cfg(kani)]
pub(crate) use model::{message, verify};

/// What a round's signature signs: SHA-256 of the round, eight bytes, most significant first.
#[cfg(not(kani))]
pub(crate) fn message(round: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(round.to_be_bytes()).into()
}

/// Whether `signature` signs `message` under `key`. Both are points of their groups in canonical
/// compressed form, and the key is not the identity.
#[cfg(not(kani))]
pub(crate) fn verify(
    key: &[u8; KEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
    message: &[u8; 32],
) -> bool {
    use blst::BLST_ERROR;
    use blst::min_sig::{PublicKey, Signature};

    let (Ok(key), Ok(signature)) = (PublicKey::from_bytes(key), Signature::from_bytes(signature))
    else {
        return false;
    };
    // The key is a constant, which a test checks to be in its group.
    signature.verify(true, message, DST, &[], &key, false) == BLST_ERROR::BLST_SUCCESS
}

/// What stands in for the curve and the hash under Kani.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::{KEY_LEN, SIGNATURE_LEN};

    /// What the last check of a signature was given and answered, in words of eight bytes.
    static ASKED: AtomicU64 = AtomicU64::new(0);
    static KEY: [AtomicU64; 12] = [const { AtomicU64::new(0) }; 12];
    static SIGNATURE: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
    static MESSAGE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    static ANSWER: AtomicBool = AtomicBool::new(false);

    /// What a check of a signature was given and answered.
    pub(crate) struct Asked {
        pub(crate) times: u64,
        pub(crate) key: [u8; KEY_LEN],
        pub(crate) signature: [u8; SIGNATURE_LEN],
        pub(crate) message: [u8; 32],
        pub(crate) answer: bool,
    }

    /// SHA-256 of the round stands in as the round's eight bytes followed by zeros: one message
    /// for each round.
    pub(crate) fn message(round: u64) -> [u8; 32] {
        let mut message = [0; 32];
        if let Some(head) = message.get_mut(..8) {
            head.copy_from_slice(&round.to_be_bytes());
        }
        message
    }

    /// Answers at will.
    pub(crate) fn verify(
        key: &[u8; KEY_LEN],
        signature: &[u8; SIGNATURE_LEN],
        message: &[u8; 32],
    ) -> bool {
        let answer = kani::any();
        ASKED.store(
            ASKED.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Relaxed,
        );
        keep(&KEY, key);
        keep(&SIGNATURE, signature);
        keep(&MESSAGE, message);
        ANSWER.store(answer, Ordering::Relaxed);
        answer
    }

    pub(crate) fn asked() -> Asked {
        Asked {
            times: ASKED.load(Ordering::Relaxed),
            key: kept(&KEY),
            signature: kept(&SIGNATURE),
            message: kept(&MESSAGE),
            answer: ANSWER.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn keep<const W: usize>(words: &[AtomicU64; W], bytes: &[u8]) {
        for (word, chunk) in words.iter().zip(bytes.chunks_exact(8)) {
            let mut eight = [0; 8];
            eight.copy_from_slice(chunk);
            word.store(u64::from_le_bytes(eight), Ordering::Relaxed);
        }
    }

    pub(crate) fn kept<const W: usize, const N: usize>(words: &[AtomicU64; W]) -> [u8; N] {
        let mut bytes = [0; N];
        for (word, chunk) in words.iter().zip(bytes.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        bytes
    }
}
