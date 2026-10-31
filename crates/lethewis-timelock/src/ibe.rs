// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The identity-based encryption of tlock: a file key encrypted to a round, which the round's
//! signature decrypts. A model of it under Kani.

#[cfg(not(kani))]
use crate::curve::KEY_LEN;
#[cfg(not(kani))]
use crate::network::SIGNATURE_LEN;

/// The length of an age file key.
pub(crate) const FILE_KEY_LEN: usize = 16;
/// The length of an encrypted file key: U, a point of G2, compressed, then V and W of 16 bytes.
pub(crate) const BODY_LEN: usize = 128;

#[cfg(kani)]
pub(crate) use model::{unwrap, wrap};

/// The candidates for r taken in constant time. A random sigma needs more with probability below
/// 2^-54; only a decryption then goes on, in variable time.
#[cfg(not(kani))]
const TRIES: u16 = 16;
/// The last candidate the reference tries.
#[cfg(not(kani))]
const LAST_TRY: u16 = 65_534;

/// The order of G1 and G2, in two halves, most significant byte first.
#[cfg(not(kani))]
const ORDER: (u128, u128) = (
    0x73ed_a753_299d_7d48_3339_d808_09a1_d805,
    0x53bd_a402_fffe_5bfe_ffff_ffff_0000_0001,
);

/// Where each of the twelve coefficients of a pairing lies in blst's serialisation, in the order
/// tlock hashes them: from the coefficient of w v^2 u down to the constant, as blst keeps them by
/// powers of w.
#[cfg(not(kani))]
const GT_ORDER: [usize; 12] = [11, 10, 7, 6, 3, 2, 9, 8, 5, 4, 1, 0];

/// Encrypts `file_key` to the round whose message is `message`, under the group key `key`, with
/// `sigma` as its randomness. False when sigma gives no scalar within the tries taken in constant
/// time.
#[cfg(not(kani))]
pub(crate) fn wrap(
    key: &[u8; KEY_LEN],
    message: &[u8; 32],
    file_key: &[u8; FILE_KEY_LEN],
    sigma: &[u8; FILE_KEY_LEN],
    body: &mut [u8; BODY_LEN],
) -> bool {
    use blst::min_sig::{PublicKey, SecretKey};
    use blst::{blst_p1_affine, blst_p2_affine};
    use zeroize::Zeroize;

    #[cfg(test)]
    crate::timing::note();
    let Ok(key) = PublicKey::from_bytes(key) else {
        return false;
    };
    let mut scalar = [0; 32];
    let found = h3(sigma, file_key, false, &mut scalar);
    let r = SecretKey::from_bytes(&scalar);
    scalar.zeroize();
    let (true, Ok(r)) = (found, r) else {
        return false;
    };
    // r times the point the round's message hashes to, so that its pairing with the group key is
    // the pairing of the round raised to r.
    let r_id: blst_p1_affine = r.sign(message, crate::curve::DST, &[]).into();
    let public: blst_p2_affine = key.into();
    let mut mask = h2(&r_id, &public);
    let Some((u, masked)) = body.split_first_chunk_mut::<KEY_LEN>() else {
        return false;
    };
    u.copy_from_slice(&r.sk_to_pk().compress());
    let (v, w) = masked.split_at_mut(FILE_KEY_LEN);
    xor_into(v, sigma, &mask);
    mask = h4(sigma);
    xor_into(w, file_key, &mask);
    mask.zeroize();
    true
}

/// Decrypts the file key `body` holds with the signature of its round, and writes it to
/// `file_key` only when the encryption checks out, with r derived again from what it gives.
#[cfg(not(kani))]
pub(crate) fn unwrap(
    signature: &[u8; SIGNATURE_LEN],
    body: &[u8; BODY_LEN],
    file_key: &mut [u8; FILE_KEY_LEN],
) -> bool {
    use blst::min_sig::{PublicKey, SecretKey, Signature};
    use blst::{blst_p1_affine, blst_p2_affine};
    use ctutils::CtEq;
    use zeroize::Zeroize;

    #[cfg(test)]
    crate::timing::note();
    let Some((u_bytes, masked)) = body.split_first_chunk::<KEY_LEN>() else {
        return false;
    };
    let (v, w) = masked.split_at(FILE_KEY_LEN);
    // A point of G2 other than the identity, in its canonical encoding.
    let (Ok(u), Ok(signature)) = (
        PublicKey::key_validate(u_bytes),
        Signature::from_bytes(signature),
    ) else {
        return false;
    };
    let (signature, u): (blst_p1_affine, blst_p2_affine) = (signature.into(), u.into());
    let mut mask = h2(&signature, &u);
    let mut sigma = [0; FILE_KEY_LEN];
    xor_into(&mut sigma, v, &mask);
    mask = h4(&sigma);
    let mut candidate = [0; FILE_KEY_LEN];
    xor_into(&mut candidate, w, &mask);
    mask.zeroize();
    let mut scalar = [0; 32];
    let found = h3(&sigma, &candidate, true, &mut scalar);
    sigma.zeroize();
    let r = SecretKey::from_bytes(&scalar);
    scalar.zeroize();
    let same = match (found, r) {
        (true, Ok(r)) => r.sk_to_pk().compress().ct_eq(u_bytes).to_bool(),
        _ => false,
    };
    if same {
        file_key.copy_from_slice(&candidate);
    }
    candidate.zeroize();
    same
}

/// Writes `a` XOR the first bytes of `mask` to `out`.
#[cfg(not(kani))]
fn xor_into(out: &mut [u8], a: &[u8], mask: &[u8; 32]) {
    for ((out, a), mask) in out.iter_mut().zip(a).zip(mask) {
        *out = a ^ mask;
    }
}

/// H2 of tlock: SHA-256 of "IBE-H2" and the pairing of `g1` and `g2`, its coefficients most
/// significant first, each most significant byte first.
#[cfg(not(kani))]
pub(crate) fn h2(g1: &blst::blst_p1_affine, g2: &blst::blst_p2_affine) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    let mut pairing = blst::blst_fp12::miller_loop(g2, g1)
        .final_exp()
        .to_bendian();
    let mut hash = Sha256::new_with_prefix(b"IBE-H2");
    for &at in &GT_ORDER {
        if let Some(coefficient) = pairing.as_chunks::<48>().0.get(at) {
            hash.update(coefficient);
        }
    }
    pairing.zeroize();
    hash.finalize().into()
}

/// H4 of tlock: SHA-256 of "IBE-H4" and sigma.
#[cfg(not(kani))]
pub(crate) fn h4(sigma: &[u8; FILE_KEY_LEN]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::new_with_prefix(b"IBE-H4")
        .chain_update(sigma)
        .finalize()
        .into()
}

/// H3 of tlock: the first candidate below the order, where candidate i is SHA-256 of i, two bytes
/// least significant first, and SHA-256 of "IBE-H3", sigma and the message, with its first byte
/// halved, read most significant byte first. Past [`TRIES`] it goes on only `beyond`.
#[cfg(not(kani))]
pub(crate) fn h3(
    sigma: &[u8; FILE_KEY_LEN],
    message: &[u8; FILE_KEY_LEN],
    beyond: bool,
    scalar: &mut [u8; 32],
) -> bool {
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    let mut inner: [u8; 32] = Sha256::new_with_prefix(b"IBE-H3")
        .chain_update(sigma)
        .chain_update(message)
        .finalize()
        .into();
    let mut found = ctutils::Choice::FALSE;
    for i in 1..=TRIES {
        let mut candidate = candidate(i, &inner);
        found = take_first(scalar, &candidate, found);
        candidate.zeroize();
    }
    let mut taken = found.to_bool();
    if !taken && beyond {
        for i in (TRIES..=LAST_TRY).skip(1) {
            let candidate = candidate(i, &inner);
            if below_order(&candidate).to_bool() {
                scalar.copy_from_slice(&candidate);
                taken = true;
                break;
            }
        }
    }
    inner.zeroize();
    taken
}

#[cfg(not(kani))]
fn candidate(i: u16, inner: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut candidate: [u8; 32] = Sha256::new_with_prefix(i.to_le_bytes())
        .chain_update(inner)
        .finalize()
        .into();
    if let Some(first) = candidate.first_mut() {
        *first >>= 1;
    }
    candidate
}

/// Takes `candidate` into `scalar` when it is below the order and none was found before.
/// Kept out of line, so that the check of its machine code finds it.
#[cfg(not(kani))]
#[inline(never)]
fn take_first(
    scalar: &mut [u8; 32],
    candidate: &[u8; 32],
    found: ctutils::Choice,
) -> ctutils::Choice {
    use ctutils::CtAssign;

    let below = below_order(candidate);
    scalar.ct_assign(candidate, below.and(found.not()));
    found.or(below)
}

/// Whether `scalar`, most significant byte first, is below the order.
#[cfg(not(kani))]
fn below_order(scalar: &[u8; 32]) -> ctutils::Choice {
    use ctutils::Choice;

    let (Some((high, low)), (order_high, order_low)) = (scalar.split_first_chunk::<16>(), ORDER)
    else {
        return Choice::FALSE;
    };
    let mut low_bytes = [0; 16];
    low_bytes.copy_from_slice(low);
    let (high, low) = (u128::from_be_bytes(*high), u128::from_be_bytes(low_bytes));
    Choice::from_u128_lt(high, order_high)
        .or(Choice::from_u128_eq(high, order_high).and(Choice::from_u128_lt(low, order_low)))
}

#[cfg(test)]
mod tests {
    use blst::{blst_p1_affine, blst_p2_affine, min_pk, min_sig};
    use sha2::{Digest, Sha256};

    use super::{BODY_LEN, FILE_KEY_LEN, ORDER, below_order, h2, take_first, unwrap, wrap};
    use crate::network::QUICKNET;
    use crate::vectors::{
        AgeParts, PAIRING_OF_GENERATORS, REFERENCE_LOCK, REFERENCE_SIGNATURE, TESTNET,
        TESTNET_LOCK, TESTNET_SIGNATURE, age_parts, dearmor, signature_of, unhex,
    };
    use crate::{age, curve};

    const FILE_KEY: [u8; FILE_KEY_LEN] = *b"sixteen byte key";
    const SIGMA: [u8; FILE_KEY_LEN] = *b"sixteen randomly";

    fn one() -> [u8; 32] {
        let mut one = [0; 32];
        one[31] = 1;
        one
    }

    fn wrapped(round: u64) -> [u8; BODY_LEN] {
        let mut body = [0; BODY_LEN];
        let message = curve::message(round);
        assert!(wrap(
            &QUICKNET.public_key,
            &message,
            &FILE_KEY,
            &SIGMA,
            &mut body
        ));
        body
    }

    #[test]
    fn the_pairing_is_hashed_in_the_order_of_the_reference() {
        let g1: blst_p1_affine = min_pk::SecretKey::from_bytes(&one())
            .unwrap()
            .sk_to_pk()
            .into();
        let g2: blst_p2_affine = min_sig::SecretKey::from_bytes(&one())
            .unwrap()
            .sk_to_pk()
            .into();
        let expected: [u8; 32] = Sha256::new_with_prefix(b"IBE-H2")
            .chain_update(unhex::<576>(&PAIRING_OF_GENERATORS.concat()))
            .finalize()
            .into();
        assert_eq!(h2(&g1, &g2), expected);
    }

    /// The header MAC of each file is the reference's own check that the file key is right.
    #[test]
    fn file_keys_the_reference_encrypted_are_decrypted() {
        for (armor, signature) in [
            (&REFERENCE_LOCK[..], REFERENCE_SIGNATURE),
            (&TESTNET_LOCK[..], TESTNET_SIGNATURE),
        ] {
            let AgeParts {
                header, body, mac, ..
            } = age_parts(&dearmor(armor));
            let mut file_key = [0; FILE_KEY_LEN];
            let body = body.try_into().unwrap();
            assert!(unwrap(&unhex(signature), &body, &mut file_key));
            assert_eq!(age::mac(&file_key, &header)[..], mac[..]);
        }
        assert_eq!(TESTNET.verify(5_423_142, &unhex(TESTNET_SIGNATURE)), Ok(()));
        assert_eq!(
            QUICKNET.verify(746_511, &unhex(REFERENCE_SIGNATURE)),
            Ok(())
        );
    }

    #[test]
    fn a_file_key_is_decrypted_with_the_signature_of_its_round_only() {
        let body = wrapped(1000);
        let mut file_key = [0; FILE_KEY_LEN];
        assert!(!unwrap(&signature_of(1), &body, &mut file_key));
        assert_eq!(file_key, [0; FILE_KEY_LEN]);
        assert!(unwrap(&signature_of(1000), &body, &mut file_key));
        assert_eq!(file_key, FILE_KEY);
        assert_ne!(wrapped(1000)[..], wrapped(1001)[..]);
    }

    #[test]
    fn a_changed_body_decrypts_nothing() {
        let body = wrapped(1000);
        let signature = signature_of(1000);
        for at in 0..BODY_LEN {
            for bit in 0..8 {
                let mut changed = body;
                changed[at] ^= 1 << bit;
                let mut file_key = [0; FILE_KEY_LEN];
                assert!(
                    !unwrap(&signature, &changed, &mut file_key),
                    "byte {at}, bit {bit}"
                );
                assert_eq!(file_key, [0; FILE_KEY_LEN]);
            }
        }
        let mut identity = body;
        identity[..96].fill(0);
        identity[0] = 0xc0;
        assert!(!unwrap(&signature, &identity, &mut [0; FILE_KEY_LEN]));
    }

    #[test]
    fn the_first_candidate_below_the_order_is_taken() {
        let order = [ORDER.0.to_be_bytes(), ORDER.1.to_be_bytes()].concat();
        let order: [u8; 32] = order.try_into().unwrap();
        let mut below = order;
        below[31] -= 1;
        let mut high_below = order;
        high_below[15] -= 1;
        high_below[16..].fill(0xff);
        for (scalar, is_below) in [
            (order, false),
            (below, true),
            (high_below, true),
            ([0xff; 32], false),
            ([0; 32], true),
        ] {
            assert_eq!(below_order(&scalar).to_bool(), is_below);
        }
        let mut scalar = [0; 32];
        let mut found = ctutils::Choice::FALSE;
        for candidate in [order, below, high_below] {
            found = take_first(&mut scalar, &candidate, found);
        }
        assert!(found.to_bool());
        assert_eq!(scalar, below);
    }
}

/// What stands in for the encryption under Kani: it answers at will and keeps what it was given.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::{BODY_LEN, FILE_KEY_LEN};
    use crate::curve::KEY_LEN;
    use crate::curve::model::{keep, kept};
    use crate::network::SIGNATURE_LEN;

    static WRAPS: AtomicU64 = AtomicU64::new(0);
    static KEY: [AtomicU64; 12] = [const { AtomicU64::new(0) }; 12];
    static MESSAGE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    static FILE_KEY: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static SIGMA: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static WRAPPED: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
    static UNWRAPS: AtomicU64 = AtomicU64::new(0);
    static SIGNATURE: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
    static BODY: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
    static UNWRAPPED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

    /// What the encryption was given and wrote.
    pub(crate) struct Wrap {
        pub(crate) times: u64,
        pub(crate) key: [u8; KEY_LEN],
        pub(crate) message: [u8; 32],
        pub(crate) file_key: [u8; FILE_KEY_LEN],
        pub(crate) sigma: [u8; FILE_KEY_LEN],
        pub(crate) body: [u8; BODY_LEN],
    }

    /// What the decryption was given and wrote.
    pub(crate) struct Unwrap {
        pub(crate) times: u64,
        pub(crate) signature: [u8; SIGNATURE_LEN],
        pub(crate) body: [u8; BODY_LEN],
        pub(crate) file_key: [u8; FILE_KEY_LEN],
    }

    pub(crate) fn wrap(
        key: &[u8; KEY_LEN],
        message: &[u8; 32],
        file_key: &[u8; FILE_KEY_LEN],
        sigma: &[u8; FILE_KEY_LEN],
        body: &mut [u8; BODY_LEN],
    ) -> bool {
        *body = kani::any();
        count(&WRAPS);
        keep(&KEY, key);
        keep(&MESSAGE, message);
        keep(&FILE_KEY, file_key);
        keep(&SIGMA, sigma);
        keep(&WRAPPED, body);
        kani::any()
    }

    pub(crate) fn unwrap(
        signature: &[u8; SIGNATURE_LEN],
        body: &[u8; BODY_LEN],
        file_key: &mut [u8; FILE_KEY_LEN],
    ) -> bool {
        let answer = kani::any();
        if answer {
            *file_key = kani::any();
        }
        count(&UNWRAPS);
        keep(&SIGNATURE, signature);
        keep(&BODY, body);
        keep(&UNWRAPPED, file_key);
        answer
    }

    pub(crate) fn wrapped() -> Wrap {
        Wrap {
            times: WRAPS.load(Ordering::Relaxed),
            key: kept(&KEY),
            message: kept(&MESSAGE),
            file_key: kept(&FILE_KEY),
            sigma: kept(&SIGMA),
            body: kept(&WRAPPED),
        }
    }

    pub(crate) fn unwrapped() -> Unwrap {
        Unwrap {
            times: UNWRAPS.load(Ordering::Relaxed),
            signature: kept(&SIGNATURE),
            body: kept(&BODY),
            file_key: kept(&UNWRAPPED),
        }
    }

    fn count(times: &AtomicU64) {
        times.store(
            times.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Relaxed,
        );
    }
}
