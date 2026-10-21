// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! X-Wing, the hybrid of ML-KEM-768 and X25519, as version 11 of its Internet-Draft specifies.

#[cfg(not(kani))]
use ml_kem::{
    B32, Ciphertext, Decapsulate, DecapsulationKey, EncapsulationKey, Key, KeyExport, MlKem768,
    Seed,
};
#[cfg(not(kani))]
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

#[cfg(not(kani))]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(kani))]
use crate::key::wipe;

/// The size of a private key, the seed both key pairs expand from.
pub(crate) const SEED_LEN: usize = 32;
pub(crate) const PUBLIC_LEN: usize = 1216;
pub(crate) const CIPHERTEXT_LEN: usize = 1120;
pub(crate) const SHARED_LEN: usize = 32;
/// The randomness of one encapsulation: the message of ML-KEM, then the ephemeral key of X25519.
pub(crate) const RANDOMNESS_LEN: usize = 64;

#[cfg(not(kani))]
const ML_KEM_PUBLIC_LEN: usize = 1184;
#[cfg(not(kani))]
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
/// The seed of ML-KEM, d then z, and the private key of X25519.
#[cfg(not(kani))]
const EXPANDED_LEN: usize = 96;
#[cfg(not(kani))]
const LABEL: &[u8; 6] = b"\\.//^\\";

/// How many bytes of stack an operation with X-Wing or on an archive key is followed by a wipe of: at
/// least twice what it uses, as tests measure in each build.
#[cfg(all(not(kani), not(lethewis_unoptimised)))]
pub(crate) const STACK_WIPE: usize = 98_304;
#[cfg(all(not(kani), lethewis_unoptimised))]
pub(crate) const STACK_WIPE: usize = 229_376;

/// The ML-KEM-768 part of a public key holds a value not reduced modulo q (FIPS 203, section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidPublicKey;

/// Writes the public key of `seed`.
#[cfg(not(kani))]
pub(crate) fn public_key(seed: &[u8; SEED_LEN], public: &mut [u8; PUBLIC_LEN]) {
    let mut expanded = [0; EXPANDED_LEN];
    expand(seed, &mut expanded);
    if let Some((ml_kem_seed, x25519_secret)) = split::<_, 64, 32>(&expanded) {
        let key = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*ml_kem_seed));
        let ml_kem_public: [u8; ML_KEM_PUBLIC_LEN] = key.encapsulation_key().to_bytes().into();
        join(
            public,
            &ml_kem_public,
            &x25519(*x25519_secret, X25519_BASEPOINT_BYTES),
        );
    }
    wipe(&mut expanded);
}

/// Encapsulates to `public` with `randomness` and writes the ciphertext and the shared secret.
/// Fails, writing neither, if the ML-KEM-768 part of `public` is not a valid key.
#[cfg(not(kani))]
pub(crate) fn encapsulate(
    public: &[u8; PUBLIC_LEN],
    randomness: &[u8; RANDOMNESS_LEN],
    ciphertext: &mut [u8; CIPHERTEXT_LEN],
    shared: &mut [u8; SHARED_LEN],
) -> Result<(), InvalidPublicKey> {
    let (Some((ml_kem_public, x25519_public)), Some((message, ephemeral))) = (
        split::<_, ML_KEM_PUBLIC_LEN, 32>(public),
        split::<_, 32, 32>(randomness),
    ) else {
        return Err(InvalidPublicKey);
    };
    let key =
        EncapsulationKey::<MlKem768>::new(&Key::<EncapsulationKey<MlKem768>>::from(*ml_kem_public))
            .map_err(|_| InvalidPublicKey)?;
    let (ml_kem_ciphertext, ml_kem_shared) = key.encapsulate_deterministic(&B32::from(*message));
    let mut ml_kem_shared: [u8; SHARED_LEN] = ml_kem_shared.into();
    let x25519_ciphertext = x25519(*ephemeral, X25519_BASEPOINT_BYTES);
    let mut x25519_shared = x25519(*ephemeral, *x25519_public);
    combine(
        shared,
        &ml_kem_shared,
        &x25519_shared,
        &x25519_ciphertext,
        x25519_public,
    );
    let ml_kem_ciphertext: [u8; ML_KEM_CIPHERTEXT_LEN] = ml_kem_ciphertext.into();
    join(ciphertext, &ml_kem_ciphertext, &x25519_ciphertext);
    wipe(&mut ml_kem_shared);
    wipe(&mut x25519_shared);
    Ok(())
}

/// Writes the shared secret of `ciphertext` under `seed`. A ciphertext not made for this key gives
/// no error but a pseudorandom secret of the key and the ciphertext: ML-KEM rejects it implicitly.
#[cfg(not(kani))]
pub(crate) fn decapsulate(
    seed: &[u8; SEED_LEN],
    ciphertext: &[u8; CIPHERTEXT_LEN],
    shared: &mut [u8; SHARED_LEN],
) {
    let mut expanded = [0; EXPANDED_LEN];
    expand(seed, &mut expanded);
    if let (Some((ml_kem_seed, x25519_secret)), Some((ml_kem_ciphertext, x25519_ciphertext))) = (
        split::<_, 64, 32>(&expanded),
        split::<_, ML_KEM_CIPHERTEXT_LEN, 32>(ciphertext),
    ) {
        let key = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*ml_kem_seed));
        let mut ml_kem_shared: [u8; SHARED_LEN] = key
            .decapsulate(&Ciphertext::<MlKem768>::from(*ml_kem_ciphertext))
            .into();
        let x25519_public = x25519(*x25519_secret, X25519_BASEPOINT_BYTES);
        let mut x25519_shared = x25519(*x25519_secret, *x25519_ciphertext);
        combine(
            shared,
            &ml_kem_shared,
            &x25519_shared,
            x25519_ciphertext,
            &x25519_public,
        );
        wipe(&mut ml_kem_shared);
        wipe(&mut x25519_shared);
    }
    wipe(&mut expanded);
}

/// SHAKE256 of the seed, 96 bytes.
#[cfg(not(kani))]
fn expand(seed: &[u8; SEED_LEN], expanded: &mut [u8; EXPANDED_LEN]) {
    use shake::{ExtendableOutput, Shake256, Update, XofReader};

    let mut shake = Shake256::default();
    shake.update(seed);
    shake.finalize_xof().read(expanded);
}

/// SHA3-256 of the two shared secrets, the ciphertext and public key of X25519, and the label.
#[cfg(not(kani))]
fn combine(
    shared: &mut [u8; SHARED_LEN],
    ml_kem: &[u8; 32],
    x25519: &[u8; 32],
    x25519_ciphertext: &[u8; 32],
    x25519_public: &[u8; 32],
) {
    use sha3::{Digest, Sha3_256};

    let mut hash = Sha3_256::new();
    for part in [ml_kem, x25519, x25519_ciphertext, x25519_public] {
        hash.update(part);
    }
    hash.update(LABEL);
    *shared = hash.finalize().into();
}

/// The first `A` bytes and the `B` after them.
#[cfg(not(kani))]
fn split<const N: usize, const A: usize, const B: usize>(
    bytes: &[u8; N],
) -> Option<(&[u8; A], &[u8; B])> {
    const { assert!(A + B == N) };
    let (first, rest) = bytes.split_first_chunk::<A>()?;
    Some((first, rest.first_chunk::<B>()?))
}

/// Writes `first` and then `second` at the start of `out`.
#[cfg(not(kani))]
fn join<const N: usize, const A: usize, const B: usize>(
    out: &mut [u8; N],
    first: &[u8; A],
    second: &[u8; B],
) {
    const { assert!(A + B == N) };
    if let Some((to_first, rest)) = out.split_first_chunk_mut::<A>() {
        *to_first = *first;
        if let Some(to_second) = rest.first_chunk_mut::<B>() {
            *to_second = *second;
        }
    }
}

/// A seed and randomness, and what X-Wing makes of them.
#[cfg(not(kani))]
pub(crate) struct Answer {
    seed: [u8; SEED_LEN],
    public: [u8; PUBLIC_LEN],
    randomness: [u8; RANDOMNESS_LEN],
    ciphertext: [u8; CIPHERTEXT_LEN],
    shared: [u8; SHARED_LEN],
}

/// An answer X-Wing has to give, and whether it has given it in this process.
#[cfg(not(kani))]
pub(crate) struct Known {
    answer: &'static Answer,
    given: AtomicBool,
}

#[cfg(not(kani))]
impl Known {
    const fn of(answer: &'static Answer) -> Self {
        Self {
            answer,
            given: AtomicBool::new(false),
        }
    }
}

/// The first test vector of the draft, which X-Wing has to give once in a process.
#[cfg(not(kani))]
pub(crate) static KNOWN: Known = Known::of(&ANSWER);

#[cfg(not(kani))]
#[rustfmt::skip]
const ANSWER: Answer = Answer {
    seed: [
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50,
        0x76, 0x05, 0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
    ],
    public: [
        0xe2, 0x23, 0x6b, 0x35, 0xa8, 0xc2, 0x4b, 0x39, 0xb1, 0x0a, 0xa1, 0x32,
        0x3a, 0x96, 0xa9, 0x19, 0xa2, 0xce, 0xd8, 0x84, 0x00, 0x63, 0x3a, 0x7b,
        0x07, 0x13, 0x17, 0x13, 0xfc, 0x14, 0xb2, 0xb5, 0xb1, 0x9c, 0xfc, 0x3d,
        0xa5, 0xfa, 0x1a, 0x92, 0xc4, 0x9f, 0x25, 0x51, 0x3e, 0x0f, 0xd3, 0x0d,
        0x6b, 0x16, 0x11, 0xc9, 0xab, 0x96, 0x35, 0xd7, 0x08, 0x67, 0x27, 0xa4,
        0xb7, 0xd2, 0x1d, 0x34, 0x24, 0x4e, 0x66, 0x96, 0x9c, 0xf1, 0x5b, 0x3b,
        0x2a, 0x78, 0x53, 0x29, 0xf6, 0x1b, 0x09, 0x6b, 0x27, 0x7e, 0xa0, 0x37,
        0x38, 0x34, 0x79, 0xa6, 0xb5, 0x56, 0xde, 0x72, 0x31, 0xfe, 0x4b, 0x7f,
        0xa9, 0xc9, 0xac, 0x24, 0xc0, 0x69, 0x9a, 0x00, 0x18, 0xa5, 0x25, 0x34,
        0x01, 0xba, 0xcf, 0xa9, 0x05, 0xca, 0x81, 0x65, 0x73, 0xe5, 0x6a, 0x2d,
        0x2e, 0x06, 0x7e, 0x9b, 0x72, 0x87, 0x53, 0x3b, 0xa1, 0x3a, 0x93, 0x7d,
        0xed, 0xb3, 0x1f, 0xa4, 0x4b, 0xac, 0xed, 0x40, 0x76, 0x99, 0x23, 0x61,
        0x00, 0x34, 0xae, 0x31, 0xe6, 0x19, 0xa1, 0x70, 0x24, 0x51, 0x99, 0xb3,
        0xc5, 0xc3, 0x98, 0x64, 0x85, 0x9f, 0xe1, 0xb4, 0xc9, 0x71, 0x7a, 0x07,
        0xc3, 0x04, 0x95, 0xbd, 0xfb, 0x98, 0xa0, 0xa0, 0x02, 0xcc, 0xf5, 0x6c,
        0x12, 0x86, 0xce, 0xf5, 0x04, 0x1d, 0xed, 0xe3, 0xc4, 0x4c, 0xf1, 0x6b,
        0xf5, 0x62, 0xc7, 0x44, 0x85, 0x18, 0x02, 0x6b, 0x3d, 0x8b, 0x99, 0x40,
        0x68, 0x0a, 0xbd, 0x38, 0xa1, 0x57, 0x5f, 0xd2, 0x7b, 0x58, 0xda, 0x06,
        0x3b, 0xfa, 0xc3, 0x2c, 0x39, 0xc3, 0x08, 0x69, 0x37, 0x4c, 0x05, 0xc1,
        0xae, 0xb1, 0x89, 0x8b, 0x6b, 0x30, 0x3c, 0xc6, 0x8b, 0xe4, 0x55, 0x34,
        0x6e, 0xe0, 0xaf, 0x69, 0x96, 0x36, 0x22, 0x4a, 0x14, 0x8c, 0xa2, 0xae,
        0xa1, 0x04, 0x63, 0x11, 0x1c, 0x70, 0x9f, 0x69, 0xb6, 0x9c, 0x70, 0xce,
        0x85, 0x38, 0x74, 0x66, 0x98, 0xc4, 0xc6, 0x0a, 0x9a, 0xef, 0x00, 0x30,
        0xc7, 0x92, 0x4c, 0xee, 0xc4, 0x2a, 0x5d, 0x36, 0x81, 0x6f, 0x54, 0x5e,
        0xae, 0x13, 0x29, 0x34, 0x60, 0xb3, 0xac, 0xb3, 0x7e, 0xa0, 0xe1, 0x3d,
        0x70, 0xe4, 0xaa, 0x78, 0x68, 0x6d, 0xa3, 0x98, 0xa8, 0x39, 0x7c, 0x08,
        0xea, 0xf9, 0x68, 0x82, 0x11, 0x3f, 0xe4, 0xf7, 0xba, 0xd4, 0xda, 0x40,
        0xb0, 0x50, 0x1e, 0x1c, 0x75, 0x3e, 0xfe, 0x73, 0x05, 0x3c, 0x87, 0x01,
        0x4e, 0x86, 0x61, 0xc3, 0x30, 0x99, 0xaf, 0xe8, 0xbe, 0xde, 0x41, 0x4a,
        0x5b, 0x1a, 0xa2, 0x7d, 0x83, 0x92, 0xb3, 0xe1, 0x31, 0xe9, 0xa7, 0x0c,
        0x10, 0x55, 0x87, 0x82, 0x40, 0xca, 0xd0, 0xf4, 0x0d, 0x5f, 0xe3, 0xcd,
        0xf8, 0x52, 0x36, 0xea, 0xd9, 0x7e, 0x2a, 0x97, 0x44, 0x83, 0x63, 0xb2,
        0x80, 0x8c, 0xaa, 0xfd, 0x51, 0x6c, 0xd2, 0x50, 0x52, 0xc5, 0xc3, 0x62,
        0x54, 0x3c, 0x25, 0x17, 0xe4, 0xac, 0xd0, 0xe6, 0x0e, 0xc0, 0x71, 0x63,
        0x00, 0x9b, 0x64, 0x25, 0xfc, 0x32, 0x27, 0x7a, 0xce, 0xe7, 0x1c, 0x24,
        0xba, 0xb5, 0x3e, 0xd9, 0xf2, 0x9e, 0x74, 0xc6, 0x6a, 0x0a, 0x35, 0x64,
        0x95, 0x59, 0x98, 0xd7, 0x6b, 0x96, 0xa9, 0xa8, 0xb5, 0x0d, 0x16, 0x35,
        0xa4, 0xd7, 0xa6, 0x7e, 0xb4, 0x2d, 0xf5, 0x64, 0x4d, 0x33, 0x04, 0x57,
        0x29, 0x3a, 0x80, 0x42, 0xf5, 0x3c, 0xc7, 0xa6, 0x92, 0x88, 0xf1, 0x7e,
        0xd5, 0x58, 0x27, 0xe8, 0x2b, 0x28, 0xe8, 0x26, 0x65, 0xa8, 0x6a, 0x14,
        0xfb, 0xd9, 0x66, 0x45, 0xec, 0xa8, 0x17, 0x2c, 0x04, 0x4f, 0x83, 0xbc,
        0x0d, 0x8c, 0x0b, 0x4c, 0x86, 0x26, 0x98, 0x56, 0x31, 0xca, 0x87, 0xaf,
        0x82, 0x90, 0x68, 0xf1, 0x35, 0x89, 0x63, 0xcb, 0x33, 0x36, 0x64, 0xca,
        0x48, 0x27, 0x63, 0xba, 0x3b, 0x3b, 0xb2, 0x08, 0x57, 0x7f, 0x9b, 0xa6,
        0xac, 0x62, 0xc2, 0x5f, 0x76, 0x59, 0x27, 0x43, 0xb6, 0x4b, 0xe5, 0x19,
        0x31, 0x77, 0x14, 0xcb, 0x41, 0x02, 0xcb, 0x7b, 0x2f, 0x9a, 0x25, 0xb2,
        0xb4, 0xf0, 0x61, 0x5d, 0xe3, 0x1d, 0xec, 0xd9, 0xca, 0x55, 0x02, 0x6d,
        0x6d, 0xa0, 0xb6, 0x51, 0x11, 0xb1, 0x6f, 0xe5, 0x2f, 0xee, 0xd8, 0xa4,
        0x87, 0xe1, 0x44, 0x46, 0x2a, 0x6d, 0xba, 0x93, 0x72, 0x8f, 0x50, 0x0b,
        0x6f, 0xfc, 0x49, 0xe5, 0x15, 0x56, 0x9e, 0xf2, 0x5f, 0xed, 0x17, 0xaf,
        0xf5, 0x20, 0x50, 0x73, 0x68, 0x25, 0x35, 0x25, 0x86, 0x0f, 0x58, 0xbe,
        0x3b, 0xe6, 0x1c, 0x96, 0x46, 0x04, 0xa6, 0xac, 0x81, 0x4e, 0x69, 0x35,
        0x59, 0x64, 0x02, 0xa5, 0x20, 0xa4, 0x67, 0x0b, 0x3d, 0x28, 0x43, 0x18,
        0x86, 0x65, 0x93, 0xd1, 0x5a, 0x4b, 0xb0, 0x1c, 0x35, 0xe3, 0xe5, 0x87,
        0xee, 0x0c, 0x67, 0xd2, 0x88, 0x0d, 0x6f, 0x24, 0x07, 0xfb, 0x7a, 0x70,
        0x71, 0x2b, 0x83, 0x8d, 0xeb, 0x96, 0xc5, 0xd7, 0xbf, 0x2b, 0x44, 0xbc,
        0xf6, 0x03, 0x8c, 0xcb, 0xe3, 0x3f, 0xbc, 0xf5, 0x1a, 0x54, 0xa5, 0x84,
        0xfe, 0x90, 0x08, 0x3c, 0x91, 0xc7, 0xa6, 0xd4, 0x3d, 0x4f, 0xb1, 0x5f,
        0x48, 0xc6, 0x0c, 0x2f, 0xd6, 0x6e, 0x0a, 0x8a, 0xad, 0x4a, 0xd6, 0x4e,
        0x5c, 0x42, 0xbb, 0x88, 0x77, 0xc0, 0xeb, 0xec, 0x2b, 0x5e, 0x38, 0x7c,
        0x8a, 0x98, 0x8f, 0xdc, 0x23, 0xbe, 0xb9, 0xe1, 0x6c, 0x87, 0x57, 0x78,
        0x1e, 0x0a, 0x14, 0x99, 0xc6, 0x1e, 0x13, 0x8c, 0x21, 0xf2, 0x16, 0xc2,
        0x9d, 0x07, 0x69, 0x79, 0x87, 0x1c, 0xaa, 0x69, 0x42, 0xba, 0xfc, 0x09,
        0x05, 0x44, 0xbe, 0xe9, 0x9b, 0x54, 0xb1, 0x6c, 0xb9, 0xa9, 0xa3, 0x64,
        0xd6, 0x24, 0x6d, 0x9f, 0x42, 0xcc, 0xe5, 0x3c, 0x66, 0xb5, 0x9c, 0x45,
        0xc8, 0xf9, 0xae, 0x92, 0x99, 0xa7, 0x5d, 0x15, 0x18, 0x0c, 0x3c, 0x95,
        0x21, 0x51, 0xa9, 0x1b, 0x7a, 0x10, 0x77, 0x24, 0x29, 0xdc, 0x4c, 0xba,
        0xe6, 0xfc, 0xc6, 0x22, 0xfa, 0x80, 0x18, 0xc6, 0x34, 0x39, 0xf8, 0x90,
        0x63, 0x0b, 0x99, 0x28, 0xdb, 0x6b, 0xb7, 0xf9, 0x43, 0x8a, 0xe4, 0x06,
        0x5e, 0xd3, 0x4d, 0x73, 0xd4, 0x86, 0xf3, 0xf5, 0x2f, 0x90, 0xf0, 0x80,
        0x7d, 0xc8, 0x8d, 0xfd, 0xd8, 0xc7, 0x28, 0xe9, 0x54, 0xf1, 0xac, 0x35,
        0xc0, 0x6c, 0x00, 0x0c, 0xe4, 0x1a, 0x05, 0x82, 0x58, 0x0e, 0x3b, 0xb5,
        0x7b, 0x67, 0x29, 0x72, 0x89, 0x0a, 0xc5, 0xe7, 0x98, 0x8e, 0x78, 0x50,
        0x65, 0x71, 0x16, 0xf1, 0xb5, 0x7d, 0x08, 0x09, 0xaa, 0xed, 0xec, 0x0b,
        0xed, 0xe1, 0xae, 0x14, 0x81, 0x48, 0x31, 0x1c, 0x6f, 0x7e, 0x31, 0x73,
        0x46, 0xe5, 0x18, 0x9f, 0xb8, 0xcd, 0x63, 0x5b, 0x98, 0x6f, 0x8c, 0x0b,
        0xdd, 0x27, 0x64, 0x1c, 0x58, 0x4b, 0x77, 0x8b, 0x3a, 0x91, 0x1a, 0x80,
        0xbe, 0x1c, 0x96, 0x92, 0xab, 0x8e, 0x1b, 0xbb, 0x12, 0x83, 0x95, 0x73,
        0xcc, 0xe1, 0x9d, 0xf1, 0x83, 0xb4, 0x58, 0x35, 0xbb, 0xb5, 0x50, 0x52,
        0xf9, 0xfc, 0x66, 0xa1, 0x67, 0x8e, 0xf2, 0xa3, 0x6d, 0xea, 0x78, 0x41,
        0x1e, 0x6c, 0x8d, 0x60, 0x50, 0x1b, 0x4e, 0x60, 0x59, 0x2d, 0x13, 0x69,
        0x8a, 0x94, 0x3b, 0x50, 0x91, 0x85, 0xdb, 0x91, 0x2e, 0x2e, 0xa1, 0x0b,
        0xe0, 0x61, 0x71, 0x23, 0x6b, 0x32, 0x7c, 0x71, 0x71, 0x60, 0x94, 0xc9,
        0x64, 0xa6, 0x8b, 0x03, 0x37, 0x7f, 0x51, 0x3a, 0x05, 0xbc, 0xd9, 0x9c,
        0x1f, 0x34, 0x65, 0x83, 0xbb, 0x05, 0x29, 0x77, 0xa1, 0x0a, 0x12, 0xad,
        0xfc, 0x75, 0x80, 0x34, 0xe5, 0x61, 0x7d, 0xa4, 0xc1, 0x27, 0x65, 0x85,
        0xe5, 0x77, 0x4e, 0x1f, 0x3b, 0x99, 0x78, 0xb0, 0x9d, 0x0e, 0x9c, 0x44,
        0xd3, 0xbc, 0x86, 0x15, 0x1c, 0x43, 0xaa, 0xd1, 0x85, 0x71, 0x27, 0x17,
        0x34, 0x02, 0x23, 0xac, 0x38, 0x1d, 0x21, 0x15, 0x0a, 0x04, 0x29, 0x4e,
        0x97, 0xbb, 0x13, 0xbb, 0xda, 0x21, 0xb5, 0xa1, 0x82, 0xb6, 0xda, 0x96,
        0x9e, 0x19, 0xa7, 0xfd, 0x07, 0x27, 0x37, 0xfa, 0x8e, 0x88, 0x0a, 0x53,
        0xc2, 0x42, 0x8e, 0x3d, 0x04, 0x9b, 0x7d, 0x21, 0x97, 0x40, 0x52, 0x96,
        0xdd, 0xb3, 0x61, 0x91, 0x2a, 0x7b, 0xcf, 0x48, 0x27, 0xce, 0xd6, 0x11,
        0xd0, 0xc7, 0xa7, 0xda, 0x10, 0x4d, 0xde, 0x43, 0x22, 0x09, 0x53, 0x39,
        0xf6, 0x4a, 0x61, 0xd5, 0xbb, 0x10, 0x8f, 0xf0, 0xbf, 0x4d, 0x78, 0x0c,
        0xae, 0x50, 0x9f, 0xb2, 0x2c, 0x25, 0x69, 0x14, 0x19, 0x3f, 0xf7, 0x34,
        0x90, 0x42, 0x58, 0x12, 0x37, 0xd5, 0x22, 0x82, 0x88, 0x24, 0xee, 0x3b,
        0xdf, 0xd0, 0x7f, 0xb0, 0x3f, 0x1f, 0x94, 0x2d, 0x2e, 0xa1, 0x79, 0xfe,
        0x72, 0x2f, 0x06, 0xcc, 0x03, 0xde, 0x5b, 0x69, 0x85, 0x9e, 0xdb, 0x06,
        0xef, 0xf3, 0x89, 0xb2, 0x7d, 0xce, 0x59, 0x84, 0x45, 0x70, 0x21, 0x62,
        0x23, 0x59, 0x3d, 0x4b, 0xa3, 0x2d, 0x9a, 0xba, 0xc8, 0xcd, 0x04, 0x90,
        0x40, 0xef, 0x65, 0x34,
    ],
    randomness: [
        0x3c, 0xb1, 0xee, 0xa9, 0x88, 0x00, 0x4b, 0x93, 0x10, 0x3c, 0xfb, 0x0a,
        0xee, 0xfd, 0x2a, 0x68, 0x6e, 0x01, 0xfa, 0x4a, 0x58, 0xe8, 0xa3, 0x63,
        0x9c, 0xa8, 0xa1, 0xe3, 0xf9, 0xae, 0x57, 0xe2, 0x35, 0xb8, 0xcc, 0x87,
        0x3c, 0x23, 0xdc, 0x62, 0xb8, 0xd2, 0x60, 0x16, 0x9a, 0xfa, 0x2f, 0x75,
        0xab, 0x91, 0x6a, 0x58, 0xd9, 0x74, 0x91, 0x88, 0x35, 0xd2, 0x5e, 0x6a,
        0x43, 0x50, 0x85, 0xb2,
    ],
    ciphertext: [
        0xb8, 0x3a, 0xa8, 0x28, 0xd4, 0xd6, 0x2b, 0x9a, 0x83, 0xce, 0xff, 0xe1,
        0xd3, 0xd3, 0xbb, 0x1e, 0xf3, 0x12, 0x64, 0x64, 0x3c, 0x07, 0x0c, 0x57,
        0x98, 0x92, 0x7e, 0x41, 0xfb, 0x07, 0x91, 0x4a, 0x27, 0x3f, 0x8f, 0x96,
        0xe7, 0x82, 0x6c, 0xd5, 0x37, 0x5a, 0x28, 0x3d, 0x7d, 0xa8, 0x85, 0x30,
        0x4c, 0x5d, 0xe0, 0x51, 0x6a, 0x0f, 0x06, 0x54, 0x24, 0x3d, 0xc5, 0xb9,
        0x7f, 0x8b, 0xfe, 0xb8, 0x31, 0xf6, 0x82, 0x51, 0x21, 0x9a, 0xab, 0xdd,
        0x72, 0x3b, 0xc6, 0x51, 0x20, 0x41, 0xac, 0xba, 0xef, 0x8a, 0xf4, 0x42,
        0x65, 0x52, 0x49, 0x42, 0xb9, 0x02, 0xe6, 0x8f, 0xfd, 0x23, 0x22, 0x1c,
        0xda, 0x70, 0xb1, 0xb5, 0x5d, 0x77, 0x6a, 0x92, 0xd1, 0x14, 0x3e, 0xa3,
        0xa0, 0xc4, 0x75, 0xf6, 0x3e, 0xe6, 0x89, 0x01, 0x57, 0xc7, 0x11, 0x6d,
        0xae, 0x3f, 0x62, 0xbf, 0x72, 0xf6, 0x0a, 0xcd, 0x2b, 0xb8, 0xcc, 0x31,
        0xce, 0x2b, 0xa0, 0xde, 0x36, 0x4f, 0x52, 0xb8, 0xed, 0x38, 0xc7, 0x9d,
        0x71, 0x97, 0x15, 0x96, 0x3a, 0x5d, 0xd3, 0x84, 0x2d, 0x8e, 0x8b, 0x43,
        0xab, 0x70, 0x4e, 0x47, 0x59, 0xb5, 0x32, 0x7b, 0xf0, 0x27, 0xc6, 0x3c,
        0x8f, 0xa8, 0x57, 0xc4, 0x90, 0x8d, 0x5a, 0x8a, 0x7b, 0x88, 0xac, 0x7f,
        0x2b, 0xe3, 0x94, 0xd9, 0x3c, 0x37, 0x06, 0xdd, 0xd4, 0xe6, 0x98, 0xcc,
        0x6c, 0xe3, 0x70, 0x10, 0x1f, 0x4d, 0x02, 0x13, 0x25, 0x42, 0x38, 0xb4,
        0xa2, 0xe8, 0x82, 0x1b, 0x6e, 0x41, 0x4a, 0x1c, 0xf2, 0x0f, 0x6c, 0x12,
        0x44, 0xb6, 0x99, 0x04, 0x6f, 0x5a, 0x01, 0xca, 0xa0, 0xa1, 0xa5, 0x55,
        0x16, 0x30, 0x0b, 0x40, 0xd2, 0x04, 0x8c, 0x77, 0xcc, 0x73, 0xaf, 0xba,
        0x79, 0xaf, 0xee, 0xa9, 0xd2, 0xc0, 0x11, 0x8b, 0xdf, 0x2a, 0xdb, 0x88,
        0x70, 0xdc, 0x32, 0x8c, 0x55, 0x16, 0xcc, 0x45, 0xb1, 0xa2, 0x05, 0x81,
        0x41, 0x03, 0x9e, 0x2c, 0x90, 0xa1, 0x10, 0xa9, 0xe1, 0x6b, 0x31, 0x8d,
        0xfb, 0x53, 0xbd, 0x49, 0xa1, 0x26, 0xd6, 0xb7, 0x3f, 0x21, 0x57, 0x87,
        0x51, 0x7b, 0x89, 0x17, 0xcc, 0x01, 0xca, 0xbd, 0x10, 0x7d, 0x06, 0x85,
        0x98, 0x54, 0xee, 0x8b, 0x4f, 0x98, 0x61, 0xc2, 0x26, 0xd3, 0x76, 0x4c,
        0x87, 0x33, 0x9a, 0xb1, 0x6c, 0x36, 0x67, 0xd2, 0xf4, 0x93, 0x84, 0xe5,
        0x54, 0x56, 0xdd, 0x40, 0x41, 0x4b, 0x70, 0xa6, 0xaf, 0x84, 0x15, 0x85,
        0xf4, 0xc9, 0x0c, 0x68, 0x72, 0x5d, 0x57, 0x70, 0x4e, 0xe8, 0xee, 0x7c,
        0xe6, 0xe2, 0xf9, 0xbe, 0x58, 0x2d, 0xbe, 0xe9, 0x85, 0xe0, 0x38, 0xff,
        0xc3, 0x46, 0xeb, 0xfb, 0x4e, 0x22, 0x15, 0x8b, 0x6c, 0x84, 0x37, 0x4a,
        0x9a, 0xb4, 0xa4, 0x4e, 0x1f, 0x91, 0xde, 0x5a, 0xac, 0x51, 0x97, 0xf8,
        0x9b, 0xc5, 0xe5, 0x44, 0x2f, 0x51, 0xf9, 0xa5, 0x93, 0x7b, 0x10, 0x2b,
        0xa3, 0xbe, 0xae, 0xbf, 0x6e, 0x1c, 0x58, 0x38, 0x0a, 0x4a, 0x5f, 0xed,
        0xce, 0x4a, 0x4e, 0x50, 0x26, 0xf8, 0x8f, 0x52, 0x8f, 0x59, 0xff, 0xd2,
        0xdb, 0x41, 0x75, 0x2b, 0x3a, 0x3d, 0x90, 0xef, 0xab, 0xe4, 0x63, 0x89,
        0x9b, 0x7d, 0x40, 0x87, 0x0c, 0x53, 0x0c, 0x88, 0x41, 0xe8, 0x71, 0x2b,
        0x73, 0x36, 0x68, 0xed, 0x03, 0x3a, 0xdb, 0xfa, 0xfb, 0x2d, 0x49, 0xd3,
        0x7a, 0x44, 0xd4, 0x06, 0x4e, 0x58, 0x63, 0xeb, 0x0a, 0xf0, 0xa0, 0x8d,
        0x47, 0xb3, 0xcc, 0x88, 0x83, 0x73, 0xbc, 0x05, 0xf7, 0xa3, 0x3b, 0x84,
        0x1b, 0xc2, 0x58, 0x7c, 0x57, 0xeb, 0x69, 0x55, 0x4e, 0x8a, 0x37, 0x67,
        0xb7, 0x50, 0x69, 0x17, 0xb6, 0xb7, 0x04, 0x98, 0x72, 0x7f, 0x16, 0xea,
        0xc1, 0xa3, 0x6e, 0xc8, 0xd8, 0xcf, 0xaf, 0x75, 0x15, 0x49, 0xf2, 0x27,
        0x7d, 0xb2, 0x77, 0xe8, 0xa5, 0x5a, 0x9a, 0x51, 0x06, 0xb2, 0x3a, 0x02,
        0x06, 0xb4, 0x72, 0x1f, 0xa9, 0xb3, 0x04, 0x85, 0x52, 0xc5, 0xbd, 0x5b,
        0x59, 0x4d, 0x6e, 0x24, 0x7f, 0x38, 0xc1, 0x8c, 0x59, 0x1a, 0xea, 0x7f,
        0x56, 0x24, 0x9c, 0x72, 0xce, 0x7b, 0x11, 0x7a, 0xfc, 0xc3, 0xa8, 0x62,
        0x15, 0x82, 0xf9, 0xcf, 0x71, 0x78, 0x7e, 0x18, 0x3d, 0xee, 0x09, 0x36,
        0x79, 0x76, 0xe9, 0x84, 0x09, 0xad, 0x92, 0x17, 0xa4, 0x97, 0xdf, 0x88,
        0x80, 0x42, 0x38, 0x4d, 0x77, 0x07, 0xa6, 0xb7, 0x8f, 0x5f, 0x7f, 0xb8,
        0x40, 0x9e, 0x3b, 0x53, 0x51, 0x75, 0x37, 0x34, 0x61, 0xb7, 0x76, 0x00,
        0x2d, 0x79, 0x9c, 0xba, 0xd6, 0x28, 0x60, 0xbe, 0x70, 0x57, 0x3e, 0xcb,
        0xe1, 0x3b, 0x24, 0x6e, 0x0d, 0xa7, 0xe9, 0x3a, 0x52, 0x16, 0x8e, 0x0f,
        0xb6, 0xa9, 0x75, 0x6b, 0x89, 0x5e, 0xf7, 0xf0, 0x14, 0x7a, 0x0d, 0xc8,
        0x1b, 0xfa, 0x64, 0x4b, 0x08, 0x8a, 0x92, 0x28, 0x16, 0x0c, 0x0f, 0x9a,
        0xcf, 0x13, 0x79, 0xa2, 0x94, 0x1c, 0xd2, 0x8c, 0x06, 0xeb, 0xc8, 0x0e,
        0x44, 0xe1, 0x7a, 0xa2, 0xf8, 0x17, 0x70, 0x10, 0xaf, 0xd7, 0x8a, 0x97,
        0xce, 0x08, 0x68, 0xd1, 0x62, 0x9e, 0xbb, 0x29, 0x4c, 0x51, 0x51, 0x81,
        0x2c, 0x58, 0x3d, 0xae, 0xb8, 0x86, 0x85, 0x22, 0x0f, 0x4d, 0xa9, 0x11,
        0x81, 0x12, 0xe0, 0x70, 0x41, 0xfc, 0xc2, 0x4d, 0x55, 0x64, 0xa9, 0x9f,
        0xdb, 0xde, 0x28, 0x86, 0x9f, 0xe0, 0x72, 0x23, 0x87, 0xd7, 0xa9, 0xa4,
        0xd1, 0x6e, 0x1c, 0xc8, 0x55, 0x59, 0x17, 0xe0, 0x99, 0x44, 0xaa, 0x5e,
        0xba, 0xaa, 0xec, 0x2c, 0xf6, 0x26, 0x93, 0xaf, 0xad, 0x42, 0xa3, 0xf5,
        0x18, 0xfc, 0xe6, 0x7d, 0x27, 0x3c, 0xc6, 0xc9, 0xfb, 0x54, 0x72, 0xb3,
        0x80, 0xe8, 0x57, 0x3e, 0xc7, 0xde, 0x06, 0xa3, 0xba, 0x2f, 0xd5, 0xf9,
        0x31, 0xd7, 0x25, 0xb4, 0x93, 0x02, 0x6c, 0xb0, 0xac, 0xbd, 0x3f, 0xe6,
        0x2d, 0x00, 0xe4, 0xc7, 0x90, 0xd9, 0x65, 0xd7, 0xa0, 0x3a, 0x3c, 0x0b,
        0x42, 0x22, 0xba, 0x8c, 0x2a, 0x9a, 0x16, 0xe2, 0xac, 0x65, 0x8f, 0x57,
        0x2a, 0xe0, 0xe7, 0x46, 0xea, 0xfc, 0x4f, 0xeb, 0xa0, 0x23, 0x57, 0x6f,
        0x08, 0x94, 0x22, 0x78, 0xa0, 0x41, 0xfb, 0x82, 0xa7, 0x0a, 0x59, 0x5d,
        0x5b, 0xac, 0xbf, 0x29, 0x7c, 0xe2, 0x02, 0x98, 0x98, 0xa7, 0x1e, 0x5c,
        0x3b, 0x0d, 0x1c, 0x62, 0x28, 0xb4, 0x85, 0xb1, 0xad, 0xe5, 0x09, 0xb3,
        0x5f, 0xbc, 0xa7, 0xec, 0xa9, 0x7b, 0x21, 0x32, 0xe7, 0xcb, 0x6b, 0xc4,
        0x65, 0x37, 0x51, 0x46, 0xb7, 0xdc, 0xea, 0xc9, 0x69, 0x30, 0x8a, 0xc0,
        0xc2, 0xac, 0x89, 0xe7, 0x86, 0x3e, 0xb8, 0x94, 0x30, 0x15, 0xb2, 0x43,
        0x14, 0xca, 0xfb, 0x9c, 0x7c, 0x0e, 0x85, 0xfe, 0x54, 0x3d, 0x56, 0x65,
        0x8c, 0x21, 0x36, 0x32, 0x59, 0x9e, 0xfa, 0xbf, 0xc1, 0xec, 0x49, 0xdd,
        0x8c, 0x88, 0x54, 0x7b, 0xb2, 0xcc, 0x40, 0xc9, 0xd3, 0x8c, 0xbd, 0x30,
        0x99, 0xb4, 0x54, 0x78, 0x40, 0x56, 0x05, 0x31, 0xd0, 0x18, 0x8c, 0xd1,
        0xe9, 0xc2, 0x3a, 0x0e, 0xbe, 0xe0, 0xa0, 0x3d, 0x55, 0x77, 0xd6, 0x6b,
        0x1d, 0x2b, 0xcb, 0x4b, 0xaa, 0xf2, 0x1c, 0xc7, 0xfe, 0xf1, 0xe0, 0x38,
        0x06, 0xca, 0x96, 0x29, 0x9d, 0xf0, 0xdf, 0xbc, 0x56, 0xe1, 0xb2, 0xb4,
        0x3e, 0x4f, 0xc2, 0x0c, 0x37, 0xf8, 0x34, 0xc4, 0xaf, 0x62, 0x12, 0x7e,
        0x7d, 0xae, 0x86, 0xc3, 0xc2, 0x5a, 0x2f, 0x69, 0x6a, 0xc8, 0xb5, 0x89,
        0xde, 0xc7, 0x1d, 0x59, 0x5b, 0xfb, 0xe9, 0x4b, 0x5e, 0xd4, 0xbc, 0x07,
        0xd8, 0x00, 0xb3, 0x30, 0x79, 0x6f, 0xda, 0x89, 0xed, 0xb7, 0x7b, 0xe0,
        0x29, 0x41, 0x36, 0x13, 0x93, 0x54, 0xeb, 0x8c, 0xd3, 0x75, 0x91, 0x57,
        0x8f, 0x9c, 0x60, 0x0d, 0xd9, 0xbe, 0x8e, 0xc6, 0x21, 0x9f, 0xdd, 0x50,
        0x7a, 0xdf, 0x33, 0x97, 0xed, 0x4d, 0x68, 0x70, 0x7b, 0x8d, 0x13, 0xb2,
        0x4c, 0xe4, 0xcd, 0x8f, 0xb2, 0x28, 0x51, 0xbf, 0xe9, 0xd6, 0x32, 0x40,
        0x7f, 0x31, 0xed, 0x6f, 0x7c, 0xb1, 0x60, 0x0d, 0xe5, 0x6f, 0x17, 0x57,
        0x67, 0x40, 0xce, 0x2a, 0x32, 0xfc, 0x51, 0x45, 0x03, 0x01, 0x45, 0xcf,
        0xb9, 0x7e, 0x63, 0xe0, 0xe4, 0x1d, 0x35, 0x42, 0x74, 0xa0, 0x79, 0xd3,
        0xe6, 0xfb, 0x2e, 0x15,
    ],
    shared: [
        0xd2, 0xdf, 0x05, 0x22, 0x12, 0x8f, 0x09, 0xdd, 0x8e, 0x2c, 0x92, 0xb1,
        0xe9, 0x05, 0xc7, 0x93, 0xd8, 0xf5, 0x7a, 0x54, 0xc3, 0xda, 0x25, 0x86,
        0x1f, 0x10, 0xbf, 0x4c, 0xa6, 0x13, 0xe3, 0x84,
    ],
};

#[cfg(test)]
extern crate std;

/// [`KNOWN`] as X-Wing has not given it yet.
#[cfg(test)]
pub(crate) fn unanswered() -> Known {
    Known::of(&ANSWER)
}

/// `answer`, which X-Wing has not given yet.
#[cfg(test)]
pub(crate) fn known(answer: Answer) -> Known {
    Known::of(std::boxed::Box::leak(std::boxed::Box::new(answer)))
}

/// [`KNOWN`] with its shared secret changed, which X-Wing does not give.
#[cfg(test)]
pub(crate) fn wrong_known() -> Known {
    let mut wrong = ANSWER;
    if let Some(first) = wrong.shared.first_mut() {
        *first ^= 1;
    }
    known(wrong)
}

/// Whether X-Wing gives `known`, which is [`KNOWN`] but in tests: the public key of its seed, the
/// ciphertext and shared secret of its randomness, and the shared secret of that ciphertext. Once it
/// has, `known` keeps that, and X-Wing is not asked for it again.
#[cfg(not(kani))]
pub(crate) fn answers(known: &Known) -> bool {
    if known.given.load(Ordering::Relaxed) {
        return true;
    }
    let known_answer = known.answer;
    let mut public = [0; PUBLIC_LEN];
    public_key(&known_answer.seed, &mut public);
    let (mut ciphertext, mut shared, mut opened) =
        ([0; CIPHERTEXT_LEN], [0; SHARED_LEN], [0; SHARED_LEN]);
    let encapsulated = encapsulate(
        &public,
        &known_answer.randomness,
        &mut ciphertext,
        &mut shared,
    );
    decapsulate(&known_answer.seed, &known_answer.ciphertext, &mut opened);
    let answered = public == known_answer.public
        && encapsulated.is_ok()
        && ciphertext == known_answer.ciphertext
        && shared == known_answer.shared
        && opened == known_answer.shared;
    if answered {
        known.given.store(true, Ordering::Relaxed);
    }
    answered
}

/// Whether the key pair of `seed` agrees with itself: an encapsulation to `public` and the
/// decapsulation of its ciphertext with `seed` give one shared secret. A pair that does not makes
/// X-Wing untrusted, and `known` is asked for again.
#[cfg(not(kani))]
pub(crate) fn agrees(known: &Known, seed: &[u8; SEED_LEN], public: &[u8; PUBLIC_LEN]) -> bool {
    let (mut ciphertext, mut shared, mut opened) =
        ([0; CIPHERTEXT_LEN], [0; SHARED_LEN], [0; SHARED_LEN]);
    let encapsulated = encapsulate(
        public,
        &known.answer.randomness,
        &mut ciphertext,
        &mut shared,
    );
    decapsulate(seed, &ciphertext, &mut opened);
    let differ = shared
        .iter()
        .zip(opened)
        .fold(0, |differ, (a, b)| differ | (a ^ b));
    wipe(&mut shared);
    wipe(&mut opened);
    let agreed = encapsulated.is_ok() && differ == 0;
    if !agreed {
        known.given.store(false, Ordering::Relaxed);
    }
    agreed
}

#[cfg(kani)]
pub(crate) use model::{KNOWN, Known, agrees, answers, decapsulate, encapsulate, public_key};

/// What stands in for X-Wing under Kani.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    use super::{
        CIPHERTEXT_LEN, InvalidPublicKey, PUBLIC_LEN, RANDOMNESS_LEN, SEED_LEN, SHARED_LEN,
    };

    /// What the last encapsulation or decapsulation was given and gave, so that a proof can follow
    /// it: the randomness or the seed, the first bytes of the public key and of the ciphertext,
    /// which the model of HKDF reads only so far, and the shared secret.
    static RANDOMNESS: [AtomicU8; RANDOMNESS_LEN] = [const { AtomicU8::new(0) }; RANDOMNESS_LEN];
    static SEED: [AtomicU8; SEED_LEN] = [const { AtomicU8::new(0) }; SEED_LEN];
    static PUBLIC: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];
    static CIPHERTEXT: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];
    static SHARED: [AtomicU8; SHARED_LEN] = [const { AtomicU8::new(0) }; SHARED_LEN];
    /// Whether the last encapsulation refused its public key, and whether any decapsulation ran.
    static REFUSED: AtomicBool = AtomicBool::new(false);
    static DECAPSULATED: AtomicBool = AtomicBool::new(false);

    /// Whether the last self-test was given the known answer, so that a proof can tell a refusal
    /// of X-Wing from one the code makes up.
    static ANSWERED: AtomicBool = AtomicBool::new(false);
    /// Whether a key pair was checked, whether it agreed with itself, and the seed and the first
    /// bytes of the public key it was.
    static PAIRED: AtomicBool = AtomicBool::new(false);
    static AGREED: AtomicBool = AtomicBool::new(false);
    static PAIR_SEED: [AtomicU8; SEED_LEN] = [const { AtomicU8::new(0) }; SEED_LEN];
    static PAIR_PUBLIC: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];

    /// The known answer, which the model does not read.
    pub(crate) struct Known;

    pub(crate) const KNOWN: Known = Known;

    /// X-Wing is beyond Kani. The public key of a seed is the seed and then zeros: one seed gives
    /// one public key, and two seeds two.
    pub(crate) fn public_key(seed: &[u8; SEED_LEN], public: &mut [u8; PUBLIC_LEN]) {
        *public = [0; PUBLIC_LEN];
        if let Some(first) = public.first_chunk_mut::<SEED_LEN>() {
            *first = *seed;
        }
    }

    /// The known answer is given or not, at will, and the model records which.
    pub(crate) fn answers(_: &Known) -> bool {
        let answered = kani::any();
        ANSWERED.store(answered, Ordering::Relaxed);
        answered
    }

    /// Whether the last self-test was given the known answer.
    pub(crate) fn answered() -> bool {
        ANSWERED.load(Ordering::Relaxed)
    }

    /// A key pair agrees with itself or not, at will, and the model records which, and the pair.
    pub(crate) fn agrees(_: &Known, seed: &[u8; SEED_LEN], public: &[u8; PUBLIC_LEN]) -> bool {
        keep(&PAIR_SEED, seed);
        if let Some(head) = public.first_chunk() {
            keep(&PAIR_PUBLIC, head);
        }
        let agreed = kani::any();
        PAIRED.store(true, Ordering::Relaxed);
        AGREED.store(agreed, Ordering::Relaxed);
        agreed
    }

    /// Whether a key pair was checked.
    pub(crate) fn paired() -> bool {
        PAIRED.load(Ordering::Relaxed)
    }

    /// Whether the last key pair checked agreed with itself.
    pub(crate) fn agreed() -> bool {
        AGREED.load(Ordering::Relaxed)
    }

    /// The seed and the first bytes of the public key of the last key pair checked.
    pub(crate) fn pair() -> ([u8; SEED_LEN], [u8; 32]) {
        (kept(&PAIR_SEED), kept(&PAIR_PUBLIC))
    }

    /// Any ciphertext and shared secret, or a refusal of the public key at will, writing neither.
    pub(crate) fn encapsulate(
        public: &[u8; PUBLIC_LEN],
        randomness: &[u8; RANDOMNESS_LEN],
        ciphertext: &mut [u8; CIPHERTEXT_LEN],
        shared: &mut [u8; SHARED_LEN],
    ) -> Result<(), InvalidPublicKey> {
        keep(&RANDOMNESS, randomness);
        if let Some(head) = public.first_chunk() {
            keep(&PUBLIC, head);
        }
        let refused = kani::any::<bool>();
        REFUSED.store(refused, Ordering::Relaxed);
        if refused {
            return Err(InvalidPublicKey);
        }
        *ciphertext = kani::any();
        *shared = kani::any();
        keep_ciphertext(ciphertext);
        keep(&SHARED, shared);
        Ok(())
    }

    /// Any shared secret.
    pub(crate) fn decapsulate(
        seed: &[u8; SEED_LEN],
        ciphertext: &[u8; CIPHERTEXT_LEN],
        shared: &mut [u8; SHARED_LEN],
    ) {
        DECAPSULATED.store(true, Ordering::Relaxed);
        keep(&SEED, seed);
        keep_ciphertext(ciphertext);
        *shared = kani::any();
        keep(&SHARED, shared);
    }

    /// Keeps `bytes` in `kept`. They are copied out first: a loop over bytes behind a pointer the
    /// proof does not pin down unwinds as far as the proof allows.
    fn keep<const N: usize>(kept: &[AtomicU8; N], bytes: &[u8; N]) {
        let bytes = *bytes;
        for (to, byte) in kept.iter().zip(bytes) {
            to.store(byte, Ordering::Relaxed);
        }
    }

    /// Keeps the first bytes of `ciphertext`.
    fn keep_ciphertext(ciphertext: &[u8; CIPHERTEXT_LEN]) {
        if let Some(head) = ciphertext.first_chunk() {
            keep(&CIPHERTEXT, head);
        }
    }

    /// The bytes kept in `kept`.
    fn kept<const N: usize>(kept: &[AtomicU8; N]) -> [u8; N] {
        let mut bytes = [0; N];
        for (to, from) in bytes.iter_mut().zip(kept) {
            *to = from.load(Ordering::Relaxed);
        }
        bytes
    }

    /// Whether the last encapsulation refused its public key.
    pub(crate) fn refused() -> bool {
        REFUSED.load(Ordering::Relaxed)
    }

    /// Whether any decapsulation ran.
    pub(crate) fn decapsulated() -> bool {
        DECAPSULATED.load(Ordering::Relaxed)
    }

    /// The randomness the last encapsulation was given.
    pub(crate) fn randomness() -> [u8; RANDOMNESS_LEN] {
        kept(&RANDOMNESS)
    }

    /// The seed the last decapsulation was given.
    pub(crate) fn seed() -> [u8; SEED_LEN] {
        kept(&SEED)
    }

    /// The first bytes of the public key the last encapsulation was given.
    pub(crate) fn public_head() -> [u8; 32] {
        kept(&PUBLIC)
    }

    /// The first bytes of the ciphertext of the last encapsulation, or of the last one decapsulated.
    pub(crate) fn ciphertext_head() -> [u8; 32] {
        kept(&CIPHERTEXT)
    }

    /// The shared secret the last encapsulation or decapsulation gave.
    pub(crate) fn shared() -> [u8; SHARED_LEN] {
        kept(&SHARED)
    }
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "a test decodes hex and walks the bits of a ciphertext"
)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use core::sync::atomic::Ordering;

    use super::{
        ANSWER, Answer, CIPHERTEXT_LEN, InvalidPublicKey, Known, PUBLIC_LEN, SHARED_LEN, agrees,
        answers, decapsulate, encapsulate, known, public_key, unanswered, wrong_known,
    };

    /// The second and third test vectors of the draft: seed, public key, randomness, ciphertext and
    /// shared secret.
    const VECTORS: [[&str; 5]; 2] = [
        [
            "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
            concat!(
                "0333285fa253661508c9fb444852caa4061636cb060e69943b431400134ae1fbc02287247cb38068",
                "bbb89e6714af10a3fcda6613acc4b5e4b0d6eb960c302a0253b1f507b596f0884d351da89b01c355",
                "43214c8e542390b2bc497967961ef10286879c34316e6483b644fc27e8019d73024ba1d1cc83650b",
                "b068a5431b33d1221b3d122dc1239010a55cb13782140893f30aca7c09380255a0c621602ffbb6a9",
                "db064c1406d12723ab3bbe2950a21fe521b160b30b16724cc359754b4c88342651333ea9412d5137",
                "791cf75558ebc5c54c520dd6c622a059f6b332ccebb9f24103e59a297cd69e4a48a3bfe53a595855",
                "9e840db5c023f66c10ce23081c2c8261d744799ba078285cfa71ac51f44708d0a6212c3993340724",
                "b3ac38f63e82a889a4fc581f6b8353cc6233ac8f5394b6cca292f892360570a3031c90c4da3f02a8",
                "95677390e60c24684a405f69ccf1a7b95312a47c844a4f9c2c4a37696dc10072a87bf41a2717d45b",
                "2a99ce09a4898d5a3f6b67085f9a626646bcf369982d483972b9cd7d244c4f49970f766a22507925",
                "eca7df99a491d80c27723e84c7b49b633a46b46785a16a41e02c538251622117364615d9c2cdaa16",
                "87a860c18bfc9ce8690efb2a524cb97cdfd1a4ea661fa7d08817998af838679b07c9db8455e2167a",
                "67c14d6a347522e89e8971270bec858364b1c1023b82c483cf8a8b76f040fe41c24dec2d49f63761",
                "70660605b80383391c4abad1136d874a77ef73b440758b6e7059add20873192e6e372e069c22c542",
                "5188e5c240cb3a6e29197ad17e87ec41a813af68531f262a6db25bbdb8a15d2ed9c9f35b9f206389",
                "0bd26ef09426f225aa1e6008d31600a29bcdf3b10d0bc72788d35e25f4976b3ca6ac7cbf0b442ae3",
                "99b225d9714d0638a864bda7018d3b7c793bd2ace6ac68f4284d10977cc029cf203c5698f15a06b1",
                "62d6c8b4fd40c6af40824f9c6101bb94e9327869ab7efd835dfc805367160d6c8571e3643ac70cba",
                "d5b96a1ad99352793f5af71705f95126cb4787392e94d808491a2245064ba5a7a30c066301392a6c",
                "315336e10dbc9c2177c7af382765b6c88eeab51588d01d6a95747f3652dc5b5c401a23863c7a0343",
                "737c737c99287a40a90896d4594730b552b910d23244684206f0eb842fb9aa316ab182282a75fb72",
                "b6806cea4774b822169c386a58773c3edc8229d85905abb87ac228f0f7a2ce9a497bb5325e17a6a8",
                "2777a997c036c3b862d29c14682ad325a9600872f3913029a1588648ba590a7157809ff740b51383",
                "80015c40e9fb90f0311107946f28e5962e21666ad65092a3a60480cd16e61ff7fb5b44b70cf12201",
                "878428ef8067fceb1e1dcb49d66c773d312c7e53238cb620e126187009472d41036b702032411dc9",
                "6cb750631df9d99452e495deb4300df660c8d35f32b424e98c7ed14b12d8ab11a289ac63c50a24d5",
                "2925950e49ba6bf4c2c38953c92d60b6cd034e575c711ac41bfa66951f62b9392828d7b45aed377a",
                "c69c35f1c6b80f388f34e0bb9ce8167eb2bc630382825c396a407e905108081b444ac8a07c250737",
                "6a750d18248ee0a81c4318d9a38fc44c3b41e8681f87c34138442659512c41276e1cc8fc4eb66e12",
                "727bcb5a9e0e405cdea21538d6ea885ab169050e6b91e1b69f7ed34bcbb48fd4c562a576549f85b5",
                "28c953926d96ea8a160b8843f1c89c62",
            ),
            concat!(
                "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9",
                "767be1fda69419dfb927e9df07348b196691abaeb580b32d",
            ),
            concat!(
                "c93beb22326705699bbc3d1d0aa6339be7a405debe61a7c337e1a91453c097a6f77c130639d1aaeb",
                "193175f1a987aa1fd789a63c9cd487ebd6965f5d8389c8d7c8cfacbba4b44d2fbe0ae84de9e96fb1",
                "1215d9b76acd51887b752329c1a3e0468ccc49392c1e0f1aad61a73c10831e60a9798cb2e7ec0759",
                "6b5803db3e243ecbb94166feade0c9197378700f8eb65a43502bbac4605992e2de2b906ab30ba401",
                "d7e1ff3c98f42cfc4b30b974d3316f331461ac05f43e0db7b41d3da702a4f567b6ee7295199c7be9",
                "2f6b4a47e7307d34278e03c872fb48647c446a64a3937dccd7c6d8de4d34b9dea45a0b065ef15b9e",
                "94d1b6df6dca7174d9bc9d14c6225e3a78a58785c3fe4e2fe6a0706f3365389e4258fbb61ecf1a19",
                "57715982b3f1844424e03acd83da7eee50573f6cd3ff396841e9a00ad679da92274129da277833d0",
                "524674feea09a98d25b888616f338412d8e65e151e65736c8c6fb448c9260fa20e7b2712148bcd3a",
                "0853865f50c1fc9e4f201aee3757120e034fd509d954b7a749ff776561382c4cb64cebcbb6aa82d0",
                "4cd5c2b40395ecaf231bde8334ecfd955d09efa8c6e7935b1cb0298fb8b6740be4593360eed5f129",
                "d59d98822a6cea37c57674e919e84d6b90f695fca58e7d29092bd70f7c97c6dfb021b9f87216a627",
                "1d8b144a364d03b6bf084f972dc59800b14a2c008bbd0992b5b82801020978f2bdddb3ca3367d876",
                "cffb3548dab695a29882cae2eb5ba7c847c3c71bd0150fa9c33aac8e6240e0c269b8e295ddb7b77e",
                "9c17bd310be65e28c0802136d086777be5652d6f1ac879d3263e9c712d1af736eac048fe848a577d",
                "6afaea1428dc71db8c430edd7b584ae6e6aeaf7257aff0fd8fe25c30840e30ccfa1d95118ef0f665",
                "7367e9070f3d97a2e9a7bae19957bd707b00e31b6b0ebb9d7df4bd22e44c060830a194b5b8288353",
                "255b52954ff5905ab2b126d9aa049e44599368c27d6cb033eae5182c2e1504ee4e3745f51488997b",
                "8f958f0209064f6f44a7e4de5226d5594d1ad9b42ac59a2d100a2f190df873a2e141552f33c923b4",
                "c927e8747c6f830c441a8bd3c5b371f6b3ab8103ebcfb18543aefc1beb6f776bbfd5344779f4aa23",
                "daaf395f69ec31dc046b491f0e5cc9c651dfc306bd8f2105be7bc7a4f4e21957f87278c771528a87",
                "40a92e2daefa76a3525f1fae17ec4362a2700988001d860011d6ca3a95f79a0205bcf634cef373a8",
                "ea273ff0f4250eb8617d0fb92102a6aa09cf0c3ee2cad1ad96438c8e4dfd6ee0fcc85833c3103dd6",
                "c1600cd305bc2df4cda89b55ca237a3f9c3f82390074ff30825fc750130ebaf13d0cf7556d2c52a9",
                "8a4bad39ca5d44aaadeaef775c695e64d06e966acfcd552a14e2df6c63ae541f0fa88fc482630896",
                "85704506a21a03856ce65d4f06d54f3157eeabd62491cb4ac7bf029e79f9fbd4c77e2a3588790c71",
                "0e611da8b2040c76a61507a8020758dcc30894ad018fef98e401cc54106e20d94bd544a8f0e1fd05",
                "00342d123f618aa8c91bdf6e0e03200693c9651e469aee6f91c98bea4127ae66312f4ae3ea155b67",
            ),
            "f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150",
        ],
        [
            "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
            concat!(
                "36244278824f77c621c660892c1c3886a9560caa52a97c461fd3958a598e749bbc8c7798ac8870ba",
                "c7318ac2b863000ca3b0bdcbbc1ccfcb1a30875df9a76976763247083e646ccb2499a4e4f0c9f412",
                "5378ba3da1999538b86f99f2328332c177d1192b849413e65510128973f679d23253850bb6c347ba",
                "7ca81b5e6ac4c574565c731740b3cd8c9756caac39fba7ac422acc60c6c1a645b94e3b6d21485eba",
                "d9c4fe5bb4ea0853670c5246652bff65ce8381cb473c40c1a0cd06b54dcec11872b351397c0eaf99",
                "5bebdb6573000cbe2496600ba76c8cb023ec260f0571e3ec12a9c82d9db3c57b3a99e8701f78db4f",
                "abc1cc58b1bae02745073a81fc8045439ba3b885581a283a1ba64e103610aabb4ddfe9959e724101",
                "1b2638b56ba6a982ef610c514a57212555db9a98fb6bcf0e91660ec15dfa66a67408596e9ccb9748",
                "9a09a073ffd1a0a7ebbe71aa5ff793cb91964160703b4b6c9c5390842c2c905d4a9f88111fed5787",
                "4ba9b03cf611e70486edf539767c7485189d5f1b08e32a274dc24a39c918fd2a4dfa946a8c897486",
                "f2c974031b2804aabc81749db430b85311372a3b8478868200b40e043f7bf4a1c3a08b0771b431e3",
                "42ee277410bca034a0c77086c8f702b3aed2b4108bbd3af471633373a1ac74b128b148d1b9412aa6",
                "6948cac6dc6614681fda02ca86675d2a756003c49c50f06e13c63ce4bc9f321c860b202ee9318349",
                "30011f485c9af86b9f642f0c353ad305c66996b9a136b753973929495f0d8048db75529edcb49359",
                "04797ac66605490f66329c3bb36b8573a3e00f817b3082162ff106674d11b261baae0506cde7e69f",
                "dce93c6c7b59b9d4c759758acf287c2e4c4bfab5170a9236daf21bdb6005e92464ee8863f845cf37",
                "978ef19969264a516fe992c93b5f7ae7cb6718ac69257d630379e4aac6029cb906f98d91c92d118c",
                "36a6d16115d4c8f16066078badd161a65ba51e0252bc358c67cd2c4beab2537e42956e08a39cfccf",
                "0cd875b5499ee952c83a162c68084f6d35cf92f71ec66baec74ab87e2243160b64df54afb5a07f78",
                "ec0f5c5759e5a4322bca2643425748a1a97c62108510c44fd9089c5a7c14e57b1b77532800013027",
                "cff91922d7c935b4202bb507aa47598a6a5a030117210d4c49c174700550ad6f82ad40e965598b86",
                "bc575448eb19d70380d465c1f870824c026d74a2522a799b7b122d06c83aa64c0974635897261433",
                "914fdfb14106c230425a83dc8467ad8234f086c72a47418be9cfb582b1dcfa3d9aa45299b79fff26",
                "5356d8286a1ca2f3c2184b2a70d15289e5b202d03b64c735a867b1154c55533ff61d6c2962770118",
                "48143bc85a4b823040ae025a29293ab77747d85310078682e0ba0ac236548d905a79494324574d41",
                "7c7a3457bd5fb5253c4876679034ae844d0d05010fec722db5621e3a67a2d58e2ff33b432269169b",
                "51f9dcc095b8406dc1864cf0aeb6a2132661a38d641877594b3c51892b9364d25c63d637140a2018",
                "d10931b0daa5a2f2a405017688c991e586b522f94b1132bc7e87a63246475816c8be9c62b731691a",
                "b912eb656ce2619225663364701a014b7d0337212caa2ecc731f34438289e0ca4590a276802d9800",
                "56b5d0d316cae2ecfea6d86696a9f161aa90ad47eaad8cadd31ae3cbc1c013747dfee80fb35b5299",
                "f555dcc2b787ea4f6f16ffdf66952461",
            ),
            concat!(
                "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c26",
                "4029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
            ),
            concat!(
                "0d2e38cbf17a2e2e4e0c87a94ca1e7701ae1552e02509b3b00f9c82c39e3fd435b05b91275f47abc",
                "9f1021429a26a346598cd6cd9efdc8adc1dbc35036d0290bf89733c835309202232f9bf652ea82f3",
                "d49280d6e8a3bd3135fb883445ab5b074d949c5350c7c7d6ac59905bdbfce6639da8a9d4b390ecc1",
                "dd05522d2956f2d37a05593996e5cb3fd8d5a9eb52417732e1ebf545588713b4760227115aab7ada",
                "178dadbca583b26cfedba2888a0c95b950bf07f750d7aa8103798aa3470a042c0105c6a037de2f9e",
                "bc396021b2ba2c16aba696fbac3454dc8e053b8fa55edd45215eeb57a1eab9106fb426b375a9b9e5",
                "c3419efc7610977e72640f9fd1b2ec337de33c35e5a7581b2aae4d8ee86d2e0ebf82a1350714de50",
                "d2d788687878a19644ae4e3175e8d59dc90171b3badeff65aeaf600e5e5483a3595fdeb40cbafcbd",
                "040c29a2f6900533ae999d24f54dfcef748c30313ca447cdddfa57ad78eaa890e90f3f7bf8d11696",
                "8a5713cc75fd0408f36364fa265c5617039304eaeac4cbee6fc49b9fe2276768cdbec2d73a507b54",
                "3cc028dc1b154b7c2b0412254c466a94a8d6ea3a47e1743469bd45c08f54cf965884be3696e96174",
                "1ede16e3b1bc4feb93faaef31d911dc0cb3fa90bcda991959a9d2cbc817a5564c5c01177a59e9577",
                "589ea344d60cf5b0aa39f31863febd54603ca87ad2363c766642a3f52557bcd9e4c05a87665842ba",
                "336b83156a677030f0bad531a8387a1486a599caa748fcea7bdc1eb63f3cdb97173551ab7c1c36b6",
                "9acbbdb2ff7a1e7bc70439632ddc67b97f3da1f59b3c1588515957cb8a2f86ab635ce0a78b7cdf24",
                "eac3445e8fc8b79ba04da9e903f49a7d912c197a84b4cfabc779b97d24788419bcf58035db99717e",
                "db9fd1c1df8c4005f700eabba528ddfcbaeda6dd30754f795948a34c9319ab653524b19931c7900c",
                "4167988af52292fe902e746b524d20ceffb4339e8f5535f41cf35f0f8ea8b4a7b949c5d2381116b1",
                "46e9b913a83a3fa1c65ff9468c835fe4114554a6c66a80e1c9a6bb064b380be3c95e5595ec979bf1",
                "c85aa938938e3f10e72b0c87811969e8ab0d83de0b0604c4016ac3a015e19514089271bdc6ebf2ec",
                "56fab6018e44de749b4c36cc235e370da8466dbdc253542a2d704eb3316fd70d5d238cb7eaaf0596",
                "6d973f62c7ef43b9a806f4ed213ac8099ea15d61a902444160883f6bf441a3e1469945c9b79489ea",
                "18390f1ebc83caca10bdb8f2429877b52bd44c94a228ef91c392ef5398c5c83982701318ccedab92",
                "f7a279c4fddebaa7fe5e986c48b7d8135b3fe4cd15be2004ce73ff86b1e55f8ecd6ba5b8114315f8",
                "e716ef3ab0a64564a4644651166ebd68b1f783e2e443dbccadfe189368647629f1a12215840b7f1d",
                "026de2f665c2eb023ff51a6df160912811ee03444ae4227fb941dc9ec4f31b445006fd384de5e60e",
                "0a5061b50cb1202f863090fc05eb814e2d42a03586c0b56f533847ac7b8184ce9690bc8dece32a88",
                "ca934f541d4cc520fa64de6b6e1c3c8e03db5971a445992227c825590688d203523f527161137334",
            ),
            "953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f",
        ],
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

    fn vectors() -> Vec<Known> {
        let mut all = std::vec![unanswered()];
        all.extend(
            VECTORS.map(|[seed, public, randomness, ciphertext, shared]| {
                known(Answer {
                    seed: array(seed),
                    public: array(public),
                    randomness: array(randomness),
                    ciphertext: array(ciphertext),
                    shared: array(shared),
                })
            }),
        );
        all
    }

    #[test]
    fn x_wing_gives_the_vectors_of_the_draft() {
        for known in vectors() {
            let mut public = [0; PUBLIC_LEN];
            public_key(&known.answer.seed, &mut public);
            assert_eq!(public, known.answer.public);
            let (mut ciphertext, mut shared) = ([0; CIPHERTEXT_LEN], [0; SHARED_LEN]);
            encapsulate(
                &public,
                &known.answer.randomness,
                &mut ciphertext,
                &mut shared,
            )
            .unwrap();
            assert_eq!(
                (ciphertext, shared),
                (known.answer.ciphertext, known.answer.shared)
            );
            let mut opened = [0; SHARED_LEN];
            decapsulate(&known.answer.seed, &ciphertext, &mut opened);
            assert_eq!(opened, known.answer.shared);
        }
    }

    /// Every changed bit of the ciphertext gives another shared secret. A change to a low bit of a
    /// value of ML-KEM leaves the decrypted message as it was, so only the comparison of the whole
    /// ciphertext with its encryption again tells it apart.
    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "nine thousand decapsulations, run in the optimised builds"
    )]
    fn every_changed_bit_of_a_ciphertext_gives_another_shared_secret() {
        let mut seen = std::collections::HashSet::new();
        for bit in 0..CIPHERTEXT_LEN * 8 {
            let mut ciphertext = ANSWER.ciphertext;
            ciphertext[bit / 8] ^= 1 << (bit % 8);
            let mut shared = [0; SHARED_LEN];
            decapsulate(&ANSWER.seed, &ciphertext, &mut shared);
            assert_ne!(shared, ANSWER.shared, "bit {bit}");
            assert!(seen.insert(shared), "bit {bit}");
        }
    }

    /// The first bit of the ciphertext changed: ML-KEM gives J(z, c) of FIPS 203, the hash of z and
    /// the ciphertext, as an independent implementation computes it with X25519 and the combiner.
    #[test]
    fn a_changed_ciphertext_gives_the_secret_of_implicit_rejection() {
        let mut ciphertext = ANSWER.ciphertext;
        ciphertext[0] ^= 1;
        let mut shared = [0; SHARED_LEN];
        decapsulate(&ANSWER.seed, &ciphertext, &mut shared);
        assert_eq!(
            shared,
            array::<SHARED_LEN>("0a403cbc6fe416a9d0582a3328819905fb512902a6a52ce32819cf80aaf2a9e8")
        );
    }

    /// The first value of the ML-KEM-768 key at q, then at 4095, and the last at 4095: refused, and
    /// neither output is touched.
    #[test]
    fn a_public_key_with_an_unreduced_value_is_refused() {
        for (at, low, high) in [(0, 0x01, 0x0d), (0, 0xff, 0x0f), (1150, 0, 0)] {
            let mut public = ANSWER.public;
            if at == 0 {
                public[0] = low;
                public[1] = (public[1] & 0xf0) | high;
            } else {
                public[1150] |= 0xf0;
                public[1151] = 0xff;
            }
            let (mut ciphertext, mut shared) = ([0x5a; CIPHERTEXT_LEN], [0xa5; SHARED_LEN]);
            assert_eq!(
                encapsulate(&public, &ANSWER.randomness, &mut ciphertext, &mut shared),
                Err(InvalidPublicKey)
            );
            assert_eq!(
                (ciphertext, shared),
                ([0x5a; CIPHERTEXT_LEN], [0xa5; SHARED_LEN])
            );
        }
    }

    #[test]
    fn x_wing_gives_the_known_answer() {
        assert!(answers(&unanswered()));
    }

    #[test]
    fn a_wrong_known_answer_fails_the_self_test() {
        for field in 0..5 {
            for at in [0, 17, 31] {
                let mut answer = ANSWER;
                match field {
                    0 => answer.seed[at] ^= 1,
                    1 => answer.public[at * 37] ^= 1,
                    2 => answer.randomness[at * 2] ^= 1,
                    3 => answer.ciphertext[at * 35] ^= 1,
                    _ => answer.shared[at] ^= 1,
                }
                assert!(!answers(&known(answer)), "field {field}, byte {at}");
            }
        }
    }

    /// A known answer once given is not asked for again; a wrong one is asked for each time.
    #[test]
    fn a_known_answer_is_asked_for_until_it_is_given() {
        let known = unanswered();
        assert!(answers(&known));
        assert!(known.given.load(Ordering::Relaxed));
        let wrong = wrong_known();
        assert!(!answers(&wrong));
        assert!(!wrong.given.load(Ordering::Relaxed));
        assert!(!answers(&wrong));
    }

    /// A seed agrees with its own public key only, and a pair that does not makes the known
    /// answer asked for again.
    #[test]
    fn a_key_pair_agrees_with_itself_only() {
        let known = unanswered();
        assert!(answers(&known));
        assert!(agrees(&known, &ANSWER.seed, &ANSWER.public));
        let mut other = [0; PUBLIC_LEN];
        public_key(&[7; 32], &mut other);
        assert!(agrees(&known, &[7; 32], &other));
        assert!(known.given.load(Ordering::Relaxed));
        let mut unreduced = ANSWER.public;
        unreduced[..2].copy_from_slice(&[0xff, 0xff]);
        for (seed, public) in [
            (ANSWER.seed, other),
            ([7; 32], ANSWER.public),
            (ANSWER.seed, unreduced),
        ] {
            assert!(answers(&known));
            assert!(!agrees(&known, &seed, &public));
            assert!(!known.given.load(Ordering::Relaxed));
        }
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    extern crate std;

    use core::hint::black_box;

    use super::{
        ANSWER, CIPHERTEXT_LEN, PUBLIC_LEN, SHARED_LEN, STACK_WIPE, agrees, answers, decapsulate,
        encapsulate, public_key, unanswered,
    };
    use crate::residue::depth_changed;

    /// The wipe covers more than any operation uses, the self-test asked for the first time
    /// included, and not needlessly more.
    #[test]
    fn the_wipe_is_deeper_than_x_wing() {
        let known = unanswered();
        let used = [
            depth_changed(|| {
                let mut public = [0; PUBLIC_LEN];
                public_key(black_box(&ANSWER.seed), &mut public);
                black_box(&public);
            }),
            depth_changed(|| {
                let (mut ciphertext, mut shared) = ([0; CIPHERTEXT_LEN], [0; SHARED_LEN]);
                let encapsulated = encapsulate(
                    black_box(&ANSWER.public),
                    &ANSWER.randomness,
                    &mut ciphertext,
                    &mut shared,
                );
                black_box((encapsulated.is_ok(), &ciphertext, &shared));
            }),
            depth_changed(|| {
                let mut shared = [0; SHARED_LEN];
                decapsulate(black_box(&ANSWER.seed), &ANSWER.ciphertext, &mut shared);
                black_box(&shared);
            }),
            depth_changed(|| {
                black_box(answers(black_box(&known)));
            }),
            depth_changed(|| {
                black_box(agrees(&known, black_box(&ANSWER.seed), &ANSWER.public));
            }),
        ];
        std::println!("X-Wing uses {used:?} bytes of stack");
        for used in used {
            assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
            assert!(used.saturating_mul(16) >= STACK_WIPE, "{used} bytes used");
        }
    }
}
