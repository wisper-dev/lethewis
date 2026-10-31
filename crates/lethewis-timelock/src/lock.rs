// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! A key locked until a round of the network, and opened with that round's signature.

use crate::age::{self, LOCKED_KEY_LEN, Lock, PAYLOAD_LEN};
use crate::decimal::Decimal;
use crate::ibe::{self, BODY_LEN, FILE_KEY_LEN};
use crate::network::{Network, SIGNATURE_LEN};
use crate::{Error, curve, timing};

/// The random bytes a lock takes: its file key, sigma and payload nonce, 16 bytes each.
pub const LOCK_RANDOM_LEN: usize = 48;
/// The longest a key is locked for: 365 days, in seconds.
pub const LOCK_MAX_SECONDS: u64 = 31_536_000;

/// At least twice the stack a lock or an opening uses in any build, as a test measures.
#[cfg(not(kani))]
const STACK_WIPE: usize = 98_304;

impl Network {
    /// Locks `key` until the first round of this network published at `until` or later, in
    /// seconds since the Unix epoch, as `now` is. `random` must be fresh random bytes, never used
    /// before. The lock is an age file that tlock tools for this network open.
    ///
    /// Wipe `random` after the call: its first 16 bytes open the lock without the round's
    /// signature.
    ///
    /// Needs 96 KiB of stack, which it wipes below itself; the work takes 24 KiB, or 38 KiB
    /// unoptimised.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTime`] when `until` is not after `now`, is more than [`LOCK_MAX_SECONDS`]
    /// after it, or `now` is before round 1; [`Error::RandomUnusable`] for random bytes that give
    /// no scalar in constant time.
    pub fn lock(
        &self,
        key: &[u8; LOCKED_KEY_LEN],
        now: u64,
        until: u64,
        random: &[u8; LOCK_RANDOM_LEN],
    ) -> Result<Lock, Error> {
        let latest = now.saturating_add(LOCK_MAX_SECONDS);
        if now < self.genesis || until <= now || until > latest {
            return Err(Error::InvalidTime);
        }
        let round = self.round_at_or_after(until);
        let decimal = round.and_then(Decimal::of);
        let (Some(round), Some(decimal)) = (round, decimal) else {
            return Err(Error::InvalidTime);
        };
        let locked = self.lock_on_stack(key, round, &decimal, random);
        wipe_stack();
        locked
    }

    /// The round whose signature opens `lock`.
    ///
    /// # Errors
    ///
    /// [`Error::LockMalformed`] for bytes that are not a lock as this library writes it,
    /// [`Error::OtherNetwork`] for a lock of another network.
    pub fn round_of(&self, lock: &[u8]) -> Result<u64, Error> {
        age::read(lock, &self.chain_hash).map(|parts| parts.round.value())
    }

    /// Opens `lock` with the signature of its round and writes the key it holds to `key`, which
    /// changes only on success.
    ///
    /// Needs 96 KiB of stack, which it wipes below itself; the work takes 23 KiB, or 37 KiB
    /// unoptimised.
    ///
    /// # Errors
    ///
    /// Those of [`Self::round_of`] and of [`Self::verify`] for the round; [`Error::LockRejected`]
    /// for a lock changed after it was made.
    pub fn open(
        &self,
        lock: &[u8],
        signature: &[u8; SIGNATURE_LEN],
        key: &mut [u8; LOCKED_KEY_LEN],
    ) -> Result<(), Error> {
        let parts = age::read(lock, &self.chain_hash)?;
        self.verify(parts.round.value(), signature)?;
        let header = lock.get(..age::COVERED).unwrap_or(&[]);
        let opened = open_on_stack(header, &parts, signature, key);
        wipe_stack();
        opened
    }

    #[inline(never)]
    fn lock_on_stack(
        &self,
        key: &[u8; LOCKED_KEY_LEN],
        round: u64,
        decimal: &Decimal,
        random: &[u8; LOCK_RANDOM_LEN],
    ) -> Result<Lock, Error> {
        let ([file_key, sigma, nonce], []) = random.as_chunks::<16>() else {
            return Err(Error::RandomUnusable);
        };
        let mut body = [0; BODY_LEN];
        let message = curve::message(round);
        let wrapped =
            timing::with(|| ibe::wrap(&self.public_key, &message, file_key, sigma, &mut body));
        if !wrapped {
            return Err(Error::RandomUnusable);
        }
        let mut lock = age::header(decimal, &self.chain_hash, &body);
        let mut payload = [0; PAYLOAD_LEN];
        let (mac, sealed) = timing::with(|| {
            (
                age::mac(file_key, lock.covered()),
                age::seal(file_key, nonce, key, &mut payload),
            )
        });
        if !sealed {
            return Err(Error::RandomUnusable);
        }
        lock.finish(&mac, nonce, &payload);
        Ok(lock)
    }
}

#[inline(never)]
fn open_on_stack(
    header: &[u8],
    parts: &age::Parts,
    signature: &[u8; SIGNATURE_LEN],
    key: &mut [u8; LOCKED_KEY_LEN],
) -> Result<(), Error> {
    let mut file_key = [0; FILE_KEY_LEN];
    let opened = timing::with(|| {
        ibe::unwrap(signature, &parts.body, &mut file_key)
            && age::same_mac(&age::mac(&file_key, header), &parts.mac)
            && age::open(&file_key, &parts.nonce, &parts.payload, key)
    });
    #[cfg(not(kani))]
    zeroize::Zeroize::zeroize(&mut file_key);
    if opened {
        Ok(())
    } else {
        Err(Error::LockRejected)
    }
}

/// Wipes the stack below the caller, where the work in the functions kept out of line ran.
fn wipe_stack() {
    // The wipe ends in inline assembly, which Kani cannot model.
    #[cfg(not(kani))]
    zeroize::zeroize_stack::<STACK_WIPE>();
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

#[cfg(test)]
mod tests {
    use super::{LOCK_MAX_SECONDS, LOCK_RANDOM_LEN};
    use crate::age::LOCKED_KEY_LEN;
    use crate::vectors::{
        AgeParts, REFERENCE_LOCK, TESTNET, TESTNET_LOCK, age_parts, dearmor, signature_of,
    };
    use crate::{Error, QUICKNET, timing};

    const KEY: [u8; LOCKED_KEY_LEN] = *b"the key locked for one round now";
    const RANDOM: [u8; LOCK_RANDOM_LEN] = *b"file key, sigma and nonce: fresh for every lock.";

    /// Times of quicknet: round 1000 comes at this one.
    const ROUND_1000: u64 = 1_692_806_364;

    #[test]
    fn a_key_opens_with_the_signature_of_the_round_it_is_locked_until() {
        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        assert_eq!(QUICKNET.round_of(lock.as_bytes()), Ok(1000));
        let mut key = [0; LOCKED_KEY_LEN];
        assert_eq!(
            QUICKNET.open(lock.as_bytes(), &signature_of(1000), &mut key),
            Ok(())
        );
        assert_eq!(key, KEY);
        assert_eq!(timing::seen(), Some(true));
    }

    #[test]
    fn a_lock_is_for_the_first_round_at_or_after_its_time() {
        for (until, round) in [
            (ROUND_1000 - 3, 999),
            (ROUND_1000 - 2, 1000),
            (ROUND_1000, 1000),
            (ROUND_1000 + 1, 1001),
        ] {
            let lock = QUICKNET.lock(&KEY, until - 1, until, &RANDOM).unwrap();
            assert_eq!(QUICKNET.round_of(lock.as_bytes()), Ok(round));
        }
    }

    #[test]
    fn a_key_is_locked_for_a_time_after_now_and_within_a_year() {
        let now = ROUND_1000;
        let genesis = QUICKNET.genesis;
        for (now, until, locked) in [
            (now, now + 1, true),
            (now, now + LOCK_MAX_SECONDS, true),
            (now, now + LOCK_MAX_SECONDS + 1, false),
            (now, now, false),
            (now, now - 1, false),
            (genesis, genesis + 1, true),
            (genesis - 1, genesis + 1, false),
            (u64::MAX - 1, u64::MAX, true),
        ] {
            let lock = QUICKNET.lock(&KEY, now, until, &RANDOM);
            assert_eq!(lock.is_ok(), locked, "now {now}, until {until}");
            if !locked {
                assert_eq!(lock.err(), Some(Error::InvalidTime));
            }
        }
    }

    #[test]
    fn a_key_opens_only_with_the_signature_of_its_round_and_as_locked() {
        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        let lock = lock.as_bytes();
        let before = [0xa5; LOCKED_KEY_LEN];
        let mut key = before;
        for round in [1, 2, 1_000_000] {
            assert_eq!(
                QUICKNET.open(lock, &signature_of(round), &mut key),
                Err(Error::SignatureRejected)
            );
        }
        for at in 0..lock.len() {
            let mut changed = lock.to_vec();
            changed[at] ^= 1;
            let opened = QUICKNET.open(&changed, &signature_of(1000), &mut key);
            assert!(
                matches!(
                    opened,
                    Err(Error::LockMalformed
                        | Error::LockRejected
                        | Error::OtherNetwork
                        | Error::InvalidRound
                        | Error::SignatureRejected)
                ),
                "byte {at}: {opened:?}"
            );
        }
        assert_eq!(key, before);
        assert_eq!(
            TESTNET.open(lock, &signature_of(1000), &mut key),
            Err(Error::OtherNetwork)
        );
    }

    /// The round written in a lock is the one its file key is encrypted to.
    #[test]
    fn a_lock_with_another_round_written_does_not_open_with_its_signature() {
        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        let mut changed = lock.as_bytes().to_vec();
        let round = 31..50;
        assert_eq!(&changed[round.clone()], b"0000000000000001000");
        changed[round].copy_from_slice(b"0000000000000000001");
        let before = [0xa5; LOCKED_KEY_LEN];
        let mut key = before;
        assert_eq!(
            QUICKNET.open(&changed, &signature_of(1), &mut key),
            Err(Error::LockRejected)
        );
        assert_eq!(key, before);
    }

    /// The header MAC covers the lock through its three dashes, under the file key drawn.
    #[test]
    fn the_mac_covers_the_header_through_its_dashes() {
        use hkdf::Hkdf;
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        let AgeParts { header, mac, .. } = age_parts(lock.as_bytes());
        assert!(header.ends_with(b"\n---"));
        let mut key = [0; 32];
        Hkdf::<Sha256>::new(None, &RANDOM[..16])
            .expand(b"header", &mut key)
            .unwrap();
        let expected = Hmac::<Sha256>::new_from_slice(&key)
            .unwrap()
            .chain_update(&header)
            .finalize()
            .into_bytes();
        assert_eq!(mac[..], expected[..]);
    }

    /// Locks hold a key of 32 bytes; the reference files hold other payloads.
    #[test]
    fn files_other_than_locks_are_not_opened() {
        for (network, armor) in [
            (QUICKNET, &REFERENCE_LOCK[..]),
            (TESTNET, &TESTNET_LOCK[..]),
        ] {
            assert_eq!(network.round_of(&dearmor(armor)), Err(Error::LockMalformed));
        }
    }

    #[test]
    fn locks_differ_with_their_random_bytes() {
        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        for at in 0..LOCK_RANDOM_LEN {
            let mut random = RANDOM;
            random[at] ^= 1;
            let other = QUICKNET
                .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &random)
                .unwrap();
            assert_ne!(other.as_bytes(), lock.as_bytes(), "byte {at}");
            let mut key = [0; LOCKED_KEY_LEN];
            QUICKNET
                .open(other.as_bytes(), &signature_of(1000), &mut key)
                .unwrap();
            assert_eq!(key, KEY);
        }
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    extern crate std;

    use std::vec::Vec;

    use blst::min_sig::{PublicKey, SecretKey};
    use blst::{blst_fp, blst_fp12, blst_p1_affine, blst_p2_affine};
    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::{LOCK_RANDOM_LEN, STACK_WIPE, open_on_stack};
    use crate::age::LOCKED_KEY_LEN;
    use crate::decimal::Decimal;
    use crate::ibe::{h2, h3, h4};
    use crate::residue::{depth, key_dependent, residue};
    use crate::vectors::signature_of;
    use crate::{QUICKNET, curve, timing};

    /// Round 1000 comes at this time.
    const ROUND_1000: u64 = 1_692_806_364;

    fn limbs(fp: &blst_fp) -> Vec<u8> {
        fp.l.iter().flat_map(|limb| limb.to_le_bytes()).collect()
    }

    /// The secrets of a lock of `key` with `random` until round 1000, as they lie in memory.
    fn secrets(key: &[u8; LOCKED_KEY_LEN], random: &[u8; LOCK_RANDOM_LEN]) -> Vec<Vec<u8>> {
        let (file_key, rest) = random.split_first_chunk::<16>().unwrap();
        let (sigma, nonce) = rest.split_first_chunk::<16>().unwrap();
        let mut scalar = [0; 32];
        assert!(h3(sigma, file_key, false, &mut scalar));
        let r = SecretKey::from_bytes(&scalar).unwrap();
        let r_id: blst_p1_affine = r.sign(&curve::message(1000), curve::DST, &[]).into();
        let public: blst_p2_affine = PublicKey::from_bytes(&QUICKNET.public_key).unwrap().into();
        let pairing: blst_fp12 = blst_fp12::miller_loop(&public, &r_id).final_exp();
        let mut header_key = [0; 32];
        Hkdf::<Sha256>::new(None, file_key)
            .expand(b"header", &mut header_key)
            .unwrap();
        let mut payload_key = [0; 32];
        Hkdf::<Sha256>::new(Some(nonce), file_key)
            .expand(b"payload", &mut payload_key)
            .unwrap();
        let mut reversed = scalar;
        reversed.reverse();
        let mut secrets = std::vec![
            key.to_vec(),
            file_key.to_vec(),
            sigma.to_vec(),
            scalar.to_vec(),
            reversed.to_vec(),
            limbs(&r_id.x),
            limbs(&r_id.y),
            h2(&r_id, &public).to_vec(),
            h4(sigma).to_vec(),
            header_key.to_vec(),
            payload_key.to_vec(),
        ];
        let coefficients = pairing
            .fp6
            .iter()
            .flat_map(|fp6| &fp6.fp2)
            .flat_map(|fp2| &fp2.fp);
        secrets.push(coefficients.flat_map(limbs).collect());
        secrets
    }

    fn pieces() -> Vec<Vec<u8>> {
        let this = secrets(&KEY, &RANDOM);
        let mut other_random = RANDOM;
        other_random.reverse();
        key_dependent(&this, &secrets(&[0x5a; LOCKED_KEY_LEN], &other_random))
    }

    const KEY: [u8; LOCKED_KEY_LEN] = *b"a key for the stack to forget it";
    const RANDOM: [u8; LOCK_RANDOM_LEN] = *b"random bytes of a lock, which no stack may keep.";

    #[test]
    fn a_lock_leaves_no_secret_on_the_stack() {
        let pieces = pieces();
        assert!(pieces.len() > 300);
        let found = residue(&pieces, || {
            QUICKNET
                .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
                .unwrap();
        });
        assert_eq!(found, 0);
        assert_eq!(timing::seen(), Some(true));
    }

    #[test]
    fn an_opening_leaves_no_secret_on_the_stack() {
        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        timing::seen();
        let pieces = pieces();
        let mut key = [0; LOCKED_KEY_LEN];
        let found = residue(&pieces, || {
            QUICKNET
                .open(lock.as_bytes(), &signature_of(1000), &mut key)
                .unwrap();
        });
        assert_eq!(key, KEY);
        assert_eq!(found, 0);
        assert_eq!(timing::seen(), Some(true));
    }

    #[test]
    fn the_wipe_reaches_its_depth() {
        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        let locking = depth(|| {
            QUICKNET
                .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
                .unwrap();
        });
        let opening = depth(|| {
            QUICKNET
                .open(
                    lock.as_bytes(),
                    &signature_of(1000),
                    &mut [0; LOCKED_KEY_LEN],
                )
                .unwrap();
        });
        assert!(
            locking.min(opening) >= STACK_WIPE,
            "{locking}, {opening} bytes wiped"
        );
    }

    #[test]
    fn the_wipe_is_deeper_than_the_work() {
        let lock = QUICKNET
            .lock(&KEY, ROUND_1000 - 100, ROUND_1000, &RANDOM)
            .unwrap();
        let parts = crate::age::read(lock.as_bytes(), &QUICKNET.chain_hash).unwrap();
        let header = lock.covered();
        let locking = depth(|| {
            QUICKNET
                .lock_on_stack(&KEY, 1000, &Decimal::of(1000).unwrap(), &RANDOM)
                .unwrap();
        });
        let opening = depth(|| {
            open_on_stack(
                header,
                &parts,
                &signature_of(1000),
                &mut [0; LOCKED_KEY_LEN],
            )
            .unwrap();
        });
        std::println!("a lock uses {locking} bytes of stack, an opening {opening}");
        let used = locking.max(opening);
        assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
        // Not needlessly deep either: a thread that cannot spare the stack would be corrupted.
        assert!(used.saturating_mul(16) >= STACK_WIPE, "{used} bytes used");
    }
}
