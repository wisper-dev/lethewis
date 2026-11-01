// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Keys from a time lock: a secret locked until a round of a drand network, and opened with that
//! round's signature.

#![cfg_attr(
    not(any(feature = "timelock", kani)),
    expect(dead_code, reason = "only the time lock and the proofs call this")
)]

use crate::derive::{Branch, SECRET_LEN, wipe_stack};
use crate::entropy::Entropy;
use crate::error::Error;
use crate::record::Purpose;
use crate::slots::{Handle, Slots};

/// The length of a time lock.
#[cfg_attr(
    not(feature = "timelock"),
    expect(unreachable_pub, reason = "public with the time lock only")
)]
pub const TIME_LOCK_LEN: usize = 386;
/// The length of the signature of a round.
#[cfg_attr(
    not(feature = "timelock"),
    expect(unreachable_pub, reason = "public with the time lock only")
)]
pub const ROUND_SIGNATURE_LEN: usize = 48;
/// The random bytes a time lock takes besides its secret.
pub(crate) const LOCK_RANDOM_LEN: usize = 48;

/// Locks a secret until a round and opens it with the round's signature. Crate-private, so a
/// secret goes only to code built into it.
pub(crate) trait TimeLocker {
    fn round_for(&self, now: u64, until: u64) -> Result<u64, Error>;

    /// `out` is written only when this succeeds.
    fn lock(
        &self,
        secret: &[u8; SECRET_LEN],
        now: u64,
        until: u64,
        random: &[u8; LOCK_RANDOM_LEN],
        out: &mut [u8; TIME_LOCK_LEN],
    ) -> Result<(), Error>;

    /// `secret` is written only when this succeeds.
    fn open(
        &self,
        lock: &[u8],
        signature: &[u8; ROUND_SIGNATURE_LEN],
        secret: &mut [u8; SECRET_LEN],
    ) -> Result<(), Error>;
}

#[cfg(feature = "timelock")]
impl TimeLocker for lethewis_timelock::Network {
    fn round_for(&self, now: u64, until: u64) -> Result<u64, Error> {
        Self::round_for(self, now, until).map_err(from_time_lock)
    }

    fn lock(
        &self,
        secret: &[u8; SECRET_LEN],
        now: u64,
        until: u64,
        random: &[u8; LOCK_RANDOM_LEN],
        out: &mut [u8; TIME_LOCK_LEN],
    ) -> Result<(), Error> {
        let lock = Self::lock(self, secret, now, until, random).map_err(from_time_lock)?;
        *out = *lock.as_bytes();
        Ok(())
    }

    fn open(
        &self,
        lock: &[u8],
        signature: &[u8; ROUND_SIGNATURE_LEN],
        secret: &mut [u8; SECRET_LEN],
    ) -> Result<(), Error> {
        Self::open(self, lock, signature, secret).map_err(from_time_lock)
    }
}

#[cfg(feature = "timelock")]
fn from_time_lock(error: lethewis_timelock::Error) -> Error {
    use lethewis_timelock::Error as Refused;
    match error {
        Refused::InvalidTime => Error::InvalidTime,
        Refused::RandomUnusable => Error::CipherFailed,
        Refused::SignatureRejected => Error::SignatureRejected,
        _ => Error::LockRejected,
    }
}

impl<'a> Slots<'a> {
    /// Creates a 32-byte wrapping key from 16 hedged bytes of `entropy`, and writes a time lock
    /// that holds them into `lock`: an age file that `tle` opens with the signature of its
    /// round, the first published at `until` or later. `now` and `until` are in seconds since the
    /// Unix epoch. Show the time of the round to whoever locks, as
    /// [`lethewis_timelock::Network::round_for`] and [`lethewis_timelock::Network::time_of`] give
    /// it: a clock set back gives a round already published, and the lock opens at once.
    ///
    /// With the `timelock` feature only. Needs 104 KiB of stack, or 108 KiB when unoptimised, and
    /// wipes it below itself.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`], then [`Error::InvalidTime`], before `entropy` is asked;
    /// [`Error::EntropyFailed`], [`Error::DerivationFailed`], [`Error::CipherFailed`] or
    /// [`Error::DuplicateKey`]. `lock` and the slots are then unchanged.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; the random bytes are then wiped and no slot changes.
    #[cfg(feature = "timelock")]
    pub fn generate_time_lock(
        &mut self,
        network: &lethewis_timelock::Network,
        now: u64,
        until: u64,
        entropy: &mut (impl Entropy + ?Sized),
        lock: &mut [u8; TIME_LOCK_LEN],
    ) -> Result<Handle<'a>, Error> {
        self.generate_time_lock_with(network, now, until, entropy, lock)
    }

    /// Derives the key [`Self::generate_time_lock`] created with `lock` into a free slot, once
    /// `signature`, the signature of the lock's round, opens it.
    ///
    /// With the `timelock` feature only. Needs 104 KiB of stack, or 108 KiB when unoptimised, and
    /// wipes it below itself.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] before any work; [`Error::SignatureRejected`] when `signature` is
    /// not that of the round, [`Error::LockRejected`] when `lock` is not one or was changed;
    /// [`Error::DerivationFailed`] or [`Error::DuplicateKey`]. The slots are then unchanged.
    #[cfg(feature = "timelock")]
    pub fn open_time_lock(
        &mut self,
        network: &lethewis_timelock::Network,
        lock: &[u8],
        signature: &[u8; ROUND_SIGNATURE_LEN],
    ) -> Result<Handle<'a>, Error> {
        self.open_time_lock_with(network, lock, signature)
    }

    pub(crate) fn generate_time_lock_with(
        &mut self,
        locker: &impl TimeLocker,
        now: u64,
        until: u64,
        entropy: &mut (impl Entropy + ?Sized),
        lock: &mut [u8; TIME_LOCK_LEN],
    ) -> Result<Handle<'a>, Error> {
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        locker.round_for(now, until)?;
        let generated = self.generate_time_lock_on_stack(locker, now, until, entropy, lock);
        wipe_stack();
        generated
    }

    #[inline(never)]
    fn generate_time_lock_on_stack(
        &mut self,
        locker: &impl TimeLocker,
        now: u64,
        until: u64,
        entropy: &mut (impl Entropy + ?Sized),
        lock: &mut [u8; TIME_LOCK_LEN],
    ) -> Result<Handle<'a>, Error> {
        let mut drawn = [0; SECRET_LEN + LOCK_RANDOM_LEN];
        let mut written = [0; TIME_LOCK_LEN];
        let generated =
            crate::timing::with(|| self.draw(entropy, Branch::HedgeTimeLock, &mut drawn)).and_then(
                |()| {
                    let (Some(secret), Some(random)) = (
                        drawn.first_chunk::<SECRET_LEN>(),
                        drawn.last_chunk::<LOCK_RANDOM_LEN>(),
                    ) else {
                        return Err(Error::DerivationFailed);
                    };
                    locker.lock(secret, now, until, random, &mut written)?;
                    self.derive_into(secret, Purpose::Wrap, Branch::FromTimeLock)
                },
            );
        if generated.is_ok() {
            *lock = written;
        }
        generated
    }

    pub(crate) fn open_time_lock_with(
        &mut self,
        locker: &impl TimeLocker,
        lock: &[u8],
        signature: &[u8; ROUND_SIGNATURE_LEN],
    ) -> Result<Handle<'a>, Error> {
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        let opened = self.open_time_lock_on_stack(locker, lock, signature);
        wipe_stack();
        opened
    }

    #[inline(never)]
    fn open_time_lock_on_stack(
        &mut self,
        locker: &impl TimeLocker,
        lock: &[u8],
        signature: &[u8; ROUND_SIGNATURE_LEN],
    ) -> Result<Handle<'a>, Error> {
        let mut secret = [0; SECRET_LEN];
        locker
            .open(lock, signature, &mut secret)
            .and_then(|()| self.derive_into(&secret, Purpose::Wrap, Branch::FromTimeLock))
    }
}

#[cfg(test)]
#[cfg(feature = "timelock")]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "a test counts the calls of a source"
)]
pub(crate) mod tests {
    extern crate std;

    use std::vec::Vec;

    use lethewis_timelock::QUICKNET;

    use super::{ROUND_SIGNATURE_LEN, TIME_LOCK_LEN};
    use crate::derive::direct::hedged_directly;
    use crate::entropy::{Entropy, EntropyError};
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::slots::{Slot, Slots};

    /// The root of the epoch, which is its key.
    const ROOT: [u8; 32] = [0x6b; 32];
    /// Times of quicknet: round 1000 comes at this one.
    pub(crate) const ROUND_1000: u64 = 1_692_806_364;
    /// The signatures quicknet published for rounds 1 and 1000.
    const SIGNATURE_1: &str = concat!(
        "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38",
        "c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b",
    );
    pub(crate) const SIGNATURE_1000: &str = concat!(
        "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b1957",
        "6350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39",
    );

    pub(crate) fn signature(hex: &str) -> [u8; ROUND_SIGNATURE_LEN] {
        let bytes: Vec<u8> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// A source that writes the bytes it counts, and how often it was asked.
    struct Counting(usize);

    impl Entropy for Counting {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            self.0 += 1;
            for (byte, at) in dest.iter_mut().zip(0_u8..) {
                *byte = at.wrapping_mul(7);
            }
            Ok(())
        }
    }

    fn slots_of<'a>(memory: &'a mut [Slot], epoch: &'a mut Epoch) -> Slots<'a> {
        Slots::new(memory, epoch, 1, &mut { ROOT })
    }

    #[test]
    fn a_time_lock_holds_the_hedged_secret_and_opens_to_the_same_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut lock = [0; TIME_LOCK_LEN];
        let mut source = Counting(0);
        slots
            .generate_time_lock(
                &QUICKNET,
                ROUND_1000 - 100,
                ROUND_1000,
                &mut source,
                &mut lock,
            )
            .unwrap();
        assert_eq!(source.0, 1);
        assert_eq!(QUICKNET.round_of(&lock), Ok(1000));
        let mut drawn = [0; 64];
        Counting(0).fill(&mut drawn).unwrap();
        let hedged = hedged_directly(&ROOT, 0, b"hedge time lock", &drawn, 64);
        let mut secret = [0; 16];
        QUICKNET
            .open(&lock, &signature(SIGNATURE_1000), &mut secret)
            .unwrap();
        assert_eq!(secret[..], hedged[..16]);
        assert_eq!(
            slots.open_time_lock(&QUICKNET, &lock, &signature(SIGNATURE_1000)),
            Err(Error::DuplicateKey)
        );
    }

    #[test]
    fn a_time_lock_opens_only_with_the_signature_of_its_round_as_written() {
        let mut lock = [0; TIME_LOCK_LEN];
        {
            let mut memory = [const { Slot::empty() }; 1];
            let mut epoch = Epoch::empty();
            let mut slots = slots_of(&mut memory, &mut epoch);
            slots
                .generate_time_lock(
                    &QUICKNET,
                    ROUND_1000 - 100,
                    ROUND_1000,
                    &mut Counting(0),
                    &mut lock,
                )
                .unwrap();
        }
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        assert_eq!(
            slots.open_time_lock(&QUICKNET, &lock, &signature(SIGNATURE_1)),
            Err(Error::SignatureRejected)
        );
        let mut changed = lock;
        changed[TIME_LOCK_LEN - 1] ^= 1;
        assert_eq!(
            slots.open_time_lock(&QUICKNET, &changed, &signature(SIGNATURE_1000)),
            Err(Error::LockRejected)
        );
        assert_eq!(
            slots.open_time_lock(&QUICKNET, &lock[1..], &signature(SIGNATURE_1000)),
            Err(Error::LockRejected)
        );
        assert!(
            slots
                .open_time_lock(&QUICKNET, &lock, &signature(SIGNATURE_1000))
                .is_ok()
        );
        assert_eq!(
            slots.open_time_lock(&QUICKNET, &lock, &signature(SIGNATURE_1000)),
            Err(Error::NoFreeSlot)
        );
    }

    #[test]
    fn the_calls_on_a_time_lock_hold_data_independent_timing() {
        use crate::timing::timed;
        assert!(!lethewis_dit::active(), "the mode is off before the work");
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut lock = [0; TIME_LOCK_LEN];
        let set = timed(|| {
            slots
                .generate_time_lock(
                    &QUICKNET,
                    ROUND_1000 - 100,
                    ROUND_1000,
                    &mut Counting(0),
                    &mut lock,
                )
                .unwrap()
        });
        slots.release(set).unwrap();
        timed(|| {
            slots
                .open_time_lock(&QUICKNET, &lock, &signature(SIGNATURE_1000))
                .unwrap()
        });
    }

    #[test]
    fn each_refusal_of_the_time_lock_gives_its_error() {
        use lethewis_timelock::Error as Refused;
        for (refused, error) in [
            (Refused::InvalidTime, Error::InvalidTime),
            (Refused::RandomUnusable, Error::CipherFailed),
            (Refused::SignatureRejected, Error::SignatureRejected),
            (Refused::InvalidRound, Error::LockRejected),
            (Refused::LockMalformed, Error::LockRejected),
            (Refused::OtherNetwork, Error::LockRejected),
            (Refused::LockRejected, Error::LockRejected),
        ] {
            assert_eq!(super::from_time_lock(refused), error, "{refused:?}");
        }
    }

    #[test]
    fn a_refused_time_lock_asks_nothing_and_writes_nothing() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut lock = [0xa5; TIME_LOCK_LEN];
        let mut source = Counting(0);
        for (now, until) in [
            (ROUND_1000, ROUND_1000),
            (ROUND_1000, ROUND_1000 - 1),
            (ROUND_1000, ROUND_1000 + 31_536_001),
            (0, 1),
        ] {
            assert_eq!(
                slots.generate_time_lock(&QUICKNET, now, until, &mut source, &mut lock),
                Err(Error::InvalidTime)
            );
        }
        assert_eq!(lock, [0xa5; TIME_LOCK_LEN]);
        slots
            .generate_time_lock(
                &QUICKNET,
                ROUND_1000 - 100,
                ROUND_1000,
                &mut source,
                &mut lock,
            )
            .unwrap();
        let written = lock;
        assert_eq!(
            slots.generate_time_lock(
                &QUICKNET,
                ROUND_1000 - 100,
                ROUND_1000,
                &mut source,
                &mut lock
            ),
            Err(Error::NoFreeSlot)
        );
        assert_eq!(source.0, 1);
        assert_eq!(lock, written);
    }
}

#[cfg(test)]
#[cfg(feature = "timelock")]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    extern crate std;

    use std::vec::Vec;

    use lethewis_timelock::QUICKNET;

    use super::TIME_LOCK_LEN;
    use super::tests::{ROUND_1000, SIGNATURE_1000, signature};
    use crate::derive::direct::hedged_directly;
    use crate::derive::stack::{epoch_bytes, hedge_secrets, secrets, secrets_for};
    use crate::derive::{Branch, SALT, STACK_WIPE, derive_from_secret};
    use crate::entropy::{Entropy, EntropyError};
    use crate::epoch::Epoch;
    use crate::key::KeyLength;
    use crate::record::Purpose;
    use crate::residue::{assert_clean, depth_changed, key_dependent};
    use crate::slots::{Slot, Slots};

    /// A source of 64 bytes whose values appear nowhere else.
    struct Fixed(u8);

    impl Entropy for Fixed {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            for (byte, at) in dest.iter_mut().zip(0_u8..) {
                *byte = at.wrapping_mul(71).wrapping_add(13) ^ self.0;
            }
            Ok(())
        }
    }

    fn slots_of<'a>(memory: &'a mut [Slot], epoch: &'a mut Epoch) -> Slots<'a> {
        Slots::new(memory, epoch, 1, &mut epoch_bytes(0))
    }

    /// What a lock made from the bytes `flip` gives leaves in memory: the bytes drawn, the hedge
    /// and the bytes it gives, the secret and the key it derives.
    fn found(flip: u8, epoch: &[u8; 32]) -> Vec<Vec<u8>> {
        let mut drawn = [0; 64];
        Fixed(flip).fill(&mut drawn).unwrap();
        let hedged = hedged_directly(epoch, 0, b"hedge time lock", &drawn, 64);
        let secret: [u8; 16] = hedged[..16].try_into().unwrap();
        let mut found = std::vec![drawn.to_vec(), hedged.clone()];
        found.extend(hedge_secrets(epoch, 0, Branch::HedgeTimeLock, &drawn));
        found.extend(secrets_for(
            &secret,
            SALT,
            Branch::FromTimeLock,
            Some(Purpose::Wrap),
        ));
        let mut key = [0; 64];
        derive_from_secret(
            &secret,
            Some(Purpose::Wrap),
            Branch::FromTimeLock,
            &mut key[..32],
        )
        .unwrap();
        found.extend(secrets(&key, SALT, KeyLength::Bytes32, Branch::KeyId));
        found
    }

    /// The stack in KiB that a time lock and its opening need, the lock's own wipe included. For
    /// an optimised build and for one without optimisation.
    const NEEDS: [usize; 2] = [104, 108];

    fn pieces() -> Vec<Vec<u8>> {
        key_dependent(&found(0, &epoch_bytes(0)), &found(0xff, &epoch_bytes(0xff)))
    }

    fn locked(memory: &mut [Slot], lock: &mut [u8; TIME_LOCK_LEN]) {
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(memory, &mut epoch);
        slots
            .generate_time_lock(&QUICKNET, ROUND_1000 - 100, ROUND_1000, &mut Fixed(0), lock)
            .unwrap();
    }

    struct Panicking;

    impl Entropy for Panicking {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            Fixed(0).fill(dest)?;
            panic!("the source broke after writing")
        }
    }

    /// With optimisation the unwinding itself overwrites where the bytes were, so only a build
    /// without it can tell.
    #[test]
    fn a_panicking_source_leaves_no_bytes() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut lock = [0; TIME_LOCK_LEN];
        assert_clean(&pieces, || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = slots.generate_time_lock(
                    &QUICKNET,
                    ROUND_1000 - 100,
                    ROUND_1000,
                    &mut Panicking,
                    &mut lock,
                );
            }));
            assert!(outcome.is_err());
        });
        assert_eq!(lock, [0; TIME_LOCK_LEN]);
        slots
            .generate_time_lock(
                &QUICKNET,
                ROUND_1000 - 100,
                ROUND_1000,
                &mut Fixed(0),
                &mut lock,
            )
            .unwrap();
    }

    #[test]
    fn a_time_lock_leaves_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 1];
        let mut lock = [0; TIME_LOCK_LEN];
        assert_clean(&pieces, || locked(&mut memory, &mut lock));
    }

    #[test]
    fn an_opening_leaves_no_residue() {
        let pieces = pieces();
        let mut lock = [0; TIME_LOCK_LEN];
        locked(&mut [const { Slot::empty() }; 1], &mut lock);
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let signature = signature(SIGNATURE_1000);
        assert_clean(&pieces, || {
            slots.open_time_lock(&QUICKNET, &lock, &signature).unwrap();
        });
    }

    #[test]
    fn the_wipe_reaches_its_depth() {
        let needs = 1024 * NEEDS[usize::from(cfg!(lethewis_unoptimised))];
        let mut memory = [const { Slot::empty() }; 1];
        let mut lock = [0; TIME_LOCK_LEN];
        let made = depth_changed(|| locked(&mut memory, &mut lock));
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let signature = signature(SIGNATURE_1000);
        let opened = depth_changed(|| {
            slots.open_time_lock(&QUICKNET, &lock, &signature).unwrap();
        });
        for wiped in [made, opened] {
            assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
            assert!(wiped <= needs, "{wiped} bytes reached");
        }
    }

    #[test]
    fn the_documentation_states_the_stack_the_calls_need() {
        let source = include_str!("timelock.rs");
        for call in ["generate_time_lock", "open_time_lock"] {
            let at = source.find(&std::format!("    pub fn {call}(")).unwrap();
            let mut lines: Vec<&str> = source[..at]
                .lines()
                .rev()
                .take_while(|line| {
                    let line = line.trim_start();
                    line.starts_with("///") || line.starts_with("#[")
                })
                .map(|line| line.trim().trim_start_matches("///").trim())
                .collect();
            lines.reverse();
            let stated = std::format!(
                "Needs {} KiB of stack, or {} KiB when unoptimised",
                NEEDS[0],
                NEEDS[1]
            );
            assert!(lines.join(" ").contains(&stated), "{call}: {stated}");
        }
    }
}
