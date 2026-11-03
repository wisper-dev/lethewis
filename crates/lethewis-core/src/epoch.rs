// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use crate::derive::{derive_epoch_root, wipe_stack};
use crate::error::Error;
use crate::key::{Key, wipe};

/// Memory for the epoch of [`Slots`](crate::Slots), provided by the caller.
///
/// It cannot be copied, cloned or compared, and holds keys only while a `Slots` over it is alive.
pub struct Epoch {
    pub(crate) number: u64,
    pub(crate) key: Key,
    pub(crate) next: Key,
    pub(crate) changing: bool,
    /// Each draw of the platform's source is hedged with its own count.
    pub(crate) drawn: u64,
}

impl Epoch {
    /// Memory holding no epoch.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            number: 0,
            key: Key::empty(),
            next: Key::empty(),
            changing: false,
            drawn: 0,
        }
    }

    pub(crate) fn wipe(&mut self) {
        self.key.wipe();
        self.next.wipe();
        self.changing = false;
        self.drawn = 0;
    }
}

impl fmt::Debug for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Epoch").finish_non_exhaustive()
    }
}

/// The key of an epoch from its root on a device, for [`Slots::new`](crate::Slots::new) and
/// [`Slots::begin_epoch`](crate::Slots::begin_epoch): HKDF over `stored`, the random bytes kept for
/// the epoch, with `answer`, the chip's answer for it, as the salt. Wipes both.
///
/// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
///
/// # Errors
///
/// Fails with [`Error::DerivationFailed`], and then leaves `out` as it was.
pub fn epoch_key(
    stored: &mut [u8; 32],
    answer: &mut [u8; 32],
    out: &mut [u8; 32],
) -> Result<(), Error> {
    let derived = crate::timing::with(|| epoch_key_on_stack(stored, answer, out));
    wipe_stack();
    wipe(stored);
    wipe(answer);
    derived
}

#[inline(never)]
fn epoch_key_on_stack(
    stored: &[u8; 32],
    answer: &[u8; 32],
    out: &mut [u8; 32],
) -> Result<(), Error> {
    let mut key = Key::empty();
    key.copy32(stored);
    let mut derived = [0; 32];
    let result = derive_epoch_root(&key, answer, &mut derived).map_err(|_| Error::DerivationFailed);
    if result.is_ok() {
        *out = derived;
    }
    wipe(&mut derived);
    key.wipe();
    result
}

/// How surely the platform has erased the root of an epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Erasure {
    /// The platform guarantees that the root is gone.
    Guaranteed,
    /// The platform has deleted the root but cannot guarantee that it is gone.
    BestEffort,
    /// The platform has not erased the root.
    NotErased,
}

/// The platform did not switch the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootFailed;

/// The platform's keeper of each epoch's root, the secret the epoch key is wrapped under on the
/// device. It makes a new root and an unused key for each change, erasing other roots at start and
/// before each.
pub trait Root {
    /// Makes the root of epoch `next` the current one in one step.
    ///
    /// # Errors
    ///
    /// [`RootFailed`] if it cannot. The old root then stays current, unless the keeper cannot
    /// tell: then either may be, until it reads the current root again.
    fn switch(&mut self, next: u64) -> Result<(), RootFailed>;

    /// Erases the root of epoch `epoch` and tells how surely it is gone.
    fn erase(&mut self, epoch: u64) -> Erasure;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::epoch_key;

    #[test]
    fn an_epoch_key_is_hkdf_with_the_answer_as_salt_and_its_label() {
        let stored: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let answer: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap() ^ 0xa5);
        let (mut stored_in, mut answer_in, mut ours) = (stored, answer, [0; 32]);
        crate::timing::timed(|| epoch_key(&mut stored_in, &mut answer_in, &mut ours)).unwrap();
        let mut info = b"lethewis".to_vec();
        info.extend_from_slice(&[1, 0, 32, 32, 0, 10]);
        info.extend_from_slice(b"epoch root");
        let mut direct = [0; 32];
        Hkdf::<Sha256>::new(Some(&answer), &stored)
            .expand(&info, &mut direct)
            .unwrap();
        assert_eq!(ours, direct);
        assert_eq!((stored_in, answer_in), ([0; 32], [0; 32]));
    }

    #[test]
    fn each_input_changes_the_key() {
        let key = |stored: u8, answer: u8| {
            let mut out = [0; 32];
            epoch_key(&mut [stored; 32], &mut [answer; 32], &mut out).unwrap();
            out
        };
        assert_ne!(key(1, 2), key(3, 2));
        assert_ne!(key(1, 2), key(1, 3));
        assert_ne!(key(1, 2), key(2, 1));
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    //! What the derivation of an epoch key leaves on the stack, read back from the memory of this
    //! process.

    extern crate std;

    use std::vec::Vec;

    use super::epoch_key;
    use crate::derive::stack::secrets_for;
    use crate::derive::{Branch, STACK_WIPE};
    use crate::residue::{assert_clean, depth_changed, key_dependent};

    /// In KiB, for an optimised build and for one without optimisation.
    const NEEDS: [usize; 2] = [9, 68];
    const WIPES: [usize; 2] = [8, 64];

    fn stored(flip: u8) -> [u8; 32] {
        core::array::from_fn(|at| u8::try_from(at).unwrap().wrapping_mul(29).wrapping_add(7) ^ flip)
    }

    fn answer(flip: u8) -> [u8; 32] {
        core::array::from_fn(|at| u8::try_from(at).unwrap().wrapping_mul(61).wrapping_add(3) ^ flip)
    }

    fn found(flip: u8) -> Vec<Vec<u8>> {
        let mut found = secrets_for(&stored(flip), &answer(flip), Branch::EpochRoot, None);
        found.push(stored(flip).to_vec());
        found.push(answer(flip).to_vec());
        found
    }

    #[test]
    fn an_epoch_key_leaves_no_residue() {
        let pieces = key_dependent(&found(0), &found(0xff));
        // The inputs and the key are the caller's, above what is read.
        let (mut stored, mut answer, mut out) = (stored(0), answer(0), [0; 32]);
        assert_clean(&pieces, || {
            epoch_key(&mut stored, &mut answer, &mut out).unwrap();
        });
        assert_ne!(out, [0; 32]);
    }

    #[test]
    fn the_wipe_reaches_its_depth() {
        let needs = 1024 * NEEDS[usize::from(cfg!(lethewis_unoptimised))];
        let mut out = [0; 32];
        let wiped = depth_changed(|| {
            epoch_key(&mut stored(0), &mut answer(0), &mut out).unwrap();
        });
        assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
        assert!(wiped <= needs, "{wiped} bytes reached");
    }

    #[test]
    fn the_documentation_states_the_stack_the_call_needs() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(WIPES[build] * 1024, STACK_WIPE);
        let source = include_str!("epoch.rs");
        let at = source.find("pub fn epoch_key(").unwrap();
        let text = source[..at]
            .lines()
            .rev()
            .take_while(|line| line.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join(" ");
        for stated in [
            std::format!("Needs {} KiB of stack, or {} KiB when", NEEDS[0], NEEDS[1]),
            std::format!(" {} KiB, or {} KiB, ", WIPES[0], WIPES[1]),
        ] {
            assert!(text.contains(&stated), "{stated}");
        }
    }
}
