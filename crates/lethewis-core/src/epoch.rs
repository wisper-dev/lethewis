// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use crate::key::Key;

/// Memory for the epoch of [`Slots`](crate::Slots), provided by the caller: the number and key of
/// the current epoch, and the key of the next while a change to it is under way.
///
/// It cannot be copied, cloned or compared, and holds keys only while a `Slots` over it is alive.
pub struct Epoch {
    pub(crate) number: u64,
    pub(crate) key: Key,
    pub(crate) next: Key,
    pub(crate) changing: bool,
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
        }
    }

    /// Wipes both keys and forgets any change under way.
    pub(crate) fn wipe(&mut self) {
        self.key.wipe();
        self.next.wipe();
        self.changing = false;
    }
}

impl fmt::Debug for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Epoch").finish_non_exhaustive()
    }
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

/// The platform, which keeps the root of each epoch: the secret that the key of the epoch is
/// wrapped under on the device.
///
/// Before a change to the next epoch begins, the platform makes a new root and the key of the next
/// epoch, never used before. At every start, and before it makes a new root, it erases every root
/// but the current one, so that a root left by a failure or a weaker erasure goes as soon as it can.
pub trait Root {
    /// Makes the root of epoch `next` the current one in one step.
    ///
    /// # Errors
    ///
    /// [`RootFailed`] if it cannot; the old root then stays current.
    fn switch(&mut self, next: u64) -> Result<(), RootFailed>;

    /// Erases the root of epoch `epoch` and tells how surely it is gone.
    fn erase(&mut self, epoch: u64) -> Erasure;
}
