// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use crate::key::Key;

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
    /// [`RootFailed`] if it cannot; the old root then stays current.
    fn switch(&mut self, next: u64) -> Result<(), RootFailed>;

    /// Erases the root of epoch `epoch` and tells how surely it is gone.
    fn erase(&mut self, epoch: u64) -> Erasure;
}
