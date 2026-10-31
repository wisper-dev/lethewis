// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The work on a key, run with data-independent timing on.

pub(crate) fn with<R>(work: impl FnOnce() -> R) -> R {
    #[cfg(test)]
    let _within = Within::enter();
    lethewis_dit::with(work)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
std::thread_local! {
    static WITHIN: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static SEEN: core::cell::Cell<Option<bool>> = const { core::cell::Cell::new(None) };
}

/// Marks the thread as running work within [`with`] while it lives, on every machine.
#[cfg(test)]
struct Within;

#[cfg(test)]
impl Within {
    fn enter() -> Self {
        WITHIN.set(WITHIN.get().saturating_add(1));
        Self
    }
}

#[cfg(test)]
impl Drop for Within {
    fn drop(&mut self) {
        WITHIN.set(WITHIN.get().saturating_sub(1));
    }
}

/// Notes whether the work that calls it runs within [`with`] with the mode as the machine offers.
#[cfg(test)]
pub(crate) fn note() {
    let now = WITHIN.get() > 0 && lethewis_dit::active() == lethewis_dit::supported();
    SEEN.set(Some(SEEN.get().unwrap_or(true) && now));
}

/// Whether all work noted since the last call ran so, or `None` if none was noted.
#[cfg(test)]
pub(crate) fn seen() -> Option<bool> {
    SEEN.take()
}
