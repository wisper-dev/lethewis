// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The work of every call that handles a key, run with data-independent timing on.

/// Runs `work` with data-independent timing on, where the processor and the operating system
/// offer it.
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

/// Notes whether the work on a secret that calls it runs within [`with`], with the mode on where
/// it is offered.
#[cfg(test)]
pub(crate) fn note() {
    let now = WITHIN.get() > 0 && lethewis_dit::active() == lethewis_dit::supported();
    SEEN.set(Some(SEEN.get().unwrap_or(true) && now));
}

/// Whether all the work on secrets on this thread since the last look ran so, and forget it.
#[cfg(test)]
pub(crate) fn seen() -> Option<bool> {
    SEEN.take()
}

/// Runs `work`, a call, and asserts that it derives, runs the cipher or X-Wing, or reads or writes
/// words inside [`with`] only, and with the mode on where it is offered.
#[cfg(test)]
pub(crate) fn timed<T>(work: impl FnOnce() -> T) -> T {
    let _ = seen();
    let done = work();
    assert_eq!(seen(), Some(true), "work on a secret outside the mode");
    done
}

#[cfg(test)]
mod tests {
    use super::{note, seen, with};

    #[test]
    fn work_is_seen_only_within_the_mode() {
        let _ = seen();
        note();
        assert_eq!(seen(), Some(false));
        with(note);
        assert_eq!(seen(), Some(true));
        with(|| with(note));
        note();
        assert_eq!(seen(), Some(false));
        assert_eq!(seen(), None);
    }
}
