// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Data-independent timing on aarch64 for a piece of work.
//!
//! [`with`] runs work with data-independent timing on: the processor then takes the same time for
//! an instruction whatever data it works on, for the instructions the architecture lists under
//! `FEAT_DIT`. The mode is switched on only where the operating system reports the feature, on
//! Linux, Android and Apple's systems, and only when it is off, and back off when the work returns
//! or unwinds. Elsewhere the work runs as it is.

#![no_std]
#![deny(missing_docs, unused_crate_dependencies)]

/// Runs `work` on the current thread with data-independent timing on, where the processor and the
/// operating system offer it.
///
/// The switch orders memory accesses and calls, and the work is called through a function that is
/// not inlined; a value the caller already holds in a register may still be computed on before the
/// switch.
pub fn with<R>(work: impl FnOnce() -> R) -> R {
    let _guard = Guard::enable();
    apart(work)
}

#[inline(never)]
fn apart<R>(work: impl FnOnce() -> R) -> R {
    work()
}

/// Switches the mode back off when dropped, if it switched it on.
struct Guard {
    switched_on: bool,
}

impl Guard {
    fn enable() -> Self {
        Self {
            switched_on: platform::switch_on(),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.switched_on {
            platform::switch_off();
        }
    }
}

/// Whether the processor and the operating system offer data-independent timing.
#[must_use]
pub fn supported() -> bool {
    platform::supported()
}

/// Whether the current thread runs with data-independent timing now.
#[must_use]
pub fn active() -> bool {
    platform::active()
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android", target_vendor = "apple"),
    not(miri),
    not(kani)
))]
#[path = "aarch64.rs"]
mod platform;

#[cfg(not(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android", target_vendor = "apple"),
    not(miri),
    not(kani)
)))]
#[path = "elsewhere.rs"]
mod platform;

#[cfg(any(
    test,
    all(target_arch = "aarch64", target_vendor = "apple", not(miri), not(kani))
))]
mod reported;

// Under Miri and Kani the guard does nothing, so the calls into the system are not built.
#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android", target_vendor = "apple"),
    any(miri, kani)
))]
use libc as _;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{Guard, active, supported, with};

    /// On aarch64 the run states what the operating system reports, `present` or `absent`, read
    /// apart from this crate; elsewhere the feature does not exist.
    #[test]
    fn the_feature_is_found_as_the_system_reports_it() {
        let expected = if cfg!(target_arch = "aarch64") {
            let stated = std::env::var("LETHEWIS_DIT").unwrap_or_default();
            assert!(
                stated == "present" || stated == "absent",
                "set LETHEWIS_DIT to present or absent"
            );
            stated == "present"
        } else {
            false
        };
        assert_eq!(supported(), expected);
    }

    #[test]
    fn work_runs_with_the_mode_on_and_it_is_put_back() {
        let before = active();
        with(|| {
            assert_eq!(active(), supported());
            with(|| assert_eq!(active(), supported()));
            assert_eq!(
                active(),
                supported(),
                "inner work leaves the outer work in the mode"
            );
        });
        assert_eq!(active(), before);
    }

    #[test]
    fn a_guard_switches_only_what_was_off() {
        let before = active();
        let guard = Guard::enable();
        assert_eq!(guard.switched_on, supported() && !before);
        drop(guard);
        assert_eq!(active(), before);
    }

    #[test]
    fn work_that_unwinds_puts_the_mode_back() {
        let before = active();
        let unwound = std::panic::catch_unwind(|| {
            with(|| std::panic::resume_unwind(std::boxed::Box::new(())));
        });
        assert!(unwound.is_err());
        assert_eq!(active(), before);
    }
}
