// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! A time lock on the drand network quicknet, which signs one round every three seconds. A key is
//! locked until a round as an age file that tlock tools open, and opened with that round's
//! signature. No network and no clock: the caller brings the signature and the time.

#![deny(missing_docs, unused_crate_dependencies)]
#![no_std]
// Line coverage is judged on proof code only, so Kani counts it nowhere else.
#![cfg_attr(kani, feature(coverage_attribute), coverage(off))]

// Under Kani the hash is a model, so it goes unused there.
#[cfg(kani)]
use sha2 as _;
// Depended on only for their zeroize feature.
#[cfg(not(kani))]
use {cipher as _, poly1305 as _};

mod age;
mod curve;
mod decimal;
mod error;
mod ibe;
mod lock;
mod network;
#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod residue;
mod timing;
#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "the test values are decoded with plain arithmetic"
)]
mod vectors;

pub use age::{LOCK_LEN, LOCKED_KEY_LEN, Lock};
pub use error::Error;
pub use lock::{LOCK_MAX_SECONDS, LOCK_RANDOM_LEN};
pub use network::{Network, QUICKNET, SIGNATURE_LEN};

#[cfg(test)]
mod tests {
    extern crate std;

    /// A misspelt flag would leave a run meant for the portable code on the hardware code.
    #[test]
    fn the_code_paths_are_the_ones_asked_for() {
        let portable = std::env::var("LETHEWIS_BACK_ENDS").is_ok_and(|paths| paths == "portable");
        assert_eq!(
            [
                cfg!(sha2_backend = "soft"),
                cfg!(chacha20_backend = "soft"),
                cfg!(poly1305_backend = "soft"),
            ],
            [portable; 3]
        );
    }
}
