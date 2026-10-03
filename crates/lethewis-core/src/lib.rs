// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Key derivation, hierarchy, lifecycle and destruction for a device that may be taken from its
//! owner.
//!
//! Pure logic: no filesystem, no network, no clock, no platform API.
//!
//! What is guaranteed, what is not, and which properties are proven:
//! <https://github.com/wisper-dev/lethewis>.

#![deny(missing_docs, unused_crate_dependencies)]
#![no_std]

/// Fails to compile if `$type` implements any of the traits.
#[cfg(test)]
macro_rules! assert_not_impl {
    ($type:ty: $($trait:path),+ $(,)?) => {
        $(
            const _: fn() = || {
                trait Ambiguous<A> {
                    fn check() {}
                }
                impl<T: ?Sized> Ambiguous<()> for T {}
                struct Implemented;
                impl<T: ?Sized + $trait> Ambiguous<Implemented> for T {}
                let _ = <$type as Ambiguous<_>>::check;
            };
        )+
    };
}

// Under Kani the wipe is plain stores, so zeroize goes unused there.
#[cfg(kani)]
use zeroize as _;

mod entropy;
mod error;
mod key;
mod slots;

pub use entropy::{Entropy, EntropyError};
pub use error::Error;
pub use key::KeyLength;
pub use slots::{Handle, Slot, Slots};
