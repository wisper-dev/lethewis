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

// Under Kani the wipe is plain stores and the derivation and the cipher are models, so these go
// unused there.
#[cfg(kani)]
use {aes_gcm_siv as _, ctutils as _, hkdf as _, sha2 as _, zeroize as _};
// Depended on only for their zeroize feature.
use {aes as _, polyval as _};

mod derive;
mod entropy;
mod error;
mod key;
mod record;
mod seal;
mod slots;

pub use entropy::{Entropy, EntropyError};
pub use error::Error;
pub use key::KeyLength;
pub use record::{Purpose, RECORD_LEN};
pub use slots::{Handle, Slot, Slots};

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
                cfg!(aes_backend = "soft"),
                cfg!(polyval_backend = "soft"),
            ],
            [portable; 3]
        );
    }
}
