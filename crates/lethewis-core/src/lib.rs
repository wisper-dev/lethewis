// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Key derivation, hierarchy, lifecycle and destruction for a device that may be taken from its
//! owner.
//!
//! Pure logic: no filesystem, no network, no clock. The one question put to the system, through
//! `lethewis-dit`, is whether the processor offers data-independent timing.
//!
//! What is guaranteed, what is not, and which properties are proven:
//! <https://github.com/wisper-dev/lethewis>.

#![deny(missing_docs, unused_crate_dependencies)]
#![no_std]
// Line coverage is judged on proof code only, so Kani counts it nowhere else.
#![cfg_attr(kani, feature(coverage_attribute), coverage(off))]

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
use {
    aes_gcm_siv as _, argon2 as _, ctutils as _, hkdf as _, polyval as _, sha2 as _, zeroize as _,
};
// Depended on only for their zeroize feature.
use {aes as _, blake2 as _};

mod block;
mod derive;
mod entropy;
mod epoch;
mod error;
mod key;
mod keyset;
mod password;
mod record;
#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod residue;
mod seal;
mod shares;
mod slots;
mod timing;
mod words;
mod xwing;

pub use block::{BLOCK_HEADER_LEN, CHUNK_LEN, CHUNK_TAG_LEN, batch_data_len, batch_len, block_len};
pub use entropy::{Entropy, EntropyError};
pub use epoch::{Epoch, Erasure, Root, RootFailed};
pub use error::Error;
pub use key::KeyLength;
pub use keyset::Position;
pub use password::{MemoryBlock, PASSWORD_PARAMS_LEN, PasswordParams};
pub use record::{
    ARCHIVE_KEY_RECORD_LEN, ARCHIVE_RECORD_LEN, END_RECORD_LEN, LOCK_RECORD_LEN, Purpose,
    RECORD_LEN,
};
pub use shares::{SHARE_COUNT, SHARE_LEN, Share, Shares};
pub use slots::{
    ArchivePublic, Exporting, Handle, Opening, Receipt, Receiving, Sealing, Slot, Slots,
};
pub use words::{WORD_COUNT, WORD_LEN, Words};

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
                cfg!(keccak_backend = "soft"),
            ],
            [portable; 4]
        );
    }
}
