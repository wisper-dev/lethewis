// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Every slot holds a key or is out of use.
    NoFreeSlot,
    /// The handle does not refer to a key held now.
    StaleHandle,
    /// The source of random bytes failed.
    EntropyFailed,
    /// A value could not be derived from a key.
    DerivationFailed,
    /// The record does not open with this key and context, holds a plaintext this version of the
    /// library cannot read, or names another key as the one it is wrapped with.
    RecordRejected,
    /// The key is disabled and cannot wrap or unwrap.
    KeyDisabled,
    /// A key cannot wrap itself.
    SameKey,
    /// The context is empty or longer than 255 bytes.
    InvalidContext,
    /// The cipher gave a known input a wrong answer or refused the input, so nothing was written.
    CipherFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoFreeSlot => "no free slot",
            Self::StaleHandle => "stale handle",
            Self::EntropyFailed => "random source failed",
            Self::DerivationFailed => "key derivation failed",
            Self::RecordRejected => "record rejected",
            Self::KeyDisabled => "key disabled",
            Self::SameKey => "a key cannot wrap itself",
            Self::InvalidContext => "invalid context",
            Self::CipherFailed => "cipher failed",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::Error;

    #[test]
    fn display_names_the_failure() {
        assert_eq!(Error::NoFreeSlot.to_string(), "no free slot");
        assert_eq!(Error::StaleHandle.to_string(), "stale handle");
        assert_eq!(Error::EntropyFailed.to_string(), "random source failed");
        assert_eq!(Error::DerivationFailed.to_string(), "key derivation failed");
        assert_eq!(Error::RecordRejected.to_string(), "record rejected");
        assert_eq!(Error::KeyDisabled.to_string(), "key disabled");
        assert_eq!(Error::SameKey.to_string(), "a key cannot wrap itself");
        assert_eq!(Error::InvalidContext.to_string(), "invalid context");
        assert_eq!(Error::CipherFailed.to_string(), "cipher failed");
    }
}
