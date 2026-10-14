// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Every slot holds a key set or is out of use.
    NoFreeSlot,
    /// The handle does not refer to a key set held now.
    StaleHandle,
    /// The source of random bytes failed.
    EntropyFailed,
    /// A value could not be derived from a key.
    DerivationFailed,
    /// The record does not open with a key of the parent set and this context, holds a plaintext
    /// this version of the library cannot read, or names a key other than the one that opens it.
    RecordRejected,
    /// The record opens only with a disabled key, and a disabled key unwraps nothing.
    KeyDisabled,
    /// A key set cannot wrap itself.
    SameKey,
    /// The context is empty or longer than 255 bytes.
    InvalidContext,
    /// The cipher gave a known input a wrong answer or refused the input, so nothing was written.
    CipherFailed,
    /// A key of the set is held here already, or the set holds one key twice: a key is held in one
    /// place only.
    DuplicateKey,
    /// Every position of the set holds a key.
    SetFull,
    /// The change does not apply to the primary key of the set.
    PrimaryKey,
    /// The position does not hold a key in the stage the change starts from.
    WrongStage,
    /// The set has changed as many times as its counter holds.
    SetExhausted,
    /// The set has changed in this epoch, and only a new epoch saves the change.
    Unsaved,
    /// A change to the next epoch has begun already.
    EpochChanging,
    /// No change to the next epoch has begun.
    NoEpochChange,
    /// This is the last epoch the counter holds.
    EpochExhausted,
    /// The platform did not switch the root of the epoch.
    RootFailed,
}

impl From<crate::keyset::Refused> for Error {
    fn from(refused: crate::keyset::Refused) -> Self {
        use crate::keyset::Refused;
        match refused {
            Refused::Full => Self::SetFull,
            Refused::Primary => Self::PrimaryKey,
            Refused::Stage => Self::WrongStage,
            Refused::Exhausted => Self::SetExhausted,
        }
    }
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
            Self::SameKey => "a key set cannot wrap itself",
            Self::InvalidContext => "invalid context",
            Self::CipherFailed => "cipher failed",
            Self::DuplicateKey => "duplicate key",
            Self::SetFull => "key set full",
            Self::PrimaryKey => "primary key",
            Self::WrongStage => "wrong stage",
            Self::SetExhausted => "key set exhausted",
            Self::Unsaved => "unsaved change",
            Self::EpochChanging => "epoch change under way",
            Self::NoEpochChange => "no epoch change",
            Self::EpochExhausted => "epochs exhausted",
            Self::RootFailed => "root not switched",
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
        assert_eq!(Error::SameKey.to_string(), "a key set cannot wrap itself");
        assert_eq!(Error::InvalidContext.to_string(), "invalid context");
        assert_eq!(Error::CipherFailed.to_string(), "cipher failed");
        assert_eq!(Error::DuplicateKey.to_string(), "duplicate key");
        assert_eq!(Error::SetFull.to_string(), "key set full");
        assert_eq!(Error::PrimaryKey.to_string(), "primary key");
        assert_eq!(Error::WrongStage.to_string(), "wrong stage");
        assert_eq!(Error::SetExhausted.to_string(), "key set exhausted");
        assert_eq!(Error::Unsaved.to_string(), "unsaved change");
        assert_eq!(Error::EpochChanging.to_string(), "epoch change under way");
        assert_eq!(Error::NoEpochChange.to_string(), "no epoch change");
        assert_eq!(Error::EpochExhausted.to_string(), "epochs exhausted");
        assert_eq!(Error::RootFailed.to_string(), "root not switched");
    }
}
