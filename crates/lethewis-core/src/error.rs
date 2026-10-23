// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Every slot holds a key set or is out of use.
    NoFreeSlot,
    /// The handle does not refer to a key set held now, or a block began before its set last
    /// changed.
    StaleHandle,
    /// The source of random bytes failed.
    EntropyFailed,
    /// A value could not be derived from a key.
    DerivationFailed,
    /// The record does not open with the key of the parent set and this context, holds a plaintext
    /// this version of the library cannot read, or names a key other than the one that opens it;
    /// or X-Wing refuses the public key of an archive key; or no block has the length given, the
    /// header of a block names no key of the set, or a chunk does not open as the next of its
    /// block.
    RecordRejected,
    /// A key set cannot wrap itself.
    SameKey,
    /// The context is empty or longer than 255 bytes.
    InvalidContext,
    /// The cipher or X-Wing gave a known input a wrong answer, a new key pair of X-Wing did not agree
    /// with itself, the cipher refused the input, or a sealed chunk did not open or seal again to
    /// the same tag and ciphertext, so nothing was written.
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
    /// The set has changed in this epoch, and only a new epoch saves the change; or a block is to
    /// be written under a set no record of this epoch holds as it is now.
    Unsaved,
    /// A change to the next epoch has begun already.
    EpochChanging,
    /// No change to the next epoch has begun.
    NoEpochChange,
    /// This is the last epoch the counter holds.
    EpochExhausted,
    /// The platform did not switch the root of the epoch.
    RootFailed,
    /// The parameters of a derivation from a password are out of bounds, or not ones this version
    /// of the library writes.
    InvalidParams,
    /// The password is empty or longer than 2^32 - 1 bytes.
    InvalidPassword,
    /// The working memory holds fewer blocks than the parameters take.
    NotEnoughMemory,
    /// A word is not one of the list.
    UnknownWord,
    /// The words are of the list, but their checksum does not hold.
    InvalidChecksum,
    /// The key set serves a purpose the call does not take.
    WrongPurpose,
    /// The purpose takes no key of this length.
    WrongLength,
    /// The set is not of the level the call takes: a key from a secret wraps only stored keys, for
    /// wrapping or of the archive; a stored key for wrapping wraps only keys for external data, keys
    /// for transfers, keys of chats for their archives and keys for data; a key for transfers
    /// exports only keys for external data.
    WrongLevel,
    /// The lock record or the record of an archive key does not open in this epoch for this
    /// context: it was not written or carried into it, or it was changed; or the public key of an
    /// archive key was read from other slots or in another epoch.
    StaleRecord,
    /// The record of an archive key holds an identifier or a public key other than the ones its seed
    /// gives, changed by someone who held the key of the epoch and the stored key it is under; or
    /// the record of a batch fails its check, archived to another public key or changed under the
    /// key of its chat.
    PublicKeyMismatch,
    /// The record of an archive was written to another archive key.
    WrongArchiveKey,
    /// A transfer has not ended: the set came in an export whose end has not been received, and is
    /// neither revealed, wrapped, exported nor changed until then, or the key for transfers carries
    /// an export the other way.
    Unfinished,
    /// The key for transfers has written or received no record of an export to end.
    NoTransfer,
    /// The block is under a key of the set that is disabled: it opens once the key is enabled
    /// again.
    KeyDisabled,
    /// The chunk is not the one its block takes next: the last one where more are due, another
    /// where the last is due, a last one of another length, longer than a chunk or empty after
    /// others, or one past as many chunks as a number of 64 bits counts.
    WrongChunk,
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
            Self::InvalidParams => "invalid password parameters",
            Self::InvalidPassword => "invalid password",
            Self::NotEnoughMemory => "not enough memory",
            Self::UnknownWord => "unknown word",
            Self::InvalidChecksum => "invalid checksum",
            Self::WrongPurpose => "wrong purpose",
            Self::WrongLength => "wrong key length",
            Self::WrongLevel => "wrong level",
            Self::StaleRecord => "stale record",
            Self::PublicKeyMismatch => "public key mismatch",
            Self::WrongArchiveKey => "wrong archive key",
            Self::Unfinished => "unfinished transfer",
            Self::NoTransfer => "no transfer",
            Self::KeyDisabled => "key disabled",
            Self::WrongChunk => "wrong chunk",
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
        assert_eq!(
            Error::InvalidParams.to_string(),
            "invalid password parameters"
        );
        assert_eq!(Error::InvalidPassword.to_string(), "invalid password");
        assert_eq!(Error::NotEnoughMemory.to_string(), "not enough memory");
        assert_eq!(Error::UnknownWord.to_string(), "unknown word");
        assert_eq!(Error::InvalidChecksum.to_string(), "invalid checksum");
        assert_eq!(Error::WrongPurpose.to_string(), "wrong purpose");
        assert_eq!(Error::WrongLength.to_string(), "wrong key length");
        assert_eq!(Error::WrongLevel.to_string(), "wrong level");
        assert_eq!(Error::StaleRecord.to_string(), "stale record");
        assert_eq!(Error::PublicKeyMismatch.to_string(), "public key mismatch");
        assert_eq!(Error::WrongArchiveKey.to_string(), "wrong archive key");
        assert_eq!(Error::Unfinished.to_string(), "unfinished transfer");
        assert_eq!(Error::NoTransfer.to_string(), "no transfer");
        assert_eq!(Error::KeyDisabled.to_string(), "key disabled");
        assert_eq!(Error::WrongChunk.to_string(), "wrong chunk");
    }
}
