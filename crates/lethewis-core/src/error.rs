// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Every slot holds a key set or is out of use.
    NoFreeSlot,
    /// The handle refers to no set held now, or a block began before its set last changed. Or,
    /// since a carried block began, another element went under its transfer key.
    StaleHandle,
    /// The source of random bytes failed.
    EntropyFailed,
    /// A value could not be derived from a key.
    DerivationFailed,
    /// A record, block, chunk or batch does not open under this key and context, or names another
    /// key. Or its length or plaintext is not one this version reads, or X-Wing refused an archive
    /// key's public key.
    RecordRejected,
    /// A key set cannot wrap itself.
    SameKey,
    /// The context is empty or longer than 255 bytes.
    InvalidContext,
    /// The cipher or X-Wing refused the input, or failed a known answer or self-check; nothing was
    /// written.
    CipherFailed,
    /// A key of the set is held here already, or the set holds one key twice.
    DuplicateKey,
    /// Every position of the set holds a key.
    SetFull,
    /// The change does not apply to the primary key of the set.
    PrimaryKey,
    /// The position does not hold a key in the stage the change starts from.
    WrongStage,
    /// The set has changed as many times as its counter holds.
    SetExhausted,
    /// The set changed in this epoch, and only a new epoch saves that. Or a block is to go under a
    /// set no current record of this epoch holds.
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
    /// writes.
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
    /// The purpose takes no key of this length, or a buffer is not as long as the call takes.
    WrongLength,
    /// The set is not of the level the call takes, as [`Purpose::Wrap`](crate::Purpose::Wrap) and
    /// [`Purpose::Transfer`](crate::Purpose::Transfer) describe.
    WrongLevel,
    /// The lock or archive key record was not written or carried into this epoch for this context,
    /// or was changed. A public key read from other slots or in another epoch gives it too.
    StaleRecord,
    /// An archive key's record names an identifier or public key not from its seed, or a batch
    /// fails its check. A holder of the keys above changed it, or the batch went to another public
    /// key.
    PublicKeyMismatch,
    /// The record of an archive was written to another archive key.
    WrongArchiveKey,
    /// A transfer has not ended, so a set it brought is not yet revealed, wrapped, exported,
    /// changed or used. A transfer key carrying an export the other way gives it too.
    Unfinished,
    /// The key for transfers has written or received no record or block of an export to end.
    NoTransfer,
    /// The block is under a key of the set that is disabled: it opens once the key is enabled
    /// again.
    KeyDisabled,
    /// The chunk is not its block's next: out of order, of a wrong length, or past a 64-bit count.
    WrongChunk,
    /// The data set did not come in the transfer under way, so no received block is written under
    /// it.
    NotReceived,
    /// A share is numbered other than 1, 2 or 3, or its words are of a later format.
    InvalidShare,
    /// The shares carry the marks of different splits.
    MixedShares,
    /// Both shares carry the same number.
    SameShare,
    /// The secret the shares give fails their check: a share was changed, or two splits share one
    /// mark.
    ChangedShare,
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
            Self::NotReceived => "set not received",
            Self::InvalidShare => "invalid share",
            Self::MixedShares => "shares of different splits",
            Self::SameShare => "same share twice",
            Self::ChangedShare => "changed share",
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
        assert_eq!(Error::NotReceived.to_string(), "set not received");
        assert_eq!(Error::InvalidShare.to_string(), "invalid share");
        assert_eq!(Error::MixedShares.to_string(), "shares of different splits");
        assert_eq!(Error::SameShare.to_string(), "same share twice");
        assert_eq!(Error::ChangedShare.to_string(), "changed share");
    }
}
