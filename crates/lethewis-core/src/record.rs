// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::key::{CAPACITY, KeyLength};
use crate::seal::{NONCE_LEN, TAG_LEN};
use crate::xwing::{CIPHERTEXT_LEN, PUBLIC_LEN};

/// The size of a record's plaintext in bytes: a key set.
pub(crate) const PLAINTEXT_LEN: usize = 233;
/// The size of a record of a wrapped key set in bytes: the nonce, the encrypted plaintext and the
/// tag.
pub const RECORD_LEN: usize = 261;
/// A lock record's size in bytes: the nonce, epoch number and a stored wrapping key's record,
/// encrypted, then the tag.
pub const LOCK_RECORD_LEN: usize = 297;
/// The size of what the outer layer of a lock record encrypts: the number of the epoch and the
/// record.
pub(crate) const LAYER_LEN: usize = 8 + RECORD_LEN;
/// The size of the record that ends an export in bytes: the nonce and the tag of an empty
/// plaintext.
pub const END_RECORD_LEN: usize = 28;
/// An archive key record's size in bytes: the nonce, then the epoch number, identifier, public key
/// and seed record, encrypted. Then the tag.
pub const ARCHIVE_KEY_RECORD_LEN: usize = 1529;
/// What the outer layer of the record of an archive key holds after the number of its epoch.
pub(crate) const ARCHIVE_BODY_LEN: usize = ID_LEN + PUBLIC_LEN + RECORD_LEN;
pub(crate) const ARCHIVE_LAYER_LEN: usize = 8 + ARCHIVE_BODY_LEN;
/// An archive record's size in bytes: the nonce, then the key identifier, X-Wing ciphertext and
/// secret check, encrypted. Then the tag.
pub const ARCHIVE_RECORD_LEN: usize = 1180;
pub(crate) const ARCHIVED_LEN: usize = ID_LEN + CIPHERTEXT_LEN + ID_LEN;
pub(crate) const MAX_CONTEXT: usize = 255;
pub(crate) const LABEL_LEN: usize = 19;
const AAD_LABEL: &[u8; LABEL_LEN] = b"lethewis key record";
pub(crate) const EXPORT_LABEL: &[u8; LABEL_LEN] = b"lethewis key export";
pub(crate) const END_LABEL: &[u8; LABEL_LEN] = b"lethewis export end";
const AAD_CAPACITY: usize = 292;
const AAD_HEAD: usize = LABEL_LEN + 2;
pub(crate) const ID_LEN: usize = 16;
/// The version of the record format, in the associated data and in the plaintext.
pub(crate) const VERSION: u8 = 1;

const _: () = assert!(NONCE_LEN + PLAINTEXT_LEN + TAG_LEN == RECORD_LEN);
const _: () = assert!(NONCE_LEN + LAYER_LEN + TAG_LEN == LOCK_RECORD_LEN);
const _: () = assert!(NONCE_LEN + TAG_LEN == END_RECORD_LEN);
const _: () = assert!(NONCE_LEN + ARCHIVE_LAYER_LEN + TAG_LEN == ARCHIVE_KEY_RECORD_LEN);
const _: () = assert!(NONCE_LEN + ARCHIVED_LEN + TAG_LEN == ARCHIVE_RECORD_LEN);
const _: () = assert!(AAD_HEAD + TAG_LEN + MAX_CONTEXT == AAD_CAPACITY);

/// What a key may be used for: a class of operations together with its algorithm. It is given when
/// the key is loaded and never changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Purpose {
    /// A wrapping key: one from a secret wraps stored keys, which wrap external data, transfer,
    /// chat archive and data keys. Of 32 or 64 bytes, alone in its set, it leaves only wrapped or
    /// once as generated words or shares.
    Wrap = 1,
    /// A 32-byte key for data an engine outside the library encrypts, such as a database. It wraps
    /// no key, and leaves only wrapped or through [`Slots::reveal32`](crate::Slots::reveal32)
    /// naming this purpose.
    ExternalData = 2,
    /// A 32-byte key whose export records carry keys for external data to another device or a
    /// backup, in any epoch. It comes from a shared secret or words, alone in its set, and leaves
    /// only wrapped or as words.
    Transfer = 3,
    /// The 32-byte seed of an X-Wing pair that keeps old history: records to its public key open
    /// only with it. Only an archive key's record creates and holds it; it never leaves the
    /// library.
    Archive = 4,
    /// A stored key of 32 bytes that wraps only the seed of an archive key. It lies only in lock
    /// records, and leaves the library only wrapped.
    ArchiveWrap = 5,
    /// A key of 32 bytes for the outer layer of the records of an archive, one for each chat. It is
    /// stored under a stored key for wrapping, and leaves the library only wrapped.
    ArchiveSeal = 6,
    /// A 32-byte key that encrypts the caller's data in blocks with AES-256-GCM-SIV; what it covers
    /// is lost with it. Only the platform's source creates it, under a stored wrapping key; it is
    /// never exported and leaves only wrapped.
    Data = 7,
}

impl Purpose {
    pub(crate) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Wrap),
            2 => Some(Self::ExternalData),
            3 => Some(Self::Transfer),
            4 => Some(Self::Archive),
            5 => Some(Self::ArchiveWrap),
            6 => Some(Self::ArchiveSeal),
            7 => Some(Self::Data),
            _ => None,
        }
    }

    pub(crate) const fn takes(self, length: KeyLength) -> bool {
        match self {
            Self::Wrap => true,
            Self::ExternalData
            | Self::Transfer
            | Self::Archive
            | Self::ArchiveWrap
            | Self::ArchiveSeal
            | Self::Data => matches!(length, KeyLength::Bytes32),
        }
    }

    /// Whether a key for this purpose may come from the caller's bytes: imported, or derived from a
    /// password or words.
    pub(crate) const fn imported(self) -> bool {
        matches!(self, Self::Wrap | Self::ExternalData | Self::Transfer)
    }

    /// Whether a key for this purpose may be generated from the platform's source alone.
    pub(crate) const fn generated(self) -> bool {
        matches!(
            self,
            Self::Wrap | Self::ExternalData | Self::ArchiveWrap | Self::ArchiveSeal | Self::Data
        )
    }

    /// Whether a set for this purpose holds up to three keys changing by stages, not one fixed key.
    pub(crate) const fn staged(self) -> bool {
        matches!(self, Self::ExternalData | Self::Data)
    }
}

/// Whether a key may be used. The value is the byte a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Status {
    Enabled = 1,
    /// It is kept, but may not be used.
    Disabled = 2,
}

impl Status {
    pub(crate) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Enabled),
            2 => Some(Self::Disabled),
            _ => None,
        }
    }
}

pub(crate) const fn length_to_byte(length: KeyLength) -> u8 {
    match length {
        KeyLength::Bytes32 => 32,
        KeyLength::Bytes64 => 64,
    }
}

pub(crate) const fn length_from_byte(byte: u8) -> Option<KeyLength> {
    match byte {
        32 => Some(KeyLength::Bytes32),
        64 => Some(KeyLength::Bytes64),
        _ => None,
    }
}

/// The bytes are not a plaintext this version of the library writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// The context is empty or longer than [`MAX_CONTEXT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidContext;

/// A record's associated data: a format label and version, the context length, and the context
/// naming its place.
pub(crate) struct AssociatedData {
    bytes: [u8; AAD_CAPACITY],
    len: usize,
}

impl AssociatedData {
    pub(crate) fn new(context: &[u8]) -> Result<Self, InvalidContext> {
        Self::labelled(AAD_LABEL, VERSION, context)
    }

    pub(crate) fn of_data(context: &[u8]) -> Result<Self, InvalidContext> {
        Self::labelled(crate::block::DATA_LABEL, crate::block::VERSION, context)
    }

    pub(crate) fn of_batch(context: &[u8]) -> Result<Self, InvalidContext> {
        Self::labelled(
            crate::block::BATCH_LABEL,
            crate::block::BATCH_VERSION,
            context,
        )
    }

    fn labelled(
        label_of: &[u8; LABEL_LEN],
        version: u8,
        context: &[u8],
    ) -> Result<Self, InvalidContext> {
        let context_len = u8::try_from(context.len())
            .ok()
            .filter(|&len| len != 0)
            .ok_or(InvalidContext)?;
        // The fixed part at fixed offsets. Under the proofs a piece of a length known only at run
        // time costs many times its bytes.
        let mut bytes = [0; AAD_CAPACITY];
        let (label, rest) = bytes
            .split_first_chunk_mut::<LABEL_LEN>()
            .ok_or(InvalidContext)?;
        *label = *label_of;
        let (head, rest) = rest.split_first_chunk_mut::<2>().ok_or(InvalidContext)?;
        *head = [version, context_len];
        rest.get_mut(..context.len())
            .ok_or(InvalidContext)?
            .copy_from_slice(context);
        let len = context.len().checked_add(AAD_HEAD).ok_or(InvalidContext)?;
        Ok(Self { bytes, len })
    }

    /// The associated data of an export record or its end, as `label` says. `chain`, the tag before
    /// or zero for the first, comes before the context.
    pub(crate) fn chained(&self, label: &[u8; LABEL_LEN], chain: &[u8; TAG_LEN]) -> Self {
        let mut bytes = [0; AAD_CAPACITY];
        // The context moves with the zeros past it, so that every copy is of a fixed length.
        if let Some((head, rest)) = bytes.split_first_chunk_mut::<AAD_HEAD>()
            && let Some((tag, context)) = rest.split_first_chunk_mut::<TAG_LEN>()
            && let Some((old_head, old_rest)) = self.bytes.split_first_chunk::<AAD_HEAD>()
            && let (Some(context), Some(old_context)) = (
                context.first_chunk_mut::<MAX_CONTEXT>(),
                old_rest.first_chunk::<MAX_CONTEXT>(),
            )
        {
            *head = *old_head;
            if let Some((new_label, _)) = head.split_first_chunk_mut::<LABEL_LEN>() {
                *new_label = *label;
            }
            *tag = *chain;
            *context = *old_context;
        }
        Self {
            bytes,
            len: self.len.saturating_add(TAG_LEN),
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.split_at(self.len.min(AAD_CAPACITY)).0
    }
}

/// Whether the bytes past the key's length are zero. Reads the whole tail, with no early exit.
pub(crate) fn tail_is_zero(key: &[u8; CAPACITY], length: KeyLength) -> bool {
    match length {
        KeyLength::Bytes32 => lanes(key).is_some_and(|[_, _, third, fourth]| third | fourth == 0),
        KeyLength::Bytes64 => true,
    }
}

// Under the proofs a number costs many times less than its bytes one at a time.
pub(crate) fn lanes(key: &[u8; CAPACITY]) -> Option<[u128; 4]> {
    let pieces: &[[u8; 16]; 4] = key.as_chunks::<16>().0.try_into().ok()?;
    let [first, second, third, fourth] = *pieces;
    Some([
        u128::from_ne_bytes(first),
        u128::from_ne_bytes(second),
        u128::from_ne_bytes(third),
        u128::from_ne_bytes(fourth),
    ])
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{AssociatedData, END_LABEL, EXPORT_LABEL, InvalidContext};

    #[test]
    fn associated_data_are_the_label_the_version_the_length_and_the_context() {
        let associated = AssociatedData::new(b"ab").unwrap();
        assert_eq!(associated.bytes(), b"lethewis key record\x01\x02ab");
        let longest = [7; 255];
        let associated = AssociatedData::new(&longest).unwrap();
        assert_eq!(associated.bytes().len(), 19 + 2 + 255);
        assert_eq!(associated.bytes()[20], 255);
        assert!(associated.bytes().ends_with(&longest));
        assert_eq!(AssociatedData::new(b"").err(), Some(InvalidContext));
        assert_eq!(AssociatedData::new(&[7; 256]).err(), Some(InvalidContext));
    }

    #[test]
    fn chained_associated_data_put_the_tag_before_the_context() {
        let chain: [u8; 16] = core::array::from_fn(|at| u8::try_from(at).unwrap() | 0x80);
        let chained = AssociatedData::new(b"ab")
            .unwrap()
            .chained(EXPORT_LABEL, &chain);
        let mut expected = b"lethewis key export\x01\x02".to_vec();
        expected.extend_from_slice(&chain);
        expected.extend_from_slice(b"ab");
        assert_eq!(chained.bytes(), &expected[..]);
        let longest = [7; 255];
        let chained = AssociatedData::new(&longest)
            .unwrap()
            .chained(END_LABEL, &[0; 16]);
        assert_eq!(chained.bytes().len(), 19 + 2 + 16 + 255);
        assert!(chained.bytes().starts_with(b"lethewis export end\x01\xff"));
        assert!(chained.bytes().ends_with(&longest));
    }
}
