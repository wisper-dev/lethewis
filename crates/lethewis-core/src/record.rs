// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::key::{CAPACITY, KeyLength};
use crate::seal::{NONCE_LEN, TAG_LEN};

/// The size of a record's plaintext in bytes: a key set.
pub(crate) const PLAINTEXT_LEN: usize = 233;
/// The size of a record of a wrapped key set in bytes: the nonce, the encrypted plaintext and the
/// tag.
pub const RECORD_LEN: usize = 261;
/// The size of a lock record in bytes: the nonce, the number of the epoch and the record of a
/// stored key for wrapping, encrypted together, and the tag.
pub const LOCK_RECORD_LEN: usize = 297;
/// The size of what the outer layer of a lock record encrypts: the number of the epoch and the
/// record.
pub(crate) const LAYER_LEN: usize = 8 + RECORD_LEN;
/// The longest context a record can be bound to, in bytes.
pub(crate) const MAX_CONTEXT: usize = 255;
const AAD_LABEL: &[u8; 19] = b"lethewis key record";
/// The label, the version, the length of the context and the longest context.
const AAD_CAPACITY: usize = 276;
/// The label and the two bytes after it.
const AAD_HEAD: usize = AAD_LABEL.len() + 2;
/// The size of a key identifier in bytes.
pub(crate) const ID_LEN: usize = 16;
/// The version of the record format, in the associated data and in the plaintext.
pub(crate) const VERSION: u8 = 1;

const _: () = assert!(NONCE_LEN + PLAINTEXT_LEN + TAG_LEN == RECORD_LEN);
const _: () = assert!(NONCE_LEN + LAYER_LEN + TAG_LEN == LOCK_RECORD_LEN);
const _: () = assert!(AAD_LABEL.len() + 2 + MAX_CONTEXT == AAD_CAPACITY);

/// What a key may be used for: a class of operations together with its algorithm. It is given when
/// the key is loaded and never changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Purpose {
    /// A key of 32 or 64 bytes that wraps other keys. Its set holds this one key and never changes.
    /// A key from a secret, such as a password, wraps only stored keys for wrapping, which
    /// [`Slots::lock`](crate::Slots::lock) keeps under it; a stored key wraps only keys for external
    /// data. Leaves the library only wrapped, or as the words
    /// [`Slots::generate_words`](crate::Slots::generate_words) writes once.
    Wrap = 1,
    /// A key of 32 bytes for data an engine outside the library encrypts, such as a database. It
    /// wraps no key, and leaves the library only as a record wrapped by another key or through
    /// [`Slots::reveal32`](crate::Slots::reveal32) naming this purpose.
    ExternalData = 2,
}

impl Purpose {
    pub(crate) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Wrap),
            2 => Some(Self::ExternalData),
            _ => None,
        }
    }

    /// Whether a key of `length` may serve this purpose.
    pub(crate) const fn takes(self, length: KeyLength) -> bool {
        match self {
            Self::Wrap => true,
            Self::ExternalData => matches!(length, KeyLength::Bytes32),
        }
    }
}

/// Whether a key may be used. The value is the byte a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Status {
    /// It may be used.
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

/// The associated data of a record: a label of the format and its version, the length of the
/// context, and the context, which names the place the record belongs to.
pub(crate) struct AssociatedData {
    bytes: [u8; AAD_CAPACITY],
    len: usize,
}

impl AssociatedData {
    pub(crate) fn new(context: &[u8]) -> Result<Self, InvalidContext> {
        let context_len = u8::try_from(context.len())
            .ok()
            .filter(|&len| len != 0)
            .ok_or(InvalidContext)?;
        // The fixed part at fixed offsets: under the proofs a piece of a length known only at run
        // time costs many times its bytes.
        let mut bytes = [0; AAD_CAPACITY];
        let (label, rest) = bytes
            .split_first_chunk_mut::<{ AAD_LABEL.len() }>()
            .ok_or(InvalidContext)?;
        *label = *AAD_LABEL;
        let (head, rest) = rest.split_first_chunk_mut::<2>().ok_or(InvalidContext)?;
        *head = [VERSION, context_len];
        rest.get_mut(..context.len())
            .ok_or(InvalidContext)?
            .copy_from_slice(context);
        let len = context.len().checked_add(AAD_HEAD).ok_or(InvalidContext)?;
        Ok(Self { bytes, len })
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

/// A key buffer as four numbers of sixteen bytes each.
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
    use super::{AssociatedData, InvalidContext};

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
}
