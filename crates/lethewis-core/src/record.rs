// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::key::{CAPACITY, Key, KeyBytes, KeyLength};
use crate::seal::{NONCE_LEN, TAG_LEN};

/// The size of a record's plaintext in bytes.
pub(crate) const PLAINTEXT_LEN: usize = 92;
/// The size of a record of a wrapped key in bytes: the nonce, the encrypted plaintext and the tag.
pub const RECORD_LEN: usize = 120;
/// The longest context a record can be bound to, in bytes.
pub(crate) const MAX_CONTEXT: usize = 255;
const AAD_LABEL: &[u8; 19] = b"lethewis key record";
/// The label, the version, the length of the context and the longest context.
const AAD_CAPACITY: usize = 276;
/// The size of a key identifier in bytes.
pub(crate) const ID_LEN: usize = 16;
const VERSION: u8 = 1;

const _: () = assert!(4 + ID_LEN + 8 + CAPACITY == PLAINTEXT_LEN);
const _: () = assert!(NONCE_LEN + PLAINTEXT_LEN + TAG_LEN == RECORD_LEN);
const _: () = assert!(AAD_LABEL.len() + 2 + MAX_CONTEXT == AAD_CAPACITY);

/// What a key may be used for: a class of operations together with its algorithm. It is given when
/// the key is loaded and never changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Purpose {
    /// Wraps other keys. Leaves the library only as a record wrapped by another key.
    Wrap = 1,
}

impl Purpose {
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Wrap),
            _ => None,
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
    const fn from_byte(byte: u8) -> Option<Self> {
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

const fn length_from_byte(byte: u8) -> Option<KeyLength> {
    match byte {
        32 => Some(KeyLength::Bytes32),
        64 => Some(KeyLength::Bytes64),
        _ => None,
    }
}

/// What a record holds about a key besides the key and its length.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(any(test, kani), derive(PartialEq, Eq))]
pub(crate) struct Attributes {
    pub(crate) purpose: Purpose,
    pub(crate) status: Status,
    /// The identifier of the key the record is wrapped with.
    pub(crate) parent: [u8; ID_LEN],
    pub(crate) epoch: u64,
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
        let mut bytes = [0; AAD_CAPACITY];
        let mut len: usize = 0;
        for part in [&AAD_LABEL[..], &[VERSION, context_len], context] {
            let end = len.checked_add(part.len()).ok_or(InvalidContext)?;
            bytes
                .get_mut(len..end)
                .ok_or(InvalidContext)?
                .copy_from_slice(part);
            len = end;
        }
        Ok(Self { bytes, len })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.split_at(self.len.min(AAD_CAPACITY)).0
    }
}

/// Writes the plaintext of a record holding `key`. Every byte of `out` is written.
pub(crate) fn build(attributes: &Attributes, key: &Key, out: &mut [u8; PLAINTEXT_LEN]) {
    let Some((control, rest)) = out.split_first_chunk_mut::<4>() else {
        return;
    };
    *control = [
        VERSION,
        attributes.purpose as u8,
        length_to_byte(key.length()),
        attributes.status as u8,
    ];
    let Some((parent, rest)) = rest.split_first_chunk_mut::<ID_LEN>() else {
        return;
    };
    *parent = attributes.parent;
    let Some((epoch, rest)) = rest.split_first_chunk_mut::<8>() else {
        return;
    };
    *epoch = attributes.epoch.to_le_bytes();
    let Some((bytes, _)) = rest.split_first_chunk_mut::<CAPACITY>() else {
        return;
    };
    key.write_into(bytes);
}

/// Reads the plaintext of a record. Anything [`build`] cannot write is refused.
pub(crate) fn parse(bytes: &[u8; PLAINTEXT_LEN]) -> Result<(Attributes, KeyBytes<'_>), Malformed> {
    let Some((&[version, purpose, length, status], rest)) = bytes.split_first_chunk::<4>() else {
        return Err(Malformed);
    };
    let Some((parent, rest)) = rest.split_first_chunk::<ID_LEN>() else {
        return Err(Malformed);
    };
    let Some((epoch, rest)) = rest.split_first_chunk::<8>() else {
        return Err(Malformed);
    };
    let Some((key, rest)) = rest.split_first_chunk::<CAPACITY>() else {
        return Err(Malformed);
    };
    let ([], Some(purpose), Some(length), Some(status)) = (
        rest,
        Purpose::from_byte(purpose),
        length_from_byte(length),
        Status::from_byte(status),
    ) else {
        return Err(Malformed);
    };
    if version != VERSION || !tail_is_zero(key, length) {
        return Err(Malformed);
    }
    let attributes = Attributes {
        purpose,
        status,
        parent: *parent,
        epoch: u64::from_le_bytes(*epoch),
    };
    Ok((attributes, KeyBytes::new(key, length)))
}

/// Whether the bytes past the key's length are zero. Reads the whole tail, with no early exit.
fn tail_is_zero(key: &[u8; CAPACITY], length: KeyLength) -> bool {
    match length {
        KeyLength::Bytes32 => {
            key.iter()
                .skip(KeyLength::Bytes32.bytes())
                .fold(0, |seen, &byte| seen | byte)
                == 0
        }
        KeyLength::Bytes64 => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AssociatedData, Attributes, InvalidContext, Malformed, PLAINTEXT_LEN, Purpose, Status,
        build, parse,
    };
    use crate::key::{Key, KeyLength, tests::padded};

    /// A record holding a 32-byte key, written out from the layout by hand.
    #[rustfmt::skip]
    const SHORT: [u8; PLAINTEXT_LEN] = [
        0x01, 0x01, 0x20, 0x01, // version, purpose, length, status
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // parent
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // epoch 0x0102030405060708
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, // key
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tail
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// A record holding a 64-byte key, written out from the layout by hand.
    #[rustfmt::skip]
    const LONG: [u8; PLAINTEXT_LEN] = [
        0x01, 0x01, 0x40, 0x02, // version, purpose, length, status
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, // parent
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // epoch 0xfffffffffffffffe
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, // key
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];

    const SHORT_ATTRIBUTES: Attributes = Attributes {
        purpose: Purpose::Wrap,
        status: Status::Enabled,
        parent: [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ],
        epoch: 0x0102_0304_0506_0708,
    };

    const LONG_ATTRIBUTES: Attributes = Attributes {
        purpose: Purpose::Wrap,
        status: Status::Disabled,
        parent: [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ],
        epoch: 0xffff_ffff_ffff_fffe,
    };

    fn short_key() -> [u8; 32] {
        core::array::from_fn(|i| 0xa0_u8.wrapping_add(u8::try_from(i).unwrap()))
    }

    fn long_key() -> [u8; 64] {
        core::array::from_fn(|i| 0x40_u8.wrapping_add(u8::try_from(i).unwrap()))
    }

    /// The attributes and the loaded key, or the error.
    fn read(bytes: &[u8; PLAINTEXT_LEN]) -> Result<(Attributes, Key), Malformed> {
        parse(bytes).map(|(attributes, key_bytes)| {
            let mut key = Key::empty();
            key_bytes.load_into(&mut key);
            (attributes, key)
        })
    }

    #[test]
    fn a_short_key_is_written_as_the_layout_says() {
        let mut key = Key::empty();
        key.load32(&mut short_key());
        let mut out = [0x55; PLAINTEXT_LEN];
        build(&SHORT_ATTRIBUTES, &key, &mut out);
        assert_eq!(out, SHORT);
    }

    #[test]
    fn a_long_key_is_written_as_the_layout_says() {
        let mut key = Key::empty();
        key.load64(&mut long_key());
        let mut out = [0x55; PLAINTEXT_LEN];
        build(&LONG_ATTRIBUTES, &key, &mut out);
        assert_eq!(out, LONG);
    }

    #[test]
    fn a_short_key_is_read_as_the_layout_says() {
        let (attributes, key) = read(&SHORT).unwrap();
        assert_eq!(attributes, SHORT_ATTRIBUTES);
        assert_eq!(key.bytes(), &padded(&short_key()));
        assert_eq!(key.length(), KeyLength::Bytes32);
    }

    #[test]
    fn a_long_key_is_read_as_the_layout_says() {
        let (attributes, key) = read(&LONG).unwrap();
        assert_eq!(attributes, LONG_ATTRIBUTES);
        assert_eq!(key.bytes(), &long_key());
        assert_eq!(key.length(), KeyLength::Bytes64);
    }

    #[test]
    fn each_control_byte_accepts_only_its_values() {
        for (position, accepted) in [(0, &[1][..]), (1, &[1]), (2, &[32, 64]), (3, &[1, 2])] {
            for value in 0..=u8::MAX {
                let mut bytes = SHORT;
                bytes[position] = value;
                assert_eq!(
                    parse(&bytes).is_ok(),
                    accepted.contains(&value),
                    "byte {position}, value {value}"
                );
            }
        }
    }

    #[test]
    fn the_tail_of_a_short_key_accepts_only_zero() {
        for position in 60..PLAINTEXT_LEN {
            for value in 0..=u8::MAX {
                let mut bytes = SHORT;
                bytes[position] = value;
                assert_eq!(
                    parse(&bytes).is_ok(),
                    value == 0,
                    "byte {position}, value {value}"
                );
            }
        }
        let mut bytes = SHORT;
        bytes[60..].fill(0xff);
        assert_eq!(parse(&bytes).err(), Some(Malformed));
    }

    #[test]
    fn every_byte_lands_in_its_field() {
        for position in 0..PLAINTEXT_LEN {
            let mut bytes = SHORT;
            bytes[position] ^= 0xff;
            let mut attributes = SHORT_ATTRIBUTES;
            let mut key = padded(&short_key());
            let mut epoch = attributes.epoch.to_le_bytes();
            match position {
                0..4 | 60.. => {
                    assert_eq!(parse(&bytes).err(), Some(Malformed), "byte {position}");
                    continue;
                }
                4..20 => attributes.parent[position.wrapping_sub(4)] ^= 0xff,
                20..28 => epoch[position.wrapping_sub(20)] ^= 0xff,
                _ => key[position.wrapping_sub(28)] ^= 0xff,
            }
            attributes.epoch = u64::from_le_bytes(epoch);
            let (read_attributes, read_key) = read(&bytes).unwrap();
            assert_eq!(read_attributes, attributes, "byte {position}");
            assert_eq!(read_key.bytes(), &key, "byte {position}");
        }
    }

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
    fn building_overwrites_every_byte() {
        let mut key = Key::empty();
        key.load32(&mut short_key());
        for old in [0x00, 0xff] {
            let mut out = [old; PLAINTEXT_LEN];
            build(&SHORT_ATTRIBUTES, &key, &mut out);
            assert_eq!(out, SHORT);
        }
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs {
    use super::{Attributes, PLAINTEXT_LEN, Purpose, Status, build, parse};
    use crate::key::{Key, KeyLength};

    /// Whether `build` can write `bytes`, decided from the layout alone, not from `parse`.
    fn writable(bytes: &[u8; PLAINTEXT_LEN]) -> bool {
        let [version, purpose, length, status, ..] = *bytes;
        let short = length == 32;
        version == 1
            && purpose == 1
            && (short || length == 64)
            && (status == 1 || status == 2)
            && (!short || bytes.iter().skip(60).all(|&byte| byte == 0))
    }

    /// A key that has held other bytes before, to show that loading clears them.
    fn used_key() -> Key {
        let mut key = Key::empty();
        key.load64(&mut kani::any());
        key
    }

    /// For any 92 bytes, parsing succeeds exactly when the layout allows them, and never panics.
    #[kani::proof]
    #[kani::unwind(93)]
    fn parsing_accepts_exactly_what_building_can_write() {
        let bytes: [u8; PLAINTEXT_LEN] = kani::any();
        let accepted = parse(&bytes).is_ok();
        kani::assert(
            accepted == writable(&bytes),
            "parsing accepts exactly what the layout allows",
        );

        let [version, purpose, length, status, ..] = bytes;
        let others_valid = version == 1 && purpose == 1 && status == 1;
        kani::cover!(accepted && length == 32, "a short key is accepted");
        kani::cover!(accepted && length == 64, "a long key is accepted");
        kani::cover!(accepted && status == 2, "a disabled key is accepted");
        kani::cover!(
            !accepted && purpose == 1 && length == 64 && status == 1,
            "only the version is refused"
        );
        kani::cover!(
            !accepted && version == 1 && length == 64 && status == 1,
            "only the purpose is refused"
        );
        kani::cover!(
            !accepted && others_valid && length != 32 && length != 64,
            "only the length is refused"
        );
        kani::cover!(
            !accepted && version == 1 && purpose == 1 && length == 64,
            "only the status is refused"
        );
        kani::cover!(
            !accepted && others_valid && length == 32,
            "only the tail is refused"
        );
    }

    /// For any attributes and any key of either length, building puts every field where the layout
    /// says, and parsing gives back the same attributes and the same key. The offsets and values
    /// are written from the layout, independently of the builder and the parser.
    #[kani::proof]
    #[kani::unwind(93)]
    fn building_then_parsing_gives_back_the_record() {
        let attributes = Attributes {
            purpose: Purpose::Wrap,
            status: if kani::any() {
                Status::Enabled
            } else {
                Status::Disabled
            },
            parent: kani::any(),
            epoch: kani::any(),
        };
        let mut key = Key::empty();
        if kani::any() {
            key.load32(&mut kani::any());
        } else {
            key.load64(&mut kani::any());
        }
        let mut out: [u8; PLAINTEXT_LEN] = kani::any();
        build(&attributes, &key, &mut out);

        let length = if key.length() == KeyLength::Bytes32 {
            32
        } else {
            64
        };
        let status = if attributes.status == Status::Enabled {
            1
        } else {
            2
        };
        kani::assert(
            out[..4] == [1, 1, length, status],
            "the control bytes are written as the layout says",
        );
        kani::assert(
            out[4..20] == attributes.parent,
            "the parent is written at its offset",
        );
        kani::assert(
            out[20..28] == attributes.epoch.to_le_bytes(),
            "the epoch is written at its offset, least significant byte first",
        );
        kani::assert(
            out[28..] == key.bytes()[..],
            "the key is written at its offset, zero past its length",
        );

        let parsed = parse(&out);
        kani::assert(parsed.is_ok(), "what building writes parses");
        // Not an `if let`: its failing path, ruled out above, would be proof code no proof reaches.
        let _ = parsed.map(|(read_attributes, key_bytes)| {
            let mut read_key = used_key();
            key_bytes.load_into(&mut read_key);
            kani::assert(
                read_attributes == attributes,
                "parsing gives back the attributes",
            );
            kani::assert(
                read_key.bytes() == key.bytes() && read_key.length() == key.length(),
                "parsing gives back the key and its length",
            );
        });

        kani::cover!(key.length() == KeyLength::Bytes32, "a short key");
        kani::cover!(key.length() == KeyLength::Bytes64, "a long key");
        kani::cover!(attributes.status == Status::Disabled, "a disabled key");
        kani::cover!(attributes.epoch == u64::MAX, "the last epoch");
    }

    /// For any 92 bytes that parse, loading the key and building again gives the same bytes: a
    /// record has exactly one way to be written.
    #[kani::proof]
    #[kani::unwind(93)]
    fn a_parsed_record_builds_back_to_the_same_bytes() {
        let bytes: [u8; PLAINTEXT_LEN] = kani::any();
        let Ok((attributes, key_bytes)) = parse(&bytes) else {
            return;
        };
        let mut key = used_key();
        key_bytes.load_into(&mut key);
        let mut out: [u8; PLAINTEXT_LEN] = kani::any();
        build(&attributes, &key, &mut out);
        kani::assert(
            out == bytes,
            "a parsed record builds back to the same bytes",
        );

        kani::cover!(key.length() == KeyLength::Bytes32, "a short key");
        kani::cover!(key.length() == KeyLength::Bytes64, "a long key");
    }
}
