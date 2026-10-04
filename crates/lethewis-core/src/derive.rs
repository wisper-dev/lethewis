// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use hkdf::Hkdf;
use sha2::Sha256;

use crate::key::{Key, KeyLength};
use crate::record::{Purpose, length_to_byte};

/// The salt of every derivation.
const SALT: &[u8] = b"lethewis derivation salt v1";
/// The first bytes of every label.
const PREFIX: &[u8; 8] = b"lethewis";
const VERSION: u8 = 1;
/// Prefix (8), version, purpose, key length, output length (2), name length, and a name of up to
/// 16 bytes.
const LABEL_CAPACITY: usize = 30;

/// What a derived value is for. Each branch has a name of its own in the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Branch {
    /// The identifier of a key.
    KeyId,
    /// The key that encrypts the records a wrapping key wraps.
    WrapKey,
}

impl Branch {
    const fn name(self) -> &'static [u8] {
        match self {
            Self::KeyId => b"key id",
            Self::WrapKey => b"wrap key",
        }
    }
}

/// The derivation could not run: the output asked for is longer than HKDF-SHA-256 gives, 255
/// blocks of 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerivationFailed;

/// Fills `out` with the value of `branch` derived from `key`, which serves `purpose`. The key goes
/// through HKDF-Extract with a fixed salt, and HKDF-Expand takes the label.
pub(crate) fn derive(
    key: &Key,
    purpose: Purpose,
    branch: Branch,
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    let (label, used) = label(purpose, key.length(), branch, out.len())?;
    let info = label.get(..used).ok_or(DerivationFailed)?;
    let material = key.material().ok_or(DerivationFailed)?;
    Hkdf::<Sha256>::new(Some(SALT), material)
        .expand(info, out)
        .map_err(|_| DerivationFailed)
}

/// The label of one derivation, and how many of its bytes are used. Every field but the name has a
/// fixed width, and the name, which comes last, is preceded by its length, so two different
/// derivations never share a label.
fn label(
    purpose: Purpose,
    length: KeyLength,
    branch: Branch,
    out_len: usize,
) -> Result<([u8; LABEL_CAPACITY], usize), DerivationFailed> {
    let out_len = u16::try_from(out_len).map_err(|_| DerivationFailed)?;
    let name = branch.name();
    let name_len = u8::try_from(name.len()).map_err(|_| DerivationFailed)?;
    let fixed = [VERSION, purpose as u8, length_to_byte(length)];
    let mut label = [0; LABEL_CAPACITY];
    let mut used: usize = 0;
    for part in [
        &PREFIX[..],
        &fixed,
        &out_len.to_le_bytes(),
        &[name_len],
        name,
    ] {
        let end = used.checked_add(part.len()).ok_or(DerivationFailed)?;
        label
            .get_mut(used..end)
            .ok_or(DerivationFailed)?
            .copy_from_slice(part);
        used = end;
    }
    Ok((label, used))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::{Branch, DerivationFailed, derive, label};
    use crate::key::{Key, KeyLength};
    use crate::record::Purpose;

    /// Input key material, salt, info, and the expected output in hexadecimal.
    type Case<'a> = (&'a [u8], Option<&'a [u8]>, &'a [u8], &'a str);

    /// RFC 5869, appendix A, test cases 1 to 3: the primitive under the wrapper.
    #[test]
    fn hkdf_sha256_matches_rfc_5869() {
        let ikm22 = [0x0b; 22];
        let salt13: [u8; 13] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let info10: [u8; 10] =
            core::array::from_fn(|i| 0xf0_u8.wrapping_add(u8::try_from(i).unwrap()));
        let ikm80: [u8; 80] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let salt80: [u8; 80] =
            core::array::from_fn(|i| 0x60_u8.wrapping_add(u8::try_from(i).unwrap()));
        let info80: [u8; 80] =
            core::array::from_fn(|i| 0xb0_u8.wrapping_add(u8::try_from(i).unwrap()));
        let cases: [Case<'_>; 3] = [
            (
                &ikm22,
                Some(&salt13),
                &info10,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                &ikm80,
                Some(&salt80),
                &info80,
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac78272\
                 71cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f\
                 1d87",
            ),
            (
                &ikm22,
                Some(&[]),
                &[],
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, expected) in cases {
            let mut okm = [0; 82];
            let okm = &mut okm[..expected.len().checked_div(2).unwrap()];
            Hkdf::<Sha256>::new(salt, ikm).expand(info, okm).unwrap();
            assert_eq!(hex(okm), expected);
        }
    }

    #[test]
    fn the_label_is_laid_out_as_documented() {
        let (bytes, used) = label(Purpose::Wrap, KeyLength::Bytes32, Branch::KeyId, 16).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 1, 32, 16, 0, 6]);
        expected.extend_from_slice(b"key id");
        assert_eq!(&bytes[..used], &expected[..]);

        let (bytes, used) = label(Purpose::Wrap, KeyLength::Bytes64, Branch::WrapKey, 32).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 1, 64, 32, 0, 8]);
        expected.extend_from_slice(b"wrap key");
        assert_eq!(&bytes[..used], &expected[..]);
    }

    /// Keys of both lengths whose bytes are all different: 0, 1, 2, ...
    fn counted_key(length: KeyLength) -> Key {
        let mut key = Key::empty();
        if length == KeyLength::Bytes32 {
            key.load32(&mut core::array::from_fn(|i| u8::try_from(i).unwrap()));
        } else {
            key.load64(&mut core::array::from_fn(|i| u8::try_from(i).unwrap()));
        }
        key
    }

    /// The wrapper against HKDF called directly with the salt and the label written out by hand,
    /// for both key lengths: the whole key goes in, and the label states its length.
    #[test]
    fn derivation_is_hkdf_with_the_salt_and_the_label() {
        for (length, length_byte) in [(KeyLength::Bytes32, 32_u8), (KeyLength::Bytes64, 64)] {
            let key = counted_key(length);
            let mut ours = [0; 16];
            derive(&key, Purpose::Wrap, Branch::KeyId, &mut ours).unwrap();

            let ikm: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
            let ikm = &ikm[..usize::from(length_byte)];
            let mut info = b"lethewis".to_vec();
            info.extend_from_slice(&[1, 1, length_byte, 16, 0, 6]);
            info.extend_from_slice(b"key id");
            let mut direct = [0; 16];
            Hkdf::<Sha256>::new(Some(b"lethewis derivation salt v1"), ikm)
                .expand(&info, &mut direct)
                .unwrap();
            assert_eq!(ours, direct, "{length:?}");
        }
    }

    /// Outputs computed by an independent implementation of HKDF-SHA-256 from the documented salt
    /// and label: they fix the derivation for every key already written.
    #[test]
    fn derivations_match_known_answers() {
        let cases = [
            (
                KeyLength::Bytes32,
                Branch::KeyId,
                "588cab681d064e3003f3d416fb3bdaeb",
            ),
            (
                KeyLength::Bytes32,
                Branch::WrapKey,
                "b888ad072bde93503369146e95a5c4205a7ceff3f8063c2b4f3b6ab61abbb8cb",
            ),
            (
                KeyLength::Bytes64,
                Branch::KeyId,
                "83d471771a447746682fcf57c3e7b7e2",
            ),
            (
                KeyLength::Bytes64,
                Branch::WrapKey,
                "36a276730fac754e12ca4c3b3a6cfdf685d2429d5347438ee3020107dfa668f2",
            ),
        ];
        for (length, branch, expected) in cases {
            let mut out = [0; 32];
            let out = &mut out[..expected.len().checked_div(2).unwrap()];
            derive(&counted_key(length), Purpose::Wrap, branch, out).unwrap();
            assert_eq!(hex(out), expected, "{length:?} {branch:?}");
        }
    }

    #[test]
    fn branches_and_output_lengths_give_unrelated_values() {
        let mut key = Key::empty();
        key.load32(&mut [7; 32]);
        let mut id = [0; 32];
        let mut wrap = [0; 32];
        let mut short = [0; 16];
        derive(&key, Purpose::Wrap, Branch::KeyId, &mut id).unwrap();
        derive(&key, Purpose::Wrap, Branch::WrapKey, &mut wrap).unwrap();
        derive(&key, Purpose::Wrap, Branch::KeyId, &mut short).unwrap();
        assert_ne!(id, wrap);
        assert_ne!(id[..16], short);
    }

    /// The label states the key length, and Extract takes the key as a message rather than as an
    /// HMAC key, which would pad a short key with zeros: either keeps a key and its zero-padded long
    /// form apart.
    #[test]
    fn a_short_key_and_its_zero_padded_long_form_differ() {
        let mut short = Key::empty();
        short.load32(&mut [7; 32]);
        let mut padded = [0; 64];
        padded[..32].fill(7);
        let mut long = Key::empty();
        long.load64(&mut padded);
        let mut from_short = [0; 16];
        let mut from_long = [0; 16];
        derive(&short, Purpose::Wrap, Branch::KeyId, &mut from_short).unwrap();
        derive(&long, Purpose::Wrap, Branch::KeyId, &mut from_long).unwrap();
        assert_ne!(from_short, from_long);
    }

    #[test]
    fn every_branch_has_a_label() {
        for branch in [Branch::KeyId, Branch::WrapKey] {
            let (_, used) = label(Purpose::Wrap, KeyLength::Bytes64, branch, 32).unwrap();
            assert_eq!(used, 14 + branch.name().len());
        }
    }

    #[test]
    fn a_label_states_any_output_length_of_two_bytes() {
        assert!(label(Purpose::Wrap, KeyLength::Bytes32, Branch::KeyId, 65_535).is_ok());
        assert!(label(Purpose::Wrap, KeyLength::Bytes32, Branch::KeyId, 65_536).is_err());
    }

    #[test]
    fn an_output_longer_than_hkdf_gives_is_refused() {
        let key = counted_key(KeyLength::Bytes32);
        assert!(derive(&key, Purpose::Wrap, Branch::KeyId, &mut [0; 8160]).is_ok());
        let mut out = [9; 8161];
        assert_eq!(
            derive(&key, Purpose::Wrap, Branch::KeyId, &mut out),
            Err(DerivationFailed)
        );
        assert!(out.iter().all(|&byte| byte == 9));
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").unwrap();
            text
        })
    }
}

#[cfg(kani)]
mod proofs {
    use super::{Branch, label};
    use crate::key::KeyLength;
    use crate::record::Purpose;

    fn any_length() -> KeyLength {
        if kani::any() {
            KeyLength::Bytes32
        } else {
            KeyLength::Bytes64
        }
    }

    fn any_branch() -> Branch {
        if kani::any() {
            Branch::KeyId
        } else {
            Branch::WrapKey
        }
    }

    /// Two derivations that differ in anything the label states never share a label.
    #[kani::proof]
    #[kani::unwind(32)]
    fn different_derivations_have_different_labels() {
        let (length_a, branch_a, out_a): (KeyLength, Branch, u16) =
            (any_length(), any_branch(), kani::any());
        let (length_b, branch_b, out_b): (KeyLength, Branch, u16) =
            (any_length(), any_branch(), kani::any());
        let a = label(Purpose::Wrap, length_a, branch_a, usize::from(out_a));
        let b = label(Purpose::Wrap, length_b, branch_b, usize::from(out_b));
        kani::assert(
            a.is_ok() && b.is_ok(),
            "a label of an output length that fits in two bytes is always built",
        );
        if let (Ok((bytes_a, used_a)), Ok((bytes_b, used_b))) = (a, b)
            && (length_a, branch_a, out_a) != (length_b, branch_b, out_b)
        {
            kani::assert(
                used_a != used_b || bytes_a[..used_a] != bytes_b[..used_b],
                "different derivations have different labels",
            );
        }
        kani::cover!(branch_a != branch_b, "two branches");
        kani::cover!(
            length_a != length_b && branch_a == branch_b,
            "two key lengths"
        );
        kani::cover!(
            out_a != out_b && length_a == length_b && branch_a == branch_b,
            "two output lengths"
        );
    }
}
