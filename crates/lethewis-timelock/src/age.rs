// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The age file of a lock: one tlock stanza, then a key of 16 bytes as the payload. Its MAC and
//! payload cipher are models under Kani.

use crate::Error;
use crate::decimal::{DIGITS, Decimal};
use crate::ibe::BODY_LEN;
#[cfg(not(kani))]
use crate::ibe::FILE_KEY_LEN;

/// The length of the payload nonce.
pub(crate) const NONCE_LEN: usize = 16;
/// The length of a locked key.
pub const LOCKED_KEY_LEN: usize = 16;
/// The length of the payload: the key, then its tag.
pub(crate) const PAYLOAD_LEN: usize = 32;
/// The length of the header MAC.
pub(crate) const MAC_LEN: usize = 32;
/// The length of a lock.
pub const LOCK_LEN: usize = 386;
/// The header through the three dashes: what the header MAC covers.
pub(crate) const COVERED: usize = 293;

/// The start of a lock, up to its round, which follows in nineteen digits.
const INTRO: &[u8; 31] = b"age-encryption.org/v1\n-> tlock ";
const ROUND_AT: usize = 31;
/// The fixed bytes after the round, and where each stands.
const SEPARATORS: [(usize, u8); 10] = [
    (50, b' '),
    (115, b'\n'),
    (180, b'\n'),
    (245, b'\n'),
    (289, b'\n'),
    (290, b'-'),
    (291, b'-'),
    (292, b'-'),
    (293, b' '),
    (337, b'\n'),
];
const HEX_AT: usize = 51;
const FIRST_LINE_AT: usize = 116;
const SECOND_LINE_AT: usize = 181;
const LAST_LINE_AT: usize = 246;
const MAC_AT: usize = 294;
const NONCE_AT: usize = 338;
const PAYLOAD_AT: usize = 354;
const HEX_LEN: usize = 64;
/// A full line of a stanza body in base64, and the bytes it stands for.
const LINE: usize = 64;
const LINE_BYTES: usize = 48;
/// The last line of a stanza body, and the MAC: 32 bytes in base64 without padding.
const LAST: usize = 43;
const LAST_BYTES: usize = 32;
/// Where the bytes of the last line start in a stanza body.
const LAST_FROM: usize = 96;

#[cfg(kani)]
pub(crate) use model::{mac, open, same_mac, seal};

/// A lock as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    bytes: [u8; LOCK_LEN],
}

impl Lock {
    /// The bytes of the lock: an age file that `tle` opens.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; LOCK_LEN] {
        &self.bytes
    }

    /// The bytes the header MAC covers.
    pub(crate) fn covered(&self) -> &[u8] {
        self.bytes.get(..COVERED).unwrap_or(&[])
    }

    /// Ends a lock [`header`] wrote with its MAC, nonce and payload.
    pub(crate) fn finish(
        &mut self,
        mac: &[u8; MAC_LEN],
        nonce: &[u8; NONCE_LEN],
        payload: &[u8; PAYLOAD_LEN],
    ) {
        put(&mut self.bytes, MAC_AT, &encode::<LAST_BYTES, LAST>(mac));
        put(&mut self.bytes, NONCE_AT, nonce);
        put(&mut self.bytes, PAYLOAD_AT, payload);
    }
}

/// What a lock holds, as read.
pub(crate) struct Parts {
    pub(crate) round: Decimal,
    pub(crate) body: [u8; BODY_LEN],
    pub(crate) mac: [u8; MAC_LEN],
    pub(crate) nonce: [u8; NONCE_LEN],
    pub(crate) payload: [u8; PAYLOAD_LEN],
}

/// Writes the header of a lock for `round` of the chain `chain_hash`, through the three dashes the
/// MAC covers, and the separators after them into a new lock.
pub(crate) fn header(round: &Decimal, chain_hash: &[u8; 32], body: &[u8; BODY_LEN]) -> Lock {
    let mut bytes = [0; LOCK_LEN];
    put(&mut bytes, 0, INTRO);
    put(&mut bytes, ROUND_AT, round.digits());
    for (at, byte) in SEPARATORS {
        put(&mut bytes, at, &[byte]);
    }
    put(&mut bytes, HEX_AT, &hex(chain_hash));
    let first = encode::<LINE_BYTES, LINE>(&part(body, 0));
    let second = encode::<LINE_BYTES, LINE>(&part(body, LINE_BYTES));
    let last = encode::<LAST_BYTES, LAST>(&part(body, LAST_FROM));
    put(&mut bytes, FIRST_LINE_AT, &first);
    put(&mut bytes, SECOND_LINE_AT, &second);
    put(&mut bytes, LAST_LINE_AT, &last);
    Lock { bytes }
}

fn put<const N: usize>(into: &mut [u8], at: usize, bytes: &[u8; N]) {
    if let Some(place) = into.get_mut(at..).and_then(<[u8]>::first_chunk_mut::<N>) {
        *place = *bytes;
    }
}

/// `M` bytes of `bytes` from `at` on.
fn part<const N: usize, const M: usize>(bytes: &[u8; N], at: usize) -> [u8; M] {
    bytes
        .get(at..)
        .and_then(<[u8]>::first_chunk::<M>)
        .copied()
        .unwrap_or([0; M])
}

/// Reads a lock of the chain `chain_hash`. Only the bytes [`header`] and [`Lock::finish`] write
/// from what is read are taken.
pub(crate) fn read(lock: &[u8], chain_hash: &[u8; 32]) -> Result<Parts, Error> {
    let lock: &[u8; LOCK_LEN] = lock.try_into().map_err(|_| Error::LockMalformed)?;
    let fixed = part::<LOCK_LEN, 31>(lock, 0) == *INTRO
        && SEPARATORS
            .iter()
            .all(|&(at, byte)| lock.get(at) == Some(&byte));
    let fields = (
        Decimal::read(&part::<LOCK_LEN, DIGITS>(lock, ROUND_AT)).filter(|_| fixed),
        from_hex(&part(lock, HEX_AT)),
        decode::<LINE, LINE_BYTES>(&part(lock, FIRST_LINE_AT)),
        decode::<LINE, LINE_BYTES>(&part(lock, SECOND_LINE_AT)),
        decode::<LAST, LAST_BYTES>(&part(lock, LAST_LINE_AT)),
        decode::<LAST, MAC_LEN>(&part(lock, MAC_AT)),
    );
    let (Some(round), Some(network), Some(first), Some(second), Some(last), Some(mac)) = fields
    else {
        return Err(Error::LockMalformed);
    };
    if network != *chain_hash {
        return Err(Error::OtherNetwork);
    }
    let mut body = [0; BODY_LEN];
    put(&mut body, 0, &first);
    put(&mut body, LINE_BYTES, &second);
    put(&mut body, LAST_FROM, &last);
    Ok(Parts {
        round,
        body,
        mac,
        nonce: part(lock, NONCE_AT),
        payload: part(lock, PAYLOAD_AT),
    })
}

fn hex(bytes: &[u8; 32]) -> [u8; HEX_LEN] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digit = |nibble: u8| DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
    let mut chars = [0; HEX_LEN];
    for (pair, byte) in chars.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
        *pair = [digit(byte.wrapping_shr(4)), digit(byte & 0x0f)];
    }
    chars
}

/// The bytes of lowercase hex `chars`.
fn from_hex(chars: &[u8; HEX_LEN]) -> Option<[u8; 32]> {
    let value = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(digit.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut bytes = [0; 32];
    for (byte, [high, low]) in bytes.iter_mut().zip(chars.as_chunks::<2>().0) {
        *byte = value(*high)?.wrapping_shl(4) | value(*low)?;
    }
    Some(bytes)
}

/// Base64 without padding, as age writes it, of a full line or of 32 bytes.
fn encode<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u8; M] {
    let mut chars = [0; M];
    let (groups, last) = bytes.as_chunks::<3>();
    let (fours, rest) = chars.as_chunks_mut::<4>();
    for (four, &[a, b, c]) in fours.iter_mut().zip(groups) {
        *four = encode_group(a, b, c);
    }
    if let (&[a, b], [w, x, y]) = (last, rest) {
        [*w, *x, *y, _] = encode_group(a, b, 0);
    }
    chars
}

/// The bytes `chars` stand for in base64 without padding, if [`encode`] writes them so: every
/// character in the alphabet, and no bit set past the last byte.
fn decode<const M: usize, const N: usize>(chars: &[u8; M]) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    let (fours, rest) = chars.as_chunks::<4>();
    let (groups, last) = bytes.as_chunks_mut::<3>();
    for (group, &[a, b, c, d]) in groups.iter_mut().zip(fours) {
        *group = decode_group(a, b, c, d)?;
    }
    if let (&[w, x, y], [a, b]) = (rest, last) {
        let [p, q, 0] = decode_group(w, x, y, b'A')? else {
            return None;
        };
        [*a, *b] = [p, q];
    }
    Some(bytes)
}

fn encode_group(a: u8, b: u8, c: u8) -> [u8; 4] {
    [
        to_char(a.wrapping_shr(2)),
        to_char((a & 0x03).wrapping_shl(4) | b.wrapping_shr(4)),
        to_char((b & 0x0f).wrapping_shl(2) | c.wrapping_shr(6)),
        to_char(c & 0x3f),
    ]
}

fn decode_group(a: u8, b: u8, c: u8, d: u8) -> Option<[u8; 3]> {
    let [a, b, c, d] = [from_char(a)?, from_char(b)?, from_char(c)?, from_char(d)?];
    Some([
        a.wrapping_shl(2) | b.wrapping_shr(4),
        b.wrapping_shl(4) | c.wrapping_shr(2),
        c.wrapping_shl(6) | d,
    ])
}

fn to_char(six: u8) -> u8 {
    match six {
        0..=25 => b'A'.wrapping_add(six),
        26..=51 => b'a'.wrapping_add(six.wrapping_sub(26)),
        52..=61 => b'0'.wrapping_add(six.wrapping_sub(52)),
        62 => b'+',
        _ => b'/',
    }
}

fn from_char(char: u8) -> Option<u8> {
    match char {
        b'A'..=b'Z' => Some(char.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(char.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(char.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The header MAC: HMAC-SHA-256 of `header` under HKDF-SHA-256 of the file key, info "header".
#[cfg(not(kani))]
pub(crate) fn mac(file_key: &[u8; FILE_KEY_LEN], header: &[u8]) -> [u8; MAC_LEN] {
    use hkdf::Hkdf;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use zeroize::Zeroize;

    #[cfg(test)]
    crate::timing::note();
    let mut key = [0; 32];
    let derived = Hkdf::<Sha256>::new(None, file_key).expand(b"header", &mut key);
    let mac = derived
        .ok()
        .and_then(|()| Hmac::<Sha256>::new_from_slice(&key).ok());
    key.zeroize();
    mac.map_or([0; MAC_LEN], |mac| {
        mac.chain_update(header).finalize().into_bytes().into()
    })
}

/// Compares two MACs in constant time.
#[cfg(not(kani))]
pub(crate) fn same_mac(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
    use ctutils::CtEq;

    a.ct_eq(b).to_bool()
}

/// Encrypts `key` as the payload: ChaCha20-Poly1305 under HKDF-SHA-256 of the file key, salt
/// `nonce`, info "payload", as the one and last chunk of the STREAM of age.
#[cfg(not(kani))]
pub(crate) fn seal(
    file_key: &[u8; FILE_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    key: &[u8; LOCKED_KEY_LEN],
    payload: &mut [u8; PAYLOAD_LEN],
) -> bool {
    use chacha20poly1305::aead::AeadInOut;

    #[cfg(test)]
    crate::timing::note();
    let (Some(cipher), Some((text, tag))) = (
        payload_cipher(file_key, nonce),
        payload.split_first_chunk_mut::<LOCKED_KEY_LEN>(),
    ) else {
        return false;
    };
    text.copy_from_slice(key);
    let sealed = cipher.encrypt_inout_detached(&LAST_CHUNK.into(), &[], text.as_mut_slice().into());
    sealed.map(|sealed| tag.copy_from_slice(&sealed)).is_ok()
}

/// Decrypts the payload `sealed` into `plain`, one byte shorter for each byte of the tag. A payload
/// that does not open leaves `plain` as it was, or zeros once the tag fails.
#[cfg(not(kani))]
pub(crate) fn open_payload(
    file_key: &[u8; FILE_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
    plain: &mut [u8],
) -> bool {
    use chacha20poly1305::aead::AeadInOut;
    use zeroize::Zeroize;

    #[cfg(test)]
    crate::timing::note();
    let Some(cipher) = payload_cipher(file_key, nonce) else {
        return false;
    };
    let Some((text, tag)) = sealed.split_at_checked(plain.len()) else {
        return false;
    };
    let Ok(tag) = <&[u8; 16]>::try_from(tag) else {
        return false;
    };
    plain.copy_from_slice(text);
    let opened = cipher
        .decrypt_inout_detached(&LAST_CHUNK.into(), &[], plain.into(), tag.into())
        .is_ok();
    if !opened {
        plain.zeroize();
    }
    opened
}

/// Decrypts the payload of a lock into `key`, which changes only when the tag checks out.
#[cfg(not(kani))]
pub(crate) fn open(
    file_key: &[u8; FILE_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    payload: &[u8; PAYLOAD_LEN],
    key: &mut [u8; LOCKED_KEY_LEN],
) -> bool {
    use zeroize::Zeroize;

    let mut plain = [0; LOCKED_KEY_LEN];
    let opened = open_payload(file_key, nonce, payload, &mut plain);
    if opened {
        *key = plain;
    }
    plain.zeroize();
    opened
}

/// The STREAM nonce of the first chunk when it is the last: counter 0, then the flag 1.
#[cfg(not(kani))]
const LAST_CHUNK: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[cfg(not(kani))]
fn payload_cipher(
    file_key: &[u8; FILE_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Option<chacha20poly1305::ChaCha20Poly1305> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroize;

    let mut key = [0; 32];
    let derived = Hkdf::<Sha256>::new(Some(nonce), file_key).expand(b"payload", &mut key);
    let cipher = derived.ok().map(|()| ChaCha20Poly1305::new(&key.into()));
    key.zeroize();
    cipher
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{
        COVERED, HEX_AT, HEX_LEN, LOCKED_KEY_LEN, Lock, MAC_LEN, NONCE_LEN, PAYLOAD_LEN, header,
        mac, open, open_payload, read, seal,
    };
    use crate::Error;
    use crate::decimal::{Decimal, LIMIT};
    use crate::ibe::{BODY_LEN, FILE_KEY_LEN, unwrap};
    use crate::network::QUICKNET;
    use crate::vectors::{
        AgeParts, REFERENCE_LOCK, REFERENCE_SIGNATURE, TESTNET, TESTNET_LOCK, TESTNET_SIGNATURE,
        TESTNET_TEXT_SHA256, age_parts, dearmor, unhex,
    };

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn counting<const N: usize>(from: u8) -> [u8; N] {
        core::array::from_fn(|at| from.wrapping_add(u8::try_from(at % 256).unwrap()))
    }

    fn written(round: u64) -> Lock {
        let round = Decimal::of(round).unwrap();
        let mut lock = header(&round, &QUICKNET.chain_hash, &counting(1));
        lock.finish(&counting(2), &counting(3), &counting(4));
        lock
    }

    #[test]
    fn a_lock_is_read_as_written() {
        for round in [1, 9, 10, 746_511, 33_512_211, LIMIT - 1] {
            let lock = written(round);
            let parts = read(lock.as_bytes(), &QUICKNET.chain_hash).unwrap();
            assert_eq!(parts.round.value(), round);
            assert_eq!(lock.as_bytes()[..COVERED], *lock.covered());
            assert!(lock.covered().ends_with(b"\n---"));
            assert_eq!(parts.body, counting::<BODY_LEN>(1));
            assert_eq!(parts.mac, counting::<MAC_LEN>(2));
            assert_eq!(parts.nonce, counting::<NONCE_LEN>(3));
            assert_eq!(parts.payload, counting::<PAYLOAD_LEN>(4));
        }
    }

    /// The header of the reference, its round in nineteen digits, and its MAC line come out byte
    /// for byte.
    #[test]
    fn the_layout_of_the_reference_is_written() {
        let reference = dearmor(&REFERENCE_LOCK);
        let round_at = reference
            .windows(13)
            .position(|window| window == b"tlock 746511 ")
            .unwrap()
            + 6;
        let file = [
            &reference[..round_at],
            b"0000000000000",
            &reference[round_at..],
        ]
        .concat();
        let AgeParts {
            header: covered,
            body,
            mac,
            nonce,
            ..
        } = age_parts(&file);
        let body = body.try_into().unwrap();
        let round = Decimal::of(746_511).unwrap();
        let mut lock = header(&round, &QUICKNET.chain_hash, &body);
        assert_eq!(lock.covered(), covered);
        lock.finish(&mac.try_into().unwrap(), &nonce, &[0; PAYLOAD_LEN]);
        assert_eq!(
            lock.as_bytes()[..covered.len() + 61],
            file[..covered.len() + 61]
        );
    }

    #[test]
    fn only_what_is_written_is_read() {
        let lock = written(746_511).as_bytes().to_vec();
        let at = |text: &[u8]| {
            lock.windows(text.len())
                .position(|window| window == text)
                .unwrap()
        };
        let replaced = |from: &[u8], to: &[u8]| {
            let start = at(from);
            [&lock[..start], to, &lock[start + from.len()..]].concat()
        };
        let mut changes: Vec<Vec<u8>> = [
            (
                &b"tlock 0000000000000746511 "[..],
                &b"tlock 000000000000+746511 "[..],
            ),
            (b"tlock 0000000000000746511 ", b"tlock  000000000000746511 "),
            (b"tlock 0000000000000746511 ", b"tlock 746511 "),
            (
                b"tlock 0000000000000746511 ",
                b"tlock 00000000000000746511 ",
            ),
            (b"v1\n", b"v2\n"),
            (b"v1\n", b"v1\r\n"),
            (b"tlock", b"tlocks"),
            (b"\n---", b" ---"),
            (b"\n--- ", b"\n---\t"),
            (b"\n--- ", b"\n---  "),
        ]
        .iter()
        .map(|(from, to)| replaced(from, to))
        .collect();
        let dashes = at(b"\n---");
        let mac_end = dashes + 48;
        assert_eq!(lock[mac_end], b'\n');
        // The last characters of the body and of the MAC carry two bits past their last byte.
        for place in [dashes - 1, mac_end - 1] {
            let six = ALPHABET
                .iter()
                .position(|&char| char == lock[place])
                .unwrap();
            assert_eq!(six % 4, 0);
            let past = (1..4).map(|bits| ALPHABET[six + bits]);
            for byte in past.chain(*b"=\n") {
                let mut edited = lock.clone();
                edited[place] = byte;
                changes.push(edited);
            }
        }
        let mut capitals = lock.clone();
        capitals[HEX_AT..HEX_AT + HEX_LEN].make_ascii_uppercase();
        assert_ne!(capitals, lock);
        changes.push(capitals);
        let mut lines_joined = lock.clone();
        assert_eq!(lines_joined[dashes - 44], b'\n');
        lines_joined[dashes - 44] = b' ';
        changes.push(lines_joined);
        let mut longer = lock.clone();
        longer.push(0);
        changes.push(longer);
        changes.push(lock[..lock.len() - 1].to_vec());
        changes.push(Vec::new());
        for changed in changes {
            assert_eq!(
                read(&changed, &QUICKNET.chain_hash).err(),
                Some(Error::LockMalformed),
                "{}",
                std::string::String::from_utf8_lossy(&changed)
            );
        }
        assert_eq!(
            read(&lock, &TESTNET.chain_hash).err(),
            Some(Error::OtherNetwork)
        );
        assert!(read(&lock, &QUICKNET.chain_hash).is_ok());
    }

    #[test]
    fn payloads_the_reference_encrypted_are_decrypted() {
        for (armor, signature, text) in [
            (&REFERENCE_LOCK[..], REFERENCE_SIGNATURE, None),
            (
                &TESTNET_LOCK[..],
                TESTNET_SIGNATURE,
                Some(TESTNET_TEXT_SHA256),
            ),
        ] {
            let AgeParts {
                body,
                nonce,
                payload,
                ..
            } = age_parts(&dearmor(armor));
            let mut file_key = [0; FILE_KEY_LEN];
            assert!(unwrap(
                &unhex(signature),
                &body.try_into().unwrap(),
                &mut file_key
            ));
            let mut plain = std::vec![0; payload.len() - 16];
            assert!(open_payload(&file_key, &nonce, &payload, &mut plain));
            match text {
                None => assert_eq!(plain, b"hello world\n"),
                Some(digest) => {
                    use sha2::{Digest, Sha256};
                    assert_eq!(Sha256::digest(&plain)[..], unhex::<32>(digest)[..]);
                }
            }
        }
    }

    #[test]
    fn a_payload_opens_only_as_sealed() {
        let (file_key, nonce, key) = (counting(5), counting(6), counting::<LOCKED_KEY_LEN>(7));
        let mut payload = [0; PAYLOAD_LEN];
        assert!(seal(&file_key, &nonce, &key, &mut payload));
        let mut opened = [0; LOCKED_KEY_LEN];
        assert!(open(&file_key, &nonce, &payload, &mut opened));
        assert_eq!(opened, key);
        for at in 0..PAYLOAD_LEN {
            let mut changed = payload;
            changed[at] ^= 1;
            let mut opened = [0xa5; LOCKED_KEY_LEN];
            assert!(!open(&file_key, &nonce, &changed, &mut opened), "byte {at}");
            assert_eq!(opened, [0xa5; LOCKED_KEY_LEN]);
        }
        let mut opened = [0xa5; LOCKED_KEY_LEN];
        assert!(!open(&counting(8), &nonce, &payload, &mut opened));
        assert!(!open(&file_key, &counting(8), &payload, &mut opened));
        assert_eq!(opened, [0xa5; LOCKED_KEY_LEN]);
        assert_ne!(mac(&file_key, b"header"), mac(&counting(8), b"header"));
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

/// What stands in for the MAC and the payload cipher under Kani: they answer at will and keep
/// what they were given.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::{LOCKED_KEY_LEN, MAC_LEN, NONCE_LEN, PAYLOAD_LEN};
    use crate::curve::model::{keep, kept};
    use crate::ibe::FILE_KEY_LEN;

    static MACS: AtomicU64 = AtomicU64::new(0);
    static MAC_FILE_KEY: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static MADE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    static SEALS: AtomicU64 = AtomicU64::new(0);
    static OPENS: AtomicU64 = AtomicU64::new(0);
    static FILE_KEY: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static NONCE: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static KEY: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static PAYLOAD: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

    /// What the last MAC was made under and was.
    pub(crate) struct Mac {
        pub(crate) times: u64,
        pub(crate) file_key: [u8; FILE_KEY_LEN],
        pub(crate) mac: [u8; MAC_LEN],
    }

    /// What the payload cipher was last given and wrote: a key sealed or opened.
    pub(crate) struct Payload {
        pub(crate) seals: u64,
        pub(crate) opens: u64,
        pub(crate) file_key: [u8; FILE_KEY_LEN],
        pub(crate) nonce: [u8; NONCE_LEN],
        pub(crate) key: [u8; LOCKED_KEY_LEN],
        pub(crate) payload: [u8; PAYLOAD_LEN],
    }

    pub(crate) fn mac(file_key: &[u8; FILE_KEY_LEN], _header: &[u8]) -> [u8; MAC_LEN] {
        let mac: [u8; MAC_LEN] = kani::any();
        count(&MACS);
        keep(&MAC_FILE_KEY, file_key);
        keep(&MADE, &mac);
        mac
    }

    pub(crate) fn same_mac(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
        a == b
    }

    pub(crate) fn seal(
        file_key: &[u8; FILE_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        key: &[u8; LOCKED_KEY_LEN],
        payload: &mut [u8; PAYLOAD_LEN],
    ) -> bool {
        *payload = kani::any();
        count(&SEALS);
        keep_payload(file_key, nonce, key, payload);
        kani::any()
    }

    pub(crate) fn open(
        file_key: &[u8; FILE_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        payload: &[u8; PAYLOAD_LEN],
        key: &mut [u8; LOCKED_KEY_LEN],
    ) -> bool {
        let answer = kani::any();
        if answer {
            *key = kani::any();
        }
        count(&OPENS);
        keep_payload(file_key, nonce, key, payload);
        answer
    }

    pub(crate) fn made() -> Mac {
        Mac {
            times: MACS.load(Ordering::Relaxed),
            file_key: kept(&MAC_FILE_KEY),
            mac: kept(&MADE),
        }
    }

    pub(crate) fn payload() -> Payload {
        Payload {
            seals: SEALS.load(Ordering::Relaxed),
            opens: OPENS.load(Ordering::Relaxed),
            file_key: kept(&FILE_KEY),
            nonce: kept(&NONCE),
            key: kept(&KEY),
            payload: kept(&PAYLOAD),
        }
    }

    fn keep_payload(
        file_key: &[u8; FILE_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        key: &[u8; LOCKED_KEY_LEN],
        payload: &[u8; PAYLOAD_LEN],
    ) {
        keep(&FILE_KEY, file_key);
        keep(&NONCE, nonce);
        keep(&KEY, key);
        keep(&PAYLOAD, payload);
    }

    fn count(times: &AtomicU64) {
        times.store(
            times.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Relaxed,
        );
    }
}
