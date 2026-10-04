// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use crate::entropy::{Entropy, EntropyError};

/// The size of the buffer behind every key, in bytes: the longest key a slot holds.
pub(crate) const CAPACITY: usize = 64;

/// How long a key is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyLength {
    /// 32 bytes.
    Bytes32,
    /// 64 bytes.
    Bytes64,
}

impl KeyLength {
    /// The length in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bytes32 => 32,
            Self::Bytes64 => 64,
        }
    }
}

/// Key material in a fixed buffer. It cannot be copied, cloned, compared or printed, and it is
/// wiped when dropped. It lives in a slot and is never moved out of it. The bytes past its length
/// are always zero.
pub(crate) struct Key {
    bytes: [u8; CAPACITY],
    length: KeyLength,
}

impl Key {
    pub(crate) const fn empty() -> Self {
        Self {
            bytes: [0; CAPACITY],
            length: KeyLength::Bytes32,
        }
    }

    /// Takes the bytes of `source` and wipes `source`.
    pub(crate) fn load32(&mut self, source: &mut [u8; 32]) {
        self.wipe();
        if let Some((head, _)) = self.bytes.split_first_chunk_mut::<32>() {
            head.copy_from_slice(source.as_slice());
        }
        self.length = KeyLength::Bytes32;
        wipe(source);
    }

    /// Takes the bytes of `source` and wipes `source`.
    pub(crate) fn load64(&mut self, source: &mut [u8; 64]) {
        self.bytes.copy_from_slice(source.as_slice());
        self.length = KeyLength::Bytes64;
        wipe(source);
    }

    /// Fills the key with `length` random bytes, asking `entropy` once. On failure the key is
    /// wiped, and so it is if `entropy` panics.
    pub(crate) fn fill(
        &mut self,
        length: KeyLength,
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<(), EntropyError> {
        self.wipe();
        let mut guard = WipeUnlessKept {
            key: self,
            keep: false,
        };
        let filled = match length {
            KeyLength::Bytes32 => guard
                .key
                .bytes
                .split_first_chunk_mut::<32>()
                .map_or(Err(EntropyError), |(head, _)| entropy.fill(head)),
            KeyLength::Bytes64 => entropy.fill(&mut guard.key.bytes),
        };
        if filled.is_ok() {
            guard.key.length = length;
            guard.keep = true;
        }
        filled
    }

    pub(crate) fn wipe(&mut self) {
        wipe(&mut self.bytes);
        self.length = KeyLength::Bytes32;
    }

    #[cfg(any(test, kani))]
    pub(crate) const fn bytes(&self) -> &[u8; CAPACITY] {
        &self.bytes
    }
}

#[cfg_attr(not(test), expect(dead_code))]
impl Key {
    pub(crate) const fn length(&self) -> KeyLength {
        self.length
    }

    /// Writes the key into `dest`, followed by zeros up to the capacity.
    pub(crate) fn write_into(&self, dest: &mut [u8; CAPACITY]) {
        dest.copy_from_slice(&self.bytes);
    }

    /// The key itself: as many bytes as its length.
    pub(crate) fn material(&self) -> Option<&[u8]> {
        self.bytes
            .split_at_checked(self.length.bytes())
            .map(|(key, _)| key)
    }
}

/// Key bytes borrowed from a buffer, with the length they hold. They can only be loaded into a
/// [`Key`], and loading leaves the buffer as it is.
#[cfg_attr(not(any(test, kani)), expect(dead_code))]
pub(crate) struct KeyBytes<'a> {
    bytes: &'a [u8; CAPACITY],
    length: KeyLength,
}

#[cfg_attr(not(any(test, kani)), expect(dead_code))]
impl<'a> KeyBytes<'a> {
    pub(crate) const fn new(bytes: &'a [u8; CAPACITY], length: KeyLength) -> Self {
        Self { bytes, length }
    }

    /// Loads as many of the bytes as the length into `key`; the rest of `key` is zero.
    pub(crate) fn load_into(self, key: &mut Key) {
        key.wipe();
        match self.length {
            KeyLength::Bytes32 => {
                if let (Some((head, _)), Some((from, _))) = (
                    key.bytes.split_first_chunk_mut::<32>(),
                    self.bytes.split_first_chunk::<32>(),
                ) {
                    head.copy_from_slice(from);
                }
            }
            KeyLength::Bytes64 => key.bytes.copy_from_slice(self.bytes),
        }
        key.length = self.length;
    }
}

/// Wipes the key when dropped unless told to keep it, so that the wipe also runs when a source of
/// random bytes panics halfway through.
struct WipeUnlessKept<'k> {
    key: &'k mut Key,
    keep: bool,
}

impl Drop for WipeUnlessKept<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.key.wipe();
        }
    }
}

fn wipe<const N: usize>(bytes: &mut [u8; N]) {
    #[cfg(not(kani))]
    zeroize::Zeroize::zeroize(bytes);
    // zeroize ends in inline assembly, which Kani cannot model. The proofs see plain stores; the
    // tests run the real zeroize.
    #[cfg(kani)]
    {
        *bytes = [0; N];
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use core::{fmt, hash::Hash};
    use std::format;

    use super::{CAPACITY, Entropy, EntropyError, Key, KeyBytes, KeyLength};

    assert_not_impl!(Key: Clone, PartialEq, Hash, Default, fmt::Display);
    assert_not_impl!(KeyBytes<'static>: Clone, PartialEq, Hash, fmt::Debug, fmt::Display);

    /// Writes 1, 2, 3, ... into every buffer it fills.
    pub(crate) struct Counting;

    impl Entropy for Counting {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            let mut next: u8 = 0;
            for byte in dest.iter_mut() {
                next = next.wrapping_add(1);
                *byte = next;
            }
            Ok(())
        }
    }

    /// Counts its calls, and remembers how many bytes it was last asked for and where.
    #[derive(Default)]
    pub(crate) struct Recording {
        pub(crate) calls: usize,
        pub(crate) asked: usize,
        pub(crate) at: usize,
    }

    impl Entropy for Recording {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            self.calls = self.calls.wrapping_add(1);
            self.asked = dest.len();
            self.at = dest.as_ptr().addr();
            dest.fill(3);
            Ok(())
        }
    }

    /// Writes some bytes, then panics.
    pub(crate) struct Panicking;

    impl Entropy for Panicking {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.fill(9);
            panic!("the source broke halfway")
        }
    }

    /// Writes some bytes, then fails.
    pub(crate) struct Failing;

    impl Entropy for Failing {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.fill(9);
            Err(EntropyError)
        }
    }

    /// `prefix` followed by zeros, as a key buffer holds it.
    pub(crate) fn padded(prefix: &[u8]) -> [u8; CAPACITY] {
        let mut bytes = [0; CAPACITY];
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes
    }

    /// 1, 2, 3, ... as `Counting` writes them.
    pub(crate) fn counted<const N: usize>() -> [u8; N] {
        core::array::from_fn(|i| u8::try_from(i.wrapping_add(1)).unwrap())
    }

    #[test]
    fn empty_is_zero() {
        let key = Key::empty();
        assert_eq!(key.bytes(), &[0; CAPACITY]);
        assert_eq!(key.length(), KeyLength::Bytes32);
    }

    #[test]
    fn load32_takes_the_bytes_and_wipes_the_source() {
        let mut key = Key::empty();
        let mut source = [7; 32];
        key.load32(&mut source);
        assert_eq!(key.bytes(), &padded(&[7; 32]));
        assert_eq!(key.length(), KeyLength::Bytes32);
        assert_eq!(source, [0; 32]);
    }

    #[test]
    fn load32_clears_the_tail_of_a_longer_key() {
        let mut key = Key::empty();
        key.load64(&mut [5; 64]);
        key.load32(&mut [7; 32]);
        assert_eq!(key.bytes(), &padded(&[7; 32]));
        assert_eq!(key.length(), KeyLength::Bytes32);
    }

    #[test]
    fn load64_takes_the_bytes_and_wipes_the_source() {
        let mut key = Key::empty();
        let mut source = [5; 64];
        key.load64(&mut source);
        assert_eq!(key.bytes(), &[5; 64]);
        assert_eq!(key.length(), KeyLength::Bytes64);
        assert_eq!(source, [0; 64]);
    }

    #[test]
    fn write_into_writes_the_key_and_zeros() {
        let mut key = Key::empty();
        key.load32(&mut counted::<32>());
        let mut dest = [9; CAPACITY];
        key.write_into(&mut dest);
        assert_eq!(dest, padded(&counted::<32>()));

        key.load64(&mut counted::<64>());
        key.write_into(&mut dest);
        assert_eq!(dest, counted::<64>());
    }

    #[test]
    fn loading_borrowed_bytes_takes_as_many_as_the_length() {
        let source = counted::<64>();
        let mut key = Key::empty();
        key.load64(&mut [5; 64]);
        KeyBytes::new(&source, KeyLength::Bytes32).load_into(&mut key);
        assert_eq!(key.bytes(), &padded(&counted::<32>()));
        assert_eq!(key.length(), KeyLength::Bytes32);

        KeyBytes::new(&source, KeyLength::Bytes64).load_into(&mut key);
        assert_eq!(key.bytes(), &counted::<64>());
        assert_eq!(key.length(), KeyLength::Bytes64);
    }

    #[test]
    fn fill_takes_as_many_bytes_as_the_length() {
        let mut key = Key::empty();
        key.load64(&mut [5; 64]);
        key.fill(KeyLength::Bytes32, &mut Counting).unwrap();
        assert_eq!(key.bytes(), &padded(&counted::<32>()));
        assert_eq!(key.length(), KeyLength::Bytes32);

        key.fill(KeyLength::Bytes64, &mut Counting).unwrap();
        assert_eq!(key.bytes(), &counted::<64>());
        assert_eq!(key.length(), KeyLength::Bytes64);
    }

    #[test]
    fn a_failed_fill_leaves_the_key_wiped() {
        let mut key = Key::empty();
        key.load64(&mut [5; 64]);
        assert_eq!(
            key.fill(KeyLength::Bytes64, &mut Failing),
            Err(EntropyError)
        );
        assert_eq!(key.bytes(), &[0; CAPACITY]);
        assert_eq!(key.length(), KeyLength::Bytes32);
    }

    #[test]
    fn a_panic_in_the_source_leaves_the_key_wiped() {
        let mut key = Key::empty();
        key.load64(&mut [5; 64]);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = key.fill(KeyLength::Bytes64, &mut Panicking);
        }));
        assert!(outcome.is_err());
        assert_eq!(key.bytes(), &[0; CAPACITY]);
        assert_eq!(key.length(), KeyLength::Bytes32);
    }

    #[test]
    fn fill_asks_the_source_once_for_the_length_into_the_key() {
        for (length, bytes) in [(KeyLength::Bytes32, 32), (KeyLength::Bytes64, 64)] {
            let mut source = Recording::default();
            let mut key = Key::empty();
            key.fill(length, &mut source).unwrap();
            assert_eq!((source.calls, source.asked), (1, bytes));
            assert_eq!(source.at, key.bytes().as_ptr().addr());
        }
    }

    #[test]
    fn wipe_zeroes_the_key() {
        let mut key = Key::empty();
        key.load64(&mut [5; 64]);
        key.wipe();
        assert_eq!(key.bytes(), &[0; CAPACITY]);
        assert_eq!(key.length(), KeyLength::Bytes32);
    }

    #[test]
    fn key_length_counts_bytes() {
        assert_eq!(KeyLength::Bytes32.bytes(), 32);
        assert_eq!(KeyLength::Bytes64.bytes(), 64);
    }

    #[test]
    fn debug_shows_no_bytes() {
        let mut key = Key::empty();
        key.load32(&mut [7; 32]);
        assert_eq!(format!("{key:?}"), "Key(..)");
    }
}
