// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::derive::{Branch, SECRET_LEN, wipe_stack};
use crate::entropy::Entropy;
use crate::error::Error;
use crate::key::wipe;
use crate::record::Purpose;
use crate::slots::{Handle, Slots};

/// How many words a key is written in.
pub const WORD_COUNT: usize = 12;
/// The length of the longest word of the list, in bytes.
pub const WORD_LEN: usize = 8;

/// Twelve words of BIP 39's English list, each in lowercase ASCII followed by zeros up to
/// [`WORD_LEN`] bytes.
pub type Words = [[u8; WORD_LEN]; WORD_COUNT];

const LIST_LEN: usize = 2048;
/// Where each of the first eleven word numbers sits in the 128 bits: 11 bits each, from the top.
/// The twelfth holds the last 7 bits and the 4 checksum bits.
const SHIFTS: [u32; WORD_COUNT - 1] = [117, 106, 95, 84, 73, 62, 51, 40, 29, 18, 7];
const NUMBER_BITS: u16 = 0x7ff;
const CHECKSUM_BITS: u16 = 0xf;

/// The English list of BIP 39, one word to a line.
const LIST_TEXT: &[u8] = include_bytes!("words/english.txt");

/// The list, each word as a number: its bytes and the zeros after them, in little-endian order.
static LIST: [u64; LIST_LEN] = numbers_of(LIST_TEXT);

/// Read at compile time: anything but 2048 lines of 3 to 8 lowercase letters fails the build.
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "evaluated at compile time, where an out of bounds index or an overflow fails the build"
)]
const fn numbers_of(text: &[u8]) -> [u64; LIST_LEN] {
    let mut list = [0; LIST_LEN];
    let (mut word, mut length, mut at) = (0, 0, 0);
    while at < text.len() {
        let byte = text[at];
        if byte == b'\n' {
            assert!(length >= 3, "a word is shorter than 3 letters");
            word += 1;
            length = 0;
        } else {
            assert!(
                byte.is_ascii_lowercase(),
                "a word holds other than lowercase letters"
            );
            assert!(length < WORD_LEN, "a word is longer than 8 letters");
            list[word] |= (byte as u64) << (8 * length);
            length += 1;
        }
        at += 1;
    }
    assert!(
        word == LIST_LEN && length == 0,
        "the list is not 2048 words"
    );
    list
}

impl<'a> Slots<'a> {
    /// Creates a 32-byte wrapping key from 16 hedged bytes of `entropy`, and writes its twelve BIP
    /// 39 words into `words`. Nothing else gives the words again; [`Self::derive_from_words`]
    /// derives the same key from them.
    ///
    /// Needs 10 KiB of stack, or 72 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] before `entropy` is asked, [`Error::EntropyFailed`],
    /// [`Error::DerivationFailed`] or [`Error::DuplicateKey`], with `words` and the slots
    /// unchanged.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; the random bytes are then wiped and no slot changes.
    pub fn generate_words(
        &mut self,
        entropy: &mut (impl Entropy + ?Sized),
        words: &mut Words,
    ) -> Result<Handle<'a>, Error> {
        self.generate_words_from(&LIST, entropy, words)
    }

    /// Derives the key [`Self::generate_words`] created with `words` into a free slot, and wipes
    /// `words`. The words are read in constant time, as lowercase ASCII bytes followed by zeros.
    ///
    /// Needs 10 KiB of stack, or 72 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownWord`], [`Error::InvalidChecksum`], [`Error::NoFreeSlot`],
    /// [`Error::DerivationFailed`] or [`Error::DuplicateKey`], with `words` and the slots
    /// unchanged.
    pub fn derive_from_words(&mut self, words: &mut Words) -> Result<Handle<'a>, Error> {
        self.derive_from_words_in(&LIST, Purpose::Wrap, words)
    }

    /// Derives from `words` the transfer key of a backup, which opens with the words alone, and
    /// wipes `words`. It differs from the key [`Self::derive_from_words`] derives from the same
    /// words.
    ///
    /// Needs 10 KiB of stack, or 72 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownWord`], [`Error::InvalidChecksum`], [`Error::NoFreeSlot`],
    /// [`Error::DerivationFailed`] or [`Error::DuplicateKey`], with `words` and the slots
    /// unchanged.
    pub fn transfer_from_words(&mut self, words: &mut Words) -> Result<Handle<'a>, Error> {
        self.derive_from_words_in(&LIST, Purpose::Transfer, words)
    }

    pub(crate) fn generate_words_from<const N: usize>(
        &mut self,
        list: &[u64; N],
        entropy: &mut (impl Entropy + ?Sized),
        words: &mut Words,
    ) -> Result<Handle<'a>, Error> {
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        let generated = self.generate_words_on_stack(list, entropy, words);
        wipe_stack();
        generated
    }

    #[inline(never)]
    fn generate_words_on_stack<const N: usize>(
        &mut self,
        list: &[u64; N],
        entropy: &mut (impl Entropy + ?Sized),
        words: &mut Words,
    ) -> Result<Handle<'a>, Error> {
        let mut bytes = [0; SECRET_LEN];
        let generated = crate::timing::with(|| self.draw(entropy, Branch::HedgeWords, &mut bytes))
            .and_then(|()| self.derive_into(&bytes, Purpose::Wrap, Branch::FromWords));
        if generated.is_ok() {
            crate::timing::with(|| encode(list, &bytes, words));
        }
        generated
    }

    pub(crate) fn derive_from_words_in<const N: usize>(
        &mut self,
        list: &[u64; N],
        purpose: Purpose,
        words: &mut Words,
    ) -> Result<Handle<'a>, Error> {
        let derived = self.derive_from_words_on_stack(list, purpose, words);
        wipe_stack();
        if derived.is_ok() {
            for word in words.iter_mut() {
                wipe(word);
            }
        }
        derived
    }

    #[inline(never)]
    fn derive_from_words_on_stack<const N: usize>(
        &mut self,
        list: &[u64; N],
        purpose: Purpose,
        words: &Words,
    ) -> Result<Handle<'a>, Error> {
        let mut bytes = [0; SECRET_LEN];
        crate::timing::with(|| decode(list, words, &mut bytes))
            .and_then(|()| self.derive_into(&bytes, purpose, Branch::FromWords))
    }
}

fn encode<const N: usize>(list: &[u64; N], bytes: &[u8; SECRET_LEN], words: &mut Words) {
    #[cfg(test)]
    crate::timing::note();
    for (word, &number) in words.iter_mut().zip(&numbers(bytes)) {
        *word = select_in(list, number).to_le_bytes();
    }
}

/// Every word is looked up and the checksum computed before either is judged; `bytes` is wiped if
/// they fail.
fn decode<const N: usize>(
    list: &[u64; N],
    words: &Words,
    bytes: &mut [u8; SECRET_LEN],
) -> Result<(), Error> {
    #[cfg(test)]
    crate::timing::note();
    let mut numbers = [0; WORD_COUNT];
    let mut listed = u8::MAX;
    for (word, number) in words.iter().zip(&mut numbers) {
        let (found, mark) = find_in(list, u64::from_le_bytes(*word));
        *number = found;
        listed &= mark;
    }
    let (read, carried) = bits_of(&numbers);
    *bytes = read;
    let holds = same_checksum(checksum(bytes), carried);
    if listed == 0 {
        wipe(bytes);
        return Err(Error::UnknownWord);
    }
    if !holds {
        wipe(bytes);
        return Err(Error::InvalidChecksum);
    }
    Ok(())
}

fn numbers(bytes: &[u8; SECRET_LEN]) -> [u16; WORD_COUNT] {
    let bits = u128::from_be_bytes(*bytes);
    let mut numbers = [0; WORD_COUNT];
    if let Some((last, first)) = numbers.split_last_mut() {
        for (number, shift) in first.iter_mut().zip(SHIFTS) {
            *number = low_bits(bits.wrapping_shr(shift));
        }
        *last = low_bits(bits.wrapping_shl(4)) | checksum(bytes);
    }
    numbers
}

pub(crate) fn bits_of(numbers: &[u16; WORD_COUNT]) -> ([u8; SECRET_LEN], u16) {
    let mut bits = 0_u128;
    let mut carried = 0;
    if let Some((&last, first)) = numbers.split_last() {
        for (&number, shift) in first.iter().zip(SHIFTS) {
            bits |= u128::from(number & NUMBER_BITS).wrapping_shl(shift);
        }
        bits |= u128::from((last & NUMBER_BITS).wrapping_shr(4));
        carried = last & CHECKSUM_BITS;
    }
    (bits.to_be_bytes(), carried)
}

fn low_bits(bits: u128) -> u16 {
    let [low, high, ..] = bits.to_le_bytes();
    u16::from_le_bytes([low, high]) & NUMBER_BITS
}

/// The first 4 bits of SHA-256 of `bytes`: the checksum BIP 39 appends to 128 bits.
#[cfg(not(kani))]
fn checksum(bytes: &[u8; SECRET_LEN]) -> u16 {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .first()
        .map_or(0, |&first| u16::from(first.wrapping_shr(4)))
}

/// Whether two checksums are the same, compared in constant time.
fn same_checksum(a: u16, b: u16) -> bool {
    #[cfg(not(kani))]
    {
        ctutils::Choice::from_u16_eq(a, b).to_bool()
    }
    #[cfg(kani)]
    {
        model::same_checksum(a, b)
    }
}

/// The number of the entry of `list` that `word` is, and whether it is one, as all ones or zero.
/// Every entry is compared, in constant time.
fn find_in<const N: usize>(list: &[u64; N], word: u64) -> (u16, u8) {
    let mut found = (0, 0);
    for (number, &entry) in (0..).zip(list) {
        found = find_step(word, entry, number, found);
    }
    found
}

/// Every entry is read, in constant time.
fn select_in<const N: usize>(list: &[u64; N], number: u16) -> u64 {
    let mut word = 0;
    for (at, &entry) in (0..).zip(list) {
        word = select_step(at, number, entry, word);
    }
    word
}

/// Kept out of line, so that the check of its machine code finds it.
#[inline(never)]
fn find_step(word: u64, entry: u64, number: u16, found: (u16, u8)) -> (u16, u8) {
    #[cfg(not(kani))]
    {
        use ctutils::{CtAssign, CtEq};
        let same = word.ct_eq(&entry);
        let (mut at, mut listed) = found;
        at.ct_assign(&number, same);
        listed.ct_assign(&u8::MAX, same);
        (at, listed)
    }
    // The comparison ends in inline assembly, which Kani cannot model.
    #[cfg(kani)]
    {
        model::find_step(word, entry, number, found)
    }
}

/// Kept out of line, so that the check of its machine code finds it.
#[inline(never)]
fn select_step(at: u16, wanted: u16, entry: u64, word: u64) -> u64 {
    #[cfg(not(kani))]
    {
        use ctutils::{CtAssign, CtEq};
        let mut word = word;
        word.ct_assign(&entry, at.ct_eq(&wanted));
        word
    }
    #[cfg(kani)]
    {
        model::select_step(at, wanted, entry, word)
    }
}

#[cfg(kani)]
use model::checksum;

/// What stands in under Kani for SHA-256, and for the comparisons that end in inline assembly.
#[cfg(kani)]
pub(crate) mod model {
    use super::{CHECKSUM_BITS, SECRET_LEN};

    pub(crate) fn same_checksum(a: u16, b: u16) -> bool {
        a == b
    }

    pub(crate) fn find_step(word: u64, entry: u64, number: u16, found: (u16, u8)) -> (u16, u8) {
        if word == entry {
            (number, u8::MAX)
        } else {
            found
        }
    }

    pub(crate) fn select_step(at: u16, wanted: u16, entry: u64, word: u64) -> u64 {
        if at == wanted { entry } else { word }
    }

    /// SHA-256 is beyond Kani: folding in every byte lets the few numbers of a short list change
    /// the checksum. Unit tests check that it is SHA-256's.
    pub(crate) fn checksum(bytes: &[u8; SECRET_LEN]) -> u16 {
        u16::from(bytes.iter().fold(0, |sum, &byte| sum ^ byte)) & CHECKSUM_BITS
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use std::string::String;
    use std::vec::Vec;

    use sha2::{Digest, Sha256};

    use super::{
        LIST, LIST_LEN, LIST_TEXT, WORD_COUNT, WORD_LEN, Words, decode, encode, find_in, select_in,
    };
    use crate::derive::direct::hedged_directly;
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::tests::{Counting, Failing, Random, Recording, from_environment};
    use crate::keyset::Position;
    use crate::record::Purpose;
    use crate::slots::{Slot, Slots};

    /// The vectors of the reference implementation of BIP 39 for 128 bits: the bytes and their
    /// words.
    const VECTORS: [(&str, &str); 8] = [
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        ),
        (
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
        ),
        (
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",
        ),
        (
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        ),
    ];

    /// Keys from words, computed by an independent HKDF-SHA-256 from the documented salt and label.
    /// They fix the derivation for all words already written.
    const KEYS: [(&str, &str); 4] = [
        (
            "00000000000000000000000000000000",
            "97becdf0db5808484f6efdb9176534dba262a7cf9590f54201f0f7ec3e836c71",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "4dd2aeeb3313bf2fcedf3921cdcbd9f9d9a1092b9ce297541117623bcffd6a98",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "d1e711fa6b67793dc1ab9c861ded8c688cee7d87b1719880c1dfd7cab49fce14",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "e2a150255ec1b3081079bf0b8b31150f6e5d186abcc746beb6bd97a17327ff3a",
        ),
    ];

    /// Keys for transfers from the same words, computed the same way, with the purpose of transfers
    /// in the label.
    const TRANSFER_KEYS: [(&str, &str); 4] = [
        (
            "00000000000000000000000000000000",
            "7b20d3696ecb531dcb3db43f393829f4c9badc6607154f430858e2a1a9c38ab0",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "0b19b8a8320459de77e66333d31b08eb649cfc680dcf78e4b6eb3e141f0caa14",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "33d4a5e2d0c76086768fdb15037b5b17a6b53836e9619d28e958e09be62dd26d",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "cfc11e5c74a5c7f026f1b7c7ff00e285b9eb27e62f4edc3df0c43bdb769eb7b4",
        ),
    ];

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let bytes: Vec<u8> = text
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").unwrap();
            text
        })
    }

    fn lines() -> Vec<&'static str> {
        core::str::from_utf8(LIST_TEXT).unwrap().lines().collect()
    }

    pub(crate) fn words_of(sentence: &str) -> Words {
        let given: Vec<&str> = sentence.split(' ').collect();
        assert_eq!(given.len(), WORD_COUNT);
        let mut words = [[0; WORD_LEN]; WORD_COUNT];
        for (word, text) in words.iter_mut().zip(given) {
            word[..text.len()].copy_from_slice(text.as_bytes());
        }
        words
    }

    fn sentence_of(words: &Words) -> String {
        let texts: Vec<&str> = words
            .iter()
            .map(|word| core::str::from_utf8(word).unwrap().trim_end_matches('\0'))
            .collect();
        texts.join(" ")
    }

    pub(crate) fn words_for(bytes: &[u8; 16]) -> Words {
        let mut words = [[0; WORD_LEN]; WORD_COUNT];
        encode(&LIST, bytes, &mut words);
        words
    }

    /// What `words` stand for, read apart from the code.
    fn reading(words: &Words) -> Result<[u8; 16], Error> {
        let lines = lines();
        let mut stream = Vec::new();
        for word in words {
            let text = core::str::from_utf8(word)
                .ok()
                .map(|text| text.trim_end_matches('\0'))
                .filter(|text| !text.contains('\0'));
            let number = text
                .and_then(|text| lines.iter().position(|line| *line == text))
                .ok_or(Error::UnknownWord)?;
            stream.extend((0..11).rev().map(|bit| number >> bit & 1 == 1));
        }
        let mut bytes = [0; 16];
        for (at, _) in stream[..128].iter().enumerate().filter(|(_, bit)| **bit) {
            bytes[at >> 3] |= 0x80 >> (at & 7);
        }
        let carried = stream[128..]
            .iter()
            .fold(0, |sum, &bit| sum << 1 | u8::from(bit));
        if Sha256::digest(bytes)[0] >> 4 == carried {
            Ok(bytes)
        } else {
            Err(Error::InvalidChecksum)
        }
    }

    #[test]
    fn the_list_is_the_english_list_of_bip_39() {
        assert_eq!(
            hex(&Sha256::digest(LIST_TEXT)),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        let lines = lines();
        assert_eq!(lines.len(), LIST_LEN);
        for (&entry, line) in LIST.iter().zip(&lines) {
            let mut padded = [0; WORD_LEN];
            padded[..line.len()].copy_from_slice(line.as_bytes());
            assert_eq!(entry, u64::from_le_bytes(padded), "{line}");
        }
        assert!(
            lines.windows(2).all(|pair| pair[0] < pair[1]),
            "in order, each word once"
        );
        let mut heads: Vec<&str> = lines
            .iter()
            .map(|line| &line[..line.len().min(4)])
            .collect();
        heads.dedup();
        assert_eq!(
            heads.len(),
            LIST_LEN,
            "the first four letters tell every word"
        );
    }

    #[test]
    fn every_word_is_found_with_its_number_and_read_back() {
        for (number, &entry) in (0..).zip(&LIST) {
            assert_eq!(find_in(&LIST, entry), (number, u8::MAX));
            assert_eq!(select_in(&LIST, number), entry);
        }
        assert_eq!(select_in(&LIST, 2048), 0);
    }

    #[test]
    fn nothing_but_a_word_of_the_list_is_found() {
        for word in [
            *b"Abandon\0",
            *b"abandon ",
            *b"aban\0\0\0\0",
            *b"abandons",
            *b"zoo\0\0\0\0\x01",
            *b"zo\0o\0\0\0\0",
            [0; WORD_LEN],
            [0xff; WORD_LEN],
        ] {
            assert_eq!(find_in(&LIST, u64::from_le_bytes(word)), (0, 0), "{word:?}");
        }
    }

    #[test]
    fn the_words_are_those_of_the_reference_vectors() {
        for (bytes, sentence) in VECTORS {
            let bytes = unhex(bytes);
            assert_eq!(sentence_of(&words_for(&bytes)), sentence);
            let mut read = [0; 16];
            decode(&LIST, &words_of(sentence), &mut read).unwrap();
            assert_eq!(read, bytes);
        }
    }

    fn random_words(random: &mut Random) -> Words {
        let entry = |random: &mut Random| LIST[random.below(LIST_LEN)].to_le_bytes();
        let mut words = words_for(&random.bytes());
        match random.below(4) {
            0 => {}
            1 => words = core::array::from_fn(|_| entry(random)),
            2 => {
                let at = random.below(WORD_COUNT);
                if random.below(2) == 0 {
                    words[at] = entry(random);
                } else {
                    words[at][random.below(WORD_LEN)] ^= 1 << random.below(8);
                }
            }
            _ => words = core::array::from_fn(|_| random.bytes()),
        }
        words
    }

    fn read_random_words(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        for round in 0..rounds {
            let words = random_words(&mut random);
            let mut read = [0x5a; 16];
            let result = decode(&LIST, &words, &mut read);
            assert_eq!(
                result.map(|()| read),
                reading(&words),
                "round {round} of seed {seed}"
            );
            if result.is_ok() {
                assert_eq!(words_for(&read), words, "round {round} of seed {seed}");
            } else {
                assert_eq!(read, [0; 16], "round {round} of seed {seed}");
            }
        }
    }

    #[test]
    fn random_words_are_read_as_the_list_says() {
        read_random_words(300, 1);
    }

    #[test]
    #[ignore = "long; the rounds and the seed come from the environment"]
    fn many_random_words_are_read_as_the_list_says() {
        read_random_words(
            from_environment("LETHEWIS_RANDOM_ROUNDS", 100_000),
            from_environment("LETHEWIS_RANDOM_SEED", 2),
        );
    }

    #[test]
    fn a_key_from_words_matches_another_implementation() {
        for (bytes, key) in KEYS {
            let mut memory = [const { Slot::empty() }; 2];
            let mut epoch = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
            let mut words = words_for(&unhex(bytes));
            slots.derive_from_words(&mut words).unwrap();
            assert_eq!(
                slots.import32(Purpose::Wrap, &mut unhex(key)).err(),
                Some(Error::DuplicateKey),
                "{bytes}"
            );
        }
    }

    #[test]
    fn a_key_for_transfers_from_words_matches_another_implementation() {
        for ((bytes, transfer), (_, secret)) in TRANSFER_KEYS.into_iter().zip(KEYS) {
            let mut memory = [const { Slot::empty() }; 3];
            let mut epoch = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
            let mut words = words_for(&unhex(bytes));
            let mut kept = words;
            slots.derive_from_words(&mut kept).unwrap();
            let derived = slots.transfer_from_words(&mut words).unwrap();
            assert_eq!(words, [[0; WORD_LEN]; WORD_COUNT]);
            assert_eq!(
                slots
                    .import32(Purpose::Transfer, &mut unhex(transfer))
                    .err(),
                Some(Error::DuplicateKey),
                "{bytes}"
            );
            assert_eq!(
                slots.import32(Purpose::Wrap, &mut unhex(secret)).err(),
                Some(Error::DuplicateKey),
                "{bytes}"
            );
            let mut out = [0; 32];
            assert_eq!(
                slots
                    .reveal32(derived, Position::First, Purpose::Transfer, &mut out)
                    .err(),
                Some(Error::WrongPurpose)
            );
            assert_eq!(
                slots.challenge(derived, &mut out).err(),
                Some(Error::WrongPurpose)
            );
        }
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut words = words_for(&unhex(TRANSFER_KEYS[0].0));
        words[3] = *b"zzzz\0\0\0\0";
        let before = words;
        assert_eq!(
            slots.transfer_from_words(&mut words).err(),
            Some(Error::UnknownWord)
        );
        assert_eq!(words, before);
    }

    #[test]
    fn generated_words_derive_the_generated_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut words = [[7; WORD_LEN]; WORD_COUNT];
        let generated = slots.generate_words(&mut Counting, &mut words).unwrap();
        let counted: [u8; 16] = core::array::from_fn(|at| u8::try_from(at + 1).unwrap());
        let hedged = hedged_directly(&[9; 32], 0, b"hedge words", &counted, 16);
        assert_eq!(
            reading(&words).map(|bytes| bytes.to_vec()),
            Ok(hedged),
            "the words of the source's bytes, hedged"
        );
        let mut again = words;
        assert_eq!(
            slots.derive_from_words(&mut again).err(),
            Some(Error::DuplicateKey),
            "the key the words derive is the one generated"
        );
        slots.release(generated).unwrap();
        slots.derive_from_words(&mut again).unwrap();
        assert_eq!(again, [[0; WORD_LEN]; WORD_COUNT]);
    }

    #[test]
    fn generation_asks_the_source_once_for_16_bytes() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut source = Recording::default();
        let mut words = [[0; WORD_LEN]; WORD_COUNT];
        slots.generate_words(&mut source, &mut words).unwrap();
        assert_eq!((source.calls, source.asked), (1, 16));
        let hedged = hedged_directly(&[9; 32], 0, b"hedge words", &[3; 16], 16);
        assert_eq!(words, words_for(&hedged.try_into().unwrap()));
        let before = words;
        assert_eq!(
            slots.generate_words(&mut source, &mut words).err(),
            Some(Error::NoFreeSlot)
        );
        assert_eq!(
            source.calls, 1,
            "without a free slot the source is not asked"
        );
        assert_eq!(words, before);
    }

    #[test]
    fn a_failed_generation_leaves_the_words_and_the_slots() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut words = [[7; WORD_LEN]; WORD_COUNT];
        assert_eq!(
            slots.generate_words(&mut Failing, &mut words).err(),
            Some(Error::EntropyFailed)
        );
        assert_eq!(words, [[7; WORD_LEN]; WORD_COUNT]);
        slots.generate_words(&mut Counting, &mut words).unwrap();
    }

    #[test]
    fn words_are_wiped_only_when_their_key_is_derived() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut unknown = words_for(&[1; 16]);
        unknown[3] = *b"abandom\0";
        let mut unsummed = words_for(&[1; 16]);
        unsummed.swap(0, 1);
        for (mut words, error) in [
            (unknown, Error::UnknownWord),
            (unsummed, Error::InvalidChecksum),
        ] {
            let before = words;
            assert_eq!(slots.derive_from_words(&mut words).err(), Some(error));
            assert_eq!(words, before);
        }
        let mut words = words_for(&[1; 16]);
        slots.derive_from_words(&mut words).unwrap();
        assert_eq!(words, [[0; WORD_LEN]; WORD_COUNT]);
        let mut words = words_for(&[2; 16]);
        assert_eq!(
            slots.derive_from_words(&mut words).err(),
            Some(Error::NoFreeSlot)
        );
        assert_eq!(words, words_for(&[2; 16]));
        assert_eq!(
            slots.derive_from_words(&mut unknown).err(),
            Some(Error::UnknownWord),
            "the words are read before a slot is looked for"
        );
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    //! What a derivation from words and a generation of words leave on the stack.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use sha2::{Digest, Sha256};

    use super::tests::words_for;
    use super::{LIST, Words, bits_of, decode, encode, find_in};
    use crate::derive::direct::hedged_directly;
    use crate::derive::stack::{
        block_forms, epoch_bytes, hash_forms, secrets, secrets_for, secrets_of, state_after,
        state_forms,
    };
    use crate::derive::{Branch, SALT, STACK_WIPE, derive_from_secret};
    use crate::entropy::{Entropy, EntropyError};
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::KeyLength;
    use crate::record::Purpose;
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::slots::{Slot, Slots};

    /// The stack in KiB that deriving and generating words need, and the depth of the wipe after
    /// them. For an optimised build and for one without optimisation.
    const NEEDS: [usize; 2] = [10, 72];
    const WIPES: [usize; 2] = [8, 64];

    /// Bytes whose values appear nowhere else, kept static so that only the copies looked for reach
    /// the stack.
    static BYTES: [u8; 16] = [
        13, 84, 155, 226, 41, 112, 183, 254, 69, 140, 211, 26, 97, 168, 239, 54,
    ];

    fn bytes() -> [u8; 16] {
        BYTES
    }

    fn other_bytes() -> [u8; 16] {
        bytes().map(|byte| byte ^ 0xff)
    }

    struct Fixed;

    impl Entropy for Fixed {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&BYTES);
            Ok(())
        }
    }

    fn read(words: &Words) -> [u8; 16] {
        let numbers = words.map(|word| find_in(&LIST, u64::from_le_bytes(word)).0);
        bits_of(&numbers).0
    }

    fn checksum_secrets(bytes: &[u8; 16]) -> Vec<Vec<u8>> {
        let mut block = [0; 64];
        block[..16].copy_from_slice(bytes);
        block[16] = 0x80;
        block[56..].copy_from_slice(&128_u64.to_be_bytes());
        let mut found = block_forms(&block);
        found.extend(state_forms(state_after(&[block])));
        found.extend(hash_forms(&Sha256::digest(bytes)));
        found
    }

    /// The bytes as they sit in memory either way round, and the numbers of their words.
    fn bytes_and_numbers(bytes: &[u8; 16]) -> Vec<Vec<u8>> {
        let numbers: Vec<u8> = words_for(bytes)
            .iter()
            .flat_map(|word| find_in(&LIST, u64::from_le_bytes(*word)).0.to_le_bytes())
            .collect();
        let reversed: Vec<u8> = bytes.iter().rev().copied().collect();
        std::vec![bytes.to_vec(), reversed, numbers]
    }

    fn derivation_secrets(bytes: &[u8; 16], purpose: Purpose) -> Vec<Vec<u8>> {
        let mut found = bytes_and_numbers(bytes);
        found.push(words_for(bytes).concat());
        found.extend(checksum_secrets(bytes));
        found.extend(secrets_for(bytes, SALT, Branch::FromWords, Some(purpose)));
        let mut key = [0; 64];
        derive_from_secret(bytes, Some(purpose), Branch::FromWords, &mut key[..32]).unwrap();
        found.extend(secrets(&key, SALT, KeyLength::Bytes32, Branch::KeyId));
        found
    }

    fn pieces_for(purpose: Purpose) -> Vec<Vec<u8>> {
        key_dependent(
            &derivation_secrets(&bytes(), purpose),
            &derivation_secrets(&other_bytes(), purpose),
        )
    }

    fn pieces() -> Vec<Vec<u8>> {
        pieces_for(Purpose::Wrap)
    }

    fn slots_of<'a>(memory: &'a mut [Slot], epoch: &'a mut Epoch) -> Slots<'a> {
        Slots::new(memory, epoch, 1, &mut epoch_bytes(0))
    }

    #[test]
    fn reading_words_without_a_wipe_leaves_residue() {
        let words = words_for(&bytes());
        let range = below_pad(false, || {
            let mut read = [0; 16];
            decode(&LIST, &words, &mut read).unwrap();
            black_box(&read);
        });
        assert!(residue(range, &pieces()) > 0);
    }

    #[test]
    fn writing_words_without_a_wipe_leaves_residue() {
        let range = below_pad(false, || {
            let mut words = [[0; 8]; 12];
            encode(&LIST, &bytes(), &mut words);
            black_box(&words);
        });
        assert!(residue(range, &pieces()) > 0);
    }

    #[test]
    fn a_derivation_from_words_leaves_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let given = words_for(&bytes());
        assert_clean(&pieces, || {
            let mut words = given;
            slots.derive_from_words(&mut words).unwrap();
            black_box(&words);
        });
    }

    #[test]
    fn a_key_for_transfers_from_words_leaves_no_residue() {
        let pieces = pieces_for(Purpose::Transfer);
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let given = words_for(&bytes());
        assert_clean(&pieces, || {
            let mut words = given;
            slots.transfer_from_words(&mut words).unwrap();
            black_box(&words);
        });
    }

    /// A derivation that fails after the key is derived, because the slots hold it already.
    #[test]
    fn a_failed_derivation_from_words_leaves_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        slots.derive_from_words(&mut words_for(&bytes())).unwrap();
        // A failure leaves the words as they were, in the caller's buffer, above what is read.
        let mut kept = words_for(&bytes());
        assert_clean(&pieces, || {
            let derived = slots.derive_from_words(&mut kept);
            assert_eq!(black_box(derived).err(), Some(Error::DuplicateKey));
        });
    }

    /// Words whose checksum does not hold, read and refused before any derivation.
    #[test]
    fn refused_words_leave_no_residue() {
        let mut swapped = words_for(&bytes());
        swapped.swap(0, 1);
        let read = read(&swapped);
        let other = read.map(|byte| byte ^ 0xff);
        let numbers = |words: &Words| -> Vec<u8> {
            words
                .iter()
                .flat_map(|word| find_in(&LIST, u64::from_le_bytes(*word)).0.to_le_bytes())
                .collect()
        };
        let reversed = |bytes: [u8; 16]| bytes.iter().rev().copied().collect::<Vec<u8>>();
        let mut found = std::vec![read.to_vec(), reversed(read), numbers(&swapped)];
        found.extend(checksum_secrets(&read));
        let mut others = std::vec![other.to_vec(), reversed(other), numbers(&words_for(&other))];
        others.extend(checksum_secrets(&other));
        let pieces = key_dependent(&found, &others);
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        assert_clean(&pieces, || {
            let derived = slots.derive_from_words(&mut swapped);
            assert_eq!(black_box(derived).err(), Some(Error::InvalidChecksum));
        });
    }

    #[test]
    fn a_generation_of_words_leaves_no_residue() {
        let hedged = |bytes: &[u8; 16], epoch: &[u8; 32]| -> [u8; 16] {
            hedged_directly(epoch, 0, b"hedge words", bytes, 16)
                .try_into()
                .unwrap()
        };
        let found = |bytes: &[u8; 16], epoch: &[u8; 32]| {
            let mut material = bytes.to_vec();
            material.extend_from_slice(&0_u64.to_le_bytes());
            let mut found = derivation_secrets(&hedged(bytes, epoch), Purpose::Wrap);
            found.extend(secrets_of(&material, epoch, Branch::HedgeWords));
            found.push(bytes.to_vec());
            found
        };
        let pieces = key_dependent(
            &found(&bytes(), &epoch_bytes(0)),
            &found(&other_bytes(), &epoch_bytes(0xff)),
        );
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        // The words are the caller's to keep, above what is read.
        let mut words = [[0; 8]; 12];
        assert_clean(&pieces, || {
            slots.generate_words(&mut Fixed, &mut words).unwrap();
        });
        assert_eq!(words, words_for(&hedged(&bytes(), &epoch_bytes(0))));
    }

    struct Panicking;

    impl Entropy for Panicking {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&BYTES);
            panic!("the source broke after writing")
        }
    }

    /// With optimisation the unwinding itself overwrites where the bytes were, so only a build
    /// without it can tell.
    #[test]
    fn a_panicking_source_leaves_no_bytes() {
        let pieces = key_dependent(&[bytes().to_vec()], &[other_bytes().to_vec()]);
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut words = [[0; 8]; 12];
        assert_clean(&pieces, || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = slots.generate_words(&mut Panicking, &mut words);
            }));
            assert!(outcome.is_err());
        });
        assert_eq!(words, [[0; 8]; 12]);
        slots.generate_words(&mut Fixed, &mut words).unwrap();
    }

    #[test]
    fn the_wipe_reaches_its_depth() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let needs = 1024 * NEEDS[usize::from(cfg!(lethewis_unoptimised))];
        let mut words = [[0; 8]; 12];
        let wiped = depth_changed(|| {
            slots.generate_words(&mut Fixed, &mut words).unwrap();
        });
        assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
        assert!(wiped <= needs, "{wiped} bytes reached");
        for outcome in [None, Some(Error::DuplicateKey)] {
            let wiped = depth_changed(|| {
                let mut words = words_for(&other_bytes());
                let derived = slots.derive_from_words(&mut words);
                assert_eq!(black_box(derived).err(), outcome);
            });
            assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
            assert!(wiped <= needs, "{wiped} bytes reached");
        }
    }

    /// The load has wipes of its own.
    #[test]
    fn the_wipe_is_deeper_than_reading_and_writing_words() {
        let words = words_for(&bytes());
        for used in [
            depth_changed(|| {
                let mut read = [0; 16];
                decode(&LIST, &words, &mut read).unwrap();
                black_box(&read);
            }),
            depth_changed(|| {
                let mut written = [[0; 8]; 12];
                encode(&LIST, &bytes(), &mut written);
                black_box(&written);
            }),
        ] {
            std::println!("reading or writing words uses {used} bytes of stack");
            assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
        }
    }

    #[test]
    fn the_documentation_states_the_stack_the_calls_need() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(WIPES[build] * 1024, STACK_WIPE);
        let source = include_str!("words.rs");
        for call in ["generate_words", "derive_from_words", "transfer_from_words"] {
            let at = source.find(&std::format!("    pub fn {call}(")).unwrap();
            let mut lines: Vec<&str> = source[..at]
                .lines()
                .rev()
                .take_while(|line| line.trim_start().starts_with("///"))
                .map(|line| line.trim().trim_start_matches("///").trim())
                .collect();
            lines.reverse();
            let text = lines.join(" ");
            for stated in [
                std::format!("Needs {} KiB of stack, or {} KiB when", NEEDS[0], NEEDS[1]),
                std::format!(" {} KiB, or {} KiB, ", WIPES[0], WIPES[1]),
            ] {
                assert!(text.contains(&stated), "{call}: {stated}");
            }
        }
    }
}

#[cfg(kani)]
#[coverage(on)]
pub(crate) mod proofs {
    use super::{
        LIST_LEN, SECRET_LEN, WORD_COUNT, Words, bits_of, checksum, decode, encode, find_in,
        numbers, select_in,
    };
    use crate::error::Error;

    pub(crate) fn expected_words(list: &[u64; 3], bytes: &[u8; SECRET_LEN]) -> Words {
        let mut words = [[0; 8]; WORD_COUNT];
        encode(list, bytes, &mut words);
        words
    }

    /// The code reads every list alike, and the list of 2048 is checked word by word by the unit
    /// tests.
    pub(crate) fn any_list() -> [u64; 3] {
        let list: [u64; 3] = kani::any();
        kani::assume(list[0] != list[1] && list[0] != list[2] && list[1] != list[2]);
        list
    }

    #[kani::proof]
    fn a_word_is_found_exactly_where_it_is_listed() {
        let list = any_list();
        let word: u64 = kani::any();
        let at: usize = kani::any();
        kani::assume(at < list.len());
        let (number, listed) = find_in(&list, word);
        if list[at] == word {
            kani::assert(
                listed == u8::MAX && usize::from(number) == at,
                "a word of the list is found with its number",
            );
        }
        kani::assert(
            listed == 0 || listed == u8::MAX && list[usize::from(number) % 3] == word,
            "a word found is the entry of its number",
        );
        kani::cover!(listed == u8::MAX, "a word of the list");
        kani::cover!(listed == 0, "a word not of the list");
    }

    #[kani::proof]
    fn the_entry_of_a_number_is_read() {
        let list = any_list();
        let number: u16 = kani::any();
        let read = select_in(&list, number);
        match list.get(usize::from(number)) {
            Some(&entry) => kani::assert(read == entry, "the entry of a number is read"),
            None => kani::assert(read == 0, "a number past the list reads nothing"),
        }
        kani::cover!(number == 2, "the last entry");
        kani::cover!(number == 3, "past the list");
    }

    #[kani::proof]
    fn bytes_are_read_back_from_their_numbers() {
        let bytes: [u8; SECRET_LEN] = kani::any();
        let numbers = numbers(&bytes);
        kani::assert(
            numbers.iter().all(|&number| usize::from(number) < LIST_LEN),
            "every number is of the list",
        );
        kani::assert(
            bits_of(&numbers) == (bytes, checksum(&bytes)),
            "the numbers stand for the bytes and carry their checksum",
        );
        kani::cover!(bytes == [0xff; SECRET_LEN], "every bit set");
    }

    #[kani::proof]
    fn numbers_stand_for_one_set_of_bytes() {
        let given: [u16; WORD_COUNT] = kani::any();
        kani::assume(given.iter().all(|&number| usize::from(number) < LIST_LEN));
        let (bytes, carried) = bits_of(&given);
        kani::assert(
            (numbers(&bytes) == given) == (carried == checksum(&bytes)),
            "numbers are the ones of their bytes exactly when their checksum holds",
        );
        kani::cover!(carried == checksum(&bytes), "the checksum holds");
        kani::cover!(carried != checksum(&bytes), "the checksum does not hold");
    }

    #[kani::proof]
    fn words_are_read_exactly_when_listed_with_their_checksum() {
        let list = any_list();
        let words: Words = kani::any();
        let mut bytes: [u8; SECRET_LEN] = kani::any();
        let result = decode(&list, &words, &mut bytes);
        let listed = words
            .iter()
            .all(|word| list.contains(&u64::from_le_bytes(*word)));
        let numbers: [u16; WORD_COUNT] = core::array::from_fn(|at| {
            let word = u64::from_le_bytes(words[at]);
            if word == list[1] {
                1
            } else if word == list[2] {
                2
            } else {
                0
            }
        });
        let (read, carried) = bits_of(&numbers);
        let holds = carried == checksum(&read);
        kani::assert(
            result
                == if !listed {
                    Err(Error::UnknownWord)
                } else if !holds {
                    Err(Error::InvalidChecksum)
                } else {
                    Ok(())
                },
            "words are read exactly when listed with their checksum, an unknown word first",
        );
        if result.is_ok() {
            kani::assert(
                bytes == read,
                "the bytes read are those the words stand for",
            );
            let mut written: Words = [[0; 8]; WORD_COUNT];
            encode(&list, &bytes, &mut written);
            kani::assert(written == words, "words read are the words of their bytes");
        } else {
            kani::assert(
                bytes == [0; SECRET_LEN],
                "the bytes are wiped when the words are refused",
            );
        }
        kani::cover!(result.is_ok(), "words are read");
        kani::cover!(result == Err(Error::UnknownWord), "an unknown word");
        kani::cover!(
            result == Err(Error::InvalidChecksum),
            "a checksum that does not hold"
        );
    }
}
