// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! A share as words of BIP 39's English list, with a Reed-Solomon check over GF(2^11).

use super::{NUMBERS, Share};
use crate::derive::wipe_stack;
use crate::error::Error;
use crate::key::wipe;
use crate::words::{LIST, WORD_LEN, find_in, select_in};

/// How many words a share is written in.
pub const SHARE_WORD_COUNT: usize = 21;

/// A share as words of BIP 39's English list, each in lowercase ASCII followed by zeros up to
/// [`WORD_LEN`] bytes.
pub type ShareWords = [[u8; WORD_LEN]; SHARE_WORD_COUNT];

const DATA: usize = 18;
const CHECK: usize = 3;
const SYMBOL_BITS: u32 = 11;
const SYMBOL: u32 = 0x7ff;
/// x^11 + x^2 + 1, which is primitive: 2 generates the field.
const POLYNOMIAL: u16 = 0x805;
/// (x + 2)(x + 4)(x + 8) below its leading term, highest first.
const GENERATOR: [u16; CHECK] = [14, 56, 64];
/// The roots of the generator, where every codeword is zero.
const ROOTS: [u16; CHECK] = [2, 4, 8];
/// The format of the words, in the first 4 bits; a later one is refused.
const VERSION: u32 = 0;
const VERSION_BITS: u32 = 4;
/// The bits a share's number takes, then each other byte.
const WIDTHS: [u32; 2] = [2, 8];
/// No place named.
const NONE: u8 = u8::MAX;

/// Writes `share` into `words` as 21 words of BIP 39's English list: 18 carry the share and 3 check
/// them. A word is chosen in constant time.
///
/// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
///
/// # Errors
///
/// [`Error::InvalidShare`] if `share` is numbered other than 1, 2 or 3; `words` then stays as it
/// was.
pub fn share_to_words(share: &Share, words: &mut ShareWords) -> Result<(), Error> {
    let written = to_words_on_stack(share, words);
    wipe_stack();
    written
}

/// Reads into `share` the share `words` stand for, and wipes `words`. Words are looked up in
/// constant time, as lowercase ASCII bytes followed by zeros.
///
/// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
///
/// # Errors
///
/// [`Error::UnknownWord`], [`Error::InvalidChecksum`], or [`Error::InvalidShare`] for a later format
/// or no number. `words` and `share` then stay as they were.
pub fn share_from_words(words: &mut ShareWords, share: &mut Share) -> Result<(), Error> {
    let read = from_words_on_stack(words, share);
    wipe_stack();
    if read.is_ok() {
        for word in words.iter_mut() {
            wipe(word);
        }
    }
    read
}

/// The position of the wrong word in `words`, from zero, if exactly one is wrong, in the list or
/// not. With two it names none, with three or more it may name a right one; it never corrects.
///
/// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
#[must_use]
pub fn wrong_share_word(words: &ShareWords) -> Option<usize> {
    let found = wrong_on_stack(words);
    wipe_stack();
    found
}

#[inline(never)]
fn to_words_on_stack(share: &Share, words: &mut ShareWords) -> Result<(), Error> {
    let [number, ..] = *share;
    if !NUMBERS.contains(&number) {
        return Err(Error::InvalidShare);
    }
    crate::timing::with(|| words_of(&symbols_of(share), words));
    Ok(())
}

#[inline(never)]
fn from_words_on_stack(words: &ShareWords, share: &mut Share) -> Result<(), Error> {
    crate::timing::with(|| {
        let (symbols, marks) = looked_up(words);
        let listed = marks.iter().fold(u8::MAX, |all, &mark| all & mark);
        read(&symbols, listed != 0, share)
    })
}

#[inline(never)]
fn wrong_on_stack(words: &ShareWords) -> Option<usize> {
    let found = crate::timing::with(|| {
        let (symbols, marks) = looked_up(words);
        let (mut outside, mut unlisted) = (0_u8, NONE);
        for (place, &mark) in (0..=u8::MAX).zip(&marks) {
            let missing = !mark & 1;
            outside = outside.wrapping_add(missing);
            ctutils::CtAssign::ct_assign(&mut unlisted, &place, ctutils::Choice::from(missing));
        }
        let values = syndromes(&symbols);
        named(changed_at(values), values, outside, unlisted)
    });
    (found != NONE).then_some(usize::from(found))
}

/// The number of each word in the list, and whether it is in it: all ones if so, else zero.
fn looked_up(words: &ShareWords) -> ([u16; SHARE_WORD_COUNT], [u8; SHARE_WORD_COUNT]) {
    #[cfg(test)]
    crate::timing::note();
    let mut symbols = [0; SHARE_WORD_COUNT];
    let mut marks = [0; SHARE_WORD_COUNT];
    for ((symbol, mark), word) in symbols.iter_mut().zip(&mut marks).zip(words) {
        (*symbol, *mark) = find_in(&LIST, u64::from_le_bytes(*word));
    }
    (symbols, marks)
}

/// Writes the word of each symbol into `words`.
fn words_of(symbols: &[u16; SHARE_WORD_COUNT], words: &mut ShareWords) {
    #[cfg(test)]
    crate::timing::note();
    for (word, &symbol) in words.iter_mut().zip(symbols) {
        *word = select_in(&LIST, symbol).to_le_bytes();
    }
}

/// The symbols of `share`: its data, the version, its number in 2 bits and its other bytes, then
/// the check.
fn symbols_of(share: &Share) -> [u16; SHARE_WORD_COUNT] {
    #[cfg(test)]
    crate::timing::note();
    let data = data_of(share);
    let mut symbols = [0; SHARE_WORD_COUNT];
    for (symbol, &value) in symbols.iter_mut().zip(data.iter().chain(&check_of(&data))) {
        *symbol = value;
    }
    symbols
}

/// Writes into `share` what `symbols` stand for if they are a codeword of this version whose share
/// has a number; `listed` tells whether every word was in the list.
fn read(symbols: &[u16; SHARE_WORD_COUNT], listed: bool, share: &mut Share) -> Result<(), Error> {
    #[cfg(test)]
    crate::timing::note();
    let mut bytes = [0; super::SHARE_LEN];
    let mut data = [0; DATA];
    for (value, &symbol) in data.iter_mut().zip(symbols) {
        *value = symbol;
    }
    let version = share_of(&data, &mut bytes);
    let [number, ..] = bytes;
    if !listed {
        return Err(Error::UnknownWord);
    }
    if syndromes(symbols) != [0; CHECK] {
        return Err(Error::InvalidChecksum);
    }
    if version != VERSION || number == 0 {
        return Err(Error::InvalidShare);
    }
    *share = bytes;
    Ok(())
}

/// The 18 data symbols: 4 bits of version, 2 of the share's number, then its other 24 bytes, 11
/// bits to a symbol from the first.
fn data_of(share: &Share) -> [u16; DATA] {
    let mut data = [0; DATA];
    let mut symbols = data.iter_mut();
    let (mut held, mut count) = (VERSION, VERSION_BITS);
    let [first, rest] = WIDTHS;
    for (&byte, width) in share
        .iter()
        .zip(core::iter::once(first).chain(core::iter::repeat(rest)))
    {
        held = held.wrapping_shl(width) | u32::from(byte);
        count = count.wrapping_add(width);
        if count >= SYMBOL_BITS {
            count = count.wrapping_sub(SYMBOL_BITS);
            if let Some(symbol) = symbols.next() {
                *symbol = low_bits(held.wrapping_shr(count));
            }
            held &= mask(count);
        }
    }
    data
}

/// Writes into `share` the number and bytes the data symbols carry, and returns their version.
fn share_of(data: &[u16; DATA], share: &mut Share) -> u32 {
    let mut bits = Bits {
        symbols: data.iter(),
        held: 0,
        count: 0,
    };
    let version = bits.take(VERSION_BITS);
    let [first, rest] = WIDTHS;
    for (byte, width) in share
        .iter_mut()
        .zip(core::iter::once(first).chain(core::iter::repeat(rest)))
    {
        let [low, ..] = bits.take(width).to_le_bytes();
        *byte = low;
    }
    version
}

/// The bits of data symbols, read from the first.
struct Bits<'a> {
    symbols: core::slice::Iter<'a, u16>,
    held: u32,
    count: u32,
}

impl Bits<'_> {
    fn take(&mut self, bits: u32) -> u32 {
        while self.count < bits {
            let next = self.symbols.next().copied().unwrap_or(0);
            self.held = self.held.wrapping_shl(SYMBOL_BITS) | u32::from(next);
            self.count = self.count.wrapping_add(SYMBOL_BITS);
        }
        self.count = self.count.wrapping_sub(bits);
        let value = self.held.wrapping_shr(self.count);
        self.held &= mask(self.count);
        value
    }
}

/// The remainder of the data times x^3 divided by the generator: the check symbols, highest first.
fn check_of(data: &[u16; DATA]) -> [u16; CHECK] {
    let [g2, g1, g0] = GENERATOR;
    let mut rest = [0; CHECK];
    for &symbol in data {
        let [r2, r1, r0] = rest;
        let feedback = symbol ^ r2;
        rest = [
            r1 ^ product(feedback, g2),
            r0 ^ product(feedback, g1),
            product(feedback, g0),
        ];
    }
    rest
}

/// The values of the polynomial of `symbols`, first symbol highest, at the roots of the generator:
/// all zero exactly for a codeword.
fn syndromes(symbols: &[u16; SHARE_WORD_COUNT]) -> [u16; CHECK] {
    #[cfg(test)]
    crate::timing::note();
    let mut values = [0; CHECK];
    for &symbol in symbols {
        for (value, root) in values.iter_mut().zip(ROOTS) {
            *value = product(*value, root) ^ symbol;
        }
    }
    values
}

/// The position of the one symbol that differs from a codeword, if one does, from its syndromes,
/// or [`NONE`].
fn changed_at(syndromes: [u16; CHECK]) -> u8 {
    #[cfg(test)]
    crate::timing::note();
    let [s1, s2, _] = syndromes;
    let mut found = NONE;
    let mut power = 1;
    for position in (0..SHARE_WORD_COUNT).rev() {
        let place = u8::try_from(position).unwrap_or(NONE);
        let scaled = [product(s1, power), product(s2, power)];
        found = locate_step(syndromes, scaled, place, found);
        power = product(power, 2);
    }
    found
}

/// `place` if the syndromes are those of one change there, given the first two times the power of
/// that place, else `found`. Constant time, and out of line so that the check of its machine code
/// finds it.
#[inline(never)]
fn locate_step(syndromes: [u16; CHECK], scaled: [u16; 2], place: u8, found: u8) -> u8 {
    #[cfg(not(kani))]
    {
        use ctutils::{CtAssign, CtEq};
        let [s1, s2, s3] = syndromes;
        let [first, second] = scaled;
        let mut found = found;
        found.ct_assign(&place, !s1.ct_eq(&0) & first.ct_eq(&s2) & second.ct_eq(&s3));
        found
    }
    // The comparisons end in inline assembly, which Kani cannot model.
    #[cfg(kani)]
    {
        model::locate_step(syndromes, scaled, place, found)
    }
}

/// The place to name: `located` if every word is in the list; if `outside` is one, `unlisted` when
/// the syndromes are zero or `located` agrees; otherwise [`NONE`]. Constant time like the step.
#[inline(never)]
fn named(located: u8, syndromes: [u16; CHECK], outside: u8, unlisted: u8) -> u8 {
    use ctutils::{CtAssign, CtEq};
    #[cfg(test)]
    crate::timing::note();
    let mut one = NONE;
    one.ct_assign(
        &unlisted,
        syndromes.ct_eq(&[0; CHECK]) | located.ct_eq(&unlisted),
    );
    let mut place = NONE;
    place.ct_assign(&one, outside.ct_eq(&1));
    place.ct_assign(&located, outside.ct_eq(&0));
    place
}

#[cfg(kani)]
mod model {
    use super::CHECK;

    pub(super) fn locate_step(
        syndromes: [u16; CHECK],
        scaled: [u16; 2],
        place: u8,
        found: u8,
    ) -> u8 {
        let [s1, s2, s3] = syndromes;
        if s1 != 0 && scaled == [s2, s3] {
            place
        } else {
            found
        }
    }
}

/// The product of `a` and `b` in GF(2^11) modulo x^11 + x^2 + 1, with no branch on either. Kept
/// out of line, so that the check of its machine code finds it.
#[inline(never)]
fn product(a: u16, b: u16) -> u16 {
    let mut product = 0;
    let mut a = a;
    for bit in 0..SYMBOL_BITS {
        product ^= a & (b.wrapping_shr(bit) & 1).wrapping_neg();
        a = a.wrapping_shl(1) ^ (POLYNOMIAL & a.wrapping_shr(10).wrapping_neg());
    }
    product
}

fn low_bits(bits: u32) -> u16 {
    let [low, high, ..] = (bits & SYMBOL).to_le_bytes();
    u16::from_le_bytes([low, high])
}

fn mask(count: u32) -> u32 {
    1_u32.wrapping_shl(count).wrapping_sub(1)
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "the field worked out apart from the code takes sums of logarithms"
)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{
        CHECK, DATA, GENERATOR, NONE, ROOTS, SHARE_WORD_COUNT, ShareWords, changed_at, check_of,
        data_of, named, product, read, share_from_words, share_of, share_to_words, symbols_of,
        syndromes, wrong_share_word,
    };
    use crate::error::Error;
    use crate::key::tests::{Random, from_environment};
    use crate::shares::{SHARE_LEN, Share};
    use crate::words::WORD_LEN;

    /// Shares and their words from an independent implementation with tables of logarithms. They
    /// fix the words of every share already written.
    const VECTORS: [(&str, &str); 3] = [
        (
            "020102030405060708090a0b0c0d0e0f101112131415161718",
            "amount cake adapt cage dose asthma letter lunar club like asthma joy affair category \
             course appear flame toast able soft sword",
        ),
        (
            "01ffffffffffffffffffffffffffffffffffffffffffffffff",
            "among zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo card inner \
             tribe",
        ),
        (
            "03000000000000000000000000000000000000000000000000",
            "army abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon system toddler maple",
        ),
    ];

    fn unhex(text: &str) -> Share {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn words_of(text: &str) -> ShareWords {
        let mut words = [[0; WORD_LEN]; SHARE_WORD_COUNT];
        for (word, given) in words.iter_mut().zip(text.split_whitespace()) {
            word[..given.len()].copy_from_slice(given.as_bytes());
        }
        words
    }

    /// The field worked out apart from [`product`]: the powers of 2 and their logarithms.
    struct Tables {
        powers: [u16; 2047],
        logarithms: [usize; 2048],
    }

    impl Tables {
        fn new() -> Self {
            let mut tables = Self {
                powers: [0; 2047],
                logarithms: [0; 2048],
            };
            let mut power: u16 = 1;
            for exponent in 0..2047 {
                tables.powers[exponent] = power;
                tables.logarithms[usize::from(power)] = exponent;
                power <<= 1;
                if power & 0x800 != 0 {
                    power ^= 0x805;
                }
            }
            tables
        }

        fn product(&self, a: u16, b: u16) -> u16 {
            if a == 0 || b == 0 {
                return 0;
            }
            let sum = self.logarithms[usize::from(a)] + self.logarithms[usize::from(b)];
            self.powers[sum % 2047]
        }
    }

    fn share(random: &mut Random) -> Share {
        let mut share: Share = random.bytes();
        share[0] = u8::try_from(random.below(3) + 1).unwrap();
        share
    }

    #[test]
    fn every_product_is_that_of_the_tables() {
        let tables = Tables::new();
        for a in 0..2048 {
            for b in 0..2048 {
                assert_eq!(product(a, b), tables.product(a, b), "{a} {b}");
            }
        }
    }

    #[test]
    fn the_generator_has_its_roots() {
        let mut coefficients = [1_u16, 0, 0, 0];
        for root in ROOTS {
            let mut next = [0; 4];
            for (at, &coefficient) in coefficients.iter().enumerate().take(3) {
                next[at] ^= coefficient;
                next[at + 1] ^= product(coefficient, root);
            }
            coefficients = next;
        }
        assert_eq!(coefficients, [1, GENERATOR[0], GENERATOR[1], GENERATOR[2]]);
        assert_eq!(ROOTS, [2, product(2, 2), product(2, product(2, 2))]);
    }

    #[test]
    fn the_words_are_those_of_an_independent_implementation() {
        for (bytes, text) in VECTORS {
            let share = unhex(bytes);
            let mut words = [[0; WORD_LEN]; SHARE_WORD_COUNT];
            share_to_words(&share, &mut words).unwrap();
            assert_eq!(words, words_of(text), "{bytes}");
            let mut read: Share = [0x5a; SHARE_LEN];
            share_from_words(&mut words, &mut read).unwrap();
            assert_eq!(read, share);
            assert_eq!(
                words, [[0; WORD_LEN]; SHARE_WORD_COUNT],
                "the words are wiped"
            );
        }
    }

    /// Every change of one symbol of a random share is refused and found where it is.
    #[test]
    fn every_changed_symbol_is_refused_and_found() {
        let symbols = symbols_of(&share(&mut Random(11)));
        assert_eq!(changed_at(syndromes(&symbols)), NONE);
        for at in 0..SHARE_WORD_COUNT {
            for change in 1..2048 {
                let mut changed = symbols;
                changed[at] ^= change;
                let mut read_back: Share = [0x5a; SHARE_LEN];
                assert_eq!(
                    read(&changed, true, &mut read_back),
                    Err(Error::InvalidChecksum)
                );
                assert_eq!(read_back, [0x5a; SHARE_LEN], "nothing is written");
                assert_eq!(
                    usize::from(changed_at(syndromes(&changed))),
                    at,
                    "{at} {change}"
                );
            }
        }
    }

    /// Two or three changed symbols, at random, are refused, and two are never taken for one.
    fn refuse_random_changes(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        for round in 0..rounds {
            let mut symbols = symbols_of(&share(&mut random));
            let changes = if round % 2 == 0 { 2 } else { 3 };
            let mut places = Vec::new();
            while places.len() < changes {
                let at = random.below(SHARE_WORD_COUNT);
                if !places.contains(&at) {
                    places.push(at);
                }
            }
            for &at in &places {
                symbols[at] ^= u16::try_from(random.below(2047) + 1).unwrap();
            }
            assert_ne!(
                syndromes(&symbols),
                [0; CHECK],
                "round {round} of seed {seed}"
            );
            let mut read_back: Share = [0x5a; SHARE_LEN];
            assert_eq!(
                read(&symbols, true, &mut read_back),
                Err(Error::InvalidChecksum),
                "round {round} of seed {seed}"
            );
            assert_eq!(read_back, [0x5a; SHARE_LEN], "round {round} of seed {seed}");
            if changes == 2 {
                assert_eq!(
                    changed_at(syndromes(&symbols)),
                    NONE,
                    "round {round} of seed {seed}"
                );
            }
        }
    }

    #[test]
    fn two_or_three_changed_symbols_are_refused() {
        refuse_random_changes(300, 12);
    }

    #[test]
    #[ignore = "long; the rounds and the seed come from the environment"]
    fn many_random_changes_of_symbols_are_refused() {
        refuse_random_changes(
            from_environment("LETHEWIS_RANDOM_ROUNDS", 100_000),
            from_environment("LETHEWIS_RANDOM_SEED", 12),
        );
    }

    #[test]
    fn a_share_is_read_back_from_its_symbols() {
        let mut random = Random(13);
        for _ in 0..1000 {
            let share = share(&mut random);
            let data = data_of(&share);
            let mut read_back = [0; SHARE_LEN];
            assert_eq!(share_of(&data, &mut read_back), 0);
            assert_eq!(read_back, share);
            let symbols = symbols_of(&share);
            assert_eq!(syndromes(&symbols), [0; CHECK]);
            assert_eq!(symbols[..DATA], data);
            assert_eq!(symbols[DATA..], check_of(&data));
        }
    }

    /// Symbols of a later version, or of a share with no number, whose check holds.
    #[test]
    fn a_later_format_or_no_number_is_refused() {
        let share = unhex(VECTORS[0].0);
        for (version, number) in [(1_u16, 2_u16), (8, 2), (0, 0)] {
            let mut data = data_of(&share);
            data[0] = (data[0] & 0x1f) | version << 7 | number << 5;
            let mut symbols = [0; SHARE_WORD_COUNT];
            symbols[..DATA].copy_from_slice(&data);
            symbols[DATA..].copy_from_slice(&check_of(&data));
            let mut read_back: Share = [0x5a; SHARE_LEN];
            assert_eq!(
                read(&symbols, true, &mut read_back),
                Err(Error::InvalidShare)
            );
            assert_eq!(read_back, [0x5a; SHARE_LEN]);
        }
        for number in [0, 4, 0xff] {
            let mut numbered = share;
            numbered[0] = number;
            let mut words = [[7; WORD_LEN]; SHARE_WORD_COUNT];
            assert_eq!(
                share_to_words(&numbered, &mut words),
                Err(Error::InvalidShare)
            );
            assert_eq!(words, [[7; WORD_LEN]; SHARE_WORD_COUNT]);
        }
    }

    fn with_words(words: &ShareWords, given: &[(usize, &str)]) -> ShareWords {
        let mut changed = *words;
        for &(at, word) in given {
            changed[at] = [0; WORD_LEN];
            changed[at][..word.len()].copy_from_slice(word.as_bytes());
        }
        changed
    }

    /// Another word of the list, or a word not in it, is refused and found. The words stay.
    #[test]
    fn a_wrong_word_is_refused_and_found() {
        let share = unhex(VECTORS[0].0);
        let words = words_of(VECTORS[0].1);
        assert_eq!(wrong_share_word(&words), None);
        for (at, replacement, error) in [
            (0, "zebra", Error::InvalidChecksum),
            (7, "abandon", Error::InvalidChecksum),
            (20, "sworm", Error::UnknownWord),
        ] {
            let mut changed = with_words(&words, &[(at, replacement)]);
            assert_eq!(wrong_share_word(&changed), Some(at));
            let before = changed;
            let mut read_back: Share = [0x5a; SHARE_LEN];
            assert_eq!(share_from_words(&mut changed, &mut read_back), Err(error));
            assert_eq!((changed, read_back), (before, [0x5a; SHARE_LEN]));
        }
        let mut words = words;
        let mut read_back = [0; SHARE_LEN];
        share_from_words(&mut words, &mut read_back).unwrap();
        assert_eq!(read_back, share);
    }

    /// Every place, syndromes zero or not, and count of words out of the list.
    #[test]
    fn the_place_named_is_the_one_documented() {
        for located in 0..=u8::MAX {
            for unlisted in 0..=u8::MAX {
                for outside in [0, 1, 2, 21, u8::MAX] {
                    for (syndromes, clear) in [
                        ([0; CHECK], true),
                        ([1, 0, 0], false),
                        ([0, 1, 0], false),
                        ([0, 0, 1], false),
                    ] {
                        let expected = match outside {
                            0 => located,
                            1 if clear || located == unlisted => unlisted,
                            _ => NONE,
                        };
                        let place = named(located, syndromes, outside, unlisted);
                        assert_eq!(place, expected, "{located} {unlisted} {outside} {clear}");
                    }
                }
            }
        }
    }

    /// A word not in the list stands for no symbol: in place of "abandon" it is still found, and
    /// with another wrong word nothing is named.
    #[test]
    fn a_word_out_of_the_list_is_named_only_alone() {
        let words = words_of(VECTORS[2].1);
        assert_eq!(&words[1][..7], b"abandon");
        let named = |given: &[(usize, &str)]| wrong_share_word(&with_words(&words, given));
        assert_eq!(named(&[(1, "abandn")]), Some(1));
        assert_eq!(named(&[(1, "abandn"), (5, "zoo")]), None);
        assert_eq!(named(&[(1, "abandn"), (5, "abandn")]), None);
        assert_eq!(named(&[(19, "toddle"), (5, "zoo")]), None);
        assert_eq!(named(&[(19, "toddle")]), Some(19));
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    //! What the calls leave on the stack, read back from the memory of this process.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use super::{
        SHARE_WORD_COUNT, ShareWords, data_of, from_words_on_stack, share_from_words,
        share_to_words, symbols_of, to_words_on_stack, wrong_on_stack, wrong_share_word,
    };
    use crate::derive::STACK_WIPE;
    use crate::error::Error;
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::shares::{SHARE_LEN, Share};
    use crate::words::WORD_LEN;

    /// In KiB, for an optimised build and for one without optimisation.
    const NEEDS: [usize; 2] = [9, 68];
    const WIPES: [usize; 2] = [8, 64];

    /// A share whose bytes appear nowhere else, kept static so that only the copies looked for
    /// reach the stack.
    static SHARE: Share = [
        2, 130, 231, 76, 177, 22, 123, 224, 69, 170, 15, 116, 217, 62, 163, 8, 109, 210, 55, 156,
        1, 102, 203, 48, 149,
    ];

    fn other() -> Share {
        let mut other = SHARE.map(|byte| byte ^ 0xff);
        other[0] = 3;
        other
    }

    fn words_of(share: &Share) -> ShareWords {
        let mut words = [[0; WORD_LEN]; SHARE_WORD_COUNT];
        share_to_words(share, &mut words).unwrap();
        words
    }

    fn found(share: &Share) -> Vec<Vec<u8>> {
        let symbols: Vec<u8> = symbols_of(share)
            .iter()
            .flat_map(|symbol| symbol.to_le_bytes())
            .collect();
        let data: Vec<u8> = data_of(share)
            .iter()
            .flat_map(|symbol| symbol.to_le_bytes())
            .collect();
        let reversed: Vec<u8> = share.iter().rev().copied().collect();
        std::vec![
            share.to_vec(),
            reversed,
            symbols,
            data,
            words_of(share).concat()
        ]
    }

    fn pieces() -> Vec<Vec<u8>> {
        key_dependent(&found(&SHARE), &found(&other()))
    }

    #[test]
    fn writing_words_without_a_wipe_leaves_residue() {
        let range = below_pad(false, || {
            let mut words = [[0; WORD_LEN]; SHARE_WORD_COUNT];
            to_words_on_stack(&SHARE, &mut words).unwrap();
            black_box(&words);
        });
        assert!(residue(range, &pieces()) > 0);
    }

    #[test]
    fn reading_words_without_a_wipe_leaves_residue() {
        let words = words_of(&SHARE);
        let range = below_pad(false, || {
            let mut read = [0; SHARE_LEN];
            from_words_on_stack(&words, &mut read).unwrap();
            black_box(&read);
        });
        assert!(residue(range, &pieces()) > 0);
    }

    /// The words and the share are the caller's, above what is read.
    #[test]
    fn the_calls_leave_no_residue() {
        let pieces = pieces();
        let mut words = [[0; WORD_LEN]; SHARE_WORD_COUNT];
        assert_clean(&pieces, || share_to_words(&SHARE, &mut words).unwrap());
        let mut changed = words;
        changed[3] = words[4];
        assert_clean(&pieces, || {
            assert_eq!(black_box(wrong_share_word(&changed)), Some(3));
        });
        let mut read = [0; SHARE_LEN];
        assert_clean(&pieces, || {
            let refused = share_from_words(&mut changed, &mut read);
            assert_eq!(black_box(refused), Err(Error::InvalidChecksum));
        });
        assert_clean(&pieces, || share_from_words(&mut words, &mut read).unwrap());
        assert_eq!(read, SHARE);
    }

    #[test]
    fn the_wipe_reaches_its_depth() {
        let needs = 1024 * NEEDS[usize::from(cfg!(lethewis_unoptimised))];
        let mut words = [[0; WORD_LEN]; SHARE_WORD_COUNT];
        let mut read = [0; SHARE_LEN];
        for wiped in [
            depth_changed(|| share_to_words(&SHARE, &mut words).unwrap()),
            depth_changed(|| {
                black_box(wrong_share_word(&words));
            }),
            depth_changed(|| share_from_words(&mut words, &mut read).unwrap()),
        ] {
            assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
            assert!(wiped <= needs, "{wiped} bytes reached");
        }
    }

    #[test]
    fn the_wipe_is_deeper_than_the_work_on_words() {
        let words = words_of(&SHARE);
        for used in [
            depth_changed(|| {
                let mut written = [[0; WORD_LEN]; SHARE_WORD_COUNT];
                to_words_on_stack(&SHARE, &mut written).unwrap();
                black_box(&written);
            }),
            depth_changed(|| {
                let mut read = [0; SHARE_LEN];
                from_words_on_stack(&words, &mut read).unwrap();
                black_box(&read);
            }),
            depth_changed(|| {
                black_box(wrong_on_stack(&words));
            }),
        ] {
            std::println!("reading, writing or checking share words uses {used} bytes of stack");
            assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
        }
    }

    #[test]
    fn the_documentation_states_the_stack_the_calls_need() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(WIPES[build] * 1024, STACK_WIPE);
        let source = include_str!("words.rs");
        for call in ["share_to_words", "share_from_words", "wrong_share_word"] {
            let at = source.find(&std::format!("\npub fn {call}(")).unwrap();
            let mut lines: Vec<&str> = source[..at]
                .lines()
                .rev()
                .skip_while(|line| line.starts_with("#["))
                .take_while(|line| line.starts_with("///"))
                .map(|line| line.trim_start_matches("///").trim())
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
mod proofs {
    use super::{
        CHECK, DATA, NONE, SHARE_WORD_COUNT, changed_at, check_of, product, read, symbols_of,
        syndromes,
    };
    use crate::error::Error;
    use crate::shares::Share;

    /// The product worked out apart from [`product`]: the polynomials multiplied, then reduced by
    /// x^11 + x^2 + 1.
    fn reference(a: u16, b: u16) -> u16 {
        let mut wide: u32 = 0;
        for bit in 0..11 {
            if b >> bit & 1 == 1 {
                wide ^= u32::from(a) << bit;
            }
        }
        for bit in (11..21).rev() {
            if wide >> bit & 1 == 1 {
                wide ^= 0x805 << (bit - 11);
            }
        }
        wide as u16
    }

    fn any_symbol() -> u16 {
        let symbol: u16 = kani::any();
        kani::assume(symbol < 2048);
        symbol
    }

    fn any_symbols() -> [u16; SHARE_WORD_COUNT] {
        core::array::from_fn(|_| any_symbol())
    }

    fn any_share() -> Share {
        let share: Share = kani::any();
        kani::assume((1..=3).contains(&share[0]));
        share
    }

    /// Any change at `N` places in order, not all of them zero.
    fn changed_at_places<const N: usize>() -> ([u16; SHARE_WORD_COUNT], [usize; N]) {
        let places: [usize; N] = kani::any();
        let mut change = [0; SHARE_WORD_COUNT];
        let mut after = 0;
        for &at in &places {
            kani::assume(after <= at && at < SHARE_WORD_COUNT);
            after = at + 1;
            change[at] = any_symbol();
        }
        kani::assume(change != [0; SHARE_WORD_COUNT]);
        (change, places)
    }

    #[kani::proof]
    #[kani::unwind(12)]
    fn the_product_is_that_of_the_field() {
        let (a, b) = (any_symbol(), any_symbol());
        kani::assert(
            product(a, b) == reference(a, b),
            "the product is that of GF(2^11)",
        );
    }

    /// With the syndromes of a share's symbols zero, those of the symbols changed are those of the
    /// change alone.
    #[kani::proof]
    fn the_syndromes_add() {
        let (a, b) = (any_symbols(), any_symbols());
        let sum: [u16; SHARE_WORD_COUNT] = core::array::from_fn(|at| a[at] ^ b[at]);
        let [a1, a2, a3] = syndromes(&a);
        let [b1, b2, b3] = syndromes(&b);
        kani::assert(
            syndromes(&sum) == [a1 ^ b1, a2 ^ b2, a3 ^ b3],
            "the syndromes of a sum are the sum of the syndromes",
        );
    }

    /// Kissat solves this one in half the time of the default solver.
    #[kani::proof]
    #[kani::solver(kissat)]
    fn up_to_three_changes_are_seen() {
        let (change, _) = changed_at_places::<3>();
        kani::assert(
            syndromes(&change) != [0; CHECK],
            "a change at up to three places has syndromes",
        );
    }

    #[kani::proof]
    fn one_change_is_found() {
        let (one, [at]) = changed_at_places::<1>();
        kani::assert(
            usize::from(changed_at(syndromes(&one))) == at,
            "one change is found",
        );
    }

    /// With syndromes that add and three changes seen, two changes are never taken for one.
    #[kani::proof]
    #[kani::unwind(22)]
    fn a_place_is_named_only_for_one_change_there() {
        let found: [u16; CHECK] = core::array::from_fn(|_| any_symbol());
        let named = changed_at(found);
        if named != NONE {
            let at = usize::from(named);
            // The inverse of x is x^10 + x, as x^11 = x^2 + 1.
            let mut value = found[0];
            for _ in at..SHARE_WORD_COUNT - 1 {
                value = product(value, 0x402);
            }
            let mut one = [0; SHARE_WORD_COUNT];
            one[at] = value;
            kani::assert(
                value != 0 && syndromes(&one) == found,
                "the syndromes are those of one change at the place named",
            );
        }
        kani::assert(
            named == NONE || usize::from(named) < SHARE_WORD_COUNT,
            "a place named is a place of a word",
        );
        kani::cover!(named != NONE, "a place is named");
        kani::cover!(named == NONE, "no place is named");
    }

    #[kani::proof]
    fn a_share_is_read_back_from_its_symbols() {
        let share = any_share();
        let symbols = symbols_of(&share);
        kani::assert(
            symbols.iter().all(|&symbol| symbol < 2048),
            "every symbol is a number of a word",
        );
        let mut read_back: Share = kani::any();
        let result = read(&symbols, true, &mut read_back);
        kani::assert(
            result == Ok(()) && read_back == share,
            "the share is read back",
        );
    }

    #[kani::proof]
    fn symbols_are_read_exactly_when_those_of_a_share() {
        let symbols = any_symbols();
        let listed: bool = kani::any();
        let given: Share = kani::any();
        let mut read_back = given;
        let result = read(&symbols, listed, &mut read_back);
        let data: [u16; DATA] = core::array::from_fn(|at| symbols[at]);
        let coded = symbols[DATA..] == check_of(&data);
        // 4 bits of version, then 2 of the number, from the top of the first symbol.
        let later = data[0] >> 7 != 0;
        let unnumbered = data[0] >> 5 & 3 == 0;
        kani::assert(
            coded == (syndromes(&symbols) == [0; CHECK]),
            "symbols followed by their check are those with no syndromes",
        );
        kani::assert(
            result
                == if !listed {
                    Err(Error::UnknownWord)
                } else if !coded {
                    Err(Error::InvalidChecksum)
                } else if later || unnumbered {
                    Err(Error::InvalidShare)
                } else {
                    Ok(())
                },
            "symbols are read exactly when listed, coded, of this version and numbered",
        );
        if result.is_ok() {
            kani::assert(
                symbols_of(&read_back) == symbols,
                "the share read is the one of the symbols",
            );
        } else {
            kani::assert(read_back == given, "a refusal writes nothing");
        }
        kani::cover!(result.is_ok(), "symbols are read");
        kani::cover!(result == Err(Error::InvalidChecksum), "a check that fails");
        kani::cover!(
            result == Err(Error::InvalidShare) && later,
            "a later version"
        );
        kani::cover!(
            result == Err(Error::InvalidShare) && unnumbered,
            "no number"
        );
    }
}
