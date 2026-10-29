// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! A key from a secret of 16 bytes split into three shares, any two of which give the secret back:
//! Shamir's scheme over GF(2^8), a line for each byte of the secret and of its check.

use crate::derive::{Branch, SECRET_LEN, derive_from_secret, wipe_stack};
use crate::entropy::Entropy;
use crate::error::Error;
use crate::key::wipe;
use crate::record::Purpose;
use crate::slots::{Handle, Slots};

/// How many shares a secret is split into; any two of them give it back.
pub const SHARE_COUNT: usize = 3;
/// The length of a share in bytes.
pub const SHARE_LEN: usize = 25;

/// One share of a split: its number, 1, 2 or 3; four bytes that mark its split; and 20 bytes.
pub type Share = [u8; SHARE_LEN];
/// The three shares of a split, numbered 1, 2 and 3 in that order.
pub type Shares = [Share; SHARE_COUNT];

/// The length of the mark of a split.
const MARK_LEN: usize = 4;
/// The length of the check of a secret, split with it.
pub(crate) const CHECK_LEN: usize = 4;
/// Where the bytes of a share begin, past its number and its mark.
const BYTES_AT: usize = 1 + MARK_LEN;
/// Where the bytes of the check begin, past those of the secret.
const CHECK_AT: usize = BYTES_AT + SECRET_LEN;
/// The numbers of the shares, where each line is read.
const NUMBERS: [u8; SHARE_COUNT] = [1, 2, 3];

/// One draw of 64 bytes for a split: the secret, a coefficient for each of its bytes, and in the
/// first bytes of the third part the mark and a coefficient for each byte of the check; the rest
/// goes unused.
type Drawn = [[u8; SECRET_LEN]; 4];

impl<'a> Slots<'a> {
    /// Creates a 32-byte wrapping key from 16 random bytes in a free slot, as a set of one whose key
    /// is the primary, and writes three shares of those bytes and of their check into `shares`, any
    /// two of which give them back. One draw of 64 bytes from `entropy`, hedged with the key of the
    /// epoch, gives the bytes, a coefficient for each byte and for each byte of the check, and the
    /// mark of the split, so a share alone fits every secret alike. [`Self::derive_from_shares`]
    /// derives the same key from any two of the shares; nothing else gives them again. `entropy` is
    /// asked once, and only when a slot is free.
    ///
    /// Needs 10 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the hedge, the derivation of the check, the derivation of the
    /// key, the derivation of its identifier, the whole load and the whole call are each followed by
    /// a wipe of 8 KiB, or 64 KiB, below them. A build that optimises this crate but not the hash
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, [`Error::EntropyFailed`] if `entropy` fails,
    /// [`Error::DerivationFailed`] if the hedge, the check, the key or its identifier cannot be
    /// derived, and
    /// [`Error::DuplicateKey`] if these slots hold the key already. `shares` is then left as it
    /// was, and no slot changes.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through after the random bytes are wiped, and no
    /// slot changes.
    pub fn generate_shares(
        &mut self,
        entropy: &mut (impl Entropy + ?Sized),
        shares: &mut Shares,
    ) -> Result<Handle<'a>, Error> {
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        let generated = self.generate_shares_on_stack(entropy, shares);
        wipe_stack();
        generated
    }

    /// Derives the key [`Self::generate_shares`] created from any two of its shares, in either
    /// order, into a free slot, as a set of one whose key is the primary, and wipes both shares.
    /// The numbers and the marks of the shares are judged first; the bytes are then combined in
    /// steps with no branch on them, and the secret they give is taken only with its check.
    ///
    /// Needs 10 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the check, the derivation of the key, the
    /// derivation of its identifier, the whole load and the whole call are each followed by a wipe
    /// of 8 KiB, or 64 KiB, below them. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidShare`] if a share is numbered other than 1, 2 or 3, [`Error::MixedShares`]
    /// if their marks differ, [`Error::SameShare`] if their numbers are the same,
    /// [`Error::ChangedShare`] if the secret they give fails its check, [`Error::NoFreeSlot`] if no
    /// slot is free, [`Error::DerivationFailed`] if the check, the key or its identifier cannot be
    /// derived, and [`Error::DuplicateKey`] if these slots hold the key already. The shares are
    /// then left as they were, and no slot changes.
    pub fn derive_from_shares(
        &mut self,
        first: &mut Share,
        second: &mut Share,
    ) -> Result<Handle<'a>, Error> {
        let derived = self.derive_from_shares_on_stack(first, second);
        wipe_stack();
        if derived.is_ok() {
            wipe(first);
            wipe(second);
        }
        derived
    }

    /// The generation itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn generate_shares_on_stack(
        &mut self,
        entropy: &mut (impl Entropy + ?Sized),
        shares: &mut Shares,
    ) -> Result<Handle<'a>, Error> {
        let mut drawn: Drawn = [[0; SECRET_LEN]; 4];
        let mut check = [0; CHECK_LEN];
        let generated = crate::timing::with(|| {
            self.draw(entropy, Branch::HedgeShares, drawn.as_flattened_mut())
        })
        .and_then(|()| {
            let [secret, ..] = drawn;
            crate::timing::with(|| check_of(&secret, &mut check))
                .and_then(|()| self.derive_into(&secret, Purpose::Wrap, Branch::FromShares))
        });
        if generated.is_ok() {
            crate::timing::with(|| split(&drawn, check, shares));
        }
        generated
    }

    /// The derivation itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn derive_from_shares_on_stack(
        &mut self,
        first: &Share,
        second: &Share,
    ) -> Result<Handle<'a>, Error> {
        let mut secret = [0; SECRET_LEN];
        let mut carried = [0; CHECK_LEN];
        let mut check = [0; CHECK_LEN];
        crate::timing::with(|| {
            combine(first, second, &mut secret, &mut carried)
                .and_then(|()| check_of(&secret, &mut check))
                .and_then(|()| {
                    same_check(check, carried)
                        .then_some(())
                        .ok_or(Error::ChangedShare)
                })
        })
        .and_then(|()| self.derive_into(&secret, Purpose::Wrap, Branch::FromShares))
    }
}

/// Writes into `check` the check of `secret` that its shares carry.
fn check_of(secret: &[u8; SECRET_LEN], check: &mut [u8; CHECK_LEN]) -> Result<(), Error> {
    derive_from_secret(secret, None, Branch::ShareCheck, check).map_err(|_| Error::DerivationFailed)
}

/// Whether two checks are the same, compared in constant time. Kept out of line, so that the check
/// of its machine code finds it.
#[inline(never)]
fn same_check(a: [u8; CHECK_LEN], b: [u8; CHECK_LEN]) -> bool {
    #[cfg(not(kani))]
    {
        use ctutils::CtEq;
        a.ct_eq(&b).to_bool()
    }
    // The comparison ends in inline assembly, which Kani cannot model.
    #[cfg(kani)]
    {
        model::same_check(a, b)
    }
}

/// What stands in under Kani for the comparison that ends in inline assembly.
#[cfg(kani)]
mod model {
    use super::CHECK_LEN;

    /// [`super::same_check`] as Kani sees it: the two checks as numbers.
    pub(super) fn same_check(a: [u8; CHECK_LEN], b: [u8; CHECK_LEN]) -> bool {
        u32::from_ne_bytes(a) == u32::from_ne_bytes(b)
    }
}

/// Writes into `shares` the three shares of the secret `drawn` begins with and of its check,
/// `check`: each holds its number, the mark drawn, and the value at its number of the line through
/// each byte of the secret and of the check with the coefficient drawn for that byte.
fn split(drawn: &Drawn, check: [u8; CHECK_LEN], shares: &mut Shares) {
    #[cfg(test)]
    crate::timing::note();
    let [secret, coefficients, rest, _] = *drawn;
    let [m0, m1, m2, m3, c0, c1, c2, c3, ..] = rest;
    for (share, number) in shares.iter_mut().zip(NUMBERS) {
        for (byte, value) in share.iter_mut().zip([number, m0, m1, m2, m3]) {
            *byte = value;
        }
        for ((byte, &value), &coefficient) in share
            .iter_mut()
            .skip(BYTES_AT)
            .zip(&secret)
            .zip(&coefficients)
        {
            *byte = share_byte(value, coefficient, number);
        }
        for ((byte, &value), &coefficient) in share
            .iter_mut()
            .skip(CHECK_AT)
            .zip(&check)
            .zip(&[c0, c1, c2, c3])
        {
            *byte = share_byte(value, coefficient, number);
        }
    }
}

/// The byte of the share numbered `number` of a byte of the secret, `secret`, on the line with
/// `coefficient`.
fn share_byte(secret: u8, coefficient: u8, number: u8) -> u8 {
    secret ^ product(coefficient, number)
}

/// Writes into `secret` and `check` the bytes that `first` and `second`, two shares of one split,
/// stand for: the value at zero of the line through each pair of their bytes. The numbers and the
/// marks are judged first, and nothing is written when they are refused.
fn combine(
    first: &Share,
    second: &Share,
    secret: &mut [u8; SECRET_LEN],
    check: &mut [u8; CHECK_LEN],
) -> Result<(), Error> {
    #[cfg(test)]
    crate::timing::note();
    let (first_number, first_mark) = number_and_mark(first);
    let (second_number, second_mark) = number_and_mark(second);
    if !NUMBERS.contains(&first_number) || !NUMBERS.contains(&second_number) {
        return Err(Error::InvalidShare);
    }
    if first_mark != second_mark {
        return Err(Error::MixedShares);
    }
    if first_number == second_number {
        return Err(Error::SameShare);
    }
    // The coefficients of Lagrange at zero, from the numbers alone: in GF(2^8) a difference is a
    // sum.
    let scale = inverse(first_number ^ second_number);
    let for_first = product(second_number, scale);
    let for_second = product(first_number, scale);
    let at_zero = |a, b| product(a, for_first) ^ product(b, for_second);
    for ((byte, &a), &b) in secret
        .iter_mut()
        .zip(first.iter().skip(BYTES_AT))
        .zip(second.iter().skip(BYTES_AT))
    {
        *byte = at_zero(a, b);
    }
    for ((byte, &a), &b) in check
        .iter_mut()
        .zip(first.iter().skip(CHECK_AT))
        .zip(second.iter().skip(CHECK_AT))
    {
        *byte = at_zero(a, b);
    }
    Ok(())
}

/// The number and the mark of `share`.
fn number_and_mark(share: &Share) -> (u8, [u8; MARK_LEN]) {
    let [number, m0, m1, m2, m3, ..] = *share;
    (number, [m0, m1, m2, m3])
}

/// The product of `a` and `b` in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, the field of AES, in
/// steps with no branch on either. Kept out of line, so that the check of its machine code finds
/// it.
#[inline(never)]
fn product(a: u8, b: u8) -> u8 {
    let mut product = 0;
    let mut a = a;
    for bit in 0..8 {
        product ^= a & (b.wrapping_shr(bit) & 1).wrapping_neg();
        a = a.wrapping_shl(1) ^ (0x1b & a.wrapping_shr(7).wrapping_neg());
    }
    product
}

/// The inverse of `a` in the field: `a` to the power 254, which is zero for zero.
fn inverse(a: u8) -> u8 {
    let mut power = product(a, a);
    let mut inverse = power;
    for _ in 0..6 {
        power = product(power, power);
        inverse = product(inverse, power);
    }
    inverse
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "the field worked out apart from the code takes sums of logarithms"
)]
pub(crate) mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{
        BYTES_AT, CHECK_LEN, Drawn, MARK_LEN, NUMBERS, SHARE_COUNT, SHARE_LEN, Share, Shares,
        check_of, combine, inverse, product, split,
    };
    use crate::derive::SECRET_LEN;
    use crate::derive::direct::hedged_directly;
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::tests::{Counting, Failing, Random, Recording};
    use crate::record::Purpose;
    use crate::slots::{Slot, Slots};
    use crate::words::tests::words_for;

    /// The shares of the draw 0, 1, ..., 63, worked out by an independent implementation of the
    /// field by tables of logarithms and of HKDF-SHA-256 for the check: they fix the split for every
    /// share already written.
    const SHARES: [&str; SHARE_COUNT] = [
        "012021222310101010101010101010101010101010275b69d3",
        "0220212223202326252c2f2a29383b3e3d343732314b3403ba",
        "032021222330323436383a3c3e20222426282a2c2e6f11259d",
    ];

    /// Keys from shares, computed by an independent implementation of HKDF-SHA-256 from the
    /// documented salt and label: they fix the derivation for every split already made.
    const KEYS: [(&str, &str); 4] = [
        (
            "00000000000000000000000000000000",
            "bedf2365d433980911c4f650117cf77aeb8760e4e181f8dacb4b75c541746ca8",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "39273cc880f3adb6505082d44671da410f362b81a11fe1b995649b2e464bb252",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "f211cf80651339bba2a897293419e903b85a7bc2b4f5f054c1f21c23af37f2fa",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "0fdbcb93968dc11e6a70e4ca7b646021a3f25ef47850f7ce0a87f3251d1f2433",
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

    /// The field worked out apart from [`product`]: the powers of 3, a generator, and their
    /// logarithms.
    struct Tables {
        powers: [u8; 255],
        logarithms: [usize; 256],
    }

    impl Tables {
        fn new() -> Self {
            let mut tables = Self {
                powers: [0; 255],
                logarithms: [0; 256],
            };
            let mut power: u8 = 1;
            for exponent in 0..255 {
                tables.powers[exponent] = power;
                tables.logarithms[usize::from(power)] = exponent;
                let doubled = (power << 1) ^ if power & 0x80 == 0 { 0 } else { 0x1b };
                power ^= doubled;
            }
            tables
        }

        fn product(&self, a: u8, b: u8) -> u8 {
            if a == 0 || b == 0 {
                return 0;
            }
            self.powers[(self.logarithms[usize::from(a)] + self.logarithms[usize::from(b)]) % 255]
        }
    }

    /// A draw of the secret, the coefficients of its bytes and of the bytes of its check, and the
    /// mark given.
    pub(crate) fn drawn_of(
        secret: &[u8; SECRET_LEN],
        coefficients: &[u8; SECRET_LEN + CHECK_LEN],
        mark: [u8; MARK_LEN],
    ) -> Drawn {
        let mut rest = [0; SECRET_LEN];
        rest[..MARK_LEN].copy_from_slice(&mark);
        rest[MARK_LEN..][..CHECK_LEN].copy_from_slice(&coefficients[SECRET_LEN..]);
        [
            *secret,
            coefficients[..SECRET_LEN].try_into().unwrap(),
            rest,
            [0; SECRET_LEN],
        ]
    }

    /// The check of `secret`.
    pub(crate) fn check_for(secret: &[u8; SECRET_LEN]) -> [u8; CHECK_LEN] {
        let mut check = [0; CHECK_LEN];
        check_of(secret, &mut check).unwrap();
        check
    }

    pub(crate) fn shares_of(drawn: &Drawn) -> Shares {
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        split(drawn, check_for(&drawn[0]), &mut shares);
        shares
    }

    #[test]
    fn a_share_is_its_number_its_mark_and_its_bytes() {
        assert_eq!(SHARE_LEN, 1 + MARK_LEN + SECRET_LEN + CHECK_LEN);
        assert_eq!(BYTES_AT, 1 + MARK_LEN);
        assert_eq!(NUMBERS.len(), SHARE_COUNT);
    }

    /// The products FIPS 197 works out in its section 4.2.
    #[test]
    fn the_product_is_that_of_fips_197() {
        for (b, expected) in [
            (0x83, 0xc1),
            (0x13, 0xfe),
            (0x02, 0xae),
            (0x04, 0x47),
            (0x08, 0x8e),
            (0x10, 0x07),
        ] {
            assert_eq!(product(0x57, b), expected, "{b:#04x}");
        }
    }

    #[test]
    fn every_product_is_that_of_the_tables() {
        let tables = Tables::new();
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                assert_eq!(product(a, b), tables.product(a, b), "{a:#04x} {b:#04x}");
            }
        }
    }

    #[test]
    fn every_byte_but_zero_has_its_inverse() {
        assert_eq!(inverse(0), 0);
        for a in 1..=u8::MAX {
            assert_eq!(product(a, inverse(a)), 1, "{a:#04x}");
        }
    }

    #[test]
    fn the_shares_are_those_of_an_independent_split() {
        let drawn: [u8; 64] = core::array::from_fn(|at| u8::try_from(at).unwrap());
        let drawn: Drawn =
            core::array::from_fn(|part| drawn[part * 16..][..16].try_into().unwrap());
        let shares = shares_of(&drawn);
        for (share, expected) in shares.iter().zip(SHARES) {
            assert_eq!(share, &unhex::<SHARE_LEN>(expected));
        }
    }

    /// Random secrets, coefficients and marks: every share is the one the tables give, and any
    /// two of them in either order give the secret and its check back.
    #[test]
    fn any_two_shares_give_the_secret_back() {
        let tables = Tables::new();
        let mut random = Random(5);
        for round in 0..1000 {
            let secret = random.bytes();
            let coefficients: [u8; SECRET_LEN + CHECK_LEN] = random.bytes();
            let mark = random.bytes();
            let check = check_for(&secret);
            let shares = shares_of(&drawn_of(&secret, &coefficients, mark));
            for (share, number) in shares.iter().zip(NUMBERS) {
                let mut expected = std::vec![number];
                expected.extend_from_slice(&mark);
                expected.extend(
                    secret
                        .iter()
                        .chain(&check)
                        .zip(&coefficients)
                        .map(|(&byte, &coefficient)| byte ^ tables.product(coefficient, number)),
                );
                assert_eq!(&share[..], &expected[..], "round {round}");
            }
            for first in 0..SHARE_COUNT {
                for second in (0..SHARE_COUNT).filter(|&second| second != first) {
                    let mut read = ([0x5a; SECRET_LEN], [0x5a; CHECK_LEN]);
                    combine(&shares[first], &shares[second], &mut read.0, &mut read.1).unwrap();
                    assert_eq!(read, (secret, check), "round {round}: {first} and {second}");
                }
            }
        }
    }

    #[test]
    fn shares_are_refused_by_their_number_then_their_mark_then_twice() {
        let shares = shares_of(&drawn_of(&[1; 16], &[2; 20], [3, 4, 5, 6]));
        let other = shares_of(&drawn_of(&[1; 16], &[2; 20], [3, 4, 5, 7]));
        let numbered = |number: u8, share: &Share| {
            let mut share = *share;
            share[0] = number;
            share
        };
        for (first, second, error) in [
            (numbered(0, &shares[0]), shares[1], Error::InvalidShare),
            (shares[0], numbered(4, &shares[1]), Error::InvalidShare),
            (numbered(0xff, &shares[0]), other[1], Error::InvalidShare),
            (shares[0], other[1], Error::MixedShares),
            (shares[0], other[0], Error::MixedShares),
            (shares[1], shares[1], Error::SameShare),
            (shares[2], numbered(3, &shares[0]), Error::SameShare),
        ] {
            let mut read = ([0x5a; SECRET_LEN], [0x5a; CHECK_LEN]);
            assert_eq!(
                combine(&first, &second, &mut read.0, &mut read.1),
                Err(error)
            );
            assert_eq!(
                read,
                ([0x5a; SECRET_LEN], [0x5a; CHECK_LEN]),
                "nothing is written"
            );
        }
    }

    fn slots_of<'a>(memory: &'a mut [Slot], epoch: &'a mut Epoch) -> Slots<'a> {
        Slots::new(memory, epoch, 1, &mut [9; 32])
    }

    #[test]
    fn a_key_from_shares_matches_another_implementation() {
        for (secret, key) in KEYS {
            let mut memory = [const { Slot::empty() }; 2];
            let mut epoch = Epoch::empty();
            let mut slots = slots_of(&mut memory, &mut epoch);
            let [mut first, mut second, _] =
                shares_of(&drawn_of(&unhex(secret), &[0xc3; 20], [1, 2, 3, 4]));
            slots.derive_from_shares(&mut second, &mut first).unwrap();
            assert_eq!(
                slots.import32(Purpose::Wrap, &mut unhex(key)).err(),
                Some(Error::DuplicateKey),
                "{secret}"
            );
        }
    }

    /// The same 16 bytes give one key as words and another as shares.
    #[test]
    fn a_key_from_shares_is_not_the_key_from_words_of_its_bytes() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let secret = [0x42; 16];
        slots.derive_from_words(&mut words_for(&secret)).unwrap();
        let [mut first, _, mut third] = shares_of(&drawn_of(&secret, &[7; 20], [0; 4]));
        slots.derive_from_shares(&mut first, &mut third).unwrap();
    }

    #[test]
    fn generated_shares_derive_the_generated_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut shares = [[7; SHARE_LEN]; SHARE_COUNT];
        let generated = slots.generate_shares(&mut Counting, &mut shares).unwrap();
        let counted: [u8; 64] = core::array::from_fn(|at| u8::try_from(at + 1).unwrap());
        let hedged = hedged_directly(&[9; 32], 0, b"hedge shares", &counted, 64);
        let drawn: Drawn =
            core::array::from_fn(|part| hedged[part * 16..][..16].try_into().unwrap());
        assert_eq!(
            shares,
            shares_of(&drawn),
            "the shares of the source's bytes, hedged"
        );
        let [mut first, mut second, mut third] = shares;
        assert_eq!(
            slots.derive_from_shares(&mut third, &mut second).err(),
            Some(Error::DuplicateKey),
            "the key the shares derive is the one generated"
        );
        slots.release(generated).unwrap();
        slots.derive_from_shares(&mut first, &mut third).unwrap();
        assert_eq!([first, third], [[0; SHARE_LEN]; 2]);
    }

    #[test]
    fn generation_asks_the_source_once_for_64_bytes() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut source = Recording::default();
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        slots.generate_shares(&mut source, &mut shares).unwrap();
        assert_eq!((source.calls, source.asked), (1, 64));
        let before = shares;
        assert_eq!(
            slots.generate_shares(&mut source, &mut shares).err(),
            Some(Error::NoFreeSlot)
        );
        assert_eq!(
            source.calls, 1,
            "without a free slot the source is not asked"
        );
        assert_eq!(shares, before);
    }

    #[test]
    fn a_failed_generation_leaves_the_shares_and_the_slots() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut shares = [[7; SHARE_LEN]; SHARE_COUNT];
        assert_eq!(
            slots.generate_shares(&mut Failing, &mut shares).err(),
            Some(Error::EntropyFailed)
        );
        assert_eq!(shares, [[7; SHARE_LEN]; SHARE_COUNT]);
        slots.generate_shares(&mut Counting, &mut shares).unwrap();
    }

    #[test]
    fn shares_are_wiped_only_when_their_key_is_derived() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let shares = shares_of(&drawn_of(&[1; 16], &[2; 20], [3; 4]));
        let other = shares_of(&drawn_of(&[1; 16], &[2; 20], [4; 4]));
        let mut unnumbered = shares[0];
        unnumbered[0] = 0;
        let mut changed = shares[0];
        changed[BYTES_AT] ^= 1;
        for (mut first, mut second, error) in [
            (unnumbered, shares[1], Error::InvalidShare),
            (shares[0], other[1], Error::MixedShares),
            (shares[2], shares[2], Error::SameShare),
            (changed, shares[1], Error::ChangedShare),
        ] {
            let before = (first, second);
            assert_eq!(
                slots.derive_from_shares(&mut first, &mut second).err(),
                Some(error)
            );
            assert_eq!((first, second), before);
        }
        let [mut first, mut second, _] = shares;
        slots.derive_from_shares(&mut first, &mut second).unwrap();
        assert_eq!([first, second], [[0; SHARE_LEN]; 2]);
        let [mut first, _, mut third] = shares_of(&drawn_of(&[5; 16], &[2; 20], [3; 4]));
        assert_eq!(
            slots.derive_from_shares(&mut first, &mut third).err(),
            Some(Error::NoFreeSlot)
        );
        assert_ne!(first, [0; SHARE_LEN]);
        let mut unnumbered = first;
        unnumbered[0] = 4;
        assert_eq!(
            slots.derive_from_shares(&mut unnumbered, &mut third).err(),
            Some(Error::InvalidShare),
            "the shares are read before a slot is looked for"
        );
        let mut changed = first;
        changed[SHARE_LEN - 1] ^= 1;
        assert_eq!(
            slots.derive_from_shares(&mut changed, &mut third).err(),
            Some(Error::ChangedShare),
            "the check is judged before a slot is looked for"
        );
    }

    /// A change to any bit of the bytes of either share, or shares of two splits that share a
    /// mark: the secret the shares give fails its check, and nothing changes.
    #[test]
    fn a_changed_share_is_refused() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let [first, second, _] = shares_of(&drawn_of(&[1; 16], &[2; 20], [3; 4]));
        let [_, other, _] = shares_of(&drawn_of(&[1; 16], &[9; 20], [3; 4]));
        let mut pairs = std::vec![(first, other)];
        for at in BYTES_AT..SHARE_LEN {
            for bit in 0..8 {
                let mut changed = first;
                changed[at] ^= 1 << bit;
                pairs.push((changed, second));
                pairs.push((second, changed));
            }
        }
        for (mut first, mut second) in pairs {
            let before = (first, second);
            assert_eq!(
                slots.derive_from_shares(&mut first, &mut second).err(),
                Some(Error::ChangedShare)
            );
            assert_eq!((first, second), before);
        }
        let (mut first, mut second) = (first, second);
        slots.derive_from_shares(&mut first, &mut second).unwrap();
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    //! What a derivation from shares and a generation of shares leave on the stack, read back from
    //! the memory of this process.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use super::tests::{check_for, shares_of};
    use super::{
        BYTES_AT, CHECK_LEN, Drawn, SHARE_COUNT, SHARE_LEN, Share, Shares, combine, split,
    };
    use crate::derive::direct::hedged_directly;
    use crate::derive::stack::{epoch_bytes, secrets, secrets_for, secrets_of};
    use crate::derive::{Branch, SALT, SECRET_LEN, STACK_WIPE, derive_from_secret};
    use crate::entropy::{Entropy, EntropyError};
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::KeyLength;
    use crate::record::Purpose;
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::slots::{Slot, Slots};

    /// The stack, in KiB, that a derivation from shares and a generation of shares need, and the
    /// depth of the wipe after them, in an optimised build and in one without optimisation.
    const NEEDS: [usize; 2] = [10, 72];
    const WIPES: [usize; 2] = [8, 64];

    /// Bytes whose values appear nowhere else, in static memory, so that no copy of them is made
    /// on the stack but the ones looked for.
    static BYTES: [u8; 64] = [
        29, 130, 231, 76, 177, 22, 123, 224, 69, 170, 15, 116, 217, 62, 163, 8, 109, 210, 55, 156,
        1, 102, 203, 48, 149, 250, 95, 196, 41, 142, 243, 88, 189, 34, 135, 236, 81, 182, 27, 128,
        229, 74, 175, 20, 121, 222, 67, 168, 13, 114, 215, 60, 161, 6, 107, 208, 53, 154, 255, 100,
        201, 46, 147, 248,
    ];

    fn drawn_from(bytes: &[u8; 64]) -> Drawn {
        let mut drawn: Drawn = [[0; SECRET_LEN]; 4];
        drawn.as_flattened_mut().copy_from_slice(bytes);
        drawn
    }

    fn drawn() -> Drawn {
        drawn_from(&BYTES)
    }

    fn other_drawn() -> Drawn {
        drawn_from(&BYTES.map(|byte| byte ^ 0xff))
    }

    /// Writes [`BYTES`].
    struct Fixed;

    impl Entropy for Fixed {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&BYTES);
            Ok(())
        }
    }

    /// The secrets the shares of `drawn` are: their bytes, alone and with the number and the
    /// mark, either way round.
    fn share_secrets(shares: &Shares) -> Vec<Vec<u8>> {
        let mut found = Vec::new();
        for share in shares {
            for bytes in [&share[..], &share[BYTES_AT..]] {
                found.push(bytes.to_vec());
                found.push(bytes.iter().rev().copied().collect());
            }
        }
        found
    }

    /// The secrets a derivation from two shares of `drawn` handles: the shares, the secret they
    /// give either way round, those of HKDF from the secret for its check and for the key, and
    /// those of the identifier of the key.
    fn derivation_secrets(drawn: &Drawn) -> Vec<Vec<u8>> {
        let [secret, ..] = drawn;
        let mut found = share_secrets(&shares_of(drawn));
        found.push(secret.to_vec());
        found.push(secret.iter().rev().copied().collect());
        found.extend(secrets_for(secret, SALT, Branch::ShareCheck, None));
        found.extend(secrets_for(
            secret,
            SALT,
            Branch::FromShares,
            Some(Purpose::Wrap),
        ));
        let mut key = [0; 64];
        derive_from_secret(
            secret,
            Some(Purpose::Wrap),
            Branch::FromShares,
            &mut key[..32],
        )
        .unwrap();
        found.extend(secrets(&key, SALT, KeyLength::Bytes32, Branch::KeyId));
        found
    }

    fn pieces() -> Vec<Vec<u8>> {
        key_dependent(
            &derivation_secrets(&drawn()),
            &derivation_secrets(&other_drawn()),
        )
    }

    fn slots_of<'a>(memory: &'a mut [Slot], epoch: &'a mut Epoch) -> Slots<'a> {
        Slots::new(memory, epoch, 1, &mut epoch_bytes(0))
    }

    /// Combines `first` and `second` into a secret and its check in a frame of its own.
    #[inline(never)]
    fn combined(first: &Share, second: &Share) {
        let mut read = ([0; SECRET_LEN], [0; CHECK_LEN]);
        combine(first, second, &mut read.0, &mut read.1).unwrap();
        black_box(&read);
    }

    /// The test can see residue: combining shares without a wipe leaves some.
    #[test]
    fn combining_shares_without_a_wipe_leaves_residue() {
        let [first, second, _] = shares_of(&drawn());
        let range = below_pad(false, || combined(&first, &second));
        assert!(residue(range, &pieces()) > 0);
    }

    /// Splits the draw into shares in a frame of its own.
    #[inline(never)]
    fn splitting(check: [u8; CHECK_LEN]) {
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        split(&drawn(), check, &mut shares);
        black_box(&shares);
    }

    /// The same for splitting a secret.
    #[test]
    fn splitting_without_a_wipe_leaves_residue() {
        let check = check_for(&drawn()[0]);
        let range = below_pad(false, || splitting(check));
        assert!(residue(range, &pieces()) > 0);
    }

    #[test]
    fn a_derivation_from_shares_leaves_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let [given_first, _, given_third] = shares_of(&drawn());
        assert_clean(&pieces, || {
            let mut first = given_first;
            let mut third = given_third;
            slots.derive_from_shares(&mut third, &mut first).unwrap();
            black_box((&first, &third));
        });
    }

    /// A derivation that fails after the key is derived, because the slots hold it already.
    #[test]
    fn a_failed_derivation_from_shares_leaves_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let [mut first, mut second, mut third] = shares_of(&drawn());
        slots.derive_from_shares(&mut first, &mut second).unwrap();
        // A failure leaves the shares as they were, in the caller's buffers, above what is read.
        let [mut first, ..] = shares_of(&drawn());
        assert_clean(&pieces, || {
            let derived = slots.derive_from_shares(&mut third, &mut first);
            assert_eq!(black_box(derived).err(), Some(Error::DuplicateKey));
        });
    }

    /// Shares whose secret fails its check, refused after the check is derived.
    #[test]
    fn shares_that_fail_their_check_leave_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let [mut first, mut second, _] = shares_of(&drawn());
        second[SHARE_LEN - 1] ^= 1;
        assert_clean(&pieces, || {
            let derived = slots.derive_from_shares(&mut first, &mut second);
            assert_eq!(black_box(derived).err(), Some(Error::ChangedShare));
        });
    }

    /// Shares of two splits, refused before their bytes are combined.
    #[test]
    fn refused_shares_leave_no_residue() {
        let mut first = shares_of(&drawn())[0];
        let mut other = shares_of(&other_drawn())[1];
        let pieces = key_dependent(
            &share_secrets(&[first, other, [0; SHARE_LEN]]),
            &share_secrets(&shares_of(&drawn_from(&BYTES.map(|byte| byte ^ 0x55)))),
        );
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        assert_clean(&pieces, || {
            let derived = slots.derive_from_shares(&mut first, &mut other);
            assert_eq!(black_box(derived).err(), Some(Error::MixedShares));
        });
    }

    #[test]
    fn a_generation_of_shares_leaves_no_residue() {
        let hedged = |bytes: &[u8; 64], epoch: &[u8; 32]| -> [u8; 64] {
            hedged_directly(epoch, 0, b"hedge shares", bytes, 64)
                .try_into()
                .unwrap()
        };
        // What the source gave, the draw once it is hedged and what it splits into, and the hedge
        // itself, the key of the epoch among its secrets.
        let found = |bytes: &[u8; 64], epoch: &[u8; 32]| {
            let drawn = hedged(bytes, epoch);
            let mut material = bytes.to_vec();
            material.extend_from_slice(&0_u64.to_le_bytes());
            let mut found = derivation_secrets(&drawn_from(&drawn));
            found.push(drawn.to_vec());
            found.extend(secrets_of(&material, epoch, Branch::HedgeShares));
            found.push(bytes.to_vec());
            found
        };
        let pieces = key_dependent(
            &found(&BYTES, &epoch_bytes(0)),
            &found(&BYTES.map(|byte| byte ^ 0xff), &epoch_bytes(0xff)),
        );
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        // The shares are the caller's to keep, above what is read.
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        assert_clean(&pieces, || {
            slots.generate_shares(&mut Fixed, &mut shares).unwrap();
        });
        assert_eq!(
            shares,
            shares_of(&drawn_from(&hedged(&BYTES, &epoch_bytes(0))))
        );
    }

    /// Writes [`BYTES`], then panics.
    struct Panicking;

    impl Entropy for Panicking {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&BYTES);
            panic!("the source broke after writing")
        }
    }

    /// A source that panics after writing leaves neither its bytes nor a key: the panic unwinds
    /// past a wipe of the bytes, and the slot stays free. With optimisation the unwinding itself
    /// overwrites where the bytes were, so only a build without it can tell.
    #[test]
    fn a_panicking_source_leaves_no_bytes() {
        let pieces = key_dependent(&[BYTES.to_vec()], &[BYTES.map(|byte| byte ^ 0xff).to_vec()]);
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        assert_clean(&pieces, || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = slots.generate_shares(&mut Panicking, &mut shares);
            }));
            assert!(outcome.is_err());
        });
        assert_eq!(shares, [[0; SHARE_LEN]; SHARE_COUNT]);
        slots.generate_shares(&mut Fixed, &mut shares).unwrap();
    }

    /// The wipe that follows a derivation from shares and a generation of shares reaches as deep
    /// as it is meant to, also when the derivation fails after the key is derived, and no deeper
    /// than the documentation says.
    #[test]
    fn the_wipe_reaches_its_depth() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch = Epoch::empty();
        let mut slots = slots_of(&mut memory, &mut epoch);
        let needs = 1024 * NEEDS[usize::from(cfg!(lethewis_unoptimised))];
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        let wiped = depth_changed(|| {
            slots.generate_shares(&mut Fixed, &mut shares).unwrap();
        });
        assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
        assert!(wiped <= needs, "{wiped} bytes reached");
        for outcome in [None, Some(Error::DuplicateKey)] {
            let wiped = depth_changed(|| {
                let [mut first, mut second, _] = shares_of(&other_drawn());
                let derived = slots.derive_from_shares(&mut first, &mut second);
                assert_eq!(black_box(derived).err(), outcome);
            });
            assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
            assert!(wiped <= needs, "{wiped} bytes reached");
        }
    }

    /// The wipe covers more than combining and splitting use; the load has wipes of its own.
    #[test]
    fn the_wipe_is_deeper_than_combining_and_splitting() {
        let [first, second, _]: [Share; SHARE_COUNT] = shares_of(&drawn());
        let check = check_for(&drawn()[0]);
        for used in [
            depth_changed(|| {
                let mut read = ([0; SECRET_LEN], [0; CHECK_LEN]);
                combine(&first, &second, &mut read.0, &mut read.1).unwrap();
                black_box(&read);
            }),
            depth_changed(|| {
                let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
                split(&drawn(), check, &mut shares);
                black_box(&shares);
            }),
        ] {
            std::println!("combining or splitting uses {used} bytes of stack");
            assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
        }
    }

    /// The documentation of every call states the stack it needs and the depth of the wipe after
    /// them, and that depth is the library's.
    #[test]
    fn the_documentation_states_the_stack_the_calls_need() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(WIPES[build] * 1024, STACK_WIPE);
        let source = include_str!("shares.rs");
        for call in ["generate_shares", "derive_from_shares"] {
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
        CHECK_LEN, Drawn, SHARE_COUNT, SHARE_LEN, Share, Shares, combine, inverse, product,
        share_byte, split,
    };
    use crate::derive::SECRET_LEN;
    use crate::derive::proofs::expected_share_check;
    use crate::error::Error;

    /// The numbers of the shares, written from the documentation apart from the code.
    const NUMBERED: [u8; SHARE_COUNT] = [1, 2, 3];

    /// The product worked out apart from [`product`]: the product of the two polynomials, then
    /// the remainder after division by x^8 + x^4 + x^3 + x + 1.
    fn reference(a: u8, b: u8) -> u8 {
        let mut wide: u16 = 0;
        for bit in 0..8 {
            if b >> bit & 1 == 1 {
                wide ^= u16::from(a) << bit;
            }
        }
        for bit in (8..15).rev() {
            if wide >> bit & 1 == 1 {
                wide ^= 0x11b << (bit - 8);
            }
        }
        wide as u8
    }

    /// The shares [`split`] writes for the draw `drawn`, with the check the model of HKDF gives for
    /// the secret it begins with.
    pub(crate) fn expected_shares(drawn: &[u8; 64]) -> Shares {
        let mut parts: Drawn = [[0; SECRET_LEN]; 4];
        parts.as_flattened_mut().copy_from_slice(drawn);
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        split(&parts, expected_share_check(&parts[0]), &mut shares);
        shares
    }

    /// The secret and the check [`combine`] reads from `first` and `second`, or its refusal.
    pub(crate) fn expected_secret_and_check(
        first: &Share,
        second: &Share,
    ) -> Result<([u8; SECRET_LEN], [u8; CHECK_LEN]), Error> {
        let mut read = ([0; SECRET_LEN], [0; CHECK_LEN]);
        combine(first, second, &mut read.0, &mut read.1).map(|()| read)
    }

    /// Any of the numbers of the shares.
    fn any_number() -> u8 {
        let number: u8 = kani::any();
        kani::assume(NUMBERED.contains(&number));
        number
    }

    /// The share at `position`, read without an index known only at run time.
    fn pick(shares: &Shares, position: usize) -> Share {
        let [first, second, third] = *shares;
        match position {
            0 => first,
            1 => second,
            _ => third,
        }
    }

    /// For any two bytes, the product is the one of GF(2^8) with the polynomial of AES.
    #[kani::proof]
    #[kani::unwind(9)]
    fn the_product_is_that_of_the_field() {
        let (a, b): (u8, u8) = (kani::any(), kani::any());
        kani::assert(
            product(a, b) == reference(a, b),
            "the product is that of the field",
        );
        kani::cover!(a == 0x57 && b == 0x83, "the product FIPS 197 works out");
    }

    /// For any byte but zero, the product with its inverse is one.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_byte_but_zero_has_its_inverse() {
        let a: u8 = kani::any();
        kani::assume(a != 0);
        kani::assert(
            product(a, inverse(a)) == 1,
            "a byte times its inverse is one",
        );
        kani::cover!(a == 0xff, "the last byte");
    }

    /// For any draw and any check, the shares are numbered 1, 2 and 3, carry the mark drawn, and
    /// hold the value at their number of the line through each byte of the secret and of the check
    /// with the coefficient drawn for it, a byte of the draw of its own; any two of them, in either
    /// order, give the secret and the check back.
    #[kani::proof]
    #[kani::unwind(21)]
    fn any_two_shares_give_the_secret_back() {
        let drawn: Drawn = kani::any();
        let check: [u8; CHECK_LEN] = kani::any();
        let mut shares = [[0; SHARE_LEN]; SHARE_COUNT];
        split(&drawn, check, &mut shares);
        let [secret, coefficients, rest, _] = drawn;
        kani::assert(
            shares.iter().zip(NUMBERED).all(|(share, number)| {
                let on_lines = |bytes: &[u8], values: &[u8], coefficients: &[u8]| {
                    bytes.iter().zip(values).zip(coefficients).all(
                        |((&byte, &value), &coefficient)| {
                            byte == value ^ product(coefficient, number)
                        },
                    )
                };
                share[0] == number
                    && share[1..5] == rest[..4]
                    && on_lines(&share[5..21], &secret, &coefficients)
                    && on_lines(&share[21..], &check, &rest[4..8])
            }),
            "the shares are numbered in order, carry the mark drawn and lie on the lines drawn",
        );
        let (first, second): (usize, usize) = (kani::any(), kani::any());
        kani::assume(first < SHARE_COUNT && second < SHARE_COUNT && first != second);
        let mut read = ([0; SECRET_LEN], [0; CHECK_LEN]);
        let result = combine(
            &pick(&shares, first),
            &pick(&shares, second),
            &mut read.0,
            &mut read.1,
        );
        kani::assert(
            result == Ok(()) && read == (secret, check),
            "any two shares give the secret and the check back",
        );
        kani::cover!(first == 2 && second == 0, "the third and the first");
    }

    /// For any byte of a secret or of its check, any byte of a share and any number of a share,
    /// exactly one coefficient puts that byte of the share on the line through that byte: a share
    /// alone fits every secret alike, and only the coefficient, drawn at random, decides it.
    #[kani::proof]
    #[kani::unwind(9)]
    fn a_share_alone_fits_every_secret_alike() {
        let (secret, value, other): (u8, u8, u8) = (kani::any(), kani::any(), kani::any());
        let number = any_number();
        let coefficient = product(value ^ secret, inverse(number));
        kani::assert(
            share_byte(secret, coefficient, number) == value,
            "a coefficient gives the share from the secret",
        );
        kani::assume(other != coefficient);
        kani::assert(
            share_byte(secret, other, number) != value,
            "no other coefficient does",
        );
        kani::cover!(
            number == 3 && value == secret,
            "a share that equals the secret"
        );
    }

    /// For any two shares: a number other than 1, 2 or 3 is refused first, then marks that differ,
    /// then the same number twice, and nothing is written then. Otherwise each byte written, of the
    /// secret or of its check, is the value at zero of the line through the two bytes of the
    /// shares: the byte of each share less that value, divided by the share's number, is one
    /// coefficient for both.
    #[kani::proof]
    #[kani::unwind(21)]
    fn shares_are_read_exactly_when_they_fit_together() {
        let (first, second): (Share, Share) = (kani::any(), kani::any());
        let mut read: ([u8; SECRET_LEN], [u8; CHECK_LEN]) = kani::any();
        let before = read;
        let result = combine(&first, &second, &mut read.0, &mut read.1);
        let expected = if !NUMBERED.contains(&first[0]) || !NUMBERED.contains(&second[0]) {
            Err(Error::InvalidShare)
        } else if first[1..5] != second[1..5] {
            Err(Error::MixedShares)
        } else if first[0] == second[0] {
            Err(Error::SameShare)
        } else {
            Ok(())
        };
        kani::assert(
            result == expected,
            "shares are refused by number, then mark, then twice",
        );
        if result.is_ok() {
            let (x, y) = (first[0], second[0]);
            let at_zero = |read: &[u8], first: &[u8], second: &[u8]| {
                read.iter()
                    .zip(first)
                    .zip(second)
                    .all(|((&byte, &a), &b)| product(a ^ byte, y) == product(b ^ byte, x))
            };
            kani::assert(
                at_zero(&read.0, &first[5..21], &second[5..21])
                    && at_zero(&read.1, &first[21..], &second[21..]),
                "each byte read is where the line through both shares meets zero",
            );
        } else {
            kani::assert(
                read == before,
                "nothing is written when the shares are refused",
            );
        }
        kani::cover!(result.is_ok(), "two shares fit together");
        kani::cover!(result == Err(Error::InvalidShare), "a share of no number");
        kani::cover!(result == Err(Error::MixedShares), "shares of two splits");
        kani::cover!(result == Err(Error::SameShare), "one share twice");
    }
}
