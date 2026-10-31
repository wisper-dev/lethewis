// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! A round in decimal, as a lock carries it.

/// The most digits of a round.
pub(crate) const DIGITS: usize = 19;
/// The first round of twenty digits, which no lock carries.
pub(crate) const LIMIT: u64 = 10_000_000_000_000_000_000;
/// Ten to the powers 18 down to 0.
const POWERS: [u64; DIGITS] = [
    1_000_000_000_000_000_000,
    100_000_000_000_000_000,
    10_000_000_000_000_000,
    1_000_000_000_000_000,
    100_000_000_000_000,
    10_000_000_000_000,
    1_000_000_000_000,
    100_000_000_000,
    10_000_000_000,
    1_000_000_000,
    100_000_000,
    10_000_000,
    1_000_000,
    100_000,
    10_000,
    1_000,
    100,
    10,
    1,
];

/// The nineteen digits of a round, with zeros before its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decimal {
    digits: [u8; DIGITS],
}

impl Decimal {
    /// `round` in decimal, if it is below [`LIMIT`].
    pub(crate) fn of(round: u64) -> Option<Self> {
        let mut rest = round;
        let mut digits = [b'0'; DIGITS];
        for (digit, &power) in digits.iter_mut().zip(&POWERS) {
            let value = digit_of(rest, power);
            rest = rest.wrapping_sub(u64::from(value).wrapping_mul(power));
            *digit = b'0'.wrapping_add(value);
        }
        (round < LIMIT).then_some(Self { digits })
    }

    /// The decimal `digits` are, if they are all digits.
    pub(crate) fn read(digits: &[u8; DIGITS]) -> Option<Self> {
        digits
            .iter()
            .all(u8::is_ascii_digit)
            .then_some(Self { digits: *digits })
    }

    /// The round this stands for.
    pub(crate) fn value(&self) -> u64 {
        self.digits
            .iter()
            .zip(&POWERS)
            .fold(0, |round, (&digit, &power)| {
                round.wrapping_add(u64::from(digit.wrapping_sub(b'0')).wrapping_mul(power))
            })
    }

    pub(crate) fn digits(&self) -> &[u8; DIGITS] {
        &self.digits
    }
}

/// How many times, up to nine, `power` fits in `rest`.
fn digit_of(rest: u64, power: u64) -> u8 {
    let mut digit = 0;
    for times in 1..=9 {
        if rest >= power.wrapping_mul(u64::from(times)) {
            digit = times;
        }
    }
    digit
}

#[cfg(kani)]
#[coverage(on)]
pub(crate) mod proofs;

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::{DIGITS, Decimal, LIMIT};

    #[test]
    fn a_round_is_written_and_read_in_nineteen_digits() {
        for round in [0, 1, 9, 10, 99, 100, 746_511, 33_512_211, LIMIT - 1] {
            let decimal = Decimal::of(round).unwrap();
            assert_eq!(decimal.digits(), format!("{round:019}").as_bytes());
            assert_eq!(decimal.value(), round);
            assert_eq!(Decimal::read(decimal.digits()), Some(decimal));
        }
        assert_eq!(Decimal::of(LIMIT), None);
        assert_eq!(Decimal::of(u64::MAX), None);
    }

    #[test]
    fn only_digits_are_read() {
        for at in 0..DIGITS {
            for byte in [b'+', b'-', b' ', b'a', b'/', b':', 0] {
                let mut digits = [b'1'; DIGITS];
                digits[at] = byte;
                assert_eq!(Decimal::read(&digits), None);
            }
        }
    }
}
