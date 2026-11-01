// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{DIGITS, Decimal, LIMIT, POWERS, digit_of};

/// Any decimal of a round as a lock carries it.
pub(crate) fn any() -> Option<Decimal> {
    Decimal::read(&kani::any())
}

/// [`Decimal::of`] takes the digit of each power in turn from what is left of the round, and
/// [`Decimal::value`] adds the same digits times the same powers in the same order. A step takes a
/// digit of at most nine, so its byte reads back as it, and no more than is left; from less than
/// ten times its power it leaves less than the power. Each power is ten times the next, the last
/// is one, and [`LIMIT`] is ten times the first. So from a round below the limit nothing is left
/// after the last power, and the products add up to the round, each partial sum at most the round.
#[kani::proof]
fn a_step_takes_the_digit_of_its_power() {
    let at: usize = kani::any();
    kani::assume(at < DIGITS);
    let power = POWERS[at];
    let rest: u64 = kani::any();
    let digit = digit_of(rest, power);
    let left = u64::from(digit)
        .checked_mul(power)
        .and_then(|taken| rest.checked_sub(taken));
    kani::assert(
        digit <= 9 && left.is_some(),
        "a step takes a digit, and no more than is left",
    );
    kani::assert(
        u128::from(rest) >= u128::from(power) * 10 || left.is_some_and(|left| left < power),
        "from less than ten times its power a step leaves less than the power",
    );
    kani::assert(
        POWERS
            .get(at + 1)
            .map_or(power == 1, |&next| next.checked_mul(10) == Some(power)),
        "each power is ten times the next, and the last is one",
    );
    kani::assert(
        POWERS[0].checked_mul(10) == Some(LIMIT),
        "the limit is ten times the first power",
    );
    kani::cover!(digit == 9, "a digit of nine");
    kani::cover!(digit == 0 && rest > 0, "a digit of zero");
}

/// A round is written exactly when it is below the limit, in digits that are read back, and
/// nineteen bytes are read exactly when they are all digits.
#[kani::proof]
fn a_decimal_is_read_exactly_as_written() {
    let round: u64 = kani::any();
    let written = Decimal::of(round);
    kani::assert(
        written.is_some() == (round < LIMIT),
        "a round is written exactly when it is below the limit",
    );
    kani::assert(
        written.is_none_or(|written| Decimal::read(written.digits()) == Some(written)),
        "a decimal written is read back",
    );
    let digits: [u8; DIGITS] = kani::any();
    let read = Decimal::read(&digits);
    kani::assert(
        read.is_some() == digits.iter().all(|digit| (b'0'..=b'9').contains(digit)),
        "nineteen bytes are read exactly when they are all digits",
    );
    kani::assert(
        read.is_none_or(|read| *read.digits() == digits),
        "a decimal is read as its digits",
    );
    kani::cover!(round == LIMIT - 1, "the last round written");
}
