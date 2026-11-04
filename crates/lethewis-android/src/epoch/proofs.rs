// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{CURRENT_LEN, ROOT_LEN, RootRecord, current_bytes, number_of, parse_current};
use crate::keystore::Level;
use crate::profile::level_of;

#[kani::proof]
fn a_pointer_is_read_as_written() {
    let number: u64 = kani::any();
    let tag: [u8; 32] = kani::any();
    kani::assert(
        parse_current(&current_bytes(number, &tag)) == Some((number, tag)),
        "a pointer is read as written",
    );
    kani::cover!(number == u64::MAX, "a pointer to the last epoch");
}

#[kani::proof]
fn only_a_written_pointer_is_read() {
    // One byte more than a pointer, as it is read.
    let bytes: [u8; CURRENT_LEN + 1] = kani::any();
    let length: usize = kani::any();
    let Some(read) = bytes.get(..length) else {
        return;
    };
    let Some((number, tag)) = parse_current(read) else {
        return;
    };
    kani::assert(
        current_bytes(number, &tag).as_slice() == read,
        "only a written pointer is read",
    );
    kani::cover!(number == 0, "a pointer to the first epoch");
}

#[kani::proof]
fn a_root_is_read_as_written() {
    let Some(level) = level_of(kani::any()) else {
        return;
    };
    let record = RootRecord {
        level,
        unlocked: kani::any(),
        stored: kani::any(),
        tag: kani::any(),
    };
    kani::assert(
        RootRecord::parse(&record.bytes()).as_ref() == Some(&record),
        "a root is read as written",
    );
    kani::cover!(
        level == Level::Unknown && record.unlocked,
        "a root of the last level, usable only unlocked"
    );
}

#[kani::proof]
fn only_a_written_root_is_read() {
    // One byte more than a root, as it is read.
    let bytes: [u8; ROOT_LEN + 1] = kani::any();
    let length: usize = kani::any();
    let Some(read) = bytes.get(..length) else {
        return;
    };
    let Some(record) = RootRecord::parse(read) else {
        return;
    };
    kani::assert(
        record.bytes().as_slice() == read,
        "only a written root is read",
    );
    kani::cover!(record.unlocked, "a root of a key usable only unlocked");
}

/// The value of decimal digits, wide enough for any twenty of them.
fn value(digits: &[u8]) -> u128 {
    digits.iter().fold(0, |value, &digit| {
        value * 10 + u128::from(digit.wrapping_sub(b'0'))
    })
}

/// Whether `text` is a number written in decimal, as this library writes one.
fn written(text: &[u8]) -> bool {
    !text.is_empty()
        && text.len() <= 20
        && text.iter().all(u8::is_ascii_digit)
        && !(text.len() > 1 && text.first() == Some(&b'0'))
        && value(text) <= u128::from(u64::MAX)
}

#[kani::proof]
#[kani::unwind(22)]
fn a_number_is_read_exactly_when_written_so() {
    let digits: [u8; 21] = kani::any();
    let length: usize = kani::any();
    let Some(text) = digits.get(..length) else {
        return;
    };
    let read = number_of(text);
    kani::assert(
        read.is_some() == written(text),
        "a number is read exactly when written so",
    );
    kani::assert(
        read.is_none_or(|number| u128::from(number) == value(text)),
        "a number is read as the value written",
    );
    kani::cover!(read == Some(u64::MAX), "the last number");
    kani::cover!(read == Some(0), "the first number");
}
