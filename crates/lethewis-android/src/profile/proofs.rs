// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Id, Level, RECORD_LEN, Record, level_of};

#[kani::proof]
fn an_identifier_is_read_as_written() {
    let id = Id(kani::any());
    kani::assert(
        Id::from_hex(&id.hex()) == Some(id),
        "an identifier is read as written",
    );
    kani::cover!(id.0 == [0xff; 16], "the last identifier");
}

#[kani::proof]
fn only_a_written_identifier_is_read() {
    let digits: [u8; 32] = kani::any();
    let Some(id) = Id::from_hex(&digits) else {
        return;
    };
    kani::assert(id.hex() == digits, "only a written identifier is read");
    kani::cover!(digits[0] == b'f', "an identifier read with a letter first");
}

#[kani::proof]
fn a_record_is_read_as_written() {
    let Some(level) = level_of(kani::any()) else {
        return;
    };
    let record = Record {
        level,
        unlocked: kani::any(),
        check: kani::any(),
        tag: kani::any(),
    };
    kani::assert(
        Record::parse(&record.bytes()) == Some(record),
        "a record is read as written",
    );
    kani::cover!(
        level == Level::Unknown && record.unlocked,
        "a record of the last level, usable only unlocked"
    );
}

#[kani::proof]
fn only_a_written_record_is_read() {
    // One byte more than a record, as `Profile::open` reads.
    let bytes: [u8; RECORD_LEN + 1] = kani::any();
    let length: usize = kani::any();
    let Some(read) = bytes.get(..length) else {
        return;
    };
    let Some(record) = Record::parse(read) else {
        return;
    };
    kani::assert(
        record.bytes().as_slice() == read,
        "only a written record is read",
    );
    kani::cover!(record.unlocked, "a record of a key usable only unlocked");
}
