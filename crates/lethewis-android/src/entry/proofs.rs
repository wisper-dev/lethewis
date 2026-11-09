// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{FILE_LEN, Way, parse_ways, ways_bytes};

fn any_way() -> Way {
    Way {
        record: kani::any(),
        salt: kani::any(),
        tag: kani::any(),
    }
}

#[kani::proof]
fn ways_in_are_read_as_written() {
    let ways = [any_way(), any_way(), any_way()];
    let mark = kani::any();
    kani::assert(
        parse_ways(&ways_bytes(&ways, &mark)) == Some((ways, mark)),
        "ways in are read as written",
    );
    let [own, _, shares] = ways;
    kani::cover!(own == shares, "two ways in alike");
}

#[kani::proof]
fn only_written_ways_in_are_read() {
    // One byte more than the file, as it is read.
    let bytes: [u8; FILE_LEN + 1] = kani::any();
    let length: usize = kani::any();
    let Some(read) = bytes.get(..length) else {
        return;
    };
    let Some((ways, mark)) = parse_ways(read) else {
        return;
    };
    kani::assert(
        ways_bytes(&ways, &mark).as_slice() == read,
        "only written ways in are read",
    );
    let [own, _, shares] = ways;
    kani::cover!(own.tag == shares.tag, "two ways in of one tag");
}
