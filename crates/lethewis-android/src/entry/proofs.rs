// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{FILE_LEN, Tail, Way, parse_ways, ways_bytes};

fn any_way() -> Way {
    Way {
        record: kani::any(),
        salt: kani::any(),
        tag: kani::any(),
    }
}

#[kani::proof]
fn ways_in_are_read_as_written() {
    let ways = [any_way(), any_way(), any_way(), any_way()];
    let tail = Tail {
        timed: kani::any(),
        mark: kani::any(),
    };
    kani::assert(
        parse_ways(&ways_bytes(&ways, &tail)) == Some((ways, tail)),
        "ways in are read as written",
    );
    let [own, _, _, timed] = ways;
    kani::cover!(own == timed, "two ways in alike");
}

#[kani::proof]
fn only_written_ways_in_are_read() {
    // One byte more than the file, as it is read.
    let bytes: [u8; FILE_LEN + 1] = kani::any();
    let length: usize = kani::any();
    let Some(read) = bytes.get(..length) else {
        return;
    };
    let Some((ways, tail)) = parse_ways(read) else {
        return;
    };
    kani::assert(
        ways_bytes(&ways, &tail).as_slice() == read,
        "only written ways in are read",
    );
    let [own, _, _, timed] = ways;
    kani::cover!(own.tag == timed.tag, "two ways in of one tag");
}
