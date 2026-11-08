// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{WAY_LEN, Way, parse_ways, ways_bytes};

fn any_way() -> Way {
    Way {
        record: kani::any(),
        salt: kani::any(),
        tag: kani::any(),
    }
}

#[kani::proof]
fn ways_in_are_read_as_written() {
    let (first, second) = (any_way(), any_way());
    kani::assert(
        parse_ways(&ways_bytes(&first, &second)) == Some([first, second]),
        "ways in are read as written",
    );
    kani::cover!(first == second, "two ways in alike");
}

#[kani::proof]
fn only_written_ways_in_are_read() {
    // One byte more than the ways in, as they are read.
    let bytes: [u8; 2 * WAY_LEN + 1] = kani::any();
    let length: usize = kani::any();
    let Some(read) = bytes.get(..length) else {
        return;
    };
    let Some([first, second]) = parse_ways(read) else {
        return;
    };
    kani::assert(
        ways_bytes(&first, &second).as_slice() == read,
        "only written ways in are read",
    );
    kani::cover!(first.tag == second.tag, "two ways in of one tag");
}
