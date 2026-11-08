// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The layout of the file of the signs watched: it is read as it was written, and nothing else is
//! read as a file of signs.

use super::{GUARDS_LEN, Guards, Watch, parse_guards};

fn any_watch() -> Watch {
    Watch {
        accepted: kani::any(),
        action: kani::any(),
    }
}

fn any_guards() -> Guards {
    Guards {
        salt: kani::any(),
        signs: core::array::from_fn(|_| any_watch()),
        alone: kani::any(),
    }
}

#[kani::proof]
fn signs_watched_are_read_as_written() {
    let guards = any_guards();
    let bytes = guards.bytes();
    kani::assert(
        parse_guards(&bytes) == Some(guards),
        "the file of the signs watched holds the salt and every tag written, in their order",
    );
    let [first, second, ..] = guards.signs;
    kani::cover!(first == second, "two signs whose tags are the same");
}

#[kani::proof]
fn only_written_signs_are_read() {
    let bytes: [u8; GUARDS_LEN + 1] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= GUARDS_LEN + 1);
    let read = &bytes[..length];
    if let Some(guards) = parse_guards(read) {
        kani::assert(
            guards.bytes().as_slice() == read,
            "a file of signs read holds what writing those signs gives",
        );
    } else {
        kani::assert(
            length != GUARDS_LEN,
            "every file of the length this library writes is read",
        );
    }
    kani::cover!(length == GUARDS_LEN, "a file of the length written");
    kani::cover!(length == GUARDS_LEN + 1, "a file one byte longer");
    kani::cover!(length == 0, "an empty file");
}
