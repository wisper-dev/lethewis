// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The layout of a block: a header of a salt and a check, then chunks, each followed by its tag.

use crate::record::LABEL_LEN;
use crate::seal::{NONCE_LEN, TAG_LEN};

/// The size of the salt a block's keys are derived with, in bytes.
pub(crate) const SALT_LEN: usize = 16;
/// The size of the check that names the key of a set a block is under, in bytes.
pub(crate) const CHECK_LEN: usize = 32;
/// The size of the header of a block in bytes: the salt, then the check.
pub const BLOCK_HEADER_LEN: usize = SALT_LEN + CHECK_LEN;
/// Bytes of data in each chunk but the last, which holds 1 to this many, or none for empty data.
pub const CHUNK_LEN: usize = 65_536;
/// The size of the tag that follows each chunk, in bytes.
pub const CHUNK_TAG_LEN: usize = TAG_LEN;
/// The label of the associated data of a chunk.
pub(crate) const DATA_LABEL: &[u8; LABEL_LEN] = b"lethewis data block";
/// The label of the associated data of a chunk of a block carried under a key for transfers.
pub(crate) const CARRY_LABEL: &[u8; LABEL_LEN] = b"lethewis data carry";
/// The label of the associated data of a chunk of the body of a batch of an archive.
pub(crate) const BATCH_LABEL: &[u8; LABEL_LEN] = b"lethewis data batch";
/// The version of the format of a block, in the associated data of each chunk.
pub(crate) const VERSION: u8 = 1;
/// The version of the format of the body of a batch, in the associated data of each chunk.
pub(crate) const BATCH_VERSION: u8 = 1;

pub(crate) const fn body_len_in<const C: usize>(len: u64) -> Option<u64> {
    let Some(tags) = chunks_in::<C>(len).0.checked_mul(TAG_LEN as u64) else {
        return None;
    };
    len.checked_add(tags)
}

pub(crate) const fn block_len_in<const C: usize>(len: u64) -> Option<u64> {
    match body_len_in::<C>(len) {
        Some(body) => body.checked_add(BLOCK_HEADER_LEN as u64),
        None => None,
    }
}

/// How many chunks of `C` bytes data of `len` bytes take, at least one, and how many the last
/// holds.
pub(crate) const fn chunks_in<const C: usize>(len: u64) -> (u64, u64) {
    let chunk = C as u64;
    match (len.checked_div(chunk), len.checked_rem(chunk)) {
        (Some(full), Some(0)) if full != 0 => (full, chunk),
        (Some(full), Some(rest)) => (full.saturating_add(1), rest),
        _ => (1, 0),
    }
}

/// The data length in a block of `block` bytes with chunks of `C` bytes, if the library writes such
/// blocks.
pub(crate) const fn data_len_in<const C: usize>(block: u64) -> Option<u64> {
    let Some(body) = block.checked_sub(BLOCK_HEADER_LEN as u64) else {
        return None;
    };
    body_data_len_in::<C>(body)
}

/// The data length that `body` bytes of `C`-byte chunks with their tags hold, if the library writes
/// such bodies.
pub(crate) const fn body_data_len_in<const C: usize>(body: u64) -> Option<u64> {
    let whole = (C as u64).saturating_add(TAG_LEN as u64);
    // A chunk and its tag take `whole` bytes; the last chunk takes at least its tag.
    let Some(past_tags) = body.checked_sub(TAG_LEN as u64) else {
        return None;
    };
    let Some(count) = past_tags.checked_div(whole) else {
        return None;
    };
    // At most the bytes of the chunks over 32, so one more fits.
    let count = count.saturating_add(1);
    let Some(tags) = count.checked_mul(TAG_LEN as u64) else {
        return None;
    };
    let Some(len) = body.checked_sub(tags) else {
        return None;
    };
    match body_len_in::<C>(len) {
        Some(again) if again == body => Some(len),
        _ => None,
    }
}

/// The length of a block of `len` data bytes, or `None` past 64 bits. That is [`BLOCK_HEADER_LEN`],
/// the data, and [`CHUNK_TAG_LEN`] per chunk of up to [`CHUNK_LEN`] bytes, one at least.
#[must_use]
pub const fn block_len(len: u64) -> Option<u64> {
    block_len_in::<CHUNK_LEN>(len)
}

/// The length of a batch body of `len` data bytes, or `None` past 64 bits. That is the data and
/// [`CHUNK_TAG_LEN`] per chunk of up to [`CHUNK_LEN`] bytes, one at least.
#[must_use]
pub const fn batch_len(len: u64) -> Option<u64> {
    body_len_in::<CHUNK_LEN>(len)
}

/// The data length a batch body of `body` bytes holds, or `None` if no body is that long.
#[must_use]
pub const fn batch_data_len(body: u64) -> Option<u64> {
    body_data_len_in::<CHUNK_LEN>(body)
}

/// Constant time, and out of line so that the check of its machine code finds it.
#[inline(never)]
pub(crate) fn same_check(a: &[u8; CHECK_LEN], b: &[u8; CHECK_LEN]) -> bool {
    #[cfg(not(kani))]
    {
        use ctutils::CtEq;
        a.ct_eq(b).to_bool()
    }
    #[cfg(kani)]
    model::same_check(a, b)
}

/// Which of three positions first holds a match, and whether any does, with no branch on the
/// matches. Kept out of line so the machine-code check finds it.
#[inline(never)]
pub(crate) fn first_match(matches: [bool; 3]) -> (usize, bool) {
    let [first, second, third] = matches.map(u8::from);
    let second_only = second & (first ^ 1);
    let third_only = third & (first ^ 1) & (second ^ 1);
    (
        usize::from(second_only).wrapping_add(usize::from(third_only) << 1),
        (first | second | third) == 1,
    )
}

pub(crate) fn chunk_nonce(index: u64, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    if let Some((number, rest)) = nonce.split_first_chunk_mut::<8>() {
        *number = index.to_le_bytes();
        if let Some(flag) = rest.last_mut() {
            *flag = u8::from(last);
        }
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_HEADER_LEN, CHUNK_LEN, block_len, block_len_in, chunk_nonce, chunks_in, data_len_in,
        first_match,
    };

    #[test]
    fn a_block_is_its_header_its_data_and_a_tag_for_each_chunk() {
        assert_eq!(BLOCK_HEADER_LEN, 48);
        assert_eq!(block_len(0), Some(64));
        assert_eq!(block_len(1), Some(65));
        assert_eq!(block_len(65_535), Some(65_599));
        assert_eq!(block_len(65_536), Some(65_600));
        assert_eq!(block_len(65_537), Some(65_617));
        assert_eq!(block_len(131_072), Some(131_152));
        assert_eq!(block_len(u64::MAX), None);
        assert_eq!(chunks_in::<CHUNK_LEN>(0), (1, 0));
        assert_eq!(chunks_in::<CHUNK_LEN>(65_536), (1, 65_536));
        assert_eq!(chunks_in::<CHUNK_LEN>(65_537), (2, 1));
    }

    #[test]
    fn only_the_lengths_of_blocks_give_a_length_of_data() {
        for len in [0, 1, 15, 16, 17, 32, 33, 1000] {
            let block = block_len_in::<16>(len).unwrap();
            assert_eq!(data_len_in::<16>(block), Some(len), "{len}");
        }
        // An empty block is 64 bytes, and 65 to 80 hold one chunk. With 32 per whole chunk, a full
        // and an empty chunk would be 81; 97 is the shortest of two.
        let lengths: [u64; 8] = [0, 47, 63, 81, 82, 96, 113, 114];
        for block in lengths {
            assert_eq!(data_len_in::<16>(block), None, "{block}");
        }
        assert_eq!(data_len_in::<16>(64), Some(0));
        assert_eq!(data_len_in::<16>(80), Some(16));
        assert_eq!(data_len_in::<16>(97), Some(17));
        assert_eq!(data_len_in::<16>(112), Some(32));
    }

    #[test]
    fn the_first_match_is_the_first_position_that_holds_one() {
        for (matches, found) in [
            ([false, false, false], (0, false)),
            ([true, false, false], (0, true)),
            ([false, true, false], (1, true)),
            ([false, false, true], (2, true)),
            ([true, true, false], (0, true)),
            ([true, false, true], (0, true)),
            ([false, true, true], (1, true)),
            ([true, true, true], (0, true)),
        ] {
            assert_eq!(first_match(matches), found, "{matches:?}");
        }
    }

    #[test]
    fn a_nonce_is_the_number_and_the_mark_of_the_last_chunk() {
        assert_eq!(chunk_nonce(0, false), [0; 12]);
        assert_eq!(chunk_nonce(0, true), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            chunk_nonce(0x0102_0304_0506_0708, true),
            [8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 1]
        );
    }
}

#[cfg(kani)]
mod model {
    use super::CHECK_LEN;

    /// The comparison ends in inline assembly, which Kani cannot model. Compared as numbers:
    /// comparing the arrays whole reads bytes from before the latest write in Kani 0.68.0.
    pub(super) fn same_check(a: &[u8; CHECK_LEN], b: &[u8; CHECK_LEN]) -> bool {
        let halves = |bytes: &[u8; CHECK_LEN]| {
            bytes
                .split_first_chunk::<16>()
                .map_or((0, 0), |(low, high)| {
                    let high = high
                        .first_chunk::<16>()
                        .map_or(0, |high| u128::from_ne_bytes(*high));
                    (u128::from_ne_bytes(*low), high)
                })
        };
        halves(a) == halves(b)
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs {
    use super::{
        BLOCK_HEADER_LEN, CHUNK_LEN, block_len_in, body_data_len_in, body_len_in, chunk_nonce,
        chunks_in, data_len_in, first_match,
    };

    /// Also in chunks of 16 bytes, as the proofs of the calls take. Worked out in numbers of 128
    /// bits, apart from the code.
    #[kani::proof]
    fn data_of_any_length_take_the_chunks_and_the_block_their_layout_says() {
        layout::<CHUNK_LEN>();
        layout::<16>();
    }

    fn layout<const C: usize>() {
        let len: u64 = kani::any();
        let (count, last) = chunks_in::<C>(len);
        let chunk = C as u128;
        kani::assert(
            count >= 1
                && u128::from(last) <= chunk
                && (last == 0) == (len == 0)
                && (u128::from(count) - 1) * chunk + u128::from(last) == u128::from(len),
            "every chunk but the last is full, and the last holds the rest, or nothing for empty \
             data",
        );
        let body = u128::from(len) + 16 * u128::from(count);
        match body_len_in::<C>(len) {
            Some(batch) => {
                kani::assert(
                    u128::from(batch) == body,
                    "the body of a batch is its data and a tag for each chunk",
                );
                kani::assert(
                    body_data_len_in::<C>(batch) == Some(len),
                    "the body of a batch gives back the length of its data",
                );
            }
            None => kani::assert(
                body > u128::from(u64::MAX),
                "only a body too long for 64 bits has no length",
            ),
        }
        let whole = BLOCK_HEADER_LEN as u128 + body;
        match block_len_in::<C>(len) {
            Some(block) => {
                kani::assert(
                    u128::from(block) == whole,
                    "a block is its header, its data and a tag for each chunk",
                );
                kani::assert(
                    data_len_in::<C>(block) == Some(len),
                    "a block gives back the length of its data",
                );
            }
            None => kani::assert(
                whole > u128::from(u64::MAX),
                "only a block too long for 64 bits has no length",
            ),
        }
        kani::cover!(count == 2 && last == 1, "two chunks, the last of one byte");
        kani::cover!(count == 1 && u128::from(last) == chunk, "one full chunk");
        kani::cover!(
            block_len_in::<C>(len).is_none() && body_len_in::<C>(len).is_some(),
            "a length too long for a block but not for the body of a batch"
        );
        kani::cover!(
            body_len_in::<C>(len).is_none(),
            "a length too long for the body of a batch"
        );
    }

    #[kani::proof]
    fn only_the_length_of_a_block_gives_a_length_of_data() {
        lengths::<CHUNK_LEN>();
        lengths::<16>();
    }

    fn lengths<const C: usize>() {
        let block: u64 = kani::any();
        let len = data_len_in::<C>(block);
        if let Some(len) = len {
            kani::assert(
                block_len_in::<C>(len) == Some(block),
                "the length of data a block gives makes a block of that length",
            );
        }
        // One full chunk and its tag, and two chunks the last of one byte, have no block between.
        let one = (BLOCK_HEADER_LEN + C + 16) as u64;
        kani::cover!(len == Some(0), "the empty block");
        kani::cover!(
            len.is_none() && block > one && block < one + 17,
            "a length between one chunk and two that no block has"
        );
        kani::cover!(
            len.is_none() && block < 64,
            "a length shorter than any block"
        );
        kani::cover!(len.is_some() && block > 1 << 40, "a long block");
        let body: u64 = kani::any();
        let held = body_data_len_in::<C>(body);
        if let Some(held) = held {
            kani::assert(
                body_len_in::<C>(held) == Some(body),
                "the length of data the body of a batch gives makes a body of that length",
            );
        }
        kani::cover!(held == Some(0), "the body of empty data");
        kani::cover!(
            held.is_none() && body > one - 48 && body < one - 31,
            "a length between the body of one chunk and two that no body has"
        );
    }

    #[kani::proof]
    fn a_nonce_holds_the_number_and_the_mark_of_its_chunk() {
        let (index, last): (u64, bool) = (kani::any(), kani::any());
        let nonce = chunk_nonce(index, last);
        kani::assert(
            nonce[..8] == index.to_le_bytes()
                && nonce[8..11] == [0; 3]
                && nonce[11] == u8::from(last),
            "the nonce is the number, three zero bytes and the mark of the last",
        );
        kani::cover!(last && index == u64::MAX, "the last of the most chunks");
    }

    #[kani::proof]
    fn the_first_match_is_found() {
        let matches: [bool; 3] = kani::any();
        let (at, any) = first_match(matches);
        let expected = matches.iter().position(|&found| found);
        kani::assert(
            any == expected.is_some() && expected.is_none_or(|position| position == at),
            "the first position that matches is given, and whether any does",
        );
        kani::cover!(matches == [false, true, true], "the second of two matches");
        kani::cover!(matches == [false; 3], "no match");
    }
}
