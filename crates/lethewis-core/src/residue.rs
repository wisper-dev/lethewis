// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Reading back what an operation on a key leaves on the stack, from the memory of this process.

extern crate std;

use core::hint::black_box;
use core::ops::Range;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::vec::Vec;

/// Room between the test's frame and the code under test, so that reading the memory back,
/// which runs at the test's depth, does not reach the stack that code used.
const PAD: usize = 64 * 1024;
/// How far below the pad the stack is read: deeper than the deepest wipe.
const SCAN: usize = 128 * 1024;
const PAINT: u8 = 0xa7;

/// Runs `code` below the pad, after painting the stack it is about to use when asked to, and
/// returns the addresses under the pad.
#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "the pad is a large array on the stack"
)]
pub(crate) fn below_pad(paint: bool, code: impl FnOnce()) -> Range<usize> {
    let pad = black_box([0x11_u8; PAD]);
    let low = black_box(&pad).as_ptr().addr();
    if paint {
        paint_stack();
    }
    code();
    black_box(&pad);
    low.saturating_sub(SCAN)..low
}

#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "the paint is a large array on the stack"
)]
fn paint_stack() {
    black_box([PAINT; SCAN]);
}

fn read(range: Range<usize>) -> Vec<u8> {
    let mut memory = File::open("/proc/self/mem").unwrap();
    memory.seek(SeekFrom::Start(range.start as u64)).unwrap();
    let mut bytes = std::vec![0; range.len()];
    memory.read_exact(&mut bytes).unwrap();
    bytes
}

/// Whether a 16-byte piece looks like data rather than a pattern: the zeros and the padding in a
/// block would match the wiped stack itself.
fn varied(piece: &[u8]) -> bool {
    let mut bytes = piece.to_vec();
    bytes.sort_unstable();
    bytes.dedup();
    bytes.len() >= 10
}

/// The 16-byte pieces of `secrets` that depend on the key: varied, and absent from `of_another`,
/// the same secrets of another key, so that constants and padding are not counted.
pub(crate) fn key_dependent(secrets: &[Vec<u8>], of_another: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let public: HashSet<Vec<u8>> = of_another
        .iter()
        .flat_map(|secret| secret.windows(16).map(<[u8]>::to_vec))
        .collect();
    secrets
        .iter()
        .flat_map(|secret| secret.windows(16).map(<[u8]>::to_vec))
        .filter(|piece| varied(piece) && !public.contains(piece))
        .collect()
}

/// How many of `pieces` the stack in `range` still holds.
pub(crate) fn residue(range: Range<usize>, pieces: &[Vec<u8>]) -> usize {
    let stack = read(range);
    let windows: HashSet<&[u8]> = stack.windows(16).collect();
    pieces
        .iter()
        .filter(|piece| windows.contains(piece.as_slice()))
        .count()
}

/// Runs `code` below the pad and asserts that it leaves none of `pieces` there.
pub(crate) fn assert_clean(pieces: &[Vec<u8>], code: impl FnOnce()) {
    let range = below_pad(false, code);
    assert_eq!(residue(range, pieces), 0);
}

/// How deep below the pad `code` changed the painted stack.
pub(crate) fn depth_changed(code: impl FnOnce()) -> usize {
    let range = below_pad(true, code);
    let stack = read(range);
    let lowest = stack.iter().position(|&byte| byte != PAINT).unwrap();
    stack.len().saturating_sub(lowest)
}
