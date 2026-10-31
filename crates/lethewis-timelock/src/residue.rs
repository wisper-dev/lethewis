// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Reading back what a lock or an opening leaves on the stack, from the memory of this process.

extern crate std;

use core::hint::black_box;
use core::ops::Range;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::vec::Vec;

/// Room between the test's frame and the code under test. Reading memory back at the test's depth
/// then misses the stack that code used.
const PAD: usize = 64 * 1024;
/// How far below the pad the stack is read: deeper than the deepest wipe.
const SCAN: usize = 256 * 1024;
const PAINT: u8 = 0xa7;

#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "the pad is a large array on the stack"
)]
fn below_pad(code: impl FnOnce()) -> Range<usize> {
    let pad = black_box([0x11_u8; PAD]);
    let low = black_box(&pad).as_ptr().addr();
    paint_stack();
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

/// Whether a 16-byte piece looks like data, not a pattern: zeros and padding would match the
/// wiped stack.
fn varied(piece: &[u8]) -> bool {
    let mut bytes = piece.to_vec();
    bytes.sort_unstable();
    bytes.dedup();
    bytes.len() >= 10
}

/// The 16-byte pieces of `secrets` that do not occur in `of_another`, the same secrets of another
/// lock, so that constants and padding are not counted.
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

/// How many of `pieces` the stack `code` uses holds once it returns.
pub(crate) fn residue(pieces: &[Vec<u8>], code: impl FnOnce()) -> usize {
    let stack = read(below_pad(code));
    let held: HashSet<&[u8]> = stack.windows(16).collect();
    pieces
        .iter()
        .filter(|piece| held.contains(piece.as_slice()))
        .count()
}

/// How deep `code` reaches into the stack.
pub(crate) fn depth(code: impl FnOnce()) -> usize {
    let stack = read(below_pad(code));
    let lowest = stack.iter().position(|&byte| byte != PAINT).unwrap();
    stack.len().saturating_sub(lowest)
}
