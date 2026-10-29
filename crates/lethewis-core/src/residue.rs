// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Reading back what an operation on a key leaves on the stack, from the memory of this process.

extern crate std;

use core::cell::Cell;
use core::hint::black_box;
use core::ops::Range;
use core::panic::AssertUnwindSafe;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::panic::catch_unwind;
use std::vec::Vec;

use crate::entropy::{Entropy, EntropyError};

/// Room between the test's frame and the code under test. Reading memory back at the test's depth
/// then misses the stack that code used.
const PAD: usize = 64 * 1024;
/// How far below the pad the stack is read: deeper than the deepest wipe.
const SCAN: usize = 256 * 1024;
const PAINT: u8 = 0xa7;

std::thread_local! {
    static LOW: Cell<usize> = const { Cell::new(0) };
}

#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "the pad is a large array on the stack"
)]
pub(crate) fn below_pad(paint: bool, code: impl FnOnce()) -> Range<usize> {
    let pad = black_box([0x11_u8; PAD]);
    let low = black_box(&pad).as_ptr().addr();
    LOW.set(low);
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

/// Whether a 16-byte piece looks like data, not a pattern: a block's zeros and padding would match
/// the wiped stack.
fn varied(piece: &[u8]) -> bool {
    let mut bytes = piece.to_vec();
    bytes.sort_unstable();
    bytes.dedup();
    bytes.len() >= 10
}

/// `of_another` holds the same secrets of another key, so that constants and padding are not
/// counted.
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

pub(crate) fn residue(range: Range<usize>, pieces: &[Vec<u8>]) -> usize {
    count(&read(range), pieces)
}

fn count(stack: &[u8], pieces: &[Vec<u8>]) -> usize {
    let mut starts = std::vec![false; 1 << 16];
    for piece in pieces {
        starts[usize::from(u16::from_le_bytes([piece[0], piece[1]]))] = true;
    }
    let held: HashSet<&[u8]> = stack
        .windows(16)
        .filter(|window| starts[usize::from(u16::from_le_bytes([window[0], window[1]]))])
        .collect();
    pieces
        .iter()
        .filter(|piece| held.contains(piece.as_slice()))
        .count()
}

pub(crate) fn assert_clean(pieces: &[Vec<u8>], code: impl FnOnce()) {
    let range = below_pad(true, code);
    assert_eq!(residue(range, pieces), 0);
}

pub(crate) fn depth_changed(code: impl FnOnce()) -> usize {
    let range = below_pad(true, code);
    let stack = read(range);
    let lowest = stack.iter().position(|&byte| byte != PAINT).unwrap();
    stack.len().saturating_sub(lowest)
}

/// The process memory is open and `stack` allocated beforehand, so reading at the panic uses little
/// stack below.
struct PanicsAt<'a, E> {
    source: E,
    at: usize,
    pieces: &'a [Vec<u8>],
    memory: File,
    stack: Vec<u8>,
    calls: usize,
    found: Option<usize>,
}

impl<E: Entropy> Entropy for PanicsAt<'_, E> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        self.calls = self.calls.wrapping_add(1);
        self.source.fill(dest)?;
        if self.calls == self.at {
            let low = LOW.get();
            assert_ne!(low, 0, "no code ran below the pad");
            let start = u64::try_from(low.saturating_sub(SCAN)).unwrap();
            self.memory.read_exact_at(&mut self.stack, start).unwrap();
            self.found = Some(count(&self.stack, self.pieces));
            // The count may leave pieces on the stack below, where the read after the unwinding
            // would find them.
            paint_stack();
            panic!("the source broke");
        }
        Ok(())
    }
}

/// Makes `source` panic on its call number `at`, and tells whether `run` got that far.
pub(crate) fn panic_at(
    pieces: &[Vec<u8>],
    (source, at): (impl Entropy, usize),
    run: impl FnOnce(&mut dyn Entropy),
) -> bool {
    let mut source = PanicsAt {
        source,
        at,
        pieces,
        memory: File::open("/proc/self/mem").unwrap(),
        stack: std::vec![0; SCAN],
        calls: 0,
        found: None,
    };
    assert_clean(pieces, || {
        let outcome = catch_unwind(AssertUnwindSafe(|| run(&mut source)));
        assert_eq!(outcome.is_err(), source.calls == at);
    });
    let reached = source.calls == at;
    assert_eq!(source.found, reached.then_some(0));
    reached
}
