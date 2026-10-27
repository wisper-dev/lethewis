// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The memory of a set of slots: the only code that reaches a slot by its number or goes over all
//! of them. A test or a change it applies is `Fn` and `Sync`, so it can count the slots only in an
//! atomic.

use super::Slot;

/// The number of a slot. Only the table makes one, for a slot it finds; a handle, and a set that
/// came in a transfer, carry it as the table gave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Index(usize);

#[cfg(kani)]
impl kani::Arbitrary for Index {
    fn any() -> Self {
        Self(kani::any())
    }
}

#[cfg(kani)]
impl From<Index> for usize {
    fn from(index: Index) -> Self {
        index.0
    }
}

#[cfg(any(test, kani))]
impl Index {
    pub(super) const fn new(number: usize) -> Self {
        Self(number)
    }

    pub(super) const fn number(self) -> usize {
        self.0
    }
}

/// The slots of a set of slots, in the memory the caller provides.
pub(super) struct Table<'a> {
    memory: &'a mut [Slot],
}

impl<'a> Table<'a> {
    pub(super) const fn new(memory: &'a mut [Slot]) -> Self {
        Self { memory }
    }

    /// The address of the memory.
    pub(super) fn id(&self) -> usize {
        self.memory.as_ptr().addr()
    }

    pub(super) fn get(&self, at: Index) -> Option<&Slot> {
        self.memory.get(at.0)
    }

    pub(super) fn get_mut(&mut self, at: Index) -> Option<&mut Slot> {
        self.memory.get_mut(at.0)
    }

    /// The first slot that passes `test`.
    pub(super) fn find(&self, test: impl Fn(&Slot) -> bool + Sync) -> Option<Index> {
        self.memory.iter().position(test).map(Index)
    }

    /// Whether any slot passes `test`.
    pub(super) fn any(&self, test: impl Fn(&Slot) -> bool + Sync) -> bool {
        self.find(test).is_some()
    }

    /// Applies `change` to every slot, once each.
    pub(super) fn each(&mut self, change: impl Fn(&mut Slot) + Sync) {
        self.memory.iter_mut().for_each(change);
    }
}

#[cfg(any(test, kani))]
impl core::ops::Deref for Table<'_> {
    type Target = [Slot];

    fn deref(&self) -> &[Slot] {
        self.memory
    }
}

#[cfg(any(test, kani))]
impl core::ops::DerefMut for Table<'_> {
    fn deref_mut(&mut self) -> &mut [Slot] {
        self.memory
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs {
    use super::{Index, Slot, Table};

    const SLOTS: usize = 8;

    /// Slots with any marks and generations: the table reads nothing of a slot, so these stand for
    /// slots in any state.
    fn any_slots() -> [Slot; SLOTS] {
        let any = || {
            let mut slot = Slot::empty();
            slot.changed = kani::any();
            slot.generation = kani::any();
            slot
        };
        [any(), any(), any(), any(), any(), any(), any(), any()]
    }

    fn any_number() -> usize {
        let number = kani::any();
        kani::assume(number < SLOTS);
        number
    }

    /// For eight slots, whichever of them pass a test, the table finds the first that passes, and
    /// none only when none does.
    #[kani::proof]
    #[kani::unwind(9)]
    fn the_table_finds_the_first_slot_that_passes() {
        let mut memory = any_slots();
        let table = Table::new(&mut memory);
        let found = table.find(|slot| slot.changed);
        let at = any_number();
        kani::assert(
            match found {
                Some(first) => table[first.0].changed && (at >= first.0 || !table[at].changed),
                None => !table[at].changed,
            },
            "the first slot that passes is found, and none only when none passes",
        );
        kani::assert(
            table.any(|slot| slot.changed) == found.is_some(),
            "a slot passes exactly when one is found",
        );
        kani::cover!(found == Some(Index(0)), "the first slot passes");
        kani::cover!(found == Some(Index(SLOTS - 1)), "only the last slot passes");
        kani::cover!(found.is_none(), "no slot passes");
    }

    /// For eight slots, a change over all of them reaches each slot once: the loop bound leaves no
    /// room for a count that wraps around to one.
    #[kani::proof]
    #[kani::unwind(9)]
    fn the_table_changes_every_slot_once() {
        let mut memory = any_slots();
        let before = memory.each_ref().map(|slot| slot.generation);
        let mut table = Table::new(&mut memory);
        table.each(|slot| slot.generation = slot.generation.wrapping_add(1));
        let at = any_number();
        kani::assert(
            table[at].generation == before[at].wrapping_add(1),
            "each slot is changed once",
        );
        kani::cover!(before[at] == u64::MAX, "a generation that wraps");
    }

    /// For eight slots, a slot is reached by its number alone, and a change through it changes
    /// no other slot.
    #[kani::proof]
    #[kani::unwind(9)]
    fn the_table_reaches_a_slot_by_its_number() {
        let mut memory = any_slots();
        let before = memory.each_ref().map(|slot| slot.generation);
        let number: usize = kani::any();
        let mut table = Table::new(&mut memory);
        let reached = table.get(Index(number)).map(|slot| slot.generation);
        kani::assert(
            reached == before.get(number).copied(),
            "a number reaches its slot, and a number past the slots none",
        );
        if let Some(slot) = table.get_mut(Index(number)) {
            slot.generation = slot.generation.wrapping_add(1);
        }
        let at = any_number();
        kani::assert(
            table[at].generation
                == if at == number {
                    before[at].wrapping_add(1)
                } else {
                    before[at]
                },
            "a change through a number changes its slot only",
        );
        kani::cover!(number >= SLOTS, "a number past the slots");
    }
}
