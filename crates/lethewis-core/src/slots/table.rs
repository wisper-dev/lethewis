// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The only code that reaches a slot by its number or goes over all of them.

use super::Slot;

/// Only the table makes one, for a slot it finds. A handle, and a set from a transfer, carry it as
/// given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Index(usize);

#[cfg(kani)]
mod model {
    use super::Index;

    impl kani::Arbitrary for Index {
        fn any() -> Self {
            Self(kani::any())
        }
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

pub(super) struct Table<'a> {
    memory: &'a mut [Slot],
}

impl<'a> Table<'a> {
    pub(super) const fn new(memory: &'a mut [Slot]) -> Self {
        Self { memory }
    }

    pub(super) fn id(&self) -> usize {
        self.memory.as_ptr().addr()
    }

    pub(super) fn get(&self, at: Index) -> Option<&Slot> {
        self.memory.get(at.0)
    }

    pub(super) fn get_mut(&mut self, at: Index) -> Option<&mut Slot> {
        self.memory.get_mut(at.0)
    }

    pub(super) fn find(&self, test: impl Fn(&Slot) -> bool + Sync) -> Option<Index> {
        self.memory.iter().position(test).map(Index)
    }

    pub(super) fn any(&self, test: impl Fn(&Slot) -> bool + Sync) -> bool {
        self.find(test).is_some()
    }

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

    /// The table reads nothing of a slot, so these stand for slots in any state.
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

    /// The loop bound leaves no room for a count that wraps around to one.
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
