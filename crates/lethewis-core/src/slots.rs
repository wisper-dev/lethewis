// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::{fmt, marker::PhantomData};

use crate::{
    error::Error,
    key::{KEY_LEN, Key},
};

/// Memory for one key, provided by the caller.
///
/// A slot cannot be copied, cloned or compared. It holds a key only while a [`Slots`] over it is
/// alive, so moving the memory afterwards copies no key.
pub struct Slot {
    key: Key,
    generation: u64,
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    Loaded,
    /// The generation counter is exhausted, so a new handle could repeat an old one.
    Retired,
}

impl Slot {
    /// A slot holding no key.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            key: Key::empty(),
            generation: 0,
            state: State::Free,
        }
    }

    fn unload(&mut self) {
        self.key.wipe();
        match self.generation.checked_add(1) {
            Some(next) => {
                self.generation = next;
                self.state = State::Free;
            }
            None => self.state = State::Retired,
        }
    }
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot").finish_non_exhaustive()
    }
}

/// Refers to a key held in [`Slots`].
///
/// A handle works only with the `Slots` that issued it, stops working when its key is released,
/// and cannot outlive the memory of its slots. It may outlive the `Slots` itself:
///
/// ```
/// use lethewis_core::{KEY_LEN, Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 1];
/// let handle;
/// {
///     let mut slots = Slots::new(&mut memory);
///     handle = slots.import(&mut [7; KEY_LEN])?;
/// }
/// let _ = handle;
/// # Ok::<(), lethewis_core::Error>(())
/// ```
///
/// The same code with the memory gone before the handle does not compile:
///
/// ```compile_fail
/// use lethewis_core::{KEY_LEN, Slot, Slots};
///
/// let handle;
/// {
///     let mut memory = [const { Slot::empty() }; 1];
///     let mut slots = Slots::new(&mut memory);
///     handle = slots.import(&mut [7; KEY_LEN])?;
/// }
/// let _ = handle;
/// # Ok::<(), lethewis_core::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Handle<'a> {
    slots: usize,
    index: usize,
    generation: u64,
    memory: PhantomData<&'a [Slot]>,
}

impl fmt::Debug for Handle<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle").finish_non_exhaustive()
    }
}

/// Keys held in slots provided by the caller.
///
/// A key goes in, and only a handle comes out: no call returns the key itself. Creating and
/// dropping `Slots` wipes every key in its slots. A `Slots` leaked instead of dropped, for example
/// through [`core::mem::forget`], [`core::mem::ManuallyDrop`] or `Box::leak`, skips that wipe, and
/// its keys stay in memory until the next `Slots` over the same memory.
///
/// ```
/// use lethewis_core::{KEY_LEN, Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 4];
/// let mut slots = Slots::new(&mut memory);
///
/// let mut secret = [7; KEY_LEN];
/// let handle = slots.import(&mut secret)?;
/// assert_eq!(secret, [0; KEY_LEN]);
///
/// slots.release(handle)?;
/// # Ok::<(), lethewis_core::Error>(())
/// ```
pub struct Slots<'a> {
    slots: &'a mut [Slot],
}

impl<'a> Slots<'a> {
    /// Keeps keys in `slots`. A key left there earlier is wiped first.
    #[must_use]
    pub fn new(slots: &'a mut [Slot]) -> Self {
        let mut this = Self { slots };
        this.unload_all();
        this
    }

    /// Takes a key from `source` into a free slot and wipes `source`.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free. `source` is then left as it was.
    pub fn import(&mut self, source: &mut [u8; KEY_LEN]) -> Result<Handle<'a>, Error> {
        let slots = self.id();
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.state == State::Free)
            .ok_or(Error::NoFreeSlot)?;
        slot.key.load(source);
        slot.state = State::Loaded;
        Ok(Handle {
            slots,
            index,
            generation: slot.generation,
            memory: PhantomData,
        })
    }

    /// Wipes the key that `handle` refers to and frees its slot.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `handle` does not refer to a key held here now.
    pub fn release(&mut self, handle: Handle<'a>) -> Result<(), Error> {
        if handle.slots != self.id() {
            return Err(Error::StaleHandle);
        }
        let slot = self
            .slots
            .get_mut(handle.index)
            .filter(|slot| slot.state == State::Loaded && slot.generation == handle.generation)
            .ok_or(Error::StaleHandle)?;
        slot.unload();
        Ok(())
    }

    /// Tells apart two `Slots` alive at once: their memory does not overlap, so neither do the
    /// addresses. Empty ones may share an address, but they issue no handles. A handle keeps its
    /// memory borrowed, so no other `Slots` can take that memory over while the handle exists.
    fn id(&self) -> usize {
        self.slots.as_ptr().addr()
    }

    fn unload_all(&mut self) {
        for slot in self.slots.iter_mut() {
            if slot.state == State::Loaded {
                slot.unload();
            }
        }
    }
}

impl Drop for Slots<'_> {
    fn drop(&mut self) {
        self.unload_all();
    }
}

impl fmt::Debug for Slots<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slots").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::marker::PhantomData;
    use std::format;

    use super::{Error, Handle, KEY_LEN, Slot, Slots, State};

    assert_not_impl!(Slot: Clone, PartialEq, Default);

    fn secret() -> [u8; KEY_LEN] {
        [7; KEY_LEN]
    }

    #[test]
    fn import_loads_the_key_and_wipes_the_source() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let mut source = secret();
        let handle = slots.import(&mut source).unwrap();
        assert_eq!((handle.index, handle.generation), (0, 0));
        assert_eq!(slots.slots[0].key.bytes(), &secret());
        assert_eq!(slots.slots[0].state, State::Loaded);
        assert_eq!(source, [0; KEY_LEN]);
    }

    #[test]
    fn import_takes_the_first_free_slot() {
        let mut memory = [const { Slot::empty() }; 3];
        memory[1].state = State::Retired;
        let mut slots = Slots::new(&mut memory);
        slots.import(&mut secret()).unwrap();
        let handle = slots.import(&mut secret()).unwrap();
        assert_eq!(handle.index, 2);
    }

    #[test]
    fn import_without_a_free_slot_keeps_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        slots.import(&mut secret()).unwrap();
        let mut source = secret();
        assert_eq!(slots.import(&mut source), Err(Error::NoFreeSlot));
        assert_eq!(source, secret());
    }

    #[test]
    fn release_wipes_only_its_own_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        slots.import(&mut secret()).unwrap();
        let second = slots.import(&mut secret()).unwrap();
        slots.release(second).unwrap();
        assert_eq!(slots.slots[1].key.bytes(), &[0; KEY_LEN]);
        assert_eq!(slots.slots[1].state, State::Free);
        assert_eq!(slots.slots[1].generation, 1);
        assert_eq!(slots.slots[0].key.bytes(), &secret());
        assert_eq!(slots.slots[0].state, State::Loaded);
    }

    #[test]
    fn a_released_handle_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import(&mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
    }

    #[test]
    fn an_old_handle_does_not_reach_a_new_key_in_the_same_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let old = slots.import(&mut secret()).unwrap();
        slots.release(old).unwrap();
        let new = slots.import(&mut secret()).unwrap();
        assert_eq!(new.index, old.index);
        assert_eq!(slots.release(old), Err(Error::StaleHandle));
        assert_eq!(slots.release(new), Ok(()));
    }

    #[test]
    fn a_handle_from_other_slots_is_stale() {
        let mut first_memory = [const { Slot::empty() }; 1];
        let mut second_memory = [const { Slot::empty() }; 1];
        let mut first = Slots::new(&mut first_memory);
        let mut second = Slots::new(&mut second_memory);
        let handle = first.import(&mut secret()).unwrap();
        second.import(&mut secret()).unwrap();
        assert_eq!(second.release(handle), Err(Error::StaleHandle));
        assert_eq!(second.slots[0].key.bytes(), &secret());
    }

    #[test]
    fn a_handle_outside_the_slots_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let id = memory.as_ptr().addr();
        let mut slots = Slots::new(&mut memory);
        slots.import(&mut secret()).unwrap();
        let outside = Handle {
            slots: id,
            index: 1,
            generation: 0,
            memory: PhantomData,
        };
        assert_eq!(slots.release(outside), Err(Error::StaleHandle));
        assert_eq!(slots.slots[0].key.bytes(), &secret());
    }

    #[test]
    fn a_slot_whose_generation_runs_out_is_retired() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].generation = u64::MAX;
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import(&mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(slots.import(&mut secret()), Err(Error::NoFreeSlot));
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
        assert_eq!(slots.slots[0].state, State::Retired);
        assert_eq!(slots.slots[0].key.bytes(), &[0; KEY_LEN]);
    }

    #[test]
    fn dropping_the_slots_wipes_every_key() {
        let mut memory = [const { Slot::empty() }; 2];
        {
            let mut slots = Slots::new(&mut memory);
            slots.import(&mut secret()).unwrap();
            slots.import(&mut secret()).unwrap();
        }
        for slot in &memory {
            assert_eq!(slot.key.bytes(), &[0; KEY_LEN]);
            assert_eq!((slot.state, slot.generation), (State::Free, 1));
        }
    }

    #[test]
    fn new_slots_wipe_a_key_left_behind() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].key.load(&mut secret());
        memory[0].state = State::Loaded;
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].key.bytes(), &[0; KEY_LEN]);
        assert_eq!(slots.slots[0].state, State::Free);
    }

    #[test]
    fn debug_shows_no_state() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import(&mut secret()).unwrap();
        assert_eq!(format!("{handle:?}"), "Handle { .. }");
        assert_eq!(format!("{:?}", slots.slots[0]), "Slot { .. }");
        assert_eq!(format!("{slots:?}"), "Slots { .. }");
    }
}

#[cfg(kani)]
mod proofs {
    use core::marker::PhantomData;

    use super::{Error, Handle, KEY_LEN, Slot, Slots, State};

    /// The shortest sequence that reaches every outcome below, including a released handle refused
    /// while its slot holds a new key; a cover property shows that case is reached.
    const STEPS: usize = 4;

    fn key(slot: &Slot) -> [u8; KEY_LEN] {
        *slot.key.bytes()
    }

    fn snapshot(slot: &Slot) -> (State, u64, [u8; KEY_LEN]) {
        (slot.state, slot.generation, key(slot))
    }

    /// Every slot but `changed` matches its snapshot. The slots are compared by concrete index:
    /// Kani 0.68.0 reports a spurious failure when two equal snapshots are compared through a
    /// symbolic index.
    fn unchanged_except(
        slots: &Slots<'_>,
        before: &[(State, u64, [u8; KEY_LEN]); 2],
        changed: usize,
    ) -> bool {
        (0..2).all(|index| index == changed || snapshot(&slots.slots[index]) == before[index])
    }

    /// A slot in any state and with any generation, holding a key only when loaded. This covers
    /// every state the code can produce and more: a key outside a loaded slot cannot arise, because
    /// every path out of the loaded state wipes the key first.
    fn any_slot() -> Slot {
        let mut slot = Slot::empty();
        slot.generation = kani::any();
        slot.state = match kani::any::<u8>() % 3 {
            0 => State::Free,
            1 => State::Loaded,
            _ => State::Retired,
        };
        if slot.state == State::Loaded {
            slot.key.load(&mut kani::any());
        }
        slot
    }

    /// From empty memory, any interleaving of four imports and releases over two slots, with any
    /// keys. A live handle reaches exactly its own key, a released key is zero at once, and a
    /// released handle is refused ever after, including while its slot holds a new key.
    #[kani::proof]
    #[kani::unwind(33)]
    fn a_handle_reaches_only_its_own_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let mut issued: [Option<(Handle<'_>, [u8; KEY_LEN])>; STEPS] = [None; STEPS];
        let mut live = [false; STEPS];

        for step in 0..STEPS {
            if kani::any() {
                let mut source: [u8; KEY_LEN] = kani::any();
                let original = source;
                match slots.import(&mut source) {
                    Ok(handle) => {
                        assert!(source == [0; KEY_LEN]);
                        issued[step] = Some((handle, original));
                        live[step] = true;
                        kani::cover!(true, "a key is imported");
                    }
                    Err(error) => {
                        assert!(error == Error::NoFreeSlot);
                        assert!(source == original);
                        kani::cover!(true, "an import finds no free slot");
                    }
                }
            } else {
                let pick: usize = kani::any();
                kani::assume(pick < STEPS);
                kani::cover!(issued[pick].is_some(), "a step releases an earlier handle");
                if let Some((handle, _)) = issued[pick] {
                    let reused = slots.slots[handle.index].state == State::Loaded;
                    let result = slots.release(handle);
                    if live[pick] {
                        assert!(result == Ok(()));
                        assert!(key(&slots.slots[handle.index]) == [0; KEY_LEN]);
                        live[pick] = false;
                        kani::cover!(true, "a live key is released");
                    } else {
                        assert!(result == Err(Error::StaleHandle));
                        kani::cover!(
                            reused,
                            "a released handle is refused while its slot holds a new key"
                        );
                    }
                }
            }

            for (entry, is_live) in issued.iter().zip(live) {
                if let (Some((handle, original)), true) = (entry, is_live) {
                    let slot = &slots.slots[handle.index];
                    assert!(slot.state == State::Loaded && slot.generation == handle.generation);
                    assert!(key(slot) == *original);
                }
            }
        }
    }

    /// From any state of two slots, a handle whose set number is not this set's is refused,
    /// whatever slot and generation it names, and no slot changes.
    #[kani::proof]
    #[kani::unwind(33)]
    fn a_handle_from_other_slots_is_refused() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];

        let foreign = Handle {
            slots: kani::any(),
            index: kani::any(),
            generation: kani::any(),
            memory: PhantomData,
        };
        kani::assume(foreign.slots != id);
        kani::cover!(
            before
                .get(foreign.index)
                .is_some_and(|&(state, generation, _)| {
                    state == State::Loaded && generation == foreign.generation
                }),
            "the foreign handle names a loaded slot and its generation"
        );

        assert!(slots.release(foreign) == Err(Error::StaleHandle));
        assert!(snapshot(&slots.slots[0]) == before[0]);
        assert!(snapshot(&slots.slots[1]) == before[1]);
    }

    /// From any state of two slots, creating `Slots` wipes every loaded key and loads none.
    #[kani::proof]
    #[kani::unwind(33)]
    fn creating_slots_wipes_every_key() {
        let mut memory = [any_slot(), any_slot()];
        kani::cover!(
            memory.iter().all(|slot| slot.state == State::Loaded),
            "both slots hold a key before"
        );
        let slots = Slots::new(&mut memory);
        for slot in slots.slots.iter() {
            assert!(slot.state != State::Loaded);
            assert!(key(slot) == [0; KEY_LEN]);
        }
    }

    /// From any state of two slots and any generation: an import takes the first free slot, issues
    /// that slot's generation, keeps it in the slot and wipes its source; a handle of this set
    /// naming any slot and generation releases a key only if that slot is loaded with that
    /// generation, and otherwise is refused and changes nothing; a release wipes the key and
    /// advances the generation by one, or retires the slot when the generation runs out; no call
    /// panics or overflows.
    #[kani::proof]
    #[kani::unwind(33)]
    fn a_handle_releases_only_a_matching_loaded_slot() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };

        if kani::any() {
            let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
            let first_free = before
                .iter()
                .position(|&(state, _, _)| state == State::Free);
            let mut source: [u8; KEY_LEN] = kani::any();
            let original = source;
            match (slots.import(&mut source), first_free) {
                (Ok(handle), Some(index)) => {
                    assert!(handle.index == index && handle.generation == before[index].1);
                    assert!(source == [0; KEY_LEN]);
                    let slot = &slots.slots[index];
                    assert!(slot.state == State::Loaded && slot.generation == before[index].1);
                    assert!(key(slot) == original);
                    assert!(unchanged_except(&slots, &before, index));
                    kani::cover!(true, "a key is imported");
                }
                (Err(error), None) => {
                    assert!(error == Error::NoFreeSlot && source == original);
                    kani::cover!(true, "no slot is free");
                }
                _ => panic!("import disagrees with the free slots"),
            }
        }

        let forged = Handle {
            slots: id,
            index: kani::any(),
            generation: kani::any(),
            memory: PhantomData,
        };
        let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
        kani::cover!(
            before.iter().all(|&(state, _, _)| state == State::Loaded),
            "both slots hold a key when the handle arrives"
        );
        kani::cover!(
            before[0].0 == State::Free,
            "the first slot is free when the handle arrives"
        );
        let target = before.get(forged.index).filter(|&&(state, generation, _)| {
            state == State::Loaded && generation == forged.generation
        });
        let result = slots.release(forged);
        match target {
            Some(&(_, generation, _)) => {
                assert!(result == Ok(()));
                let slot = &slots.slots[forged.index];
                assert!(key(slot) == [0; KEY_LEN]);
                if generation == u64::MAX {
                    assert!(slot.state == State::Retired);
                    kani::cover!(true, "a slot is retired when its generation runs out");
                } else {
                    assert!(
                        slot.state == State::Free
                            && Some(slot.generation) == generation.checked_add(1)
                    );
                    kani::cover!(true, "a release advances the generation by one");
                }
                assert!(unchanged_except(&slots, &before, forged.index));
            }
            None => {
                assert!(result == Err(Error::StaleHandle));
                assert!(snapshot(&slots.slots[0]) == before[0]);
                assert!(snapshot(&slots.slots[1]) == before[1]);
                kani::cover!(
                    before.iter().any(|&(state, _, _)| state == State::Loaded),
                    "a handle is refused while a key is loaded"
                );
            }
        }
    }
}
