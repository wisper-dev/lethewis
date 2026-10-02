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
