// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::{fmt, marker::PhantomData};

use crate::{
    entropy::{Entropy, EntropyError},
    error::Error,
    key::{Key, KeyLength},
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
/// use lethewis_core::{Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 1];
/// let handle;
/// {
///     let mut slots = Slots::new(&mut memory);
///     handle = slots.import32(&mut [7; 32])?;
/// }
/// let _ = handle;
/// # Ok::<(), lethewis_core::Error>(())
/// ```
///
/// The same code with the memory gone before the handle does not compile:
///
/// ```compile_fail
/// use lethewis_core::{Slot, Slots};
///
/// let handle;
/// {
///     let mut memory = [const { Slot::empty() }; 1];
///     let mut slots = Slots::new(&mut memory);
///     handle = slots.import32(&mut [7; 32])?;
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
/// use lethewis_core::{Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 4];
/// let mut slots = Slots::new(&mut memory);
///
/// let mut secret = [7; 32];
/// let handle = slots.import32(&mut secret)?;
/// assert_eq!(secret, [0; 32]);
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

    /// Takes a 32-byte key from `source` into a free slot and wipes `source`.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free. `source` is then left as it was.
    pub fn import32(&mut self, source: &mut [u8; 32]) -> Result<Handle<'a>, Error> {
        self.load(|key| {
            key.load32(source);
            Ok(())
        })
    }

    /// Takes a 64-byte key from `source` into a free slot and wipes `source`.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free. `source` is then left as it was.
    pub fn import64(&mut self, source: &mut [u8; 64]) -> Result<Handle<'a>, Error> {
        self.load(|key| {
            key.load64(source);
            Ok(())
        })
    }

    /// Creates a key of `length` random bytes from `entropy` in a free slot. The bytes are written
    /// straight into the slot, and the library makes no copy of them. `entropy` is asked once, and
    /// only when a slot is free.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, and [`Error::EntropyFailed`] if `entropy` fails.
    /// No slot changes then.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and the slot stays free and wiped.
    pub fn generate(
        &mut self,
        length: KeyLength,
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<Handle<'a>, Error> {
        self.load(|key| {
            key.fill(length, entropy)
                .map_err(|EntropyError| Error::EntropyFailed)
        })
    }

    /// Puts a key into the first free slot with `fill` and issues a handle if `fill` succeeds.
    fn load(
        &mut self,
        fill: impl FnOnce(&mut Key) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        let slots = self.id();
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.state == State::Free)
            .ok_or(Error::NoFreeSlot)?;
        fill(&mut slot.key)?;
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

    /// Wipes the key in every slot, loaded or not, and frees the loaded ones.
    fn unload_all(&mut self) {
        for slot in self.slots.iter_mut() {
            if slot.state == State::Loaded {
                slot.unload();
            } else {
                slot.key.wipe();
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

    use super::{Entropy, EntropyError, Error, Handle, KeyLength, Slot, Slots, State};
    use crate::key::tests::{Counting, Failing, Panicking, Recording, counted, padded};

    assert_not_impl!(Slot: Clone, PartialEq, Default);

    /// Fails the test if it is ever asked for bytes.
    struct Untouched;

    impl Entropy for Untouched {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
            panic!("no slot is free, so no bytes should be asked for")
        }
    }

    fn secret() -> [u8; 32] {
        [7; 32]
    }

    #[test]
    fn import32_loads_the_key_and_wipes_the_source() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let mut source = secret();
        let handle = slots.import32(&mut source).unwrap();
        assert_eq!((handle.index, handle.generation), (0, 0));
        assert_eq!(slots.slots[0].key.bytes(), &padded(&secret()));
        assert_eq!(slots.slots[0].key.length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[0].state, State::Loaded);
        assert_eq!(source, [0; 32]);
    }

    #[test]
    fn import64_loads_the_key_and_wipes_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let mut source = [5; 64];
        slots.import64(&mut source).unwrap();
        assert_eq!(slots.slots[0].key.bytes(), &[5; 64]);
        assert_eq!(slots.slots[0].key.length(), KeyLength::Bytes64);
        assert_eq!(slots.slots[0].state, State::Loaded);
        assert_eq!(source, [0; 64]);
    }

    #[test]
    fn generate_writes_random_bytes_into_the_slot() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let short = slots.generate(KeyLength::Bytes32, &mut Counting).unwrap();
        let long = slots.generate(KeyLength::Bytes64, &mut Counting).unwrap();
        assert_eq!((short.index, long.index), (0, 1));
        assert_eq!(slots.slots[0].key.bytes(), &padded(&counted::<32>()));
        assert_eq!(slots.slots[0].key.length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[1].key.bytes(), &counted::<64>());
        assert_eq!(slots.slots[1].key.length(), KeyLength::Bytes64);
        assert_eq!(slots.slots[1].state, State::Loaded);
    }

    #[test]
    fn a_failed_generate_leaves_the_slot_free_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        assert_eq!(
            slots.generate(KeyLength::Bytes64, &mut Failing),
            Err(Error::EntropyFailed)
        );
        assert_eq!(slots.slots[0].state, State::Free);
        assert_eq!(slots.slots[0].generation, 0);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
    }

    #[test]
    fn generate_asks_the_source_once_for_the_length() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let mut source = Recording::default();
        slots.generate(KeyLength::Bytes64, &mut source).unwrap();
        assert_eq!((source.calls, source.asked), (1, 64));
        assert_eq!(source.at, slots.slots[0].key.bytes().as_ptr().addr());
    }

    #[test]
    fn generate_takes_a_source_behind_a_trait_object() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let source: &mut dyn Entropy = &mut Counting;
        slots.generate(KeyLength::Bytes32, source).unwrap();
        assert_eq!(slots.slots[0].key.bytes(), &padded(&counted::<32>()));
    }

    #[test]
    fn a_panic_in_the_source_leaves_the_slot_free_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = slots.generate(KeyLength::Bytes64, &mut Panicking);
        }));
        assert!(outcome.is_err());
        assert_eq!(slots.slots[0].state, State::Free);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
        assert!(slots.generate(KeyLength::Bytes32, &mut Counting).is_ok());
    }

    #[test]
    fn generate_without_a_free_slot_asks_for_no_bytes() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        slots.import32(&mut secret()).unwrap();
        assert_eq!(
            slots.generate(KeyLength::Bytes32, &mut Untouched),
            Err(Error::NoFreeSlot)
        );
    }

    #[test]
    fn import_takes_the_first_free_slot() {
        let mut memory = [const { Slot::empty() }; 3];
        memory[1].state = State::Retired;
        let mut slots = Slots::new(&mut memory);
        slots.import32(&mut secret()).unwrap();
        let handle = slots.import64(&mut [5; 64]).unwrap();
        assert_eq!(handle.index, 2);
    }

    #[test]
    fn import_without_a_free_slot_keeps_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        slots.import32(&mut secret()).unwrap();
        let mut short = secret();
        assert_eq!(slots.import32(&mut short), Err(Error::NoFreeSlot));
        assert_eq!(short, secret());
        let mut long = [5; 64];
        assert_eq!(slots.import64(&mut long), Err(Error::NoFreeSlot));
        assert_eq!(long, [5; 64]);
    }

    #[test]
    fn release_wipes_only_its_own_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        slots.import32(&mut secret()).unwrap();
        let second = slots.import64(&mut [5; 64]).unwrap();
        slots.release(second).unwrap();
        assert_eq!(slots.slots[1].key.bytes(), &padded(&[]));
        assert_eq!(slots.slots[1].key.length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[1].state, State::Free);
        assert_eq!(slots.slots[1].generation, 1);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&secret()));
        assert_eq!(slots.slots[0].state, State::Loaded);
    }

    #[test]
    fn a_released_handle_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import32(&mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
    }

    #[test]
    fn an_old_handle_does_not_reach_a_new_key_in_the_same_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let old = slots.import32(&mut secret()).unwrap();
        slots.release(old).unwrap();
        let new = slots.generate(KeyLength::Bytes64, &mut Counting).unwrap();
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
        let handle = first.import32(&mut secret()).unwrap();
        second.import32(&mut secret()).unwrap();
        assert_eq!(second.release(handle), Err(Error::StaleHandle));
        assert_eq!(second.slots[0].key.bytes(), &padded(&secret()));
    }

    #[test]
    fn a_handle_outside_the_slots_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let id = memory.as_ptr().addr();
        let mut slots = Slots::new(&mut memory);
        slots.import32(&mut secret()).unwrap();
        let outside = Handle {
            slots: id,
            index: 1,
            generation: 0,
            memory: PhantomData,
        };
        assert_eq!(slots.release(outside), Err(Error::StaleHandle));
        assert_eq!(slots.slots[0].key.bytes(), &padded(&secret()));
    }

    #[test]
    fn a_slot_whose_generation_runs_out_is_retired() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].generation = u64::MAX;
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import32(&mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(slots.import32(&mut secret()), Err(Error::NoFreeSlot));
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
        assert_eq!(slots.slots[0].state, State::Retired);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
    }

    #[test]
    fn dropping_the_slots_wipes_every_key() {
        let mut memory = [const { Slot::empty() }; 2];
        {
            let mut slots = Slots::new(&mut memory);
            slots.import32(&mut secret()).unwrap();
            slots.import64(&mut [5; 64]).unwrap();
        }
        for slot in &memory {
            assert_eq!(slot.key.bytes(), &padded(&[]));
            assert_eq!(slot.key.length(), KeyLength::Bytes32);
            assert_eq!((slot.state, slot.generation), (State::Free, 1));
        }
    }

    #[test]
    fn new_slots_wipe_a_key_left_behind() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].key.load64(&mut [5; 64]);
        memory[0].state = State::Loaded;
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
        assert_eq!(slots.slots[0].state, State::Free);
    }

    #[test]
    fn new_slots_wipe_bytes_left_in_a_free_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].key.load64(&mut [5; 64]);
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
        assert_eq!(
            (slots.slots[0].state, slots.slots[0].generation),
            (State::Free, 0)
        );
    }

    #[test]
    fn debug_shows_no_state() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import32(&mut secret()).unwrap();
        assert_eq!(format!("{handle:?}"), "Handle { .. }");
        assert_eq!(format!("{:?}", slots.slots[0]), "Slot { .. }");
        assert_eq!(format!("{slots:?}"), "Slots { .. }");
    }
}

#[cfg(kani)]
mod proofs {
    use core::marker::PhantomData;

    use super::{Entropy, EntropyError, Error, Handle, KeyLength, Slot, Slots, State};

    /// The shortest sequence that reaches every outcome below, including a released handle refused
    /// while its slot holds a new key; a cover property shows that case is reached.
    const STEPS: usize = 4;

    type Bytes = [u8; 64];
    type Snapshot = (State, u64, KeyLength, Bytes);

    fn key(slot: &Slot) -> Bytes {
        *slot.key.bytes()
    }

    fn snapshot(slot: &Slot) -> Snapshot {
        (slot.state, slot.generation, slot.key.length(), key(slot))
    }

    // Kani 0.68.0 reports spurious failures when a key buffer is read through a symbolic index,
    // so every read below picks the slot or snapshot by a concrete index.

    fn slot_at<'s>(slots: &'s Slots<'_>, index: usize) -> &'s Slot {
        if index == 0 {
            &slots.slots[0]
        } else {
            &slots.slots[1]
        }
    }

    fn snapshot_at(before: &[Snapshot; 2], index: usize) -> Snapshot {
        if index == 0 { before[0] } else { before[1] }
    }

    /// Every slot but `changed` matches its snapshot.
    fn unchanged_except(slots: &Slots<'_>, before: &[Snapshot; 2], changed: usize) -> bool {
        (0..2).all(|index| index == changed || snapshot(&slots.slots[index]) == before[index])
    }

    fn any_length() -> KeyLength {
        if kani::any() {
            KeyLength::Bytes32
        } else {
            KeyLength::Bytes64
        }
    }

    /// The first `length` bytes of `bytes`, followed by zeros.
    fn padded(bytes: Bytes, length: KeyLength) -> Bytes {
        let mut out = [0; 64];
        for index in 0..length.bytes() {
            out[index] = bytes[index];
        }
        out
    }

    /// A slot in any state and with any generation, holding a key of either length only when
    /// loaded. This covers every state the code can produce and more: a key outside a loaded slot
    /// cannot arise, because every path out of the loaded state wipes the key first, and bytes a
    /// generation writes into a free slot are wiped when it fails, which the last proof checks, or
    /// panics, which a unit test checks.
    fn any_slot() -> Slot {
        let mut slot = Slot::empty();
        slot.generation = kani::any();
        slot.state = match kani::any::<u8>() % 3 {
            0 => State::Free,
            1 => State::Loaded,
            _ => State::Retired,
        };
        if slot.state == State::Loaded {
            if kani::any() {
                slot.key.load32(&mut kani::any());
            } else {
                slot.key.load64(&mut kani::any());
            }
        }
        slot
    }

    /// A platform source that writes any bytes and then either succeeds or fails, as a real one
    /// may fail after writing part of its output. It remembers how often and for how many bytes it
    /// was asked, and what it wrote.
    struct AnyEntropy {
        written: Bytes,
        calls: u8,
        requested: usize,
        at: usize,
        failed: bool,
    }

    impl Entropy for AnyEntropy {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            self.calls = self.calls.saturating_add(1);
            self.requested = dest.len();
            self.at = dest.as_ptr().addr();
            for (index, byte) in dest.iter_mut().enumerate() {
                *byte = kani::any();
                self.written[index] = *byte;
            }
            self.failed = kani::any();
            if self.failed {
                kani::cover!(
                    self.written.iter().any(|&byte| byte != 0),
                    "the source fails after writing bytes"
                );
                return Err(EntropyError);
            }
            Ok(())
        }
    }

    /// Imports one key of either length with any bytes. Returns the outcome and, on success, the
    /// bytes and length the slot must now hold.
    fn import_any(slots: &mut Slots<'_>) -> (Result<Handle<'static>, Error>, Bytes, KeyLength) {
        let (result, expected, length) = if kani::any() {
            let mut source: [u8; 32] = kani::any();
            let original = source;
            let result = slots.import32(&mut source);
            let mut bytes = [0; 64];
            bytes[..32].copy_from_slice(&original);
            assert!(source == if result.is_ok() { [0; 32] } else { original });
            (result, bytes, KeyLength::Bytes32)
        } else {
            let mut source: [u8; 64] = kani::any();
            let original = source;
            let result = slots.import64(&mut source);
            assert!(source == if result.is_ok() { [0; 64] } else { original });
            (result, original, KeyLength::Bytes64)
        };
        let result = result.map(|handle| Handle {
            slots: handle.slots,
            index: handle.index,
            generation: handle.generation,
            memory: PhantomData,
        });
        (result, expected, length)
    }

    /// Loads one key by any of the three ways, with any key and length. Returns the outcome and,
    /// on success, the bytes and length the slot must now hold.
    fn load_any(slots: &mut Slots<'_>) -> (Result<Handle<'static>, Error>, Bytes, KeyLength) {
        let mut entropy = AnyEntropy {
            written: [0; 64],
            calls: 0,
            requested: 0,
            at: 0,
            failed: false,
        };
        let way: u8 = kani::any();
        let (result, expected, length) = if way % 3 == 0 {
            let mut source: [u8; 32] = kani::any();
            let original = source;
            let result = slots.import32(&mut source);
            let mut bytes = [0; 64];
            bytes[..32].copy_from_slice(&original);
            assert!(source == if result.is_ok() { [0; 32] } else { original });
            (result, bytes, KeyLength::Bytes32)
        } else if way % 3 == 1 {
            let mut source: [u8; 64] = kani::any();
            let original = source;
            let result = slots.import64(&mut source);
            assert!(source == if result.is_ok() { [0; 64] } else { original });
            (result, original, KeyLength::Bytes64)
        } else {
            let length = any_length();
            let result = slots.generate(length, &mut entropy);
            if result == Err(Error::NoFreeSlot) {
                assert!(entropy.calls == 0);
            } else {
                assert!(entropy.calls == 1 && entropy.requested == length.bytes());
                assert!(result.is_ok() == !entropy.failed);
            }
            if let Ok(handle) = result {
                let buffer = slot_at(slots, handle.index).key.bytes().as_ptr().addr();
                assert!(entropy.at == buffer);
            }
            if result == Err(Error::EntropyFailed) {
                kani::cover!(true, "the platform source fails");
            }
            kani::cover!(
                result.is_ok() && length == KeyLength::Bytes32,
                "a short key is generated"
            );
            kani::cover!(
                result.is_ok() && length == KeyLength::Bytes64,
                "a long key is generated"
            );
            (result, padded(entropy.written, length), length)
        };
        let result = result.map(|handle| Handle {
            slots: handle.slots,
            index: handle.index,
            generation: handle.generation,
            memory: PhantomData,
        });
        (result, expected, length)
    }

    /// From empty memory, any interleaving of four imports and releases over two slots, with any
    /// keys of either length. A live handle reaches exactly its own key, a released key is zero at
    /// once, and a released handle is refused ever after, including while its slot holds a new
    /// key. Every load goes through the same code, so generated keys are covered by the last proof,
    /// which checks each way of loading from any state.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_handle_reaches_only_its_own_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let mut issued: [Option<(Handle<'_>, Bytes, KeyLength)>; STEPS] = [None; STEPS];
        let mut live = [false; STEPS];

        for step in 0..STEPS {
            if kani::any() {
                let (result, expected, length) = import_any(&mut slots);
                match result {
                    Ok(handle) => {
                        issued[step] = Some((handle, expected, length));
                        live[step] = true;
                        kani::cover!(true, "a key is loaded");
                    }
                    Err(error) => {
                        assert!(error == Error::NoFreeSlot);
                        kani::cover!(true, "an import finds no free slot");
                    }
                }
            } else {
                let pick: usize = kani::any();
                kani::assume(pick < STEPS);
                kani::cover!(issued[pick].is_some(), "a step releases an earlier handle");
                if let Some((handle, _, _)) = issued[pick] {
                    let reused = slot_at(&slots, handle.index).state == State::Loaded;
                    let result = slots.release(handle);
                    if live[pick] {
                        assert!(result == Ok(()));
                        assert!(key(slot_at(&slots, handle.index)) == [0; 64]);
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
                if let (Some((handle, expected, length)), true) = (entry, is_live) {
                    let slot = slot_at(&slots, handle.index);
                    assert!(slot.state == State::Loaded && slot.generation == handle.generation);
                    assert!(key(slot) == *expected && slot.key.length() == *length);
                }
            }
        }
    }

    /// From any state of two slots, a handle whose set number is not this set's is refused,
    /// whatever slot and generation it names, and no slot changes.
    #[kani::proof]
    #[kani::unwind(65)]
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
            foreign.index < 2 && {
                let (state, generation, _, _) = snapshot_at(&before, foreign.index);
                state == State::Loaded && generation == foreign.generation
            },
            "the foreign handle names a loaded slot and its generation"
        );

        assert!(slots.release(foreign) == Err(Error::StaleHandle));
        assert!(snapshot(&slots.slots[0]) == before[0]);
        assert!(snapshot(&slots.slots[1]) == before[1]);
    }

    /// A slot in any state and with any generation whose buffer holds a key of any bytes and either
    /// length, loaded or not.
    fn any_dirty_slot() -> Slot {
        let mut slot = any_slot();
        if kani::any() {
            slot.key.load32(&mut kani::any());
        } else {
            slot.key.load64(&mut kani::any());
        }
        slot
    }

    /// From any state of two slots, with any bytes left in any buffer, creating `Slots` wipes every
    /// buffer and loads no slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn creating_slots_wipes_every_key() {
        let mut memory = [any_dirty_slot(), any_dirty_slot()];
        kani::cover!(
            memory
                .iter()
                .all(|slot| slot.state == State::Loaded && slot.key.length() == KeyLength::Bytes64),
            "both slots hold a long key before"
        );
        kani::cover!(
            memory.iter().any(|slot| {
                slot.state == State::Free && slot.key.bytes().iter().any(|&byte| byte != 0)
            }),
            "a free slot holds bytes before"
        );
        let slots = Slots::new(&mut memory);
        for slot in slots.slots.iter() {
            assert!(slot.state != State::Loaded);
            assert!(key(slot) == [0; 64] && slot.key.length() == KeyLength::Bytes32);
        }
    }

    /// From any state of two slots and any generation: a load by import or from the platform
    /// source takes the first free slot, issues that slot's generation, keeps it in the slot and
    /// leaves exactly the expected bytes there, zero past the key's length; a failed source or a
    /// full set changes no slot, and a full set asks the source for nothing. A handle of this set
    /// naming any slot and generation releases a key only if that slot is loaded with that
    /// generation, and otherwise is refused and changes nothing; a release wipes the key and
    /// advances the generation by one, or retires the slot when the generation runs out; no call
    /// panics or overflows.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_handle_releases_only_a_matching_loaded_slot() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };

        if kani::any() {
            let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
            let first_free = before
                .iter()
                .position(|&(state, _, _, _)| state == State::Free);
            let (result, expected, length) = load_any(&mut slots);
            match (result, first_free) {
                (Ok(handle), Some(index)) => {
                    let generation = snapshot_at(&before, index).1;
                    assert!(handle.index == index && handle.generation == generation);
                    let slot = slot_at(&slots, index);
                    assert!(slot.state == State::Loaded && slot.generation == generation);
                    assert!(key(slot) == expected && slot.key.length() == length);
                    assert!(unchanged_except(&slots, &before, index));
                    kani::cover!(length == KeyLength::Bytes32, "a short key is loaded");
                    kani::cover!(length == KeyLength::Bytes64, "a long key is loaded");
                }
                (Err(Error::EntropyFailed), Some(_)) | (Err(Error::NoFreeSlot), None) => {
                    assert!(unchanged_except(&slots, &before, 2));
                    kani::cover!(first_free.is_none(), "no slot is free");
                }
                _ => panic!("the load disagrees with the free slots"),
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
            before
                .iter()
                .all(|&(state, _, _, _)| state == State::Loaded),
            "both slots hold a key when the handle arrives"
        );
        kani::cover!(
            before[0].0 == State::Free,
            "the first slot is free when the handle arrives"
        );
        let target = Some(forged.index)
            .filter(|&index| index < 2)
            .map(|index| snapshot_at(&before, index))
            .filter(|&(state, generation, _, _)| {
                state == State::Loaded && generation == forged.generation
            });
        let result = slots.release(forged);
        match target {
            Some((_, generation, _, _)) => {
                assert!(result == Ok(()));
                let slot = slot_at(&slots, forged.index);
                assert!(key(slot) == [0; 64] && slot.key.length() == KeyLength::Bytes32);
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
                    before
                        .iter()
                        .any(|&(state, _, _, _)| state == State::Loaded),
                    "a handle is refused while a key is loaded"
                );
            }
        }
    }
}
