// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::{fmt, marker::PhantomData};

use crate::{
    derive::{KeyId, derive_key_id, derive_wrap_key, wipe_cipher_stack},
    entropy::{Entropy, EntropyError},
    error::Error,
    key::{Key, KeyLength, wipe},
    record::{self, AssociatedData, Attributes, PLAINTEXT_LEN, Purpose, RECORD_LEN, Status},
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, NONCE_LEN, TAG_LEN},
};

/// Memory for one key, provided by the caller.
///
/// A slot cannot be copied, cloned or compared. It holds a key only while a [`Slots`] over it is
/// alive, so moving the memory afterwards copies no key.
pub struct Slot {
    key: Key,
    id: KeyId,
    purpose: Purpose,
    status: Status,
    generation: u64,
    occupancy: Occupancy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Occupancy {
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
            id: KeyId::empty(),
            purpose: Purpose::Wrap,
            status: Status::Enabled,
            generation: 0,
            occupancy: Occupancy::Free,
        }
    }

    fn unload(&mut self) {
        self.key.wipe();
        self.id.wipe();
        match self.generation.checked_add(1) {
            Some(next) => {
                self.generation = next;
                self.occupancy = Occupancy::Free;
            }
            None => self.occupancy = Occupancy::Retired,
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
/// use lethewis_core::{Purpose, Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 1];
/// let handle;
/// {
///     let mut slots = Slots::new(&mut memory);
///     handle = slots.import32(Purpose::Wrap, &mut [7; 32])?;
/// }
/// let _ = handle;
/// # Ok::<(), lethewis_core::Error>(())
/// ```
///
/// The same code with the memory gone before the handle does not compile:
///
/// ```compile_fail
/// use lethewis_core::{Purpose, Slot, Slots};
///
/// let handle;
/// {
///     let mut memory = [const { Slot::empty() }; 1];
///     let mut slots = Slots::new(&mut memory);
///     handle = slots.import32(Purpose::Wrap, &mut [7; 32])?;
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
/// use lethewis_core::{Purpose, Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 4];
/// let mut slots = Slots::new(&mut memory);
///
/// let mut secret = [7; 32];
/// let handle = slots.import32(Purpose::Wrap, &mut secret)?;
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

    /// Takes a 32-byte key for `purpose` from `source` into a free slot and wipes `source`.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe
    /// of 8 KiB, or 64 KiB, below it. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, and [`Error::DerivationFailed`] if the identifier
    /// of the key cannot be derived. `source` is then left as it was, and no slot changes.
    pub fn import32(
        &mut self,
        purpose: Purpose,
        source: &mut [u8; 32],
    ) -> Result<Handle<'a>, Error> {
        let handle = self.load(purpose, Status::Enabled, |key| {
            key.copy32(source);
            Ok(())
        })?;
        wipe(source);
        Ok(handle)
    }

    /// Takes a 64-byte key for `purpose` from `source` into a free slot and wipes `source`.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe
    /// of 8 KiB, or 64 KiB, below it. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, and [`Error::DerivationFailed`] if the identifier
    /// of the key cannot be derived. `source` is then left as it was, and no slot changes.
    pub fn import64(
        &mut self,
        purpose: Purpose,
        source: &mut [u8; 64],
    ) -> Result<Handle<'a>, Error> {
        let handle = self.load(purpose, Status::Enabled, |key| {
            key.copy64(source);
            Ok(())
        })?;
        wipe(source);
        Ok(handle)
    }

    /// Creates a key for `purpose` of `length` random bytes from `entropy` in a free slot. The
    /// bytes are written straight into the slot, and the library's own code makes no copy of them;
    /// the stack the derivation of the key's identifier used is wiped after it. `entropy` is asked
    /// once, and only when a slot is free.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe
    /// of 8 KiB, or 64 KiB, below it. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, [`Error::EntropyFailed`] if `entropy` fails, and
    /// [`Error::DerivationFailed`] if the identifier of the key cannot be derived. No slot changes
    /// then.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and the slot stays free and wiped.
    pub fn generate(
        &mut self,
        purpose: Purpose,
        length: KeyLength,
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<Handle<'a>, Error> {
        self.load(purpose, Status::Enabled, |key| {
            key.fill(length, entropy)
                .map_err(|EntropyError| Error::EntropyFailed)
        })
    }

    /// Wraps the key that `key` refers to under the key that `parent` refers to and writes the
    /// record into `record`. The record opens only with that parent and the same `context`, which
    /// names the place the record is kept, from 1 to 255 bytes. The nonce comes from `entropy`.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if either handle does not refer to a key held here now,
    /// [`Error::SameKey`] if both refer to the same key, held once or loaded twice,
    /// [`Error::KeyDisabled`] if the parent is disabled, [`Error::EntropyFailed`] if `entropy`
    /// fails, [`Error::DerivationFailed`] if the key that encrypts the record cannot be derived,
    /// and [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails.
    /// `record` is then left as it was.
    pub fn wrap(
        &mut self,
        key: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; RECORD_LEN],
    ) -> Result<(), Error> {
        let wrapped =
            lethewis_dit::with(|| self.wrap_on_stack(key, parent, context, entropy, record));
        wipe_cipher_stack();
        wrapped
    }

    /// The wrap itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn wrap_on_stack(
        &mut self,
        key: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; RECORD_LEN],
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let (child, wrapping) = (self.loaded(key)?, self.loaded(parent)?);
        let (Some(child), Some(wrapping)) = (self.slots.get(child), self.slots.get(wrapping))
        else {
            return Err(Error::StaleHandle);
        };
        if child.id.same(&wrapping.id) {
            return Err(Error::SameKey);
        }
        if wrapping.status != Status::Enabled {
            return Err(Error::KeyDisabled);
        }
        let mut nonce = [0; NONCE_LEN];
        entropy
            .fill(&mut nonce)
            .map_err(|EntropyError| Error::EntropyFailed)?;
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        if derive_wrap_key(&wrapping.key, wrapping.purpose, &mut cipher_key).is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let attributes = Attributes {
            purpose: child.purpose,
            status: child.status,
            parent: wrapping.id.bytes(),
            epoch: 0,
        };
        let mut sealed = [0; PLAINTEXT_LEN];
        record::build(&attributes, &child.key, &mut sealed);
        let tag = seal::seal(&cipher_key, &nonce, associated.bytes(), &mut sealed);
        wipe(&mut cipher_key);
        let tag = tag.map_err(|_| Error::CipherFailed)?;
        write_record(record, &nonce, &sealed, &tag);
        Ok(())
    }

    /// Unwraps `record` with the key that `parent` refers to and the `context` it was wrapped for,
    /// into a free slot. The key comes out with the purpose and the status the record holds.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `parent` does not refer to a key held here now,
    /// [`Error::KeyDisabled`] if the parent is disabled, [`Error::NoFreeSlot`] if no slot is free,
    /// [`Error::DerivationFailed`] if a value cannot be derived from a key, and
    /// [`Error::RecordRejected`] if the record does not open with this parent and context, holds a
    /// plaintext this version of the library cannot read, or names another key as its parent. No
    /// slot changes then.
    pub fn unwrap(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let unwrapped = lethewis_dit::with(|| self.unwrap_on_stack(parent, context, record));
        wipe_cipher_stack();
        unwrapped
    }

    /// The unwrap itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn unwrap_on_stack(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.loaded(parent)?;
        let wrapping = self.slots.get(index).ok_or(Error::StaleHandle)?;
        if wrapping.status != Status::Enabled {
            return Err(Error::KeyDisabled);
        }
        if !self
            .slots
            .iter()
            .any(|slot| slot.occupancy == Occupancy::Free)
        {
            return Err(Error::NoFreeSlot);
        }
        let (nonce, mut sealed, tag) = split_record(record);
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        if derive_wrap_key(&wrapping.key, wrapping.purpose, &mut cipher_key).is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let opened = seal::open(&cipher_key, &nonce, associated.bytes(), &mut sealed, &tag);
        wipe(&mut cipher_key);
        let admitted = match opened {
            Ok(()) => self.admit(index, &sealed),
            Err(_) => Err(Error::RecordRejected),
        };
        wipe(&mut sealed);
        admitted
    }

    /// Loads the key a record's plaintext holds into a free slot, if the plaintext parses and names
    /// the key in slot `parent` as the one it is wrapped with. `parent` is a loaded slot.
    fn admit(
        &mut self,
        parent: usize,
        plaintext: &[u8; PLAINTEXT_LEN],
    ) -> Result<Handle<'a>, Error> {
        let (attributes, key) = record::parse(plaintext).map_err(|_| Error::RecordRejected)?;
        let names_parent = self
            .slots
            .get(parent)
            .is_some_and(|slot| slot.id.is(&attributes.parent));
        if !names_parent {
            return Err(Error::RecordRejected);
        }
        self.load(attributes.purpose, attributes.status, |slot_key| {
            key.load_into(slot_key);
            Ok(())
        })
    }

    /// The index of the slot `handle` refers to, if it is loaded with the handle's generation.
    fn loaded(&self, handle: Handle<'a>) -> Result<usize, Error> {
        if handle.slots != self.id() {
            return Err(Error::StaleHandle);
        }
        self.slots
            .get(handle.index)
            .filter(|slot| {
                slot.occupancy == Occupancy::Loaded && slot.generation == handle.generation
            })
            .map(|_| handle.index)
            .ok_or(Error::StaleHandle)
    }

    /// Puts a key for `purpose` with `status` into the first free slot with `fill`, derives its
    /// identifier, and issues a handle if both succeed, with data-independent timing on. If the
    /// derivation fails, the key and what the derivation wrote are wiped.
    fn load(
        &mut self,
        purpose: Purpose,
        status: Status,
        fill: impl FnOnce(&mut Key) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        lethewis_dit::with(|| self.load_in_slot(purpose, status, fill))
    }

    fn load_in_slot(
        &mut self,
        purpose: Purpose,
        status: Status,
        fill: impl FnOnce(&mut Key) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        let slots = self.id();
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.occupancy == Occupancy::Free)
            .ok_or(Error::NoFreeSlot)?;
        fill(&mut slot.key)?;
        // Derived in a local buffer and copied in at once: the derivation writes byte by byte, and
        // each write through a reference to a slot chosen at run time multiplies the proofs' work.
        let mut id = KeyId::empty();
        if derive_key_id(&slot.key, purpose, &mut id).is_err() {
            slot.key.wipe();
            return Err(Error::DerivationFailed);
        }
        slot.id.take(&mut id);
        slot.purpose = purpose;
        slot.status = status;
        slot.occupancy = Occupancy::Loaded;
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
        let index = self.loaded(handle)?;
        self.slots
            .get_mut(index)
            .ok_or(Error::StaleHandle)?
            .unload();
        Ok(())
    }

    /// Tells apart two `Slots` alive at once: their memory does not overlap, so neither do the
    /// addresses. Empty ones may share an address, but they issue no handles. A handle keeps its
    /// memory borrowed, so no other `Slots` can take that memory over while the handle exists.
    fn id(&self) -> usize {
        self.slots.as_ptr().addr()
    }

    /// Wipes the key and its identifier in every slot, loaded or not, and frees the loaded ones.
    fn unload_all(&mut self) {
        for slot in self.slots.iter_mut() {
            if slot.occupancy == Occupancy::Loaded {
                slot.unload();
            } else {
                slot.key.wipe();
                slot.id.wipe();
            }
        }
    }
}

/// The nonce, the encrypted plaintext and the tag of a record.
fn split_record(
    record: &[u8; RECORD_LEN],
) -> ([u8; NONCE_LEN], [u8; PLAINTEXT_LEN], [u8; TAG_LEN]) {
    let mut parts = ([0; NONCE_LEN], [0; PLAINTEXT_LEN], [0; TAG_LEN]);
    if let Some((nonce, rest)) = record.split_first_chunk::<NONCE_LEN>()
        && let Some((sealed, tag)) = rest.split_first_chunk::<PLAINTEXT_LEN>()
        && let Ok(tag) = <[u8; TAG_LEN]>::try_from(tag)
    {
        parts = (*nonce, *sealed, tag);
    }
    parts
}

fn write_record(
    record: &mut [u8; RECORD_LEN],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8; PLAINTEXT_LEN],
    tag: &[u8; TAG_LEN],
) {
    if let Some((nonce_out, rest)) = record.split_first_chunk_mut::<NONCE_LEN>()
        && let Some((sealed_out, tag_out)) = rest.split_first_chunk_mut::<PLAINTEXT_LEN>()
    {
        *nonce_out = *nonce;
        *sealed_out = *sealed;
        tag_out.copy_from_slice(tag);
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
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "a test decodes hex and picks bits of a record"
)]
mod tests {
    extern crate std;

    use core::marker::PhantomData;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use super::{
        AssociatedData, Attributes, CIPHER_KEY_LEN, Entropy, EntropyError, Error, Handle,
        KeyLength, Occupancy, PLAINTEXT_LEN, Purpose, RECORD_LEN, Slot, Slots, Status,
        derive_wrap_key, record, seal, write_record,
    };
    use crate::derive::{CIPHER_STACK_WIPE, KeyId, STACK_WIPE, derive_key_id};
    use crate::key::{
        Key,
        tests::{Counting, Failing, Panicking, Recording, counted, padded},
    };

    assert_not_impl!(Slot: Clone, PartialEq, Default);

    /// Every import, generation, wrap and unwrap derives with data-independent timing on, where the
    /// processor and the operating system offer it.
    #[test]
    fn every_call_that_derives_holds_data_independent_timing() {
        use crate::derive::timing::seen;
        assert!(!lethewis_dit::active(), "the mode is off before the work");
        let _ = seen();
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let parent = slots.import64(Purpose::Wrap, &mut [7; 64]).unwrap();
        assert_eq!(seen(), Some(true));
        let key = slots.import32(Purpose::Wrap, &mut [9; 32]).unwrap();
        assert_eq!(seen(), Some(true));
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
        assert_eq!(seen(), Some(true));
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(key, parent, b"context", &mut Counting, &mut record)
            .unwrap();
        assert_eq!(seen(), Some(true));
        slots.unwrap(parent, b"context", &record).unwrap();
        assert_eq!(seen(), Some(true));
    }

    /// The stack, in KiB, that a load and that a wrap or an unwrap need, and the depth of the wipes
    /// that follow them, in an optimised build and in one without optimisation.
    pub(super) const LOAD_NEEDS: [usize; 2] = [9, 68];
    pub(super) const WRAP_NEEDS: [usize; 2] = [25, 72];
    const LOAD_WIPES: [usize; 2] = [8, 64];
    const WRAP_WIPES: [usize; 2] = [24, 64];

    /// The documentation of the public call `name` in this file, its lines joined.
    fn documentation(name: &str) -> String {
        let source = include_str!("slots.rs");
        let at = source.find(&format!("    pub fn {name}(")).unwrap();
        let mut lines: Vec<&str> = source[..at]
            .lines()
            .rev()
            .take_while(|line| line.trim_start().starts_with("///"))
            .map(|line| line.trim().trim_start_matches("///").trim())
            .collect();
        lines.reverse();
        lines.join(" ")
    }

    /// The documentation of each import, generation, wrap and unwrap states the stack it needs and
    /// the depth of the wipe after it, and those depths are the library's.
    #[test]
    fn the_documentation_states_the_stack_calls_need() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(LOAD_WIPES[build] * 1024, STACK_WIPE);
        assert_eq!(WRAP_WIPES[build] * 1024, CIPHER_STACK_WIPE);
        let loads = (LOAD_NEEDS, LOAD_WIPES);
        let wraps = (WRAP_NEEDS, WRAP_WIPES);
        for (call, (needs, wipes)) in [
            ("import32", loads),
            ("import64", loads),
            ("generate", loads),
            ("wrap", wraps),
            ("unwrap", wraps),
        ] {
            let text = documentation(call);
            for stated in [
                format!("Needs {} KiB of stack, or {} KiB when", needs[0], needs[1]),
                format!(" {} KiB, or {} KiB, ", wipes[0], wipes[1]),
            ] {
                assert!(text.contains(&stated), "{call}: {stated}");
            }
        }
    }

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
        let handle = slots.import32(Purpose::Wrap, &mut source).unwrap();
        assert_eq!((handle.index, handle.generation), (0, 0));
        assert_eq!(slots.slots[0].key.bytes(), &padded(&secret()));
        assert_eq!(slots.slots[0].key.length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[0].occupancy, Occupancy::Loaded);
        assert_eq!(source, [0; 32]);
    }

    #[test]
    fn import64_loads_the_key_and_wipes_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let mut source = [5; 64];
        slots.import64(Purpose::Wrap, &mut source).unwrap();
        assert_eq!(slots.slots[0].key.bytes(), &[5; 64]);
        assert_eq!(slots.slots[0].key.length(), KeyLength::Bytes64);
        assert_eq!(slots.slots[0].occupancy, Occupancy::Loaded);
        assert_eq!(source, [0; 64]);
    }

    #[test]
    fn generate_writes_random_bytes_into_the_slot() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let short = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let long = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
        assert_eq!((short.index, long.index), (0, 1));
        assert_eq!(slots.slots[0].key.bytes(), &padded(&counted::<32>()));
        assert_eq!(slots.slots[0].key.length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[1].key.bytes(), &counted::<64>());
        assert_eq!(slots.slots[1].key.length(), KeyLength::Bytes64);
        assert_eq!(slots.slots[1].occupancy, Occupancy::Loaded);
    }

    #[test]
    fn a_failed_generate_leaves_the_slot_free_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        assert_eq!(
            slots.generate(Purpose::Wrap, KeyLength::Bytes64, &mut Failing),
            Err(Error::EntropyFailed)
        );
        assert_eq!(slots.slots[0].occupancy, Occupancy::Free);
        assert_eq!(slots.slots[0].generation, 0);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
    }

    #[test]
    fn generate_asks_the_source_once_for_the_length() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let mut source = Recording::default();
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut source)
            .unwrap();
        assert_eq!((source.calls, source.asked), (1, 64));
        assert_eq!(source.at, slots.slots[0].key.bytes().as_ptr().addr());
    }

    #[test]
    fn generate_takes_a_source_behind_a_trait_object() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let source: &mut dyn Entropy = &mut Counting;
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, source)
            .unwrap();
        assert_eq!(slots.slots[0].key.bytes(), &padded(&counted::<32>()));
    }

    #[test]
    fn a_panic_in_the_source_leaves_the_slot_free_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = slots.generate(Purpose::Wrap, KeyLength::Bytes64, &mut Panicking);
        }));
        assert!(outcome.is_err());
        assert_eq!(slots.slots[0].occupancy, Occupancy::Free);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
        assert!(
            slots
                .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
                .is_ok()
        );
    }

    #[test]
    fn generate_without_a_free_slot_asks_for_no_bytes() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_eq!(
            slots.generate(Purpose::Wrap, KeyLength::Bytes32, &mut Untouched),
            Err(Error::NoFreeSlot)
        );
    }

    fn id_of(key: &Key) -> KeyId {
        let mut id = KeyId::empty();
        derive_key_id(key, Purpose::Wrap, &mut id).unwrap();
        id
    }

    #[test]
    fn a_load_keeps_the_purpose_and_the_identifier_of_the_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
        let mut short = Key::empty();
        short.load32(&mut secret());
        let mut long = Key::empty();
        long.load64(&mut counted::<64>());
        assert_eq!(slots.slots[0].purpose, Purpose::Wrap);
        assert_eq!(slots.slots[1].purpose, Purpose::Wrap);
        assert_eq!(slots.slots[0].status, Status::Enabled);
        assert_eq!(slots.slots[1].status, Status::Enabled);
        assert_eq!(slots.slots[0].id, id_of(&short));
        assert_eq!(slots.slots[1].id, id_of(&long));
        assert_ne!(slots.slots[0].id, slots.slots[1].id);
    }

    #[test]
    fn release_wipes_the_identifier() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_ne!(slots.slots[0].id, KeyId::empty());
        slots.release(handle).unwrap();
        assert_eq!(slots.slots[0].id, KeyId::empty());
    }

    #[test]
    fn new_slots_wipe_an_identifier_left_behind() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut key = Key::empty();
        key.load32(&mut secret());
        memory[0].id = id_of(&key);
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].id, KeyId::empty());
    }

    #[test]
    fn import_takes_the_first_free_slot() {
        let mut memory = [const { Slot::empty() }; 3];
        memory[1].occupancy = Occupancy::Retired;
        let mut slots = Slots::new(&mut memory);
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        let handle = slots.import64(Purpose::Wrap, &mut [5; 64]).unwrap();
        assert_eq!(handle.index, 2);
    }

    #[test]
    fn import_without_a_free_slot_keeps_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        let mut short = secret();
        assert_eq!(
            slots.import32(Purpose::Wrap, &mut short),
            Err(Error::NoFreeSlot)
        );
        assert_eq!(short, secret());
        let mut long = [5; 64];
        assert_eq!(
            slots.import64(Purpose::Wrap, &mut long),
            Err(Error::NoFreeSlot)
        );
        assert_eq!(long, [5; 64]);
    }

    #[test]
    fn release_wipes_only_its_own_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        let second = slots.import64(Purpose::Wrap, &mut [5; 64]).unwrap();
        slots.release(second).unwrap();
        assert_eq!(slots.slots[1].key.bytes(), &padded(&[]));
        assert_eq!(slots.slots[1].key.length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[1].occupancy, Occupancy::Free);
        assert_eq!(slots.slots[1].generation, 1);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&secret()));
        assert_eq!(slots.slots[0].occupancy, Occupancy::Loaded);
    }

    #[test]
    fn a_released_handle_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
    }

    #[test]
    fn an_old_handle_does_not_reach_a_new_key_in_the_same_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let old = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        slots.release(old).unwrap();
        let new = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
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
        let handle = first.import32(Purpose::Wrap, &mut secret()).unwrap();
        second.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_eq!(second.release(handle), Err(Error::StaleHandle));
        assert_eq!(second.slots[0].key.bytes(), &padded(&secret()));
    }

    #[test]
    fn a_handle_outside_the_slots_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let id = memory.as_ptr().addr();
        let mut slots = Slots::new(&mut memory);
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
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
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(
            slots.import32(Purpose::Wrap, &mut secret()),
            Err(Error::NoFreeSlot)
        );
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
        assert_eq!(slots.slots[0].occupancy, Occupancy::Retired);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
    }

    #[test]
    fn dropping_the_slots_wipes_every_key() {
        let mut memory = [const { Slot::empty() }; 2];
        {
            let mut slots = Slots::new(&mut memory);
            slots.import32(Purpose::Wrap, &mut secret()).unwrap();
            slots.import64(Purpose::Wrap, &mut [5; 64]).unwrap();
        }
        for slot in &memory {
            assert_eq!(slot.key.bytes(), &padded(&[]));
            assert_eq!(slot.key.length(), KeyLength::Bytes32);
            assert_eq!((slot.occupancy, slot.generation), (Occupancy::Free, 1));
        }
    }

    #[test]
    fn new_slots_wipe_a_key_left_behind() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].key.load64(&mut [5; 64]);
        memory[0].occupancy = Occupancy::Loaded;
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
        assert_eq!(slots.slots[0].occupancy, Occupancy::Free);
    }

    #[test]
    fn new_slots_wipe_bytes_left_in_a_free_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].key.load64(&mut [5; 64]);
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].key.bytes(), &padded(&[]));
        assert_eq!(
            (slots.slots[0].occupancy, slots.slots[0].generation),
            (Occupancy::Free, 0)
        );
    }

    /// Writes the bytes it was made with.
    struct Fixed(&'static [u8]);

    impl Entropy for Fixed {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(self.0);
            Ok(())
        }
    }

    const NONCE: [u8; 12] = [
        0x05, 0x16, 0x27, 0x38, 0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xc0,
    ];

    fn pattern<const N: usize>(times: u8, plus: u8) -> [u8; N] {
        core::array::from_fn(|i| {
            u8::try_from(i % 256)
                .unwrap()
                .wrapping_mul(times)
                .wrapping_add(plus)
        })
    }

    fn hex(text: &str) -> [u8; RECORD_LEN] {
        core::array::from_fn(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
    }

    /// Records computed by an implementation independent of this library: a 32-byte parent with a
    /// 64-byte key in "chat 7", and a 64-byte parent with a 32-byte key in "profile".
    const KNOWN_RECORDS: [&str; 2] = [
        concat!(
            "05162738495a6b7c8d9eafc0596125dc8d63bdc5707613fe3db68a5b0c8f72b0",
            "288221ab83d210edcf24460158c9ebcfbdca07d696c4c13d5ed0bda41a9ea5d0",
            "b4ac2e42f061126a8ee8cce25684404cef97043612e9bae8e8599303d8e8bc6f",
            "a28485888f5c1750f6dd64a52ad633b30f4366098bff39de",
        ),
        concat!(
            "05162738495a6b7c8d9eafc0bd5ba124c6c1d61373302d6d60df6c57eb19e45d",
            "2a62f6bb41a3b4f6b591ab4066c5b7744db8f57260ebc972e934581918b9b4c3",
            "612d8a18ef2076ded6110b315dbec9a1418a736d26e92b496926430a407d1b75",
            "bff36ed8f27b3870267311bf3a77fceff9be10432f52bfc7",
        ),
    ];

    #[test]
    fn records_match_ones_computed_independently() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let short_parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let long_key = slots
            .import64(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(
                long_key,
                short_parent,
                b"chat 7",
                &mut Fixed(&NONCE),
                &mut record,
            )
            .unwrap();
        assert_eq!(record, hex(KNOWN_RECORDS[0]));

        let long_parent = slots.import64(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let short_key = slots
            .import32(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        slots
            .wrap(
                short_key,
                long_parent,
                b"profile",
                &mut Fixed(&NONCE),
                &mut record,
            )
            .unwrap();
        assert_eq!(record, hex(KNOWN_RECORDS[1]));
    }

    #[test]
    fn an_unwrapped_key_is_the_key_that_was_wrapped() {
        for (parent_bytes, key_bytes, context) in [
            (
                &pattern::<32>(97, 13)[..],
                &pattern::<64>(59, 201)[..],
                &b"chat 7"[..],
            ),
            (
                &pattern::<64>(97, 13)[..],
                &pattern::<32>(59, 201)[..],
                &b"profile"[..],
            ),
        ] {
            let mut memory = [const { Slot::empty() }; 2];
            let mut slots = Slots::new(&mut memory);
            let parent = match parent_bytes.len() {
                32 => slots.import32(Purpose::Wrap, &mut parent_bytes.try_into().unwrap()),
                _ => slots.import64(Purpose::Wrap, &mut parent_bytes.try_into().unwrap()),
            }
            .unwrap();
            let record = hex(KNOWN_RECORDS[usize::from(parent_bytes.len() == 64)]);
            let key = slots.unwrap(parent, context, &record).unwrap();
            let slot = &slots.slots[key.index];
            let mut expected = Key::empty();
            match key_bytes.len() {
                32 => expected.load32(&mut key_bytes.try_into().unwrap()),
                _ => expected.load64(&mut key_bytes.try_into().unwrap()),
            }
            assert_eq!(slot.key.bytes(), expected.bytes());
            assert_eq!(slot.key.length(), expected.length());
            assert_eq!(
                (slot.purpose, slot.status),
                (Purpose::Wrap, Status::Enabled)
            );
            assert_eq!(slot.id, id_of(&expected));
            assert_eq!(slot.occupancy, Occupancy::Loaded);
        }
    }

    /// Two slots holding a parent and a key, and the record of the key under the parent.
    fn wrapped(memory: &mut [Slot]) -> (Slots<'_>, Handle<'_>, [u8; RECORD_LEN]) {
        let mut slots = Slots::new(memory);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let key = slots
            .import64(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(key, parent, b"chat 7", &mut Counting, &mut record)
            .unwrap();
        slots.release(key).unwrap();
        (slots, parent, record)
    }

    #[test]
    fn every_changed_bit_of_a_record_is_rejected() {
        let mut memory = [const { Slot::empty() }; 2];
        let (mut slots, parent, record) = wrapped(&mut memory);
        for bit in 0..RECORD_LEN * 8 {
            let mut changed = record;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                slots.unwrap(parent, b"chat 7", &changed),
                Err(Error::RecordRejected),
                "bit {bit}"
            );
            assert_eq!(slots.slots[1].occupancy, Occupancy::Free);
            assert_eq!(slots.slots[1].key.bytes(), &padded(&[]));
        }
        assert!(slots.unwrap(parent, b"chat 7", &record).is_ok());
    }

    #[test]
    fn a_record_opens_only_with_its_parent_and_context() {
        let mut memory = [const { Slot::empty() }; 3];
        let (mut slots, parent, record) = wrapped(&mut memory);
        let other = slots.import32(Purpose::Wrap, &mut pattern(97, 14)).unwrap();
        assert_eq!(
            slots.unwrap(other, b"chat 7", &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            slots.unwrap(parent, b"chat 8", &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(slots.slots[2].occupancy, Occupancy::Free);
        assert!(slots.unwrap(parent, b"chat 7", &record).is_ok());
    }

    /// A record sealed under `parent` holding `attributes` and a 32-byte key, built without
    /// `wrap`.
    fn sealed_record(
        slots: &Slots<'_>,
        parent: Handle<'_>,
        attributes: &Attributes,
        version: u8,
    ) -> [u8; RECORD_LEN] {
        let parent_key = &slots.slots[parent.index].key;
        let mut key = Key::empty();
        key.load32(&mut pattern(59, 201));
        let mut plaintext = [0; PLAINTEXT_LEN];
        record::build(attributes, &key, &mut plaintext);
        plaintext[0] = version;
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        derive_wrap_key(parent_key, Purpose::Wrap, &mut cipher_key).unwrap();
        let associated = AssociatedData::new(b"chat 7").unwrap();
        let tag = seal::seal(&cipher_key, &NONCE, associated.bytes(), &mut plaintext).unwrap();
        let mut out = [0; RECORD_LEN];
        write_record(&mut out, &NONCE, &plaintext, &tag);
        out
    }

    /// Random bytes from a fixed seed, so that a failing round repeats.
    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = self.0;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            mixed ^ (mixed >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
        }

        fn bytes<const N: usize>(&mut self) -> [u8; N] {
            let mut out = [0; N];
            for chunk in out.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
            }
            out
        }
    }

    type Holding = (
        Occupancy,
        u64,
        [u8; 64],
        KeyLength,
        [u8; 16],
        Purpose,
        Status,
    );

    fn holdings(slots: &Slots<'_>) -> Vec<Holding> {
        slots
            .slots
            .iter()
            .map(|slot| {
                (
                    slot.occupancy,
                    slot.generation,
                    *slot.key.bytes(),
                    slot.key.length(),
                    slot.id.bytes(),
                    slot.purpose,
                    slot.status,
                )
            })
            .collect()
    }

    fn import_any<'a>(slots: &mut Slots<'a>, random: &mut Random) -> Handle<'a> {
        if random.below(2) == 0 {
            slots.import32(Purpose::Wrap, &mut random.bytes())
        } else {
            slots.import64(Purpose::Wrap, &mut random.bytes())
        }
        .unwrap()
    }

    /// Records sealed under the parent through the real derivation and cipher, with random keys,
    /// plaintexts, contexts of 0 to 300 bytes, a parent of either length in any slot among other
    /// keys, released slots and random changes to the record or the context: unwrapping never
    /// panics, refuses exactly what it should, loads the key the plaintext holds, with its length,
    /// purpose, status and identifier, into the first free slot with that slot's generation when it
    /// accepts, and changes no other slot, or none when it refuses.
    fn unwrap_random_records(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        for round in 0..rounds {
            let mut memory = [const { Slot::empty() }; 3];
            let mut slots = Slots::new(&mut memory);
            let parent = random_slots(&mut slots, &mut random);
            let parent_id = slots.slots[parent.index].id.bytes();
            let plaintext = random_plaintext(&mut random, parent_id);
            let context: Vec<u8> = (0..random.below(301))
                .map(|_| random.bytes::<1>()[0])
                .collect();
            let valid_context = (1..=record::MAX_CONTEXT).contains(&context.len());
            let sealed_for = if valid_context {
                &context[..]
            } else {
                b"chat 7"
            };
            let mut record = sealed_under(&slots, parent, sealed_for, &plaintext, &mut random);
            let changed = random.below(4) == 0;
            if changed {
                record[random.below(RECORD_LEN)] ^= 1_u8 << random.below(8);
            }
            let mut asked = context.clone();
            let other_context = valid_context && random.below(8) == 0;
            if other_context {
                let at = random.below(asked.len());
                asked[at] ^= 1_u8 << random.below(8);
            }

            let names_parent =
                record::parse(&plaintext).is_ok_and(|(found, _)| found.parent == parent_id);
            let before = holdings(&slots);
            let first_free = before
                .iter()
                .position(|holding| holding.0 == Occupancy::Free);
            let expected = if !valid_context {
                Err(Error::InvalidContext)
            } else if first_free.is_none() {
                Err(Error::NoFreeSlot)
            } else if changed || other_context || !names_parent {
                Err(Error::RecordRejected)
            } else {
                Ok(())
            };
            let result = slots.unwrap(parent, &asked, &record);
            assert_eq!(result.map(|_| ()), expected, "round {round} of seed {seed}");
            let mut after = before.clone();
            if let Ok(handle) = result {
                let at = first_free.unwrap();
                after[at] = loaded_from(&plaintext, before[at].1);
                assert_eq!(
                    (handle.index, handle.generation),
                    (at, before[at].1),
                    "round {round} of seed {seed}"
                );
            }
            assert_eq!(holdings(&slots), after, "round {round} of seed {seed}");
        }
    }

    /// Loads one to three keys of either length, releases and loads again up to twice, and returns
    /// one of the keys left.
    fn random_slots<'a>(slots: &mut Slots<'a>, random: &mut Random) -> Handle<'a> {
        let mut loaded: Vec<Handle<'a>> = Vec::new();
        for _ in 0..=random.below(3) {
            loaded.push(import_any(slots, random));
        }
        for _ in 0..random.below(3) {
            let gone = loaded.swap_remove(random.below(loaded.len()));
            slots.release(gone).unwrap();
            if loaded.is_empty() || random.below(2) == 0 {
                loaded.push(import_any(slots, random));
            }
        }
        loaded[random.below(loaded.len())]
    }

    /// The plaintext of a random key under `parent`, or under another parent, left as built, wholly
    /// random or with one byte changed.
    fn random_plaintext(random: &mut Random, parent: [u8; 16]) -> [u8; PLAINTEXT_LEN] {
        let mut key = Key::empty();
        if random.below(2) == 0 {
            key.load32(&mut random.bytes());
        } else {
            key.load64(&mut random.bytes());
        }
        let attributes = Attributes {
            purpose: Purpose::Wrap,
            status: if random.below(2) == 0 {
                Status::Enabled
            } else {
                Status::Disabled
            },
            parent: if random.below(8) == 0 {
                random.bytes()
            } else {
                parent
            },
            epoch: random.next(),
        };
        let mut plaintext = [0; PLAINTEXT_LEN];
        record::build(&attributes, &key, &mut plaintext);
        match random.below(4) {
            0 => plaintext = random.bytes(),
            1 => plaintext[random.below(PLAINTEXT_LEN)] ^= random.bytes::<1>()[0] | 1,
            _ => {}
        }
        plaintext
    }

    /// `plaintext` sealed under `parent` for `context` with a random nonce.
    fn sealed_under(
        slots: &Slots<'_>,
        parent: Handle<'_>,
        context: &[u8],
        plaintext: &[u8; PLAINTEXT_LEN],
        random: &mut Random,
    ) -> [u8; RECORD_LEN] {
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        derive_wrap_key(
            &slots.slots[parent.index].key,
            Purpose::Wrap,
            &mut cipher_key,
        )
        .unwrap();
        let associated = AssociatedData::new(context).unwrap();
        let nonce: [u8; 12] = random.bytes();
        let mut sealed = *plaintext;
        let tag = seal::seal(&cipher_key, &nonce, associated.bytes(), &mut sealed).unwrap();
        let mut record = [0; RECORD_LEN];
        write_record(&mut record, &nonce, &sealed, &tag);
        record
    }

    /// The slot that holds the key of an accepted `plaintext`: its bytes from offset 28, as long as
    /// the length byte says, with the purpose and status it states and the identifier derived from
    /// them.
    fn loaded_from(plaintext: &[u8; PLAINTEXT_LEN], generation: u64) -> Holding {
        let length = if plaintext[2] == 32 {
            KeyLength::Bytes32
        } else {
            KeyLength::Bytes64
        };
        let mut held = [0; 64];
        held[..length.bytes()].copy_from_slice(&plaintext[28..28 + length.bytes()]);
        let (stated, _) = record::parse(plaintext).unwrap();
        let mut key = Key::empty();
        match length {
            KeyLength::Bytes32 => key.load32(&mut held[..32].try_into().unwrap()),
            KeyLength::Bytes64 => key.load64(&mut held),
        }
        let mut id = KeyId::empty();
        derive_key_id(&key, stated.purpose, &mut id).unwrap();
        (
            Occupancy::Loaded,
            generation,
            *key.bytes(),
            length,
            id.bytes(),
            stated.purpose,
            stated.status,
        )
    }

    #[test]
    fn random_records_unwrap_as_their_plaintext_says() {
        unwrap_random_records(300, 1);
    }

    /// The same over as many rounds and from the seed `LETHEWIS_RANDOM_ROUNDS` and
    /// `LETHEWIS_RANDOM_SEED` give.
    #[test]
    #[ignore = "long; the rounds and the seed come from the environment"]
    fn many_random_records_unwrap_as_their_plaintext_says() {
        let read = |name: &str, default: u64| {
            std::env::var(name).map_or(default, |value| {
                value
                    .parse()
                    .unwrap_or_else(|_| panic!("{name} is not a number: {value}"))
            })
        };
        unwrap_random_records(
            read("LETHEWIS_RANDOM_ROUNDS", 100_000),
            read("LETHEWIS_RANDOM_SEED", 2),
        );
    }

    #[test]
    fn a_record_that_names_another_parent_or_is_malformed_is_rejected() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let attributes = Attributes {
            purpose: Purpose::Wrap,
            status: Status::Enabled,
            parent: slots.slots[0].id.bytes(),
            epoch: 0,
        };
        let good = sealed_record(&slots, parent, &attributes, 1);
        let refused: Vec<[u8; RECORD_LEN]> = (0..16)
            .map(|at| {
                let mut foreign = attributes;
                foreign.parent[at] ^= 1;
                sealed_record(&slots, parent, &foreign, 1)
            })
            .chain([sealed_record(&slots, parent, &attributes, 2)])
            .collect();
        for record in refused {
            assert_eq!(
                slots.unwrap(parent, b"chat 7", &record),
                Err(Error::RecordRejected)
            );
            assert_eq!(slots.slots[1].occupancy, Occupancy::Free);
        }
        assert!(slots.unwrap(parent, b"chat 7", &good).is_ok());
    }

    #[test]
    fn a_disabled_key_unwraps_disabled_and_cannot_wrap_or_unwrap() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let attributes = Attributes {
            purpose: Purpose::Wrap,
            status: Status::Disabled,
            parent: slots.slots[0].id.bytes(),
            epoch: 0,
        };
        let record = sealed_record(&slots, parent, &attributes, 1);
        let disabled = slots.unwrap(parent, b"chat 7", &record).unwrap();
        assert_eq!(slots.slots[disabled.index].status, Status::Disabled);
        let key = slots.import32(Purpose::Wrap, &mut pattern(3, 4)).unwrap();
        let mut out = [0x55; RECORD_LEN];
        assert_eq!(
            slots.wrap(key, disabled, b"chat 7", &mut Counting, &mut out),
            Err(Error::KeyDisabled)
        );
        assert_eq!(out, [0x55; RECORD_LEN]);
        assert_eq!(
            slots.unwrap(disabled, b"chat 7", &record),
            Err(Error::KeyDisabled)
        );
        slots
            .wrap(disabled, parent, b"chat 7", &mut Fixed(&NONCE), &mut out)
            .unwrap();
        assert_eq!(out, record);
    }

    #[test]
    fn a_failed_wrap_leaves_the_record_as_it_was() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut slots = Slots::new(&mut memory);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let key = slots
            .import64(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        let twin = slots
            .import64(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        let long = [7; 256];
        let mut out = [0x55; RECORD_LEN];
        for (outcome, error) in [
            (
                slots.wrap(key, key, b"chat 7", &mut Counting, &mut out),
                Error::SameKey,
            ),
            (
                slots.wrap(key, twin, b"chat 7", &mut Counting, &mut out),
                Error::SameKey,
            ),
            (
                slots.wrap(key, parent, b"", &mut Counting, &mut out),
                Error::InvalidContext,
            ),
            (
                slots.wrap(key, parent, &long, &mut Counting, &mut out),
                Error::InvalidContext,
            ),
            (
                slots.wrap(key, parent, b"chat 7", &mut Failing, &mut out),
                Error::EntropyFailed,
            ),
        ] {
            assert_eq!(outcome, Err(error));
            assert_eq!(out, [0x55; RECORD_LEN]);
        }
        slots.release(key).unwrap();
        assert_eq!(
            slots.wrap(key, parent, b"chat 7", &mut Counting, &mut out),
            Err(Error::StaleHandle)
        );
        assert_eq!(out, [0x55; RECORD_LEN]);
        assert!(
            slots
                .wrap(parent, parent, &long[..255], &mut Counting, &mut out)
                .is_err()
        );
    }

    #[test]
    fn a_context_of_1_to_255_bytes_is_taken() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut slots = Slots::new(&mut memory);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let key = slots
            .import32(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        for context in [&[9][..], &[9; 255]] {
            let mut record = [0; RECORD_LEN];
            slots
                .wrap(key, parent, context, &mut Counting, &mut record)
                .unwrap();
            let unwrapped = slots.unwrap(parent, context, &record).unwrap();
            assert_eq!(
                slots.unwrap(parent, &[], &record),
                Err(Error::InvalidContext)
            );
            assert_eq!(
                slots.unwrap(parent, &[9; 256], &record),
                Err(Error::InvalidContext)
            );
            slots.release(unwrapped).unwrap();
        }
    }

    #[test]
    fn unwrap_needs_a_live_enabled_parent_and_a_free_slot_before_it_decrypts() {
        let mut memory = [const { Slot::empty() }; 2];
        let (mut slots, parent, record) = wrapped(&mut memory);
        let filler = slots.import32(Purpose::Wrap, &mut pattern(1, 1)).unwrap();
        assert_eq!(
            slots.unwrap(parent, b"chat 7", &record),
            Err(Error::NoFreeSlot)
        );
        assert_eq!(
            slots.unwrap(parent, b"chat 7", &[0; RECORD_LEN]),
            Err(Error::NoFreeSlot)
        );
        slots.release(filler).unwrap();
        assert_eq!(
            slots.unwrap(filler, b"chat 7", &record),
            Err(Error::StaleHandle)
        );
        assert!(slots.unwrap(parent, b"chat 7", &record).is_ok());
    }

    #[test]
    fn debug_shows_no_state() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_eq!(format!("{handle:?}"), "Handle { .. }");
        assert_eq!(format!("{:?}", slots.slots[0]), "Slot { .. }");
        assert_eq!(format!("{slots:?}"), "Slots { .. }");
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "a test expands an AES key and builds counter blocks"
)]
mod stack {
    //! What wrapping and unwrapping leave on the stack, read back from the memory of this process.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use aes::Aes256;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    use super::tests::{LOAD_NEEDS, WRAP_NEEDS};
    use super::{Entropy, EntropyError, Error, Handle, Purpose, RECORD_LEN, Slot, Slots};
    use crate::derive::{Branch, CIPHER_STACK_WIPE, derive_wrap_key, stack::secrets};
    use crate::key::{
        Key, KeyLength,
        tests::{Counting, Failing},
    };
    use crate::record::{AssociatedData, PLAINTEXT_LEN};
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::seal;

    const CONTEXT: &[u8] = b"chat 7";
    const NONCE: [u8; 12] = [
        0x31, 0x9c, 0x07, 0xe2, 0x5d, 0xa8, 0x14, 0x6f, 0xc3, 0x2b, 0x90, 0x4e,
    ];

    /// Writes the same nonce every time.
    struct Fixed;

    impl Entropy for Fixed {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&NONCE);
            Ok(())
        }
    }

    fn parent_bytes(flip: u8) -> [u8; 32] {
        core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(41).wrapping_add(7) ^ flip)
    }

    fn key_bytes(flip: u8) -> [u8; 64] {
        core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(29).wrapping_add(101) ^ flip)
    }

    /// The S-box of AES, FIPS 197, section 5.1.1: the inverse in GF(2^8), zero for zero, then the
    /// affine transformation.
    fn sbox(byte: u8) -> u8 {
        let inverse = (1..=255)
            .find(|&other| multiply(byte, other) == 1)
            .unwrap_or(0);
        (1..5).fold(inverse ^ 0x63, |out, shift| {
            out ^ inverse.rotate_left(shift)
        })
    }

    fn multiply(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0;
        while b != 0 {
            if b & 1 != 0 {
                product ^= a;
            }
            a = xtime(a);
            b >>= 1;
        }
        product
    }

    fn xtime(byte: u8) -> u8 {
        (byte << 1) ^ if byte & 0x80 == 0 { 0 } else { 0x1b }
    }

    /// The fifteen round keys of AES-256, FIPS 197, section 5.2.
    fn round_keys(key: &[u8; 32]) -> Vec<Vec<u8>> {
        let sub = |word: [u8; 4]| word.map(sbox);
        let mut words: Vec<[u8; 4]> = key.chunks(4).map(|word| word.try_into().unwrap()).collect();
        let mut rcon = 1;
        for i in 8..60 {
            let mut word = words[i - 1];
            if i % 8 == 0 {
                word = sub([word[1], word[2], word[3], word[0]]);
                word[0] ^= rcon;
                rcon = xtime(rcon);
            } else if i % 8 == 4 {
                word = sub(word);
            }
            words.push(core::array::from_fn(|j| words[i - 8][j] ^ word[j]));
        }
        words.chunks(4).map(<[[u8; 4]]>::concat).collect()
    }

    /// The S-box at zero and at the example of FIPS 197, section 5.1.1, and the key expansion of
    /// its appendix A.3.
    #[test]
    fn the_s_box_and_the_round_keys_are_those_of_fips_197() {
        let bytes = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect()
        };
        let key = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let keys = round_keys(&key.try_into().unwrap());
        assert_eq!((sbox(0), sbox(0x53)), (0x63, 0xed));
        assert_eq!(keys.len(), 15);
        assert_eq!(keys[2], bytes("9ba354118e6925afa51a8b5f2067fcde"));
        assert_eq!(keys[14], bytes("fe4890d1e6188d0b046df344706c631e"));
    }

    fn encrypt(key: &[u8; 32], block: [u8; 16]) -> [u8; 16] {
        let mut block = block.into();
        Aes256::new(key.into()).encrypt_block(&mut block);
        block.into()
    }

    /// The keys AES-256-GCM-SIV derives for one message, RFC 8452, section 4: the POLYVAL key and
    /// the encryption key.
    fn message_keys(key: &[u8; 32], nonce: &[u8; 12]) -> ([u8; 16], [u8; 32]) {
        let halves: Vec<u8> = (0_u32..6)
            .flat_map(|counter| {
                let mut block = [0; 16];
                block[..4].copy_from_slice(&counter.to_le_bytes());
                block[4..].copy_from_slice(nonce);
                encrypt(key, block)[..8].to_vec()
            })
            .collect();
        (
            halves[..16].try_into().unwrap(),
            halves[16..].try_into().unwrap(),
        )
    }

    /// The keystream of a record whose tag is `tag`: counter blocks from the tag with its top bit
    /// set, the first word counting up, RFC 8452, section 4.
    fn keystream(enc_key: &[u8; 32], tag: &[u8; 16]) -> Vec<u8> {
        let mut block = *tag;
        block[15] |= 0x80;
        let first = u32::from_le_bytes(block[..4].try_into().unwrap());
        (0_u32..6)
            .flat_map(|step| {
                block[..4].copy_from_slice(&first.wrapping_add(step).to_le_bytes());
                encrypt(enc_key, block)
            })
            .collect()
    }

    /// Two slots holding the parent and the key, made from `flip`ped patterns.
    fn loaded(slots: &mut Slots<'_>, flip: u8) -> (Handle<'static>, Handle<'static>) {
        let parent = slots
            .import32(Purpose::Wrap, &mut parent_bytes(flip))
            .unwrap();
        let key = slots.import64(Purpose::Wrap, &mut key_bytes(flip)).unwrap();
        let shorten = |handle: Handle<'_>| Handle {
            slots: handle.slots,
            index: handle.index,
            generation: handle.generation,
            memory: core::marker::PhantomData,
        };
        (shorten(parent), shorten(key))
    }

    /// The secrets a wrap of the key under the parent made from `flip`ped patterns handles, and
    /// an unwrap of that record too when asked: the derivation of the cipher key, the cipher key,
    /// the message keys, the round keys of the cipher key and of the message encryption key in the
    /// layout of FIPS 197, the keystream and the record's plaintext; and for an unwrap the
    /// derivation of the key's identifier.
    fn handled(flip: u8, unwrap: bool) -> Vec<Vec<u8>> {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let (parent, key) = loaded(&mut slots, flip);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(key, parent, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        let mut parent_key = Key::empty();
        parent_key.load32(&mut parent_bytes(flip));
        let mut cipher_key = [0; 32];
        derive_wrap_key(&parent_key, Purpose::Wrap, &mut cipher_key).unwrap();
        let tag: [u8; 16] = record[NONCE.len() + PLAINTEXT_LEN..].try_into().unwrap();
        let mut plaintext: [u8; PLAINTEXT_LEN] = record[NONCE.len()..NONCE.len() + PLAINTEXT_LEN]
            .try_into()
            .unwrap();
        let associated = AssociatedData::new(CONTEXT).unwrap();
        seal::open(
            &cipher_key,
            &NONCE,
            associated.bytes(),
            &mut plaintext,
            &tag,
        )
        .unwrap();
        let (mac_key, enc_key) = message_keys(&cipher_key, &NONCE);

        let mut handled = secrets(&parent_bytes(flip), KeyLength::Bytes32, Branch::WrapKey);
        handled.extend([
            cipher_key.to_vec(),
            mac_key.to_vec(),
            enc_key.to_vec(),
            keystream(&enc_key, &tag),
            plaintext.to_vec(),
        ]);
        handled.extend(round_keys(&cipher_key));
        handled.extend(round_keys(&enc_key));
        if unwrap {
            handled.extend(secrets(&key_bytes(flip), KeyLength::Bytes64, Branch::KeyId));
        }
        handled
    }

    fn pieces(unwrap: bool) -> Vec<Vec<u8>> {
        key_dependent(&handled(0, unwrap), &handled(0xff, unwrap))
    }

    #[test]
    fn a_wrap_without_the_wipe_leaves_residue() {
        let pieces = pieces(false);
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let (parent, key) = loaded(&mut slots, 0);
        let mut record = [0; RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .wrap_on_stack(key, parent, CONTEXT, &mut Fixed, &mut record)
                .unwrap();
            black_box(&record);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn a_wrap_leaves_no_residue() {
        let pieces = pieces(false);
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let (parent, key) = loaded(&mut slots, 0);
        let mut record = [0; RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .wrap(key, parent, CONTEXT, &mut Fixed, &mut record)
                .unwrap();
            black_box(&record);
        });
    }

    /// A parent loaded in one slot, the other free, and the record of the key under the parent.
    fn wrapped(slots: &mut Slots<'_>) -> (Handle<'static>, [u8; RECORD_LEN]) {
        let (parent, key) = loaded(slots, 0);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(key, parent, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        slots.release(key).unwrap();
        (parent, record)
    }

    #[test]
    fn an_unwrap_leaves_no_residue() {
        let pieces = pieces(true);
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let (parent, record) = wrapped(&mut slots);
        assert_clean(&pieces, || {
            black_box(slots.unwrap(parent, CONTEXT, &record).unwrap());
        });
    }

    /// A record whose ciphertext was changed is decrypted before its tag fails. This is also the
    /// unwrap that shows the test sees residue: after a successful one, the wipe that follows the
    /// derivation of the new key's identifier already covers the frames the cipher used, and no
    /// key material is left even without the wipe after the unwrap.
    #[test]
    fn a_rejected_unwrap_leaves_no_residue() {
        let pieces = pieces(false);
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let (parent, mut record) = wrapped(&mut slots);
        record[40] ^= 1;
        let range = below_pad(false, || {
            let refused = slots.unwrap_on_stack(parent, CONTEXT, &record);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        });
        assert!(residue(range, &pieces) > 0);
        assert_clean(&pieces, || {
            let refused = slots.unwrap(parent, CONTEXT, &record);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        });
    }

    /// The wipe that follows covers more than the cipher uses; the derivations a wrap and an
    /// unwrap run are measured with the derivation, and wiped after it besides.
    #[test]
    fn the_wipe_is_deeper_than_the_cipher() {
        let key = [7; 32];
        let associated = AssociatedData::new(CONTEXT).unwrap();
        let mut sealed = [9; PLAINTEXT_LEN];
        let mut tag = [0; 16];
        let sealing = depth_changed(|| {
            tag = seal::seal(&key, &NONCE, associated.bytes(), &mut sealed).unwrap();
            black_box(&sealed);
        });
        let opening = depth_changed(|| {
            seal::open(&key, &NONCE, associated.bytes(), &mut sealed, &tag).unwrap();
            black_box(&sealed);
        });
        std::println!("sealing uses {sealing} bytes of stack, opening {opening}");
        for used in [sealing, opening] {
            assert!(
                used.saturating_mul(2) <= CIPHER_STACK_WIPE,
                "{used} bytes used"
            );
            // Not needlessly deep either: a thread that cannot spare the stack would be corrupted.
            // The bound is wide: the path taken here may be lighter than another path in the build.
            assert!(
                used.saturating_mul(16) >= CIPHER_STACK_WIPE,
                "{used} bytes used"
            );
        }
    }

    /// The stack a wrap or an unwrap and a load need in this build, in bytes.
    const WRAP_STACK: usize = 1024 * WRAP_NEEDS[if cfg!(lethewis_unoptimised) { 1 } else { 0 }];
    const LOAD_STACK: usize = 1024 * LOAD_NEEDS[if cfg!(lethewis_unoptimised) { 1 } else { 0 }];

    /// The wipes that follow a wrap and an unwrap reach as deep as they are meant to, also when
    /// the call fails, and no call reaches deeper than its documentation says it needs.
    #[test]
    fn wraps_unwraps_and_loads_wipe_and_need_the_stack_documented() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut slots = Slots::new(&mut memory);
        let (parent, record) = wrapped(&mut slots);
        let mut changed = record;
        changed[40] ^= 1;
        let mut wraps = Vec::new();
        wraps.push(depth_changed(|| {
            black_box(slots.unwrap(parent, CONTEXT, &record).unwrap());
        }));
        wraps.push(depth_changed(|| {
            assert_eq!(
                black_box(slots.unwrap(parent, CONTEXT, &changed)),
                Err(Error::RecordRejected)
            );
        }));
        let key = slots.import64(Purpose::Wrap, &mut key_bytes(5)).unwrap();
        let mut out = [0; RECORD_LEN];
        wraps.push(depth_changed(|| {
            slots
                .wrap(key, parent, CONTEXT, &mut Fixed, &mut out)
                .unwrap();
            black_box(&out);
        }));
        wraps.push(depth_changed(|| {
            let failed = slots.wrap(key, parent, CONTEXT, &mut Failing, &mut out);
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        for depth in wraps {
            assert!(depth >= CIPHER_STACK_WIPE, "{depth} bytes wiped");
            assert!(depth <= WRAP_STACK, "{depth} bytes reached");
        }
        let mut short: [u8; 32] = key_bytes(7)[..32].try_into().unwrap();
        let loads = [
            depth_changed(|| {
                black_box(slots.import32(Purpose::Wrap, &mut short).unwrap());
            }),
            depth_changed(|| {
                black_box(slots.import64(Purpose::Wrap, &mut key_bytes(9)).unwrap());
            }),
            depth_changed(|| {
                let generated = slots.generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting);
                black_box(generated.unwrap());
            }),
        ];
        for depth in loads {
            assert!(depth <= LOAD_STACK, "{depth} bytes reached");
        }
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs {
    use core::marker::PhantomData;

    use super::{
        Entropy, EntropyError, Error, Handle, KeyLength, Occupancy, PLAINTEXT_LEN, Purpose,
        RECORD_LEN, Slot, Slots, Status, record,
    };
    use crate::derive::{
        model::{failed, id_bytes, id_from_bytes},
        proofs::expected_key_id,
    };
    use crate::record::ID_LEN;
    use crate::seal::model::rejected;

    type Bytes = [u8; 64];
    type Snapshot = (
        Occupancy,
        u64,
        KeyLength,
        Bytes,
        Purpose,
        Status,
        [u8; ID_LEN],
    );

    fn key(slot: &Slot) -> Bytes {
        *slot.key.bytes()
    }

    fn snapshot(slot: &Slot) -> Snapshot {
        (
            slot.occupancy,
            slot.generation,
            slot.key.length(),
            key(slot),
            slot.purpose,
            slot.status,
            *id_bytes(&slot.id),
        )
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

    /// A slot in any state, with any generation and either status, holding a key of either length
    /// and any identifier only when loaded. This covers every state the code can produce and more:
    /// a key or an identifier outside a loaded slot cannot arise, because every path out of the
    /// loaded state wipes both first, and what a failed load writes into a free slot is wiped,
    /// which `a_load_takes_the_first_free_slot` checks, as is what a generation writes before its
    /// source panics, which a unit test checks.
    fn any_slot() -> Slot {
        let mut slot = Slot::empty();
        slot.generation = kani::any();
        slot.occupancy = match kani::any::<u8>() % 3 {
            0 => Occupancy::Free,
            1 => Occupancy::Loaded,
            _ => Occupancy::Retired,
        };
        if slot.occupancy == Occupancy::Loaded {
            if kani::any() {
                slot.key.load32(&mut kani::any());
            } else {
                slot.key.load64(&mut kani::any());
            }
            slot.id = id_from_bytes(kani::any());
        }
        slot.status = if kani::any() {
            Status::Enabled
        } else {
            Status::Disabled
        };
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
            let bytes: Bytes = kani::any();
            dest.copy_from_slice(&bytes[..dest.len()]);
            self.written[..dest.len()].copy_from_slice(dest);
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
            let result = slots.import32(Purpose::Wrap, &mut source);
            let mut bytes = [0; 64];
            bytes[..32].copy_from_slice(&original);
            kani::assert(
                source == if result.is_ok() { [0; 32] } else { original },
                "an import wipes its source exactly when it succeeds",
            );
            (result, bytes, KeyLength::Bytes32)
        } else {
            let mut source: [u8; 64] = kani::any();
            let original = source;
            let result = slots.import64(Purpose::Wrap, &mut source);
            kani::assert(
                source == if result.is_ok() { [0; 64] } else { original },
                "an import wipes its source exactly when it succeeds",
            );
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

    /// Loads one key by any of the three ways, with any key and length. Returns the outcome, the
    /// bytes and length the slot must hold on success, and whether a platform source was asked and
    /// failed.
    fn load_any(slots: &mut Slots<'_>) -> (Result<Handle<'static>, Error>, Bytes, KeyLength, bool) {
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
            let result = slots.import32(Purpose::Wrap, &mut source);
            let mut bytes = [0; 64];
            bytes[..32].copy_from_slice(&original);
            kani::assert(
                source == if result.is_ok() { [0; 32] } else { original },
                "an import wipes its source exactly when it succeeds",
            );
            (result, bytes, KeyLength::Bytes32)
        } else if way % 3 == 1 {
            let mut source: [u8; 64] = kani::any();
            let original = source;
            let result = slots.import64(Purpose::Wrap, &mut source);
            kani::assert(
                source == if result.is_ok() { [0; 64] } else { original },
                "an import wipes its source exactly when it succeeds",
            );
            (result, original, KeyLength::Bytes64)
        } else {
            let length = any_length();
            let result = slots.generate(Purpose::Wrap, length, &mut entropy);
            if result == Err(Error::NoFreeSlot) {
                kani::assert(entropy.calls == 0, "a full set asks the source for nothing");
            } else {
                kani::assert(
                    entropy.calls == 1 && entropy.requested == length.bytes(),
                    "the source is asked once, for the length of the key",
                );
                kani::assert(
                    (result == Err(Error::EntropyFailed)) == entropy.failed,
                    "a generation fails with EntropyFailed exactly when the source fails",
                );
            }
            if let Ok(handle) = result {
                let buffer = slot_at(slots, handle.index).key.bytes().as_ptr().addr();
                kani::assert(
                    entropy.at == buffer,
                    "the source writes straight into the buffer of the slot",
                );
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
        (result, expected, length, entropy.failed)
    }

    /// Whether `handle`, issued for the key `expected` of `length`, either still reaches exactly
    /// that key in a slot loaded with its generation, or can never be live again: its slot is
    /// retired or has moved past its generation, which no call ever moves back.
    fn own_key_or_never_again(
        slots: &Slots<'_>,
        handle: &Handle<'_>,
        expected: &Bytes,
        length: KeyLength,
    ) -> bool {
        let slot = slot_at(slots, handle.index);
        (slot.occupancy == Occupancy::Loaded
            && slot.generation == handle.generation
            && key(slot) == *expected
            && slot.key.length() == length)
            || slot.occupancy == Occupancy::Retired
            || slot.generation > handle.generation
    }

    /// One step of any sequence of imports and releases. From any state of two slots, for any
    /// handle of this set that reaches exactly its own key or can never be live again, one import
    /// of any key of either length or one release of that or any other handle of this set keeps it
    /// so, and a live handle stays live unless it is the one released; a handle the import issues
    /// is a live handle of this set that reaches exactly its own key; a release of a live handle
    /// wipes the key and its identifier at once, and any other is refused. By induction over the
    /// steps, from the moment a handle is issued it reaches exactly its own key until it is
    /// released, and after that every call refuses it, also while its slot holds a new key.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_step_keeps_every_handle_to_its_own_key() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let tracked = Handle {
            slots: id,
            index: if kani::any() { 0 } else { 1 },
            generation: kani::any(),
            memory: PhantomData,
        };
        let expected: Bytes = kani::any();
        let length = any_length();
        kani::assume(own_key_or_never_again(&slots, &tracked, &expected, length));
        let live = |slots: &Slots<'_>, handle: &Handle<'_>| {
            handle.slots == id && handle.index < 2 && {
                let slot = slot_at(slots, handle.index);
                slot.occupancy == Occupancy::Loaded && slot.generation == handle.generation
            }
        };
        let tracked_live = live(&slots, &tracked);
        let mut tracked_released = false;

        if kani::any() {
            let (result, issued, issued_length) = import_any(&mut slots);
            match result {
                Ok(handle) => {
                    kani::assert(
                        live(&slots, &handle)
                            && own_key_or_never_again(&slots, &handle, &issued, issued_length),
                        "a new handle reaches exactly its own key",
                    );
                    kani::cover!(!tracked_live, "a key is loaded beside a released handle");
                    kani::cover!(tracked_live, "a key is loaded beside a live handle");
                }
                Err(error) => {
                    kani::assert(
                        error == Error::NoFreeSlot || error == Error::DerivationFailed,
                        "an import fails only with NoFreeSlot or DerivationFailed",
                    );
                    kani::cover!(error == Error::NoFreeSlot, "an import finds no free slot");
                    kani::cover!(
                        error == Error::DerivationFailed,
                        "an import fails to derive the identifier"
                    );
                }
            }
        } else {
            let target = if kani::any() {
                tracked
            } else {
                forged(&slots, id)
            };
            let target_live = live(&slots, &target);
            let result = slots.release(target);
            if target_live {
                kani::assert(result == Ok(()), "a live handle releases its key");
                let slot = slot_at(&slots, target.index);
                kani::assert(
                    key(slot) == [0; 64] && *id_bytes(&slot.id) == [0; ID_LEN],
                    "a released key and its identifier are zero at once",
                );
                tracked_released = tracked_live && target.index == tracked.index;
                kani::cover!(tracked_released, "the tracked key is released");
            } else {
                kani::assert(
                    result == Err(Error::StaleHandle),
                    "a handle that is not live is refused",
                );
                kani::cover!(
                    !tracked_live
                        && target.index == tracked.index
                        && target.generation == tracked.generation
                        && slot_at(&slots, tracked.index).occupancy == Occupancy::Loaded,
                    "a released handle is refused while its slot holds a new key"
                );
            }
        }
        kani::assert(
            own_key_or_never_again(&slots, &tracked, &expected, length),
            "a handle reaches exactly its own key or can never be live again",
        );
        kani::assert(
            !tracked_live || tracked_released || live(&slots, &tracked),
            "a live handle stays live until it is released",
        );
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
                let (state, generation, ..) = snapshot_at(&before, foreign.index);
                state == Occupancy::Loaded && generation == foreign.generation
            },
            "the foreign handle names a loaded slot and its generation"
        );

        kani::assert(
            slots.release(foreign) == Err(Error::StaleHandle),
            "a handle from other slots is refused",
        );
        kani::assert(
            snapshot(&slots.slots[0]) == before[0],
            "the first slot is unchanged",
        );
        kani::assert(
            snapshot(&slots.slots[1]) == before[1],
            "the second slot is unchanged",
        );
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
        slot.id = id_from_bytes(kani::any());
        slot
    }

    /// From any state of two slots, with any bytes left in any buffer, creating `Slots` wipes every
    /// key and identifier and loads no slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn creating_slots_wipes_every_key() {
        let mut memory = [any_dirty_slot(), any_dirty_slot()];
        kani::cover!(
            memory.iter().all(|slot| slot.occupancy == Occupancy::Loaded
                && slot.key.length() == KeyLength::Bytes64),
            "both slots hold a long key before"
        );
        kani::cover!(
            memory.iter().any(|slot| {
                slot.occupancy == Occupancy::Free && slot.key.bytes().iter().any(|&byte| byte != 0)
            }),
            "a free slot holds bytes before"
        );
        let slots = Slots::new(&mut memory);
        for slot in slots.slots.iter() {
            kani::assert(
                slot.occupancy != Occupancy::Loaded,
                "creating slots loads no slot",
            );
            kani::assert(
                key(slot) == [0; 64]
                    && slot.key.length() == KeyLength::Bytes32
                    && *id_bytes(&slot.id) == [0; ID_LEN],
                "creating slots wipes every key and identifier",
            );
        }
    }

    /// From any state of two slots and any generation: a load by import or from the platform source
    /// takes the first free slot, issues that slot's generation, keeps it in the slot and leaves
    /// exactly the expected bytes there, zero past the key's length, with the purpose given, the
    /// enabled status and the identifier derived from those bytes; a load fails to derive the
    /// identifier exactly when the derivation fails; a failed source, a failed derivation or a full
    /// set changes no slot, and a full set asks the source for nothing; no load panics or
    /// overflows.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_load_takes_the_first_free_slot() {
        let mut memory = [any_slot(), any_slot()];
        let mut slots = Slots { slots: &mut memory };

        let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
        let first_free = before
            .iter()
            .position(|&(state, ..)| state == Occupancy::Free);
        let (result, expected, length, source_failed) = load_any(&mut slots);
        kani::assert(
            if first_free.is_none() {
                result == Err(Error::NoFreeSlot)
            } else if source_failed {
                result == Err(Error::EntropyFailed)
            } else {
                (result == Err(Error::DerivationFailed)) == failed()
                    && (result.is_ok() || result == Err(Error::DerivationFailed))
            },
            "a load fails with NoFreeSlot without a free slot, with EntropyFailed when the source \
             fails, with DerivationFailed when the derivation fails, and otherwise succeeds",
        );
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "a load fails to derive the identifier"
        );
        if let (Ok(handle), Some(index)) = (result, first_free) {
            let generation = snapshot_at(&before, index).1;
            kani::assert(
                handle.index == index && handle.generation == generation,
                "a load takes the first free slot and issues its generation",
            );
            let slot = slot_at(&slots, index);
            kani::assert(
                slot.occupancy == Occupancy::Loaded && slot.generation == generation,
                "the slot is loaded and keeps its generation",
            );
            kani::assert(
                key(slot) == expected && slot.key.length() == length,
                "the slot holds exactly the key, zero past its length",
            );
            kani::assert(
                *id_bytes(&slot.id) == expected_key_id(&expected, length, Purpose::Wrap)
                    && slot.purpose == Purpose::Wrap
                    && slot.status == Status::Enabled,
                "the slot keeps the purpose, the identifier derived from its key and the enabled \
                 status",
            );
            kani::assert(
                unchanged_except(&slots, &before, index),
                "a load changes no other slot",
            );
            kani::cover!(length == KeyLength::Bytes32, "a short key is loaded");
            kani::cover!(length == KeyLength::Bytes64, "a long key is loaded");
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a failed load changes no slot",
            );
            kani::cover!(first_free.is_none(), "no slot is free");
        }
    }

    /// From any state of two slots and any generation, which includes every state a load leaves: a
    /// handle of this set naming any slot and generation releases a key only if that slot is loaded
    /// with that generation, and otherwise is refused and changes nothing; a release wipes the key
    /// and its identifier and advances the generation by one, or retires the slot when the
    /// generation runs out; no release panics or overflows.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_handle_releases_only_a_matching_loaded_slot() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };

        let forged = Handle {
            slots: id,
            index: kani::any(),
            generation: kani::any(),
            memory: PhantomData,
        };
        let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
        kani::cover!(
            before.iter().all(|&(state, ..)| state == Occupancy::Loaded),
            "both slots hold a key when the handle arrives"
        );
        kani::cover!(
            before[0].0 == Occupancy::Free,
            "the first slot is free when the handle arrives"
        );
        let target = Some(forged.index)
            .filter(|&index| index < 2)
            .map(|index| snapshot_at(&before, index))
            .filter(|&(state, generation, ..)| {
                state == Occupancy::Loaded && generation == forged.generation
            });
        let result = slots.release(forged);
        match target {
            Some((_, generation, ..)) => {
                kani::assert(result == Ok(()), "a matching handle releases its key");
                let slot = slot_at(&slots, forged.index);
                kani::assert(
                    key(slot) == [0; 64]
                        && slot.key.length() == KeyLength::Bytes32
                        && *id_bytes(&slot.id) == [0; ID_LEN],
                    "a release wipes the key and its identifier",
                );
                if generation == u64::MAX {
                    kani::assert(
                        slot.occupancy == Occupancy::Retired,
                        "a slot whose generation runs out is retired",
                    );
                    kani::cover!(true, "a slot is retired when its generation runs out");
                } else {
                    kani::assert(
                        slot.occupancy == Occupancy::Free
                            && Some(slot.generation) == generation.checked_add(1),
                        "a release frees the slot and advances the generation by one",
                    );
                    kani::cover!(true, "a release advances the generation by one");
                }
                kani::assert(
                    unchanged_except(&slots, &before, forged.index),
                    "a release changes no other slot",
                );
            }
            None => {
                kani::assert(
                    result == Err(Error::StaleHandle),
                    "any other handle is refused",
                );
                kani::assert(
                    snapshot(&slots.slots[0]) == before[0],
                    "the first slot is unchanged",
                );
                kani::assert(
                    snapshot(&slots.slots[1]) == before[1],
                    "the second slot is unchanged",
                );
                kani::cover!(
                    before.iter().any(|&(state, ..)| state == Occupancy::Loaded),
                    "a handle is refused while a key is loaded"
                );
            }
        }
    }

    fn plaintext_key(plaintext: &[u8; PLAINTEXT_LEN], length: KeyLength) -> Bytes {
        let mut out = [0; 64];
        for index in 0..length.bytes() {
            out[index] = plaintext[28 + index];
        }
        out
    }

    /// From any state of two slots, with the parent loaded in either slot and any 92 bytes of
    /// plaintext: admitting the plaintext loads the key it holds, with the length, purpose and
    /// status it states, into the first free slot and derives the key's identifier, exactly when
    /// the bytes parse, the parent identifier they state is the parent's, a slot is free and the
    /// derivation succeeds; otherwise no slot changes. The offsets are written from the layout,
    /// independently of the parser.
    #[kani::proof]
    #[kani::unwind(93)]
    fn admitting_a_plaintext_loads_exactly_the_key_it_holds() {
        let mut memory = [any_slot(), any_slot()];
        let mut slots = Slots { slots: &mut memory };
        let parent: usize = if kani::any() { 0 } else { 1 };
        let plaintext: [u8; PLAINTEXT_LEN] = kani::any();
        let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
        kani::assume(snapshot_at(&before, parent).0 == Occupancy::Loaded);
        let first_free = before
            .iter()
            .position(|&(occupancy, ..)| occupancy == Occupancy::Free);
        let parses = record::parse(&plaintext).is_ok();
        let parent_id = snapshot_at(&before, parent).6;
        let names_parent = parses && plaintext[4..20] == parent_id;

        let result = slots.admit(parent, &plaintext);
        kani::assert(
            if !names_parent {
                result == Err(Error::RecordRejected)
            } else if first_free.is_none() {
                result == Err(Error::NoFreeSlot)
            } else {
                (result == Err(Error::DerivationFailed)) == failed()
                    && (result.is_ok() || result == Err(Error::DerivationFailed))
            },
            "a plaintext is admitted exactly when it parses, names the parent, finds a free slot \
             and its key's identifier is derived",
        );
        if let (Ok(handle), Some(index)) = (result, first_free) {
            let length = if plaintext[2] == 32 {
                KeyLength::Bytes32
            } else {
                KeyLength::Bytes64
            };
            let status = if plaintext[3] == 1 {
                Status::Enabled
            } else {
                Status::Disabled
            };
            let expected = plaintext_key(&plaintext, length);
            let slot = slot_at(&slots, index);
            kani::assert(
                handle.index == index && slot.generation == snapshot_at(&before, index).1,
                "the key goes into the first free slot, which keeps its generation",
            );
            kani::assert(
                slot.occupancy == Occupancy::Loaded
                    && key(slot) == expected
                    && slot.key.length() == length,
                "the slot holds exactly the key the plaintext holds, zero past its length",
            );
            kani::assert(
                slot.purpose == Purpose::Wrap
                    && slot.status == status
                    && *id_bytes(&slot.id) == expected_key_id(&expected, length, Purpose::Wrap),
                "the slot keeps the purpose and status the plaintext states, and the identifier",
            );
            kani::assert(
                unchanged_except(&slots, &before, index),
                "admitting changes no other slot",
            );
            kani::cover!(status == Status::Disabled, "a disabled key is admitted");
            kani::cover!(length == KeyLength::Bytes32, "a short key is admitted");
            kani::cover!(length == KeyLength::Bytes64, "a long key is admitted");
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a refused plaintext changes no slot",
            );
            kani::cover!(
                parses && !names_parent,
                "a plaintext naming another parent is refused"
            );
            kani::cover!(!parses, "a malformed plaintext is refused");
        }
    }

    fn forged(slots: &Slots<'_>, id: usize) -> Handle<'static> {
        let _ = slots;
        Handle {
            slots: id,
            index: kani::any(),
            generation: kani::any(),
            memory: PhantomData,
        }
    }

    /// Whether `handle` names a loaded slot with its generation, read from the snapshots.
    fn names_loaded(before: &[Snapshot; 2], handle: &Handle<'_>) -> bool {
        handle.index < 2 && {
            let (occupancy, generation, ..) = snapshot_at(before, handle.index);
            occupancy == Occupancy::Loaded && generation == handle.generation
        }
    }

    /// Any context of up to two bytes.
    fn any_context(bytes: &[u8; 2]) -> &[u8] {
        let length: usize = kani::any();
        kani::assume(length <= 2);
        &bytes[..length]
    }

    /// From any state of two slots, for a handle of this set naming any slot and generation, any
    /// record and any context of up to two bytes, whatever the cipher does: unwrapping refuses an
    /// empty context, a stale or disabled parent and a full set before it decrypts; a record the
    /// cipher rejects is refused as `RecordRejected`; a refused unwrap changes no slot, and one
    /// that succeeds changes only the first free slot.
    #[kani::proof]
    #[kani::unwind(93)]
    fn a_refused_unwrap_changes_no_slot() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let parent = forged(&slots, id);
        let record: [u8; RECORD_LEN] = kani::any();
        let context_bytes: [u8; 2] = kani::any();
        let context = any_context(&context_bytes);
        let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
        let live = names_loaded(&before, &parent);
        let first_free = before
            .iter()
            .position(|&(occupancy, ..)| occupancy == Occupancy::Free);

        let result = slots.unwrap(parent, context, &record);
        kani::assert(
            if context.is_empty() {
                result == Err(Error::InvalidContext)
            } else if !live {
                result == Err(Error::StaleHandle)
            } else if snapshot_at(&before, parent.index).5 == Status::Disabled {
                result == Err(Error::KeyDisabled)
            } else if first_free.is_none() {
                result == Err(Error::NoFreeSlot)
            } else {
                !rejected() || result == Err(Error::RecordRejected)
            },
            "an unwrap refuses a bad context, a stale or disabled parent, a full set and a \
             rejected record",
        );
        if let (Ok(handle), Some(index)) = (result, first_free) {
            kani::assert(
                handle.index == index && unchanged_except(&slots, &before, index),
                "an unwrap changes only the first free slot",
            );
            kani::cover!(true, "a record is unwrapped");
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a refused unwrap changes no slot",
            );
            kani::cover!(rejected(), "the cipher rejects a record");
            kani::cover!(
                result == Err(Error::RecordRejected) && !rejected(),
                "a record that opens is refused"
            );
        }
    }

    /// From any state of two slots, for handles of this set naming any slots and generations, any
    /// context of up to two bytes and any record buffer, whatever the platform's source and the
    /// cipher do: wrapping changes no slot; it writes the record only when it succeeds, starting
    /// with the nonce the source gave; it refuses an empty context, a stale handle, two keys with
    /// one identifier and a disabled parent.
    #[kani::proof]
    #[kani::unwind(121)]
    fn a_wrap_changes_no_slot_and_writes_only_when_it_succeeds() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let (key, parent) = (forged(&slots, id), forged(&slots, id));
        let context_bytes: [u8; 2] = kani::any();
        let context = any_context(&context_bytes);
        let original: [u8; RECORD_LEN] = kani::any();
        let mut record = original;
        let mut entropy = AnyEntropy {
            written: [0; 64],
            calls: 0,
            requested: 0,
            at: 0,
            failed: false,
        };
        let before = [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])];
        let live = names_loaded(&before, &key) && names_loaded(&before, &parent);

        let result = slots.wrap(key, parent, context, &mut entropy, &mut record);
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a wrap changes no slot",
        );
        kani::assert(
            if context.is_empty() {
                result == Err(Error::InvalidContext)
            } else if !live {
                result == Err(Error::StaleHandle)
            } else if snapshot_at(&before, key.index).6 == snapshot_at(&before, parent.index).6 {
                result == Err(Error::SameKey)
            } else if snapshot_at(&before, parent.index).5 == Status::Disabled {
                result == Err(Error::KeyDisabled)
            } else if entropy.failed {
                result == Err(Error::EntropyFailed)
            } else {
                result.is_ok()
                    || result == Err(Error::DerivationFailed)
                    || result == Err(Error::CipherFailed)
            },
            "a wrap refuses a bad context, a stale handle, a key wrapping itself, a disabled \
             parent and a failed source",
        );
        kani::assert(
            if result.is_ok() {
                record[..12] == entropy.written[..12]
            } else {
                record == original
            },
            "a wrap writes the record only when it succeeds, starting with the nonce",
        );
        kani::cover!(result.is_ok(), "a key is wrapped");
        kani::cover!(result == Err(Error::CipherFailed), "the cipher fails");
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "the derivation fails"
        );
    }
}
