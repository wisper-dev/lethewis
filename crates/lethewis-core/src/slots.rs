// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::{fmt, marker::PhantomData};

use crate::{
    derive::{KeyId, derive_key_id, derive_wrap_key},
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
    /// Needs 8 KiB of stack, or 64 KiB when this crate is built without optimisation or with `--cfg
    /// lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe of that
    /// much. A build that optimises this crate but not the hash code it calls has to set that flag.
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
    /// Needs 8 KiB of stack, or 64 KiB when this crate is built without optimisation or with `--cfg
    /// lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe of that
    /// much. A build that optimises this crate but not the hash code it calls has to set that flag.
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
    /// Like an import, this needs 8 KiB of stack, or 64 KiB when this crate is built without
    /// optimisation or with `--cfg lethewis_unoptimised`, for that wipe; a build that optimises
    /// this crate but not the hash code it calls has to set that flag.
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
    /// Needs 8 KiB of stack, or 64 KiB when this crate is built without optimisation or with `--cfg
    /// lethewis_unoptimised`, for the wipe that follows each derivation from a key. A build that
    /// optimises this crate but not the hash code it calls has to set that flag.
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
    /// Needs 8 KiB of stack, or 64 KiB when this crate is built without optimisation or with `--cfg
    /// lethewis_unoptimised`, for the wipe that follows each derivation from a key. A build that
    /// optimises this crate but not the hash code it calls has to set that flag.
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
    /// identifier, and issues a handle if both succeed. If the derivation fails, the key and what
    /// the derivation wrote are wiped.
    fn load(
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
    use std::vec::Vec;

    use super::{
        AssociatedData, Attributes, CIPHER_KEY_LEN, Entropy, EntropyError, Error, Handle,
        KeyLength, Occupancy, PLAINTEXT_LEN, Purpose, RECORD_LEN, Slot, Slots, Status,
        derive_wrap_key, record, seal, write_record,
    };
    use crate::derive::{KeyId, derive_key_id};
    use crate::key::{
        Key,
        tests::{Counting, Failing, Panicking, Recording, counted, padded},
    };

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

#[cfg(kani)]
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

    /// The shortest sequence that reaches every outcome below, including a released handle refused
    /// while its slot holds a new key; a cover property shows that case is reached.
    const STEPS: usize = 4;

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

    /// From empty memory, any interleaving of four imports and releases over two slots, with any
    /// keys of either length. A live handle reaches exactly its own key, a released key and its
    /// identifier are zero at once, and a released handle is refused ever after, including while
    /// its slot holds a new key. Every load goes through the same code, so generated keys, and the
    /// identifier a load derives, are covered by `a_load_takes_the_first_free_slot`, which checks
    /// each way of loading from any state.
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
                let pick: usize = kani::any();
                kani::assume(pick < STEPS);
                kani::cover!(issued[pick].is_some(), "a step releases an earlier handle");
                if let Some((handle, _, _)) = issued[pick] {
                    let reused = slot_at(&slots, handle.index).occupancy == Occupancy::Loaded;
                    let result = slots.release(handle);
                    if live[pick] {
                        kani::assert(result == Ok(()), "a live handle releases its key");
                        let slot = slot_at(&slots, handle.index);
                        kani::assert(
                            key(slot) == [0; 64] && *id_bytes(&slot.id) == [0; ID_LEN],
                            "a released key and its identifier are zero at once",
                        );
                        live[pick] = false;
                        kani::cover!(true, "a live key is released");
                    } else {
                        kani::assert(
                            result == Err(Error::StaleHandle),
                            "a released handle is refused",
                        );
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
                    kani::assert(
                        slot.occupancy == Occupancy::Loaded && slot.generation == handle.generation,
                        "the slot of a live handle is loaded with its generation",
                    );
                    kani::assert(
                        key(slot) == *expected && slot.key.length() == *length,
                        "a live handle reaches exactly its own key",
                    );
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
