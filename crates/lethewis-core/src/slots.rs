// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::{fmt, marker::PhantomData};

use crate::{
    derive::{KeyId, derive_key_id, derive_wrap_key, wipe_cipher_stack},
    entropy::{Entropy, EntropyError},
    error::Error,
    key::{Key, KeyBytes, KeyLength, wipe},
    keyset::{self, Header, MEMBERS, Stages},
    record::{AssociatedData, PLAINTEXT_LEN, Purpose, RECORD_LEN, Status},
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, NONCE_LEN, Rejected, TAG_LEN},
};

/// Memory for one key set, provided by the caller: up to three keys, the stage of each, and which
/// of them is the primary.
///
/// A slot cannot be copied, cloned or compared. It holds keys only while a [`Slots`] over it is
/// alive, so moving the memory afterwards copies no key.
pub struct Slot {
    keys: [Key; MEMBERS],
    ids: [KeyId; MEMBERS],
    stages: Stages,
    purpose: Purpose,
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
            keys: [const { Key::empty() }; MEMBERS],
            ids: [const { KeyId::empty() }; MEMBERS],
            stages: Stages::one(),
            purpose: Purpose::Wrap,
            generation: 0,
            occupancy: Occupancy::Free,
        }
    }

    // Here and below each position is named rather than iterated, or reached through an array of
    // references: under the proofs either costs many times a field access.
    fn wipe_keys(&mut self) {
        let [first, second, third] = &mut self.keys;
        first.wipe();
        second.wipe();
        third.wipe();
        let [first_id, second_id, third_id] = &mut self.ids;
        first_id.wipe();
        second_id.wipe();
        third_id.wipe();
    }

    fn unload(&mut self) {
        self.wipe_keys();
        match self.generation.checked_add(1) {
            Some(next) => {
                self.generation = next;
                self.occupancy = Occupancy::Free;
            }
            None => self.occupancy = Occupancy::Retired,
        }
    }

    /// Whether the slot holds a key with the identifier `id`.
    fn holds(&self, id: &KeyId) -> bool {
        let [first, second, third] = &self.ids;
        let at =
            |position: usize, held: &KeyId| self.stages.stage(position).is_some() && held.same(id);
        self.occupancy == Occupancy::Loaded && (at(0, first) || at(1, second) || at(2, third))
    }

    /// The primary key of the set and its identifier.
    fn primary(&self) -> (&Key, &KeyId) {
        let [first, second, third] = &self.keys;
        let [first_id, second_id, third_id] = &self.ids;
        match self.stages.primary() {
            0 => (first, first_id),
            1 => (second, second_id),
            _ => (third, third_id),
        }
    }
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot").finish_non_exhaustive()
    }
}

/// Refers to a key set held in [`Slots`].
///
/// A handle works only with the `Slots` that issued it, stops working when its set is released,
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

/// Key sets held in slots provided by the caller.
///
/// A key goes in, and only a handle to its set comes out: no call returns a key itself. A key is
/// held in one place only: a load that would hold a key these slots already hold is refused.
/// Creating and dropping `Slots` wipes every key in its slots. A `Slots` leaked instead of dropped,
/// for example through [`core::mem::forget`], [`core::mem::ManuallyDrop`] or `Box::leak`, skips that
/// wipe, and its keys stay in memory until the next `Slots` over the same memory.
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

/// What opens a sealed plaintext: AES-256-GCM-SIV, or a model of it in the proofs.
trait Open:
    FnMut(
    &[u8; CIPHER_KEY_LEN],
    &[u8; NONCE_LEN],
    &[u8],
    &mut [u8; PLAINTEXT_LEN],
    &[u8; TAG_LEN],
) -> Result<(), Rejected>
{
}

impl<F> Open for F where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8; PLAINTEXT_LEN],
        &[u8; TAG_LEN],
    ) -> Result<(), Rejected>
{
}

impl<'a> Slots<'a> {
    /// Keeps key sets in `slots`. A key left there earlier is wiped first.
    #[must_use]
    pub fn new(slots: &'a mut [Slot]) -> Self {
        let mut this = Self { slots };
        this.unload_all();
        this
    }

    /// Takes a 32-byte key for `purpose` from `source` into a free slot, as a set of one whose key
    /// is the primary, and wipes `source`.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe
    /// of 8 KiB, or 64 KiB, below it. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, [`Error::DerivationFailed`] if the identifier of
    /// the key cannot be derived, and [`Error::DuplicateKey`] if these slots hold the key already.
    /// `source` is then left as it was, and no slot changes.
    pub fn import32(
        &mut self,
        purpose: Purpose,
        source: &mut [u8; 32],
    ) -> Result<Handle<'a>, Error> {
        let handle = self.load(purpose, Stages::one(), |[first, ..]| {
            first.copy32(source);
            Ok(())
        })?;
        wipe(source);
        Ok(handle)
    }

    /// Takes a 64-byte key for `purpose` from `source` into a free slot, as a set of one whose key
    /// is the primary, and wipes `source`.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe
    /// of 8 KiB, or 64 KiB, below it. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, [`Error::DerivationFailed`] if the identifier of
    /// the key cannot be derived, and [`Error::DuplicateKey`] if these slots hold the key already.
    /// `source` is then left as it was, and no slot changes.
    pub fn import64(
        &mut self,
        purpose: Purpose,
        source: &mut [u8; 64],
    ) -> Result<Handle<'a>, Error> {
        let handle = self.load(purpose, Stages::one(), |[first, ..]| {
            first.copy64(source);
            Ok(())
        })?;
        wipe(source);
        Ok(handle)
    }

    /// Creates a key for `purpose` of `length` random bytes from `entropy` in a free slot, as a set
    /// of one whose key is the primary. The bytes are written straight into the slot, and the
    /// library's own code makes no copy of them; the stack the derivation of the key's identifier
    /// used is wiped after it. `entropy` is asked once, and only when a slot is free.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier is followed by a wipe
    /// of 8 KiB, or 64 KiB, below it. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeSlot`] if no slot is free, [`Error::EntropyFailed`] if `entropy` fails,
    /// [`Error::DerivationFailed`] if the identifier of the key cannot be derived, and
    /// [`Error::DuplicateKey`] if these slots hold the key already. No slot changes then.
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
        self.load(purpose, Stages::one(), |[first, ..]| {
            first
                .fill(length, entropy)
                .map_err(|EntropyError| Error::EntropyFailed)
        })
    }

    /// Wraps the key set that `set` refers to under the primary key of the set that `parent` refers
    /// to and writes the record into `record`. The record holds every key of the set, its stage and
    /// which key is the primary, and opens only with that key of the parent and the same `context`,
    /// which names the place the record is kept, from 1 to 255 bytes. The nonce comes from
    /// `entropy`.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if either handle does not refer to a set held here now,
    /// [`Error::SameKey`] if both refer to the same set, [`Error::EntropyFailed`] if `entropy`
    /// fails, [`Error::DerivationFailed`] if the key that encrypts the record cannot be derived,
    /// and [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails.
    /// `record` is then left as it was.
    pub fn wrap(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; RECORD_LEN],
    ) -> Result<(), Error> {
        let wrapped =
            lethewis_dit::with(|| self.wrap_on_stack(set, parent, context, entropy, record));
        wipe_cipher_stack();
        wrapped
    }

    /// The wrap itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn wrap_on_stack(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; RECORD_LEN],
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let (child, wrapping) = (self.loaded(set)?, self.loaded(parent)?);
        if child == wrapping {
            return Err(Error::SameKey);
        }
        let (Some(child), Some(wrapping)) = (self.slots.get(child), self.slots.get(wrapping))
        else {
            return Err(Error::StaleHandle);
        };
        let (parent_key, parent_id) = wrapping.primary();
        let mut nonce = [0; NONCE_LEN];
        entropy
            .fill(&mut nonce)
            .map_err(|EntropyError| Error::EntropyFailed)?;
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        if derive_wrap_key(parent_key, wrapping.purpose, &mut cipher_key).is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let header = Header {
            purpose: child.purpose,
            parent: parent_id.bytes(),
            epoch: 0,
        };
        let [first, second, third] = &child.keys;
        let mut sealed = [0; PLAINTEXT_LEN];
        keyset::build(&header, &child.stages, [first, second, third], &mut sealed);
        let tag = seal::seal(&cipher_key, &nonce, associated.bytes(), &mut sealed);
        wipe(&mut cipher_key);
        let tag = tag.map_err(|_| Error::CipherFailed)?;
        write_record(record, &nonce, &sealed, &tag);
        Ok(())
    }

    /// Unwraps `record` with the set that `parent` refers to and the `context` it was wrapped for,
    /// into a free slot. Every key of the parent set is tried, whichever opens the record; the set
    /// comes out with the keys, stages and primary the record holds.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `parent` does not refer to a set held here now,
    /// [`Error::NoFreeSlot`] if no slot is free, [`Error::DerivationFailed`] if a value cannot be
    /// derived from a key, [`Error::RecordRejected`] if the record does not open with a key of the
    /// parent and this context, names a key other than the one that opens it, or holds a plaintext
    /// this version of the library cannot read, [`Error::KeyDisabled`] if only a disabled key of
    /// the parent opens it, and [`Error::DuplicateKey`] if these slots hold a key of the set already
    /// or the set holds one key twice. No slot changes then.
    pub fn unwrap(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let unwrapped =
            lethewis_dit::with(|| self.unwrap_on_stack(parent, context, record, seal::open));
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
        mut open: impl Open,
    ) -> Result<Handle<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.loaded(parent)?;
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        let mut plaintext = [0; PLAINTEXT_LEN];
        let admitted = self
            .open_under(index, associated.bytes(), record, &mut plaintext, &mut open)
            .and_then(|()| self.admit(&plaintext));
        wipe(&mut plaintext);
        admitted
    }

    /// Tries every key of the set in slot `parent` on `record`, without stopping at the first that
    /// opens it. Keeps in `found` the plaintext of the first key that opens the record and whose
    /// identifier the plaintext names as the parent's, and refuses it as `KeyDisabled` if that key
    /// is disabled.
    fn open_under(
        &self,
        parent: usize,
        aad: &[u8],
        record: &[u8; RECORD_LEN],
        found: &mut [u8; PLAINTEXT_LEN],
        open: &mut impl Open,
    ) -> Result<(), Error> {
        let set = self.slots.get(parent).ok_or(Error::StaleHandle)?;
        let (nonce, mut sealed, tag) = split_record(record);
        // The winner in two plain values: Kani 0.68.0 decodes values packed around `Status`, such as
        // `Result<Status, Error>`, wrongly.
        let mut won = false;
        let mut won_stage = Status::Enabled;
        let mut failed = false;
        let mut try_key = |stage: Option<Status>, key: &Key, id: &KeyId| {
            let Some(stage) = stage else {
                return;
            };
            let mut cipher_key = [0; CIPHER_KEY_LEN];
            failed |= derive_wrap_key(key, set.purpose, &mut cipher_key).is_err();
            let mut trial = sealed;
            let opened = open(&cipher_key, &nonce, aad, &mut trial, &tag).is_ok();
            wipe(&mut cipher_key);
            if opened && id.is(keyset::parent_of(&trial)) && !won {
                *found = trial;
                won = true;
                won_stage = stage;
            }
            wipe(&mut trial);
        };
        let [first, second, third] = &set.keys;
        let [first_id, second_id, third_id] = &set.ids;
        try_key(set.stages.stage(0), first, first_id);
        try_key(set.stages.stage(1), second, second_id);
        try_key(set.stages.stage(2), third, third_id);
        wipe(&mut sealed);
        if failed {
            Err(Error::DerivationFailed)
        } else if !won {
            Err(Error::RecordRejected)
        } else if won_stage == Status::Disabled {
            Err(Error::KeyDisabled)
        } else {
            Ok(())
        }
    }

    /// Loads the key set a record's plaintext holds into a free slot, if one is and the plaintext
    /// parses.
    fn admit(&mut self, plaintext: &[u8; PLAINTEXT_LEN]) -> Result<Handle<'a>, Error> {
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        let (header, stages, keys) = keyset::parse(plaintext).map_err(|_| Error::RecordRejected)?;
        self.load(header.purpose, stages, |[first, second, third]| {
            let [first_bytes, second_bytes, third_bytes] = keys;
            let load = |key: &mut Key, bytes: Option<KeyBytes<'_>>| {
                if let Some(bytes) = bytes {
                    bytes.load_into(key);
                }
            };
            load(first, first_bytes);
            load(second, second_bytes);
            load(third, third_bytes);
            Ok(())
        })
    }

    fn has_free(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.occupancy == Occupancy::Free)
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

    /// Puts the keys of a set for `purpose` with `stages` into the first free slot with `fill`,
    /// derives their identifiers, and issues a handle if that succeeds, no key is held already and
    /// none twice, with data-independent timing on. On failure the slot is left free and wiped.
    fn load(
        &mut self,
        purpose: Purpose,
        stages: Stages,
        fill: impl FnOnce(&mut [Key; MEMBERS]) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        lethewis_dit::with(|| self.load_in_slot(purpose, stages, fill))
    }

    fn load_in_slot(
        &mut self,
        purpose: Purpose,
        stages: Stages,
        fill: impl FnOnce(&mut [Key; MEMBERS]) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        let slots = self.id();
        let index = self
            .slots
            .iter()
            .position(|slot| slot.occupancy == Occupancy::Free)
            .ok_or(Error::NoFreeSlot)?;
        let filled = self
            .slots
            .get_mut(index)
            .map_or(Err(Error::NoFreeSlot), |slot| fill(&mut slot.keys));
        let identified = filled.and_then(|()| self.identify(index, purpose, &stages));
        let slot = self.slots.get_mut(index).ok_or(Error::NoFreeSlot)?;
        let mut ids = match identified {
            Ok(ids) => ids,
            Err(error) => {
                slot.wipe_keys();
                return Err(error);
            }
        };
        let [first, second, third] = &mut slot.ids;
        let [first_id, second_id, third_id] = &mut ids;
        first.take(first_id);
        second.take(second_id);
        third.take(third_id);
        slot.stages = stages;
        slot.purpose = purpose;
        slot.occupancy = Occupancy::Loaded;
        Ok(Handle {
            slots,
            index,
            generation: slot.generation,
            memory: PhantomData,
        })
    }

    /// The identifiers of the keys `stages` places in the free slot `index`, derived for
    /// `purpose`. A key that a loaded slot holds, or that the set holds twice, is refused.
    // Derived into local buffers and copied in at once: the derivation writes byte by byte, and
    // each write through a reference to a slot chosen at run time multiplies the proofs' work.
    fn identify(
        &self,
        index: usize,
        purpose: Purpose,
        stages: &Stages,
    ) -> Result<[KeyId; MEMBERS], Error> {
        let slot = self.slots.get(index).ok_or(Error::NoFreeSlot)?;
        let derive = |position: usize, key: &Key, id: &mut KeyId| {
            if stages.stage(position).is_some() {
                derive_key_id(key, purpose, id).map_err(|_| Error::DerivationFailed)?;
            }
            Ok(())
        };
        let [first, second, third] = &slot.keys;
        let mut ids = [const { KeyId::empty() }; MEMBERS];
        let [first_id, second_id, third_id] = &mut ids;
        derive(0, first, first_id)?;
        derive(1, second, second_id)?;
        derive(2, third, third_id)?;
        let [first_id, second_id, third_id] = &ids;
        let filled = |position: usize| stages.stage(position).is_some();
        let held = |id: &KeyId| self.slots.iter().any(|other| other.holds(id));
        let repeated = (filled(0) && held(first_id))
            || (filled(1) && (held(second_id) || (filled(0) && first_id.same(second_id))))
            || (filled(2)
                && (held(third_id)
                    || (filled(0) && first_id.same(third_id))
                    || (filled(1) && second_id.same(third_id))));
        if repeated {
            return Err(Error::DuplicateKey);
        }
        Ok(ids)
    }

    /// Wipes every key of the set that `handle` refers to and frees its slot.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `handle` does not refer to a set held here now.
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

    /// Wipes every key and identifier in every slot, loaded or not, and frees the loaded ones.
    fn unload_all(&mut self) {
        for slot in self.slots.iter_mut() {
            if slot.occupancy == Occupancy::Loaded {
                slot.unload();
            } else {
                slot.wipe_keys();
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
        AssociatedData, CIPHER_KEY_LEN, Entropy, EntropyError, Error, Handle, Header, KeyLength,
        MEMBERS, Occupancy, PLAINTEXT_LEN, Purpose, RECORD_LEN, Slot, Slots, Stages, Status,
        derive_wrap_key, keyset, seal, write_record,
    };
    use crate::derive::{CIPHER_STACK_WIPE, KeyId, STACK_WIPE, derive_key_id};
    use crate::key::{
        Key,
        tests::{Counting, Failing, Panicking, Recording, counted, padded},
    };
    use crate::record::MAX_CONTEXT;

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
        slots.release(key).unwrap();
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
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&secret()));
        assert_eq!(slots.slots[0].keys[0].length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[0].occupancy, Occupancy::Loaded);
        assert_eq!(source, [0; 32]);
    }

    #[test]
    fn import64_loads_the_key_and_wipes_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let mut source = [5; 64];
        slots.import64(Purpose::Wrap, &mut source).unwrap();
        assert_eq!(slots.slots[0].keys[0].bytes(), &[5; 64]);
        assert_eq!(slots.slots[0].keys[0].length(), KeyLength::Bytes64);
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
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&counted::<32>()));
        assert_eq!(slots.slots[0].keys[0].length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[1].keys[0].bytes(), &counted::<64>());
        assert_eq!(slots.slots[1].keys[0].length(), KeyLength::Bytes64);
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
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&[]));
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
        assert_eq!(source.at, slots.slots[0].keys[0].bytes().as_ptr().addr());
    }

    #[test]
    fn generate_takes_a_source_behind_a_trait_object() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let source: &mut dyn Entropy = &mut Counting;
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, source)
            .unwrap();
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&counted::<32>()));
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
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&[]));
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
        assert_eq!(slots.slots[0].stages.stage(0), Some(Status::Enabled));
        assert_eq!(slots.slots[1].stages.stage(0), Some(Status::Enabled));
        assert_eq!(slots.slots[0].ids[0], id_of(&short));
        assert_eq!(slots.slots[1].ids[0], id_of(&long));
        assert_ne!(slots.slots[0].ids[0], slots.slots[1].ids[0]);
    }

    #[test]
    fn release_wipes_the_identifier() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_ne!(slots.slots[0].ids[0], KeyId::empty());
        slots.release(handle).unwrap();
        assert_eq!(slots.slots[0].ids[0], KeyId::empty());
    }

    #[test]
    fn new_slots_wipe_an_identifier_left_behind() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut key = Key::empty();
        key.load32(&mut secret());
        memory[0].ids[0] = id_of(&key);
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].ids[0], KeyId::empty());
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
        assert_eq!(slots.slots[1].keys[0].bytes(), &padded(&[]));
        assert_eq!(slots.slots[1].keys[0].length(), KeyLength::Bytes32);
        assert_eq!(slots.slots[1].occupancy, Occupancy::Free);
        assert_eq!(slots.slots[1].generation, 1);
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&secret()));
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
        assert_eq!(second.slots[0].keys[0].bytes(), &padded(&secret()));
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
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&secret()));
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
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&[]));
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
            assert_eq!(slot.keys[0].bytes(), &padded(&[]));
            assert_eq!(slot.keys[0].length(), KeyLength::Bytes32);
            assert_eq!((slot.occupancy, slot.generation), (Occupancy::Free, 1));
        }
    }

    #[test]
    fn new_slots_wipe_a_key_left_behind() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].keys[0].load64(&mut [5; 64]);
        memory[0].occupancy = Occupancy::Loaded;
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&[]));
        assert_eq!(slots.slots[0].occupancy, Occupancy::Free);
    }

    #[test]
    fn new_slots_wipe_bytes_left_in_a_free_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].keys[0].load64(&mut [5; 64]);
        let slots = Slots::new(&mut memory);
        assert_eq!(slots.slots[0].keys[0].bytes(), &padded(&[]));
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

    /// Records computed by an implementation independent of this library: under a 32-byte parent,
    /// a set of one 64-byte key in "chat 7"; under a 64-byte parent, a set of one 32-byte key in
    /// "profile"; and under the 32-byte parent, in "archive", a full set at revision 9: a disabled
    /// 64-byte key, an enabled 32-byte key, and the primary, an enabled 64-byte key.
    const KNOWN_RECORDS: [&str; 3] = [
        concat!(
            "05162738495a6b7c8d9eafc0ff05955c91a5db9d5571ee2ef4ab20a64de07207",
            "7ed17a8fc57c373bf13c65458ce9776280c7dd47ea624064c2485ee86c273ad8",
            "ea11746f76409a1c11f86659c8fb0f0458ba461eb215e303046006d4da77f411",
            "730341925a0506f36e3023484fd88e658e931aca37bf493b723f706d6ac560cd",
            "3b8ae9cbae5f6cd05b7c82a25b3d1f901180dcf1ea374761b38f8c27fa598648",
            "4a31a56b3c76751272a7d33e48d67e366351e5ba5cdc86bc48a1001ec760f000",
            "bd6720cf0103ae9921e274506543bac0d735c92e52df4889d00ffe30e5b6e150",
            "917fb056a997a58bb351a9a2b30ee159d979eda09aad6b1291d0f5c985854818",
            "b271eb36c5",
        ),
        concat!(
            "05162738495a6b7c8d9eafc0664c5a9a3eac62e6aed93b05aa1bb4b2496a5db8",
            "6ee42ecca737f2ed4bdc3b36481dfb6c1202dd234a27e94ccfac981aea57c630",
            "beb8eb98381d5b08931a188e9dbaf81993ef64549417195666f6de43b2722f54",
            "3d87be751f5463e9a05f6ce0b16efa69366b201708222e8031dd1b00f1ee844f",
            "cad9dab97a9c73aaad76d834377da5e59273b5e8356f1073781cfa949398ba7d",
            "bfc3e6ac62cdd8c2222d7760190536ed2f616544535b7a527bdc2b51e621fce7",
            "b8f3b17d5c7557c80b0e4c6db782c760f9658a48fffd7575d66033d519a875f1",
            "a7394e8db2f356c4ba2b92558dcc2bf026aa0f5bcaee668d4e385653ec351c80",
            "8a99b1d2be",
        ),
        concat!(
            "05162738495a6b7c8d9eafc0d85956d048dac26b35da8edef5b8c0237d2de9a0",
            "1d4c6df6ddf4afe323f2dfa5a34e71beb45a1a8901323524543f6dfe24c4a7ec",
            "dd6c5100b206dbba2bcba29b56f34717c14d565a0705708604564c84cfca0d32",
            "0d156360a72e98cb93fe28ee0389b0952e9ffaac6033307e5aa1aea87ee9e8ab",
            "3e1b84dd31b2446d11fb36f2122d5f3cb6071325d02947b6526cb7e90f7fc6c8",
            "23c5f37d79f1428161fd8589b9d32218f2e805091d9293679739596fa5f01495",
            "a00bb4bfc1bdceaf5fd6792411b96046be5f2263164912d31eb2741494b6a41d",
            "c3e052841f07860f0dc4d45b16f9ab89a55a1c37639da0f6cbd6de847b58f78e",
            "816093a4dc",
        ),
    ];

    fn key_from(bytes: &[u8]) -> Key {
        let mut key = Key::empty();
        match bytes.len() {
            32 => key.load32(&mut bytes.try_into().unwrap()),
            _ => key.load64(&mut bytes.try_into().unwrap()),
        }
        key
    }

    type Member<'b> = Option<(Status, &'b [u8])>;
    /// A parent's bytes, a context, the members of a set and its primary.
    type Case<'b> = (&'b [u8], &'b [u8], [Member<'b>; MEMBERS], usize);

    /// Asserts that the set `handle` refers to holds `members` at their positions, each with its
    /// stage and the identifier derived from it, with `primary` as the primary, and nothing at an
    /// empty position.
    fn assert_holds(
        slots: &Slots<'_>,
        handle: Handle<'_>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
    ) {
        let slot = &slots.slots[handle.index];
        assert_eq!(slot.occupancy, Occupancy::Loaded);
        assert_eq!(
            (slot.stages.primary(), slot.purpose),
            (primary, Purpose::Wrap)
        );
        for (at, member) in members.into_iter().enumerate() {
            if let Some((stage, bytes)) = member {
                let expected = key_from(bytes);
                assert_eq!(slot.keys[at].bytes(), expected.bytes(), "position {at}");
                assert_eq!(slot.keys[at].length(), expected.length(), "position {at}");
                assert_eq!(slot.ids[at], id_of(&expected), "position {at}");
                assert_eq!(slot.stages.stage(at), Some(stage), "position {at}");
            } else {
                assert_eq!(slot.keys[at].bytes(), &padded(&[]), "position {at}");
                assert_eq!(slot.ids[at], KeyId::empty(), "position {at}");
                assert_eq!(slot.stages.stage(at), None, "position {at}");
            }
        }
    }

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

        slots.release(long_key).unwrap();
        let full = slots
            .unwrap(short_parent, b"archive", &hex(KNOWN_RECORDS[2]))
            .unwrap();
        slots
            .wrap(
                full,
                short_parent,
                b"archive",
                &mut Fixed(&NONCE),
                &mut record,
            )
            .unwrap();
        assert_eq!(record, hex(KNOWN_RECORDS[2]));
    }

    #[test]
    fn an_unwrapped_set_is_the_set_that_was_wrapped() {
        let short_parent = pattern::<32>(97, 13);
        let long_parent = pattern::<64>(97, 13);
        let long_key = pattern::<64>(59, 201);
        let short_key = pattern::<32>(59, 201);
        let middle = pattern::<32>(31, 7);
        let last = pattern::<64>(83, 111);
        let cases: [Case<'_>; 3] = [
            (
                &short_parent,
                b"chat 7",
                [Some((Status::Enabled, &long_key)), None, None],
                0,
            ),
            (
                &long_parent,
                b"profile",
                [Some((Status::Enabled, &short_key)), None, None],
                0,
            ),
            (
                &short_parent,
                b"archive",
                [
                    Some((Status::Disabled, &long_key)),
                    Some((Status::Enabled, &middle)),
                    Some((Status::Enabled, &last)),
                ],
                2,
            ),
        ];
        for ((parent_bytes, context, members, primary), known) in
            cases.into_iter().zip(KNOWN_RECORDS)
        {
            let mut memory = [const { Slot::empty() }; 2];
            let mut slots = Slots::new(&mut memory);
            let parent = match parent_bytes.len() {
                32 => slots.import32(Purpose::Wrap, &mut parent_bytes.try_into().unwrap()),
                _ => slots.import64(Purpose::Wrap, &mut parent_bytes.try_into().unwrap()),
            }
            .unwrap();
            let set = slots.unwrap(parent, context, &hex(known)).unwrap();
            assert_holds(&slots, set, members, primary);
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
            assert_eq!(slots.slots[1].keys[0].bytes(), &padded(&[]));
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

    /// `plaintext` sealed under the key derived from `sealer` for `context`, with `nonce`.
    fn seal_plaintext(
        sealer: &Key,
        plaintext: &[u8; PLAINTEXT_LEN],
        context: &[u8],
        nonce: &[u8; 12],
    ) -> [u8; RECORD_LEN] {
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        derive_wrap_key(sealer, Purpose::Wrap, &mut cipher_key).unwrap();
        let associated = AssociatedData::new(context).unwrap();
        let mut encrypted = *plaintext;
        let tag = seal::seal(&cipher_key, nonce, associated.bytes(), &mut encrypted).unwrap();
        let mut record = [0; RECORD_LEN];
        write_record(&mut record, nonce, &encrypted, &tag);
        record
    }

    /// The plaintext of the set `members` with `primary`, naming `named` as its parent, built
    /// without `wrap`.
    fn set_plaintext(
        members: [Member<'_>; MEMBERS],
        primary: usize,
        named: [u8; 16],
    ) -> [u8; PLAINTEXT_LEN] {
        let keys =
            members.map(|member| member.map_or_else(Key::empty, |(_, bytes)| key_from(bytes)));
        let stages = Stages::from_parts(
            members.map(|member| member.map(|(stage, _)| stage)),
            primary,
            0,
        );
        let header = Header {
            purpose: Purpose::Wrap,
            parent: named,
            epoch: 0,
        };
        let mut plaintext = [0; PLAINTEXT_LEN];
        keyset::build(
            &header,
            &stages,
            [&keys[0], &keys[1], &keys[2]],
            &mut plaintext,
        );
        plaintext
    }

    /// The record of the set `members` with `primary`, sealed under the key at `at` of the set
    /// `parent` refers to and naming that key, for `context`.
    fn sealed_under(
        slots: &Slots<'_>,
        parent: Handle<'_>,
        at: usize,
        members: [Member<'_>; MEMBERS],
        primary: usize,
        context: &[u8],
    ) -> [u8; RECORD_LEN] {
        let slot = &slots.slots[parent.index];
        let plaintext = set_plaintext(members, primary, slot.ids[at].bytes());
        seal_plaintext(&slot.keys[at], &plaintext, context, &NONCE)
    }

    /// Loads the set `members` with `primary` by unwrapping a record of it under `root`.
    fn loaded_set<'a>(
        slots: &mut Slots<'a>,
        root: Handle<'a>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
    ) -> Handle<'a> {
        let record = sealed_under(slots, root, 0, members, primary, b"set");
        slots.unwrap(root, b"set", &record).unwrap()
    }

    /// A record under any key of the parent set opens; under a disabled one it is refused as
    /// `KeyDisabled` and loads nothing; every key of the parent is tried each time, and only its
    /// keys.
    #[test]
    fn every_key_of_the_parent_is_tried() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut slots = Slots::new(&mut memory);
        let root = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let (first, second, third) = (
            pattern::<32>(5, 2),
            pattern::<64>(7, 3),
            pattern::<32>(11, 4),
        );
        let parent = loaded_set(
            &mut slots,
            root,
            [
                Some((Status::Disabled, &first)),
                Some((Status::Enabled, &second)),
                Some((Status::Enabled, &third)),
            ],
            2,
        );
        let child = pattern::<64>(13, 5);
        let only = [Some((Status::Enabled, &child[..])), None, None];
        for (at, expected) in [(0, Err(Error::KeyDisabled)), (1, Ok(())), (2, Ok(()))] {
            let record = sealed_under(&slots, parent, at, only, 0, b"chat 7");
            let mut tried = 0;
            let result = slots.unwrap_on_stack(
                parent,
                b"chat 7",
                &record,
                |key, nonce, aad, buffer, tag| {
                    tried += 1;
                    seal::open(key, nonce, aad, buffer, tag)
                },
            );
            assert_eq!(tried, 3, "position {at}");
            assert_eq!(result.map(|_| ()), expected, "position {at}");
            if let Ok(handle) = result {
                assert_holds(&slots, handle, only, 0);
                slots.release(handle).unwrap();
            }
            assert_eq!(slots.slots[2].occupancy, Occupancy::Free, "position {at}");
            assert_eq!(
                slots.slots[2].keys[0].bytes(),
                &padded(&[]),
                "position {at}"
            );
        }
        let record = sealed_under(&slots, root, 0, only, 0, b"chat 7");
        let mut tried = 0;
        let result =
            slots.unwrap_on_stack(root, b"chat 7", &record, |key, nonce, aad, buffer, tag| {
                tried += 1;
                seal::open(key, nonce, aad, buffer, tag)
            });
        assert_eq!((tried, result.is_ok()), (1, true));
    }

    /// A set is wrapped under the primary key of its parent wherever the primary sits: the record is
    /// the one computed independently under that key alone.
    #[test]
    fn a_set_is_wrapped_under_the_primary_of_its_parent() {
        let primary = pattern::<32>(97, 13);
        let (other, last) = (pattern::<64>(7, 3), pattern::<32>(11, 4));
        for at in 0..MEMBERS {
            let mut memory = [const { Slot::empty() }; 3];
            let mut slots = Slots::new(&mut memory);
            let root = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
            let mut others =
                [(Status::Disabled, &other[..]), (Status::Enabled, &last[..])].into_iter();
            let members: [Member<'_>; MEMBERS] = core::array::from_fn(|position| {
                if position == at {
                    Some((Status::Enabled, &primary[..]))
                } else {
                    others.next()
                }
            });
            let parent = loaded_set(&mut slots, root, members, at);
            let child = slots
                .import64(Purpose::Wrap, &mut pattern(59, 201))
                .unwrap();
            let mut record = [0; RECORD_LEN];
            slots
                .wrap(child, parent, b"chat 7", &mut Fixed(&NONCE), &mut record)
                .unwrap();
            assert_eq!(record, hex(KNOWN_RECORDS[0]), "primary at {at}");
        }
    }

    /// A key is held in one place only: an import of a key held here, and a set that holds such a
    /// key or one key twice, are refused, and leave the source and every slot as they were.
    #[test]
    fn a_key_is_held_in_one_place_only() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut slots = Slots::new(&mut memory);
        let held = pattern::<32>(97, 13);
        let mut source = held;
        let root = slots.import32(Purpose::Wrap, &mut source).unwrap();
        let mut again = held;
        assert_eq!(
            slots.import32(Purpose::Wrap, &mut again),
            Err(Error::DuplicateKey)
        );
        assert_eq!(again, held);
        let generated = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        assert_eq!(
            slots.generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting),
            Err(Error::DuplicateKey)
        );
        slots.release(generated).unwrap();
        let other = pattern::<64>(5, 6);
        for members in [
            [
                Some((Status::Enabled, &other[..])),
                Some((Status::Enabled, &held[..])),
                None,
            ],
            [
                Some((Status::Enabled, &other[..])),
                None,
                Some((Status::Disabled, &other[..])),
            ],
        ] {
            let record = sealed_under(&slots, root, 0, members, 0, b"chat 7");
            let before = holdings(&slots);
            assert_eq!(
                slots.unwrap(root, b"chat 7", &record),
                Err(Error::DuplicateKey)
            );
            assert_eq!(holdings(&slots), before);
        }
        let mut source = other;
        let long = slots.import64(Purpose::Wrap, &mut source).unwrap();
        slots.release(long).unwrap();
        let mut source = other;
        assert!(slots.import64(Purpose::Wrap, &mut source).is_ok());
    }

    #[test]
    fn a_set_cannot_wrap_itself() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut slots = Slots::new(&mut memory);
        let set = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let mut record = [0x55; RECORD_LEN];
        assert_eq!(
            slots.wrap(set, set, b"chat 7", &mut Counting, &mut record),
            Err(Error::SameKey)
        );
        assert_eq!(record, [0x55; RECORD_LEN]);
    }

    /// A set keeps the stage of each key and its primary through an unwrap and a wrap.
    #[test]
    fn a_set_comes_out_of_a_wrap_as_it_went_in() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let root = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let (first, third) = (pattern::<64>(5, 2), pattern::<32>(11, 4));
        let members = [
            Some((Status::Enabled, &first[..])),
            None,
            Some((Status::Disabled, &third[..])),
        ];
        let record = sealed_under(&slots, root, 0, members, 0, b"chat 7");
        let set = slots.unwrap(root, b"chat 7", &record).unwrap();
        assert_holds(&slots, set, members, 0);
        let mut out = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"chat 7", &mut Fixed(&NONCE), &mut out)
            .unwrap();
        assert_eq!(out, record);
    }

    #[test]
    fn a_record_that_names_another_parent_or_is_malformed_is_rejected() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let child = pattern::<32>(59, 201);
        let members = [Some((Status::Enabled, &child[..])), None, None];
        let parent_id = slots.slots[0].ids[0].bytes();
        let parent_key = key_from(&pattern::<32>(97, 13));
        let good = set_plaintext(members, 0, parent_id);
        let refused: Vec<[u8; PLAINTEXT_LEN]> = (0..16)
            .map(|at| {
                let mut foreign = parent_id;
                foreign[at] ^= 1;
                set_plaintext(members, 0, foreign)
            })
            .chain([{
                let mut version = good;
                version[0] = 2;
                version
            }])
            .collect();
        for plaintext in refused {
            let record = seal_plaintext(&parent_key, &plaintext, b"chat 7", &NONCE);
            assert_eq!(
                slots.unwrap(parent, b"chat 7", &record),
                Err(Error::RecordRejected)
            );
            assert_eq!(slots.slots[1].occupancy, Occupancy::Free);
        }
        let record = seal_plaintext(&parent_key, &good, b"chat 7", &NONCE);
        assert!(slots.unwrap(parent, b"chat 7", &record).is_ok());
    }

    #[test]
    fn a_failed_wrap_leaves_the_record_as_it_was() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut slots = Slots::new(&mut memory);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let key = slots
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
        let mut key = slots
            .import32(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        for context in [&[9][..], &[9; 255]] {
            let mut record = [0; RECORD_LEN];
            slots
                .wrap(key, parent, context, &mut Counting, &mut record)
                .unwrap();
            slots.release(key).unwrap();
            assert_eq!(
                slots.unwrap(parent, &[], &record),
                Err(Error::InvalidContext)
            );
            assert_eq!(
                slots.unwrap(parent, &[9; 256], &record),
                Err(Error::InvalidContext)
            );
            key = slots.unwrap(parent, context, &record).unwrap();
        }
    }

    #[test]
    fn unwrap_needs_a_live_parent_and_a_free_slot_before_it_decrypts() {
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

        fn key(&mut self) -> Vec<u8> {
            if self.below(2) == 0 {
                self.bytes::<32>().to_vec()
            } else {
                self.bytes::<64>().to_vec()
            }
        }
    }

    type Holding = (
        Occupancy,
        u64,
        [[u8; 64]; MEMBERS],
        [KeyLength; MEMBERS],
        [[u8; 16]; MEMBERS],
        Stages,
        Purpose,
    );

    fn holdings(slots: &Slots<'_>) -> Vec<Holding> {
        slots
            .slots
            .iter()
            .map(|slot| {
                (
                    slot.occupancy,
                    slot.generation,
                    core::array::from_fn(|at| *slot.keys[at].bytes()),
                    core::array::from_fn(|at| slot.keys[at].length()),
                    core::array::from_fn(|at| slot.ids[at].bytes()),
                    slot.stages,
                    slot.purpose,
                )
            })
            .collect()
    }

    /// The bytes of every key held in `slots`.
    fn held_keys(slots: &Slots<'_>) -> Vec<Vec<u8>> {
        slots
            .slots
            .iter()
            .filter(|slot| slot.occupancy == Occupancy::Loaded)
            .flat_map(|slot| {
                (0..MEMBERS).filter_map(|at| {
                    slot.stages
                        .stage(at)
                        .map(|_| slot.keys[at].bytes()[..slot.keys[at].length().bytes()].to_vec())
                })
            })
            .collect()
    }

    /// Random stages of three positions whose primary holds an enabled key.
    fn random_stages(random: &mut Random) -> ([Option<Status>; MEMBERS], usize) {
        let mut members: [Option<Status>; MEMBERS] =
            core::array::from_fn(|_| match random.below(3) {
                0 => None,
                1 => Some(Status::Enabled),
                _ => Some(Status::Disabled),
            });
        let primary = random.below(MEMBERS);
        members[primary] = Some(Status::Enabled);
        (members, primary)
    }

    /// The parent of a round: a key imported as a set of one, or a set of up to three keys loaded
    /// under such a key, among other sets and released slots.
    fn random_parent<'a>(slots: &mut Slots<'a>, random: &mut Random) -> Handle<'a> {
        let root = match random.key().len() {
            32 => slots.import32(Purpose::Wrap, &mut random.bytes()),
            _ => slots.import64(Purpose::Wrap, &mut random.bytes()),
        }
        .unwrap();
        let parent = if random.below(2) == 0 {
            root
        } else {
            let (stages, primary) = random_stages(random);
            let keys: Vec<Vec<u8>> = (0..MEMBERS).map(|_| random.key()).collect();
            let members: [Member<'_>; MEMBERS] =
                core::array::from_fn(|at| stages[at].map(|stage| (stage, &keys[at][..])));
            let parent = loaded_set(slots, root, members, primary);
            if random.below(2) == 0 {
                slots.release(root).unwrap();
            }
            parent
        };
        for _ in 0..random.below(3) {
            let filler = slots.import64(Purpose::Wrap, &mut random.bytes()).unwrap();
            if random.below(2) == 0 {
                slots.release(filler).unwrap();
            }
        }
        parent
    }

    /// The plaintext of a random set at a random revision naming `named`, at times with a key held
    /// in `held` or one key twice, left as built, wholly random or with one byte changed.
    fn random_plaintext(
        random: &mut Random,
        named: [u8; 16],
        held: &[Vec<u8>],
    ) -> [u8; PLAINTEXT_LEN] {
        let (stages, primary) = random_stages(random);
        let mut keys: Vec<Vec<u8>> = (0..MEMBERS).map(|_| random.key()).collect();
        match random.below(8) {
            0 if !held.is_empty() => {
                keys[random.below(MEMBERS)] = held[random.below(held.len())].clone();
            }
            1 => {
                let first = random.below(MEMBERS);
                let second = (first + 1 + random.below(MEMBERS - 1)) % MEMBERS;
                keys[second] = keys[first].clone();
            }
            _ => {}
        }
        let members: [Member<'_>; MEMBERS] =
            core::array::from_fn(|at| stages[at].map(|stage| (stage, &keys[at][..])));
        let mut plaintext = set_plaintext(members, primary, named);
        plaintext[27..35].copy_from_slice(&random.bytes::<8>());
        match random.below(4) {
            0 => plaintext = random.bytes(),
            1 => plaintext[random.below(PLAINTEXT_LEN)] ^= random.bytes::<1>()[0] | 1,
            _ => {}
        }
        plaintext
    }

    /// The keys of `plaintext` by position, if the layout accepts it: version 1, purpose 1, each
    /// position zero throughout or stage 1 or 2 with length 32 or 64 and zeros past the key, and
    /// an enabled key at the primary position. Read from the layout, not by the parser.
    fn accepted_keys(plaintext: &[u8; PLAINTEXT_LEN]) -> Option<[Option<Vec<u8>>; MEMBERS]> {
        let primary = usize::from(plaintext[2]);
        if plaintext[..2] != [1, 1] || primary >= MEMBERS || plaintext[35 + 66 * primary] != 1 {
            return None;
        }
        let mut keys: [Option<Vec<u8>>; MEMBERS] = Default::default();
        for (at, key) in keys.iter_mut().enumerate() {
            let position = &plaintext[35 + 66 * at..35 + 66 * (at + 1)];
            let length = usize::from(position[1]);
            match position[0] {
                0 if position.iter().all(|&byte| byte == 0) => {}
                1 | 2
                    if (length == 32 || length == 64)
                        && position[2 + length..].iter().all(|&byte| byte == 0) =>
                {
                    *key = Some(position[2..2 + length].to_vec());
                }
                _ => return None,
            }
        }
        Some(keys)
    }

    /// The slot that holds the set of an accepted `plaintext`, as the layout states it.
    fn loaded_from(plaintext: &[u8; PLAINTEXT_LEN], generation: u64) -> Holding {
        let mut holding: Holding = (
            Occupancy::Loaded,
            generation,
            [[0; 64]; MEMBERS],
            [KeyLength::Bytes32; MEMBERS],
            [[0; 16]; MEMBERS],
            Stages::one(),
            Purpose::Wrap,
        );
        let mut stages = [None; MEMBERS];
        for (at, slot_stage) in stages.iter_mut().enumerate() {
            let start = 35 + 66 * at;
            let stage = match plaintext[start] {
                0 => continue,
                1 => Status::Enabled,
                _ => Status::Disabled,
            };
            let length = usize::from(plaintext[start + 1]);
            let key = key_from(&plaintext[start + 2..start + 2 + length]);
            holding.2[at] = *key.bytes();
            holding.3[at] = key.length();
            holding.4[at] = id_of(&key).bytes();
            *slot_stage = Some(stage);
        }
        let revision = u64::from_le_bytes(plaintext[27..35].try_into().unwrap());
        holding.5 = Stages::from_parts(stages, usize::from(plaintext[2]), revision);
        holding
    }

    /// Records sealed through the real derivation and cipher under a key of a random parent set or
    /// under a key outside it, with random sets, keys held elsewhere, contexts of 0 to 300 bytes,
    /// and random changes to the plaintext, the record or the context: unwrapping never panics,
    /// refuses exactly what it should, with the error it should, loads the set the plaintext holds
    /// into the first free slot with that slot's generation when it accepts, and changes no other
    /// slot, or none when it refuses.
    fn unwrap_random_records(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        for round in 0..rounds {
            let mut memory = [const { Slot::empty() }; 4];
            let mut slots = Slots::new(&mut memory);
            let parent = random_parent(&mut slots, &mut random);
            let parent_slot = &slots.slots[parent.index];
            let positions: Vec<usize> = (0..MEMBERS)
                .filter(|&at| parent_slot.stages.stage(at).is_some())
                .collect();
            let sealer_at =
                (random.below(8) != 0).then(|| positions[random.below(positions.len())]);
            let outsider = key_from(&random.key());
            let sealer = key_from(match sealer_at {
                Some(at) => &parent_slot.keys[at].bytes()[..parent_slot.keys[at].length().bytes()],
                None => &outsider.bytes()[..outsider.length().bytes()],
            });
            let sealer_id = id_of(&sealer).bytes();
            let other_member = positions
                .iter()
                .find(|&&at| Some(at) != sealer_at)
                .map(|&at| parent_slot.ids[at].bytes());
            let named = match (random.below(8), other_member) {
                (0, _) => random.bytes(),
                (1, Some(other)) => other,
                _ => sealer_id,
            };
            let sealer_stage = sealer_at.and_then(|at| parent_slot.stages.stage(at));
            let held = held_keys(&slots);
            let plaintext = random_plaintext(&mut random, named, &held);
            let context: Vec<u8> = (0..random.below(301))
                .map(|_| random.bytes::<1>()[0])
                .collect();
            let valid_context = (1..=MAX_CONTEXT).contains(&context.len());
            let sealed_for = if valid_context {
                &context[..]
            } else {
                b"chat 7"
            };
            let mut record = seal_plaintext(&sealer, &plaintext, sealed_for, &random.bytes());
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

            let before = holdings(&slots);
            let first_free = before
                .iter()
                .position(|holding| holding.0 == Occupancy::Free);
            let opens =
                !changed && !other_context && sealer_at.is_some() && plaintext[3..19] == sealer_id;
            let parsed = accepted_keys(&plaintext)
                .map(|keys| keys.into_iter().flatten().collect::<Vec<Vec<u8>>>());
            let expected = if !valid_context {
                Err(Error::InvalidContext)
            } else if first_free.is_none() {
                Err(Error::NoFreeSlot)
            } else if !opens {
                Err(Error::RecordRejected)
            } else if sealer_stage == Some(Status::Disabled) {
                Err(Error::KeyDisabled)
            } else if let Some(keys) = parsed {
                let repeated = keys
                    .iter()
                    .enumerate()
                    .any(|(at, key)| held.contains(key) || keys[..at].contains(key));
                if repeated {
                    Err(Error::DuplicateKey)
                } else {
                    Ok(())
                }
            } else {
                Err(Error::RecordRejected)
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
    use super::{
        Entropy, EntropyError, Error, Handle, Header, MEMBERS, Purpose, RECORD_LEN, Slot, Slots,
        Stages, Status, keyset, write_record,
    };
    use crate::derive::{Branch, CIPHER_STACK_WIPE, derive_wrap_key, stack::secrets};
    use crate::key::{
        Key, KeyLength,
        tests::{Counting, Failing},
    };
    use crate::record::{AssociatedData, PLAINTEXT_LEN};
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::seal;

    const CONTEXT: &[u8] = b"chat 7";
    const SET_CONTEXT: &[u8] = b"set";
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

    /// `length` bytes whose values appear nowhere else, made from a `flip`ped pattern.
    fn pattern(times: u8, plus: u8, length: usize, flip: u8) -> Vec<u8> {
        (0..length)
            .map(|i| {
                u8::try_from(i)
                    .unwrap()
                    .wrapping_mul(times)
                    .wrapping_add(plus)
                    ^ flip
            })
            .collect()
    }

    /// The keys of the root, which wraps both sets.
    fn root_bytes(flip: u8) -> [u8; 32] {
        pattern(53, 3, 32, flip).try_into().unwrap()
    }

    /// The keys of the parent set: 32, 64 and 32 bytes.
    fn parent_keys(flip: u8) -> [Vec<u8>; MEMBERS] {
        [
            pattern(41, 7, 32, flip),
            pattern(43, 9, 64, flip),
            pattern(47, 11, 32, flip),
        ]
    }

    /// The keys of the child set: 64, 32 and 64 bytes.
    fn child_keys(flip: u8) -> [Vec<u8>; MEMBERS] {
        [
            pattern(29, 101, 64, flip),
            pattern(31, 103, 32, flip),
            pattern(37, 107, 64, flip),
        ]
    }

    fn key_from(bytes: &[u8]) -> Key {
        let mut key = Key::empty();
        match bytes.len() {
            32 => key.load32(&mut bytes.try_into().unwrap()),
            _ => key.load64(&mut bytes.try_into().unwrap()),
        }
        key
    }

    fn widen(handle: Handle<'_>) -> Handle<'static> {
        Handle {
            slots: handle.slots,
            index: handle.index,
            generation: handle.generation,
            memory: core::marker::PhantomData,
        }
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
    /// set, the first word counting up, RFC 8452, section 4; as long as a record's plaintext.
    fn keystream(enc_key: &[u8; 32], tag: &[u8; 16]) -> Vec<u8> {
        let mut block = *tag;
        block[15] |= 0x80;
        let first = u32::from_le_bytes(block[..4].try_into().unwrap());
        let blocks = u32::try_from(PLAINTEXT_LEN.div_ceil(16)).unwrap();
        (0..blocks)
            .flat_map(|step| {
                block[..4].copy_from_slice(&first.wrapping_add(step).to_le_bytes());
                encrypt(enc_key, block)
            })
            .collect()
    }

    /// Loads, under the set of one `root` refers to, the set of `keys` with `stages` and
    /// `primary`, by unwrapping a record of it.
    fn loaded_set(
        slots: &mut Slots<'_>,
        root: Handle<'static>,
        keys: &[Vec<u8>; MEMBERS],
        stages: [Option<Status>; MEMBERS],
        primary: usize,
    ) -> Handle<'static> {
        let keys = keys.each_ref().map(|bytes| key_from(bytes));
        let header = Header {
            purpose: Purpose::Wrap,
            parent: slots.slots[root.index].ids[0].bytes(),
            epoch: 0,
        };
        let mut plaintext = [0; PLAINTEXT_LEN];
        keyset::build(
            &header,
            &Stages::from_parts(stages, primary, 0),
            [&keys[0], &keys[1], &keys[2]],
            &mut plaintext,
        );
        let mut cipher_key = [0; 32];
        derive_wrap_key(
            &slots.slots[root.index].keys[0],
            Purpose::Wrap,
            &mut cipher_key,
        )
        .unwrap();
        let associated = AssociatedData::new(SET_CONTEXT).unwrap();
        let tag = seal::seal(&cipher_key, &NONCE, associated.bytes(), &mut plaintext).unwrap();
        let mut record = [0; RECORD_LEN];
        write_record(&mut record, &NONCE, &plaintext, &tag);
        widen(slots.unwrap(root, SET_CONTEXT, &record).unwrap())
    }

    /// A root, the parent set, whose second key is the primary and whose third is disabled, and
    /// the child set, whose first key is disabled and whose third is the primary, all made from
    /// `flip`ped patterns.
    fn sets(slots: &mut Slots<'_>, flip: u8) -> (Handle<'static>, Handle<'static>) {
        let root = widen(
            slots
                .import32(Purpose::Wrap, &mut root_bytes(flip))
                .unwrap(),
        );
        let (enabled, disabled) = (Some(Status::Enabled), Some(Status::Disabled));
        let parent = loaded_set(
            slots,
            root,
            &parent_keys(flip),
            [enabled, enabled, disabled],
            1,
        );
        let child = loaded_set(
            slots,
            root,
            &child_keys(flip),
            [disabled, enabled, enabled],
            2,
        );
        (parent, child)
    }

    /// What is measured: a wrap, the trials of an unwrap whose record no key opens, or a whole
    /// unwrap.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Work {
        Wrap,
        Trials,
        Unwrap,
    }

    /// The secrets the work handles on the sets made from `flip`ped patterns. For each key of the
    /// parent it tries, or for the primary alone when it wraps: the derivation of the cipher key,
    /// the cipher key, the message keys, the round keys of the cipher key and of the message
    /// encryption key in the layout of FIPS 197, the keystream, and what the record decrypts to
    /// under that key, the plaintext itself under the primary. For a whole unwrap, also the
    /// derivations of the identifiers of the child's keys.
    fn handled(flip: u8, work: Work) -> Vec<Vec<u8>> {
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let (parent, child) = sets(&mut slots, flip);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(child, parent, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        let tag: [u8; 16] = record[NONCE.len() + PLAINTEXT_LEN..].try_into().unwrap();
        let ciphertext = &record[NONCE.len()..NONCE.len() + PLAINTEXT_LEN];
        let parent_keys = parent_keys(flip);
        let tried = if work == Work::Wrap { 1..2 } else { 0..MEMBERS };
        let mut handled = Vec::new();
        for bytes in &parent_keys[tried] {
            let key = key_from(bytes);
            let mut cipher_key = [0; 32];
            derive_wrap_key(&key, Purpose::Wrap, &mut cipher_key).unwrap();
            let (mac_key, enc_key) = message_keys(&cipher_key, &NONCE);
            let stream = keystream(&enc_key, &tag);
            let decrypted = ciphertext.iter().zip(&stream).map(|(c, k)| c ^ k).collect();
            handled.extend(secrets(bytes, key.length(), Branch::WrapKey));
            handled.extend([
                cipher_key.to_vec(),
                mac_key.to_vec(),
                enc_key.to_vec(),
                stream,
                decrypted,
            ]);
            handled.extend(round_keys(&cipher_key));
            handled.extend(round_keys(&enc_key));
        }
        handled.extend(parent_keys.iter().cloned());
        if work == Work::Unwrap {
            for bytes in child_keys(flip) {
                handled.extend(secrets(&bytes, key_from(&bytes).length(), Branch::KeyId));
            }
        }
        handled
    }

    fn pieces(work: Work) -> Vec<Vec<u8>> {
        key_dependent(&handled(0, work), &handled(0xff, work))
    }

    #[test]
    fn a_wrap_without_the_wipe_leaves_residue() {
        let pieces = pieces(Work::Wrap);
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let (parent, child) = sets(&mut slots, 0);
        let mut record = [0; RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .wrap_on_stack(child, parent, CONTEXT, &mut Fixed, &mut record)
                .unwrap();
            black_box(&record);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn a_wrap_leaves_no_residue() {
        let pieces = pieces(Work::Wrap);
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let (parent, child) = sets(&mut slots, 0);
        let mut record = [0; RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .wrap(child, parent, CONTEXT, &mut Fixed, &mut record)
                .unwrap();
            black_box(&record);
        });
    }

    /// The parent set, a free slot, and the record of the child set under the parent.
    fn wrapped(slots: &mut Slots<'_>) -> (Handle<'static>, [u8; RECORD_LEN]) {
        let (parent, child) = sets(slots, 0);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(child, parent, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        slots.release(child).unwrap();
        (parent, record)
    }

    #[test]
    fn an_unwrap_leaves_no_residue() {
        let pieces = pieces(Work::Unwrap);
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let (parent, record) = wrapped(&mut slots);
        assert_clean(&pieces, || {
            black_box(slots.unwrap(parent, CONTEXT, &record).unwrap());
        });
    }

    /// A record whose ciphertext was changed is decrypted under every key of the parent before
    /// each tag fails. This is also the unwrap that shows the test sees residue: after a successful
    /// one, the wipes that follow the derivations of the new keys' identifiers already cover the
    /// frames the cipher used.
    #[test]
    fn a_rejected_unwrap_leaves_no_residue() {
        let pieces = pieces(Work::Trials);
        let mut memory = [const { Slot::empty() }; 4];
        let mut slots = Slots::new(&mut memory);
        let (parent, mut record) = wrapped(&mut slots);
        record[40] ^= 1;
        let range = below_pad(false, || {
            let refused = slots.unwrap_on_stack(parent, CONTEXT, &record, seal::open);
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
        let mut memory = [const { Slot::empty() }; 8];
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
        let key = slots
            .import64(Purpose::Wrap, &mut pattern(5, 5, 64, 0).try_into().unwrap())
            .unwrap();
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
        let mut short: [u8; 32] = pattern(7, 7, 32, 0).try_into().unwrap();
        let loads = [
            depth_changed(|| {
                black_box(slots.import32(Purpose::Wrap, &mut short).unwrap());
            }),
            depth_changed(|| {
                let mut long: [u8; 64] = pattern(9, 9, 64, 0).try_into().unwrap();
                black_box(slots.import64(Purpose::Wrap, &mut long).unwrap());
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
        CIPHER_KEY_LEN, Entropy, EntropyError, Error, Handle, Key, KeyId, KeyLength, MEMBERS,
        Occupancy, PLAINTEXT_LEN, Purpose, RECORD_LEN, Rejected, Slot, Slots, Stages, Status,
    };
    use crate::derive::{
        model::{any_failed, failed, id_bytes, id_from_bytes},
        proofs::{expected_key_id, expected_wrap_key},
    };
    use crate::keyset::proofs::any_whole_stages;
    use crate::record::ID_LEN;

    type Bytes = [u8; 64];
    type Id = [u8; ID_LEN];
    /// One of each position. Keys and identifiers are kept apart rather than in one array: an array
    /// of them is compared in one piece, which needs a deeper unwinding than any key.
    type Three<T> = (T, T, T);

    /// Everything a slot holds. A structure read by field, not a tuple taken apart: Kani 0.68.0
    /// reports spurious failures on values taken from a large tuple by a pattern.
    #[derive(Clone, Copy, PartialEq)]
    struct Snapshot {
        occupancy: Occupancy,
        generation: u64,
        lengths: [KeyLength; MEMBERS],
        keys: Three<Bytes>,
        ids: Three<Id>,
        stages: Stages,
        purpose: Purpose,
    }

    fn snapshot(slot: &Slot) -> Snapshot {
        let [first, second, third] = &slot.keys;
        let [first_id, second_id, third_id] = &slot.ids;
        Snapshot {
            occupancy: slot.occupancy,
            generation: slot.generation,
            lengths: [first.length(), second.length(), third.length()],
            keys: (*first.bytes(), *second.bytes(), *third.bytes()),
            ids: (
                *id_bytes(first_id),
                *id_bytes(second_id),
                *id_bytes(third_id),
            ),
            stages: slot.stages,
            purpose: slot.purpose,
        }
    }

    // Kani 0.68.0 reports spurious failures when a key buffer is read through a symbolic index, so
    // the reads below take every element and then pick one, with no check left behind a branch.

    fn slot_at<'s>(slots: &'s Slots<'_>, index: usize) -> &'s Slot {
        let (first, second) = (&slots.slots[0], &slots.slots[1]);
        if index == 0 { first } else { second }
    }

    fn snapshot_at(before: &[Snapshot; 2], index: usize) -> Snapshot {
        let [first, second] = *before;
        if index == 0 { first } else { second }
    }

    fn at<T: Copy>(items: &[T; MEMBERS], position: usize) -> T {
        let [first, second, third] = *items;
        match position {
            0 => first,
            1 => second,
            _ => third,
        }
    }

    fn pick<T: Copy>(items: &Three<T>, position: usize) -> T {
        match position {
            0 => items.0,
            1 => items.1,
            _ => items.2,
        }
    }

    /// Whether two buffers hold the same bytes, compared in pieces no longer than a key.
    fn same<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
        a.chunks(64).zip(b.chunks(64)).all(|(x, y)| x == y)
    }

    fn snapshots(slots: &Slots<'_>) -> [Snapshot; 2] {
        [snapshot(&slots.slots[0]), snapshot(&slots.slots[1])]
    }

    /// Every slot but `changed` matches its snapshot.
    fn unchanged_except(slots: &Slots<'_>, before: &[Snapshot; 2], changed: usize) -> bool {
        (0..2).all(|index| index == changed || snapshot(&slots.slots[index]) == before[index])
    }

    /// Whether the slot holds no key and no identifier at any position.
    fn wiped(slot: &Slot) -> bool {
        let now = snapshot(slot);
        now.lengths == [KeyLength::Bytes32; MEMBERS]
            && now.keys == ([0; 64], [0; 64], [0; 64])
            && now.ids == ([0; ID_LEN], [0; ID_LEN], [0; ID_LEN])
    }

    fn first_free(before: &[Snapshot; 2]) -> Option<usize> {
        before
            .iter()
            .position(|snapshot| snapshot.occupancy == Occupancy::Free)
    }

    fn any_length() -> KeyLength {
        if kani::any() {
            KeyLength::Bytes32
        } else {
            KeyLength::Bytes64
        }
    }

    fn any_key(key: &mut Key) {
        key.fill_any();
    }

    /// The first `length` bytes of `bytes`, followed by zeros.
    fn padded(bytes: Bytes, length: KeyLength) -> Bytes {
        let mut out = bytes;
        if length == KeyLength::Bytes32 {
            out[32..].copy_from_slice(&[0; 32]);
        }
        out
    }

    /// A slot in any state, with any generation and any stages whose primary is enabled, holding a
    /// key of either length and any identifier at each position the stages fill, only when loaded.
    fn any_slot() -> Slot {
        any_slot_in(match kani::any::<u8>() % 3 {
            0 => Occupancy::Free,
            1 => Occupancy::Loaded,
            _ => Occupancy::Retired,
        })
    }

    fn any_slot_in(occupancy: Occupancy) -> Slot {
        let mut slot = Slot::empty();
        slot.generation = kani::any();
        slot.occupancy = occupancy;
        slot.stages = any_whole_stages();
        if slot.occupancy == Occupancy::Loaded {
            let stages = slot.stages;
            let fill = |position: usize, key: &mut Key, id: &mut KeyId| {
                if stages.stage(position).is_some() {
                    any_key(key);
                    *id = id_from_bytes(kani::any());
                }
            };
            let [first, second, third] = &mut slot.keys;
            let [first_id, second_id, third_id] = &mut slot.ids;
            fill(0, first, first_id);
            fill(1, second, second_id);
            fill(2, third, third_id);
        }
        slot
    }

    // Three cases by the state of the first slot cover every state; the slot written has a constant
    // state on every path, since a write to a slot chosen at run time costs both.

    /// `check` with the first slot free, the slot written, and the second in any state.
    fn into_the_first<T>(check: impl Fn([Slot; 2]) -> T) -> T {
        check([any_slot_in(Occupancy::Free), any_slot()])
    }

    /// `check` with the first slot in `first`, and the second free, loaded or retired.
    fn past_a<T>(first: Occupancy, check: impl Fn([Slot; 2]) -> T) -> T {
        match kani::any::<u8>() % 3 {
            0 => check([any_slot_in(first), any_slot_in(Occupancy::Free)]),
            1 => check([any_slot_in(first), any_slot_in(Occupancy::Loaded)]),
            _ => check([any_slot_in(first), any_slot_in(Occupancy::Retired)]),
        }
    }

    /// Whether a loaded slot of `before` holds a key with the identifier `id`.
    fn held(before: &[Snapshot; 2], id: &Id) -> bool {
        before.iter().any(|snapshot| {
            snapshot.occupancy == Occupancy::Loaded
                && (0..MEMBERS).any(|position| {
                    snapshot.stages.stage(position).is_some()
                        && pick(&snapshot.ids, position) == *id
                })
        })
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

    impl AnyEntropy {
        fn new() -> Self {
            Self {
                written: [0; 64],
                calls: 0,
                requested: 0,
                at: 0,
                failed: false,
            }
        }
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

    fn widen(handle: Handle<'_>) -> Handle<'static> {
        Handle {
            slots: handle.slots,
            index: handle.index,
            generation: handle.generation,
            memory: PhantomData,
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
        (result.map(widen), expected, length)
    }

    /// Loads one key by any of the three ways, with any key and length. Returns the outcome, the
    /// bytes and length the slot must hold on success, and whether a platform source was asked and
    /// failed.
    fn load_any(slots: &mut Slots<'_>) -> (Result<Handle<'static>, Error>, Bytes, KeyLength, bool) {
        if kani::any() {
            let (result, expected, length) = import_any(slots);
            return (result, expected, length, false);
        }
        let mut entropy = AnyEntropy::new();
        let length = any_length();
        let result = slots.generate(Purpose::Wrap, length, &mut entropy);
        let full = result == Err(Error::NoFreeSlot);
        kani::assert(
            if full {
                entropy.calls == 0
            } else {
                entropy.calls == 1 && entropy.requested == length.bytes()
            },
            "a full set asks the source for nothing, and otherwise once, for the length of the key",
        );
        kani::assert(
            full || (result == Err(Error::EntropyFailed)) == entropy.failed,
            "a generation fails with EntropyFailed exactly when the source fails",
        );
        if let Ok(handle) = result {
            let buffer = slot_at(slots, handle.index).keys[0].bytes().as_ptr().addr();
            kani::assert(
                entropy.at == buffer,
                "the source writes straight into the buffer of the slot",
            );
        }
        kani::cover!(
            result == Err(Error::EntropyFailed),
            "the platform source fails"
        );
        kani::cover!(
            result.is_ok() && length == KeyLength::Bytes32,
            "a short key is generated"
        );
        kani::cover!(
            result.is_ok() && length == KeyLength::Bytes64,
            "a long key is generated"
        );
        (
            result.map(widen),
            padded(entropy.written, length),
            length,
            entropy.failed,
        )
    }

    /// Whether `handle`, issued for a set whose key at `position` is `expected` of `length`,
    /// either still reaches exactly that key in a slot loaded with its generation, or can never be
    /// live again: its slot is retired or has moved past its generation, which no call ever moves
    /// back.
    fn own_key_or_never_again(
        slots: &Slots<'_>,
        handle: &Handle<'_>,
        position: usize,
        expected: &Bytes,
        length: KeyLength,
    ) -> bool {
        // Read field by field: a whole snapshot of a slot chosen at run time costs a copy of both.
        let slot = slot_at(slots, handle.index);
        let [first, second, third] = &slot.keys;
        let key = match position {
            0 => first,
            1 => second,
            _ => third,
        };
        (slot.occupancy == Occupancy::Loaded
            && slot.generation == handle.generation
            && at(
                &[
                    slot.stages.stage(0),
                    slot.stages.stage(1),
                    slot.stages.stage(2),
                ],
                position,
            )
            .is_some()
            && key.bytes() == expected
            && key.length() == length)
            || slot.occupancy == Occupancy::Retired
            || slot.generation > handle.generation
    }

    fn forged(id: usize) -> Handle<'static> {
        Handle {
            slots: id,
            index: kani::any(),
            generation: kani::any(),
            memory: PhantomData,
        }
    }

    /// A handle of this set naming either slot with any generation, and any position whose key the
    /// handle reaches exactly or that can never be live again.
    struct Tracked {
        handle: Handle<'static>,
        position: usize,
        expected: Bytes,
        length: KeyLength,
        live: bool,
    }

    fn live(slots: &Slots<'_>, id: usize, handle: &Handle<'_>) -> bool {
        handle.slots == id && handle.index < 2 && {
            let slot = slot_at(slots, handle.index);
            slot.occupancy == Occupancy::Loaded && slot.generation == handle.generation
        }
    }

    fn track(slots: &Slots<'_>, id: usize) -> Tracked {
        let handle = Handle {
            slots: id,
            index: if kani::any() { 0 } else { 1 },
            generation: kani::any(),
            memory: PhantomData,
        };
        let position: usize = kani::any();
        kani::assume(position < MEMBERS);
        let expected: Bytes = kani::any();
        let length = any_length();
        kani::assume(own_key_or_never_again(
            slots, &handle, position, &expected, length,
        ));
        let live = live(slots, id, &handle);
        Tracked {
            handle,
            position,
            expected,
            length,
            live,
        }
    }

    /// After one step: the tracked handle still reaches exactly its own key or can never be live
    /// again, and a live one stays live unless it was released.
    fn kept(slots: &Slots<'_>, id: usize, tracked: &Tracked, released: bool) {
        kani::assert(
            own_key_or_never_again(
                slots,
                &tracked.handle,
                tracked.position,
                &tracked.expected,
                tracked.length,
            ),
            "a handle reaches exactly its own key or can never be live again",
        );
        kani::assert(
            !tracked.live || released || live(slots, id, &tracked.handle),
            "a live handle stays live until it is released",
        );
        kani::cover!(
            tracked.live && tracked.position == 2,
            "a live handle reaches the key at the last position"
        );
    }

    /// The step of an import, from `memory`: for any handle of this set and any position whose key
    /// the handle reaches exactly or that can never be live again, the import keeps it so, and a
    /// live handle stays live; a handle the import issues is a live handle of this set that
    /// reaches exactly its own key. Returns whether the import succeeded and whether the handle
    /// was live.
    fn import_step(mut memory: [Slot; 2]) -> (bool, bool) {
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let tracked = track(&slots, id);
        let (result, issued, issued_length) = import_any(&mut slots);
        kani::assert(
            match result {
                Ok(handle) => {
                    live(&slots, id, &handle)
                        && own_key_or_never_again(&slots, &handle, 0, &issued, issued_length)
                }
                Err(_) => true,
            },
            "a new handle reaches exactly its own key",
        );
        kept(&slots, id, &tracked, false);
        (result.is_ok(), tracked.live)
    }

    /// The step of an import with the first slot free; with the next two and
    /// `a_step_by_a_release`, one step of any sequence of imports and releases from any state of
    /// two slots. By induction over the steps, from the moment a handle is issued it reaches
    /// exactly its own keys until it is released, and after that every call refuses it, also while
    /// its slot holds a new set.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_step_by_an_import_into_the_first_slot() {
        let (imported, live) = into_the_first(import_step);
        kani::cover!(
            imported && !live,
            "a key is imported beside a released handle"
        );
        kani::cover!(imported && live, "a key is imported beside a live handle");
    }

    /// The step of an import with the first slot loaded.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_step_by_an_import_past_a_loaded_slot() {
        let (imported, live) = past_a(Occupancy::Loaded, import_step);
        kani::cover!(
            imported && !live,
            "a key is imported beside a released handle"
        );
        kani::cover!(imported && live, "a key is imported beside a live handle");
    }

    /// The step of an import with the first slot retired, where no handle is live beside a free
    /// slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_step_by_an_import_past_a_retired_slot() {
        let (imported, _) = past_a(Occupancy::Retired, import_step);
        kani::cover!(imported, "a key is imported beside a released handle");
    }

    /// The step of a release, from any state of two slots: for any handle of this set and any
    /// position whose key the handle reaches exactly or that can never be live again, the release
    /// keeps it so, and a live handle stays live unless it is the one released; a release of a live
    /// handle wipes every key and identifier of its set at once, and any other is refused.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_step_by_a_release() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let tracked = track(&slots, id);
        let target = if kani::any() {
            tracked.handle
        } else {
            forged(id)
        };
        let target_live = live(&slots, id, &target);
        let result = slots.release(target);
        let released = target_live && tracked.live && target.index == tracked.handle.index;
        kani::assert(
            if target_live {
                result == Ok(()) && wiped(slot_at(&slots, target.index))
            } else {
                result == Err(Error::StaleHandle)
            },
            "a live handle releases its set, whose keys and identifiers are zero at once, and any \
             other is refused",
        );
        kani::cover!(released, "the tracked set is released");
        kani::cover!(
            !tracked.live
                && !target_live
                && target.index == tracked.handle.index
                && target.generation == tracked.handle.generation
                && slot_at(&slots, tracked.handle.index).occupancy == Occupancy::Loaded,
            "a released handle is refused while its slot holds a new set"
        );
        kept(&slots, id, &tracked, released);
    }

    /// From any state of two slots, a handle whose set number is not this set's is refused,
    /// whatever slot and generation it names, and no slot changes.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_handle_from_other_slots_is_refused() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let before = snapshots(&slots);

        let foreign = Handle {
            slots: kani::any(),
            index: kani::any(),
            generation: kani::any(),
            memory: PhantomData,
        };
        kani::assume(foreign.slots != id);
        kani::cover!(
            foreign.index < 2 && {
                let named = snapshot_at(&before, foreign.index);
                named.occupancy == Occupancy::Loaded && named.generation == foreign.generation
            },
            "the foreign handle names a loaded slot and its generation"
        );

        kani::assert(
            slots.release(foreign) == Err(Error::StaleHandle),
            "a handle from other slots is refused",
        );
        kani::assert(unchanged_except(&slots, &before, 2), "no slot changes");
    }

    /// A slot in any state and with any generation whose buffers hold keys of any bytes and either
    /// length and any identifiers at every position, loaded or not.
    fn any_dirty_slot() -> Slot {
        let mut slot = Slot::empty();
        slot.generation = kani::any();
        slot.occupancy = match kani::any::<u8>() % 3 {
            0 => Occupancy::Free,
            1 => Occupancy::Loaded,
            _ => Occupancy::Retired,
        };
        let [first, second, third] = &mut slot.keys;
        any_key(first);
        any_key(second);
        any_key(third);
        slot.ids = [
            id_from_bytes(kani::any()),
            id_from_bytes(kani::any()),
            id_from_bytes(kani::any()),
        ];
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
                && slot.keys[2].length() == KeyLength::Bytes64),
            "both slots hold a long key in the last position before"
        );
        kani::cover!(
            memory.iter().any(|slot| {
                slot.occupancy == Occupancy::Free
                    && slot.keys[1].bytes().iter().any(|&byte| byte != 0)
            }),
            "a free slot holds bytes before"
        );
        let slots = Slots::new(&mut memory);
        for slot in slots.slots.iter() {
            kani::assert(
                slot.occupancy != Occupancy::Loaded,
                "creating slots loads no slot",
            );
            kani::assert(wiped(slot), "creating slots wipes every key and identifier");
        }
    }

    /// A load by import or from the platform source, from `memory`: it takes the first free slot,
    /// issues that slot's generation, keeps it in the slot and leaves a set of one there: exactly
    /// the expected bytes at the first position, zero past the key's length, enabled and the
    /// primary, with the purpose given and the identifier derived from those bytes, and nothing at
    /// the other positions; it fails with `NoFreeSlot` without a free slot, with `EntropyFailed`
    /// when the source fails, with `DerivationFailed` when the derivation fails, and with
    /// `DuplicateKey` exactly when a loaded slot holds a key with that identifier; a failed load
    /// changes no slot, and a full set asks the source for nothing; no load panics or overflows.
    fn load_from(mut memory: [Slot; 2]) -> Result<Handle<'static>, Error> {
        let mut slots = Slots { slots: &mut memory };
        let before = snapshots(&slots);
        let first_free = first_free(&before);
        let (result, expected, length, source_failed) = load_any(&mut slots);
        let id = expected_key_id(&expected, length, Purpose::Wrap);
        kani::assert(
            if first_free.is_none() {
                result == Err(Error::NoFreeSlot)
            } else if source_failed {
                result == Err(Error::EntropyFailed)
            } else if failed() {
                result == Err(Error::DerivationFailed)
            } else if held(&before, &id) {
                result == Err(Error::DuplicateKey)
            } else {
                result.is_ok()
            },
            "a load fails with NoFreeSlot without a free slot, with EntropyFailed when the source \
             fails, with DerivationFailed when the derivation fails, with DuplicateKey when the key \
             is held, and otherwise succeeds",
        );
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "a load fails to derive the identifier"
        );
        if let (Ok(handle), Some(index)) = (result, first_free) {
            let generation = snapshot_at(&before, index).generation;
            kani::assert(
                handle.index == index && handle.generation == generation,
                "a load takes the first free slot and issues its generation",
            );
            let now = snapshot(slot_at(&slots, index));
            kani::assert(
                now.occupancy == Occupancy::Loaded && now.generation == generation,
                "the slot is loaded and keeps its generation",
            );
            kani::assert(
                now.keys == (expected, [0; 64], [0; 64]) && now.lengths[0] == length,
                "the slot holds exactly the key at the first position, zero past its length, and \
                 nothing elsewhere",
            );
            kani::assert(
                now.ids == (id, [0; ID_LEN], [0; ID_LEN])
                    && now.stages == Stages::one()
                    && now.purpose == Purpose::Wrap,
                "the slot keeps the purpose, a set of one and the identifier derived from its key",
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
        }
        result
    }

    /// A load with the first slot free; with the next two, any state of two slots.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_load_into_the_first_slot() {
        let result = into_the_first(load_from);
        kani::cover!(
            result == Err(Error::DuplicateKey),
            "a load finds its key held"
        );
    }

    /// A load with the first slot loaded.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_load_past_a_loaded_slot() {
        let result = past_a(Occupancy::Loaded, load_from);
        kani::cover!(
            result == Err(Error::DuplicateKey),
            "a load finds its key held"
        );
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// A load with the first slot retired, where no key is held beside a free slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_load_past_a_retired_slot() {
        let result = past_a(Occupancy::Retired, load_from);
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// From any state of two slots and any generation, which includes every state a load leaves: a
    /// handle of this set naming any slot and generation releases a set only if that slot is
    /// loaded with that generation, and otherwise is refused and changes nothing; a release wipes
    /// every key and identifier of the set and advances the generation by one, or retires the slot
    /// when the generation runs out; no release panics or overflows.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_handle_releases_only_a_matching_loaded_slot() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };

        let handle = forged(id);
        let before = snapshots(&slots);
        kani::cover!(
            before
                .iter()
                .all(|snapshot| snapshot.occupancy == Occupancy::Loaded),
            "both slots hold a set when the handle arrives"
        );
        kani::cover!(
            before[0].occupancy == Occupancy::Free,
            "the first slot is free when the handle arrives"
        );
        let target = Some(handle.index)
            .filter(|&index| index < 2)
            .map(|index| snapshot_at(&before, index))
            .filter(|named| {
                named.occupancy == Occupancy::Loaded && named.generation == handle.generation
            });
        let result = slots.release(handle);
        if let Some(named) = target {
            kani::assert(result == Ok(()), "a matching handle releases its set");
            let slot = slot_at(&slots, handle.index);
            kani::assert(
                wiped(slot),
                "a release wipes every key and identifier of the set",
            );
            if named.generation == u64::MAX {
                kani::assert(
                    slot.occupancy == Occupancy::Retired,
                    "a slot whose generation runs out is retired",
                );
                kani::cover!(true, "a slot is retired when its generation runs out");
            } else {
                kani::assert(
                    slot.occupancy == Occupancy::Free
                        && Some(slot.generation) == named.generation.checked_add(1),
                    "a release frees the slot and advances the generation by one",
                );
                kani::cover!(true, "a release advances the generation by one");
            }
            kani::assert(
                unchanged_except(&slots, &before, handle.index),
                "a release changes no other slot",
            );
        } else {
            kani::assert(
                result == Err(Error::StaleHandle),
                "any other handle is refused",
            );
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a refused handle changes no slot",
            );
            kani::cover!(
                before
                    .iter()
                    .any(|snapshot| snapshot.occupancy == Occupancy::Loaded),
                "a handle is refused while a set is loaded"
            );
        }
    }

    /// The key at `position` of a set's plaintext, as long as its length byte says, followed by
    /// zeros, and its length; read from the layout, not by the parser.
    fn plaintext_key(plaintext: &[u8; PLAINTEXT_LEN], position: usize) -> (Bytes, KeyLength) {
        let start = 35 + 66 * position;
        let length = if plaintext[start + 1] == 32 {
            KeyLength::Bytes32
        } else {
            KeyLength::Bytes64
        };
        let key: Bytes = plaintext[start + 2..start + 66].try_into().unwrap();
        (padded(key, length), length)
    }

    /// Admitting any 233 bytes of plaintext into `memory`: the set it holds goes into the first
    /// free slot exactly when a slot is free, the bytes parse, each key's identifier is derived,
    /// and no key is held in a loaded slot or twice in the set; then the slot holds, at each
    /// position the plaintext fills, exactly the key it holds there with the stage it states and the
    /// identifier derived from it, nothing at the others, and the primary and revision the
    /// plaintext states. Otherwise no slot changes, and the failure is `NoFreeSlot`,
    /// `RecordRejected`, `DerivationFailed` or `DuplicateKey`, in that order. The offsets are written
    /// from the layout, independently of the parser.
    fn admit_from(mut memory: [Slot; 2]) {
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let plaintext: [u8; PLAINTEXT_LEN] = kani::any();
        let before = snapshots(&slots);
        let first_free = first_free(&before);
        let result = slots.admit(&plaintext);
        kani::assert(
            first_free.is_some()
                || (result == Err(Error::NoFreeSlot) && unchanged_except(&slots, &before, 2)),
            "with no slot free a plaintext is refused as NoFreeSlot and changes no slot",
        );
        // Worked out only when a slot is free, so that the states with none cost the solver
        // nothing.
        let Some(index) = first_free else {
            return;
        };
        let parsed = crate::keyset::parse(&plaintext).map(|(_, stages, _)| stages);
        let members = [0, 1, 2].map(|position| plaintext_key(&plaintext, position));
        let ids = members.map(|(key, length)| expected_key_id(&key, length, Purpose::Wrap));
        let filled = [0, 1, 2].map(|position| plaintext[35 + 66 * position] != 0);
        let repeated = (0..MEMBERS).any(|position| {
            at(&filled, position)
                && (held(&before, &at(&ids, position))
                    || (0..position).any(|earlier| {
                        at(&filled, earlier) && at(&ids, earlier) == at(&ids, position)
                    }))
        });
        kani::assert(
            if parsed.is_err() {
                result == Err(Error::RecordRejected)
            } else if any_failed() {
                result == Err(Error::DerivationFailed)
            } else if repeated {
                result == Err(Error::DuplicateKey)
            } else {
                result.is_ok()
            },
            "a plaintext is admitted exactly when it parses, finds a free slot, its keys' \
             identifiers are derived and none is held already or twice",
        );
        if let (Ok(handle), Ok(stages)) = (result, parsed) {
            let now = snapshot(slot_at(&slots, index));
            kani::assert(
                handle.index == index
                    && live(&slots, id, &handle)
                    && now.generation == snapshot_at(&before, index).generation,
                "the set goes into the first free slot, which keeps its generation, and its handle \
                 is live in these slots",
            );
            for position in 0..MEMBERS {
                let (key, length) = at(&members, position);
                let stage = match plaintext[35 + 66 * position] {
                    0 => None,
                    1 => Some(Status::Enabled),
                    _ => Some(Status::Disabled),
                };
                kani::assert(
                    now.stages.stage(position) == stage,
                    "each position keeps the stage the plaintext states",
                );
                if stage.is_some() {
                    kani::assert(
                        pick(&now.keys, position) == key
                            && at(&now.lengths, position) == length
                            && pick(&now.ids, position) == at(&ids, position),
                        "each key is exactly the one the plaintext holds, with its identifier",
                    );
                } else {
                    kani::assert(
                        pick(&now.keys, position) == [0; 64]
                            && pick(&now.ids, position) == [0; ID_LEN],
                        "an empty position holds nothing",
                    );
                }
            }
            kani::assert(
                now.stages == stages
                    && now.stages.primary() == usize::from(plaintext[2])
                    && now.purpose == Purpose::Wrap,
                "the slot keeps the primary, the revision and the purpose the plaintext states",
            );
            kani::assert(
                unchanged_except(&slots, &before, index),
                "admitting changes no other slot",
            );
            kani::cover!(
                filled == [true, true, true] && plaintext[35] == 2,
                "a full set with a disabled key is admitted"
            );
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a refused plaintext changes no slot",
            );
        }
        kani::cover!(parsed.is_err(), "a malformed plaintext is refused");
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "an identifier is not derived"
        );
        kani::cover!(
            result == Err(Error::DuplicateKey) && filled[1] && ids[0] == ids[1],
            "a set that holds one key twice is refused"
        );
    }

    /// Admitting with the first slot free; with the next two, any state of two slots.
    #[kani::proof]
    #[kani::unwind(65)]
    fn admitting_into_the_first_slot() {
        into_the_first(admit_from);
    }

    /// Admitting with the first slot loaded.
    #[kani::proof]
    #[kani::unwind(65)]
    fn admitting_past_a_loaded_slot() {
        past_a(Occupancy::Loaded, admit_from);
    }

    /// Admitting with the first slot retired.
    #[kani::proof]
    #[kani::unwind(65)]
    fn admitting_past_a_retired_slot() {
        past_a(Occupancy::Retired, admit_from);
    }

    /// Stands in for the cipher: writes any bytes, accepts or rejects at will, and remembers, call
    /// by call, the key it was given, what it wrote and whether it accepted.
    struct AnyCipher {
        calls: usize,
        keys: [[u8; CIPHER_KEY_LEN]; MEMBERS],
        written: [[u8; PLAINTEXT_LEN]; MEMBERS],
        accepted: [bool; MEMBERS],
    }

    impl AnyCipher {
        fn new() -> Self {
            Self {
                calls: 0,
                keys: [[0; CIPHER_KEY_LEN]; MEMBERS],
                written: [[0; PLAINTEXT_LEN]; MEMBERS],
                accepted: [false; MEMBERS],
            }
        }

        fn open(
            &mut self,
            key: &[u8; CIPHER_KEY_LEN],
            buffer: &mut [u8; PLAINTEXT_LEN],
        ) -> Result<(), Rejected> {
            let written: [u8; PLAINTEXT_LEN] = kani::any();
            let accepted: bool = kani::any();
            *buffer = written;
            let [first_key, second_key, third_key] = &mut self.keys;
            let [first, second, third] = &mut self.written;
            let [first_accepted, second_accepted, third_accepted] = &mut self.accepted;
            match self.calls {
                0 => (*first_key, *first, *first_accepted) = (*key, written, accepted),
                1 => (*second_key, *second, *second_accepted) = (*key, written, accepted),
                _ => (*third_key, *third, *third_accepted) = (*key, written, accepted),
            }
            self.calls = self.calls.saturating_add(1);
            if accepted { Ok(()) } else { Err(Rejected) }
        }
    }

    /// The positions a set fills, in order, and how many.
    fn filled_positions(stages: &Stages) -> ([usize; MEMBERS], usize) {
        let mut order = [0; MEMBERS];
        let mut count = 0;
        for position in 0..MEMBERS {
            if stages.stage(position).is_some() {
                let [first, second, third] = &mut order;
                match count {
                    0 => *first = position,
                    1 => *second = position,
                    _ => *third = position,
                }
                count += 1;
            }
        }
        (order, count)
    }

    /// The call of the cipher that wins, from what it was given and did: the first that accepted
    /// and wrote a plaintext naming the identifier of the key at that position. Read from the
    /// layout, not by the code under proof.
    fn winning_call(
        cipher: &AnyCipher,
        parent: &Snapshot,
        order: &[usize; MEMBERS],
        count: usize,
    ) -> Option<usize> {
        // Up to the most calls rather than up to `count`: a loop whose end the solver does not know
        // unrolls to the whole bound of the proof.
        (0..MEMBERS).find(|&call| {
            let position = at(order, call);
            let written = at(&cipher.written, call);
            call < count
                && at(&cipher.accepted, call)
                && written[3..19] == pick(&parent.ids, position)
        })
    }

    /// For a loaded parent set in any state, any 261-byte record, any associated data of up to two
    /// bytes and any behaviour of the cipher its interface allows: opening tries every key of the
    /// set, once each, in order of position, with the cipher key derived from that key, also after
    /// one has opened the record; it leaves in the output the plaintext of the first key whose
    /// trial the cipher accepts and whose plaintext names that key's identifier as its parent, and
    /// succeeds if that key is enabled and fails with `KeyDisabled` if it is disabled; it fails
    /// with `DerivationFailed` when a derivation fails, and otherwise with `RecordRejected` when no
    /// trial does both.
    #[kani::proof]
    #[kani::unwind(65)]
    fn opening_tries_every_key_of_the_parent() {
        let mut memory = [any_slot_in(Occupancy::Loaded)];
        let slots = Slots { slots: &mut memory };
        let record: [u8; RECORD_LEN] = kani::any();
        let aad: [u8; 2] = kani::any();
        let before = snapshot(&slots.slots[0]);
        let (order, count) = filled_positions(&before.stages);
        let mut cipher = AnyCipher::new();
        let mut found: [u8; PLAINTEXT_LEN] = kani::any();

        let result = slots.open_under(0, &aad, &record, &mut found, &mut |key, _, _, buffer, _| {
            cipher.open(key, buffer)
        });
        kani::assert(cipher.calls == count, "every key of the set is tried once");
        for call in 0..MEMBERS {
            let position = at(&order, call);
            kani::assert(
                call >= count
                    || any_failed()
                    || at(&cipher.keys, call)
                        == expected_wrap_key(
                            &pick(&before.keys, position),
                            at(&before.lengths, position),
                            Purpose::Wrap,
                        ),
                "each trial uses the cipher key derived from the key at its position",
            );
        }
        let winner = winning_call(&cipher, &before, &order, count);
        kani::assert(
            if any_failed() {
                result == Err(Error::DerivationFailed)
            } else {
                match winner {
                    Some(call) => {
                        let stages = [
                            before.stages.stage(0),
                            before.stages.stage(1),
                            before.stages.stage(2),
                        ];
                        let disabled = at(&stages, at(&order, call)) == Some(Status::Disabled);
                        result
                            == if disabled {
                                Err(Error::KeyDisabled)
                            } else {
                                Ok(())
                            }
                            && same(&found, &at(&cipher.written, call))
                    }
                    None => result == Err(Error::RecordRejected),
                }
            },
            "opening keeps the plaintext of the first key that opens the record and is named in it, \
             and refuses it as KeyDisabled exactly when that key is disabled",
        );
        kani::cover!(
            winner == Some(0) && count == 3 && cipher.accepted[2],
            "the first key wins, and the last is still tried and accepts"
        );
        kani::cover!(
            winner.is_some_and(|call| at(&order, call) == 2),
            "the key at the last position opens the record"
        );
        kani::cover!(
            result == Err(Error::KeyDisabled),
            "a disabled key opens the record"
        );
        kani::cover!(
            result == Err(Error::RecordRejected) && cipher.accepted[0],
            "a key opens the record but is not named in it"
        );
    }

    /// Any context of up to two bytes.
    fn any_context(bytes: &[u8; 2]) -> &[u8] {
        let length: usize = kani::any();
        kani::assume(length <= 2);
        &bytes[..length]
    }

    /// Whether `handle` names a loaded slot with its generation, read from the snapshots.
    fn names_loaded(before: &[Snapshot; 2], handle: &Handle<'_>) -> bool {
        handle.index < 2 && {
            let named = snapshot_at(before, handle.index);
            named.occupancy == Occupancy::Loaded && named.generation == handle.generation
        }
    }

    /// Unwrapping in `memory`, for a handle of this set naming any slot and generation, any record
    /// and any context of up to two bytes, whatever the cipher does: unwrapping refuses an empty
    /// context, a stale parent and a full set before it decrypts; a refused unwrap changes no slot,
    /// and one that succeeds changes only the first free slot, and needs a trial the cipher accepts
    /// and every derivation to succeed. What the trial of the parent's keys gives, `KeyDisabled`
    /// among it, `opening_tries_every_key_of_the_parent` proves.
    fn unwrap_from(mut memory: [Slot; 2]) -> Result<(), Error> {
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let parent = forged(id);
        let record: [u8; RECORD_LEN] = kani::any();
        let context_bytes: [u8; 2] = kani::any();
        let context = any_context(&context_bytes);
        let before = snapshots(&slots);
        let parent_live = names_loaded(&before, &parent);
        let first_free = first_free(&before);
        let mut cipher = AnyCipher::new();

        let result = slots.unwrap_on_stack(parent, context, &record, |key, _, _, buffer, _| {
            cipher.open(key, buffer)
        });
        let refused_before = context.is_empty() || !parent_live || first_free.is_none();
        kani::assert(
            if context.is_empty() {
                result == Err(Error::InvalidContext)
            } else if !parent_live {
                result == Err(Error::StaleHandle)
            } else if first_free.is_none() {
                result == Err(Error::NoFreeSlot)
            } else {
                true
            },
            "an unwrap refuses a bad context, a stale parent and a full set",
        );
        kani::assert(
            !refused_before || cipher.calls == 0,
            "those refusals come before any decryption",
        );
        let [first, second, third] = cipher.accepted;
        kani::assert(
            result.is_err() || ((first || second || third) && !any_failed()),
            "an unwrap loads a set only after a trial the cipher accepts and when every derivation \
             succeeds",
        );
        kani::assert(
            match (result, first_free) {
                (Ok(handle), Some(index)) => {
                    handle.index == index
                        && handle.slots == id
                        && handle.generation == snapshot_at(&before, index).generation
                        && unchanged_except(&slots, &before, index)
                }
                _ => result.is_err() && unchanged_except(&slots, &before, 2),
            },
            "a refused unwrap changes no slot, and one that succeeds only the first free slot, whose \
             handle names these slots and that slot's generation",
        );
        result.map(|_| ())
    }

    /// The outcomes of an unwrap that decrypts.
    fn every_outcome(result: Result<(), Error>) {
        kani::cover!(result.is_ok(), "a record is unwrapped");
        kani::cover!(
            result == Err(Error::KeyDisabled),
            "a disabled key opens the record"
        );
        kani::cover!(result == Err(Error::RecordRejected), "a record is rejected");
    }

    /// Unwrapping with the first slot free; with the next two, any state of two slots.
    #[kani::proof]
    #[kani::unwind(65)]
    fn an_unwrap_into_the_first_slot() {
        every_outcome(into_the_first(unwrap_from));
    }

    /// Unwrapping with the first slot loaded.
    #[kani::proof]
    #[kani::unwind(65)]
    fn an_unwrap_past_a_loaded_slot() {
        every_outcome(past_a(Occupancy::Loaded, unwrap_from));
    }

    /// Unwrapping with the first slot retired, where a live parent leaves no slot free, so nothing
    /// is decrypted.
    #[kani::proof]
    #[kani::unwind(65)]
    fn an_unwrap_past_a_retired_slot() {
        let result = past_a(Occupancy::Retired, unwrap_from);
        kani::cover!(
            result == Err(Error::NoFreeSlot),
            "a live parent leaves no slot free"
        );
    }

    /// From any state of two slots, for handles of this set naming any slots and generations, any
    /// context of up to two bytes and any record buffer, whatever the platform's source and the
    /// cipher do: wrapping changes no slot; it writes the record only when it succeeds, starting
    /// with the nonce the source gave; it refuses an empty context, a stale handle, a set wrapped
    /// under itself and a failed source.
    #[kani::proof]
    #[kani::unwind(234)]
    fn a_wrap_changes_no_slot_and_writes_only_when_it_succeeds() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut slots = Slots { slots: &mut memory };
        let (set, parent) = (forged(id), forged(id));
        let context_bytes: [u8; 2] = kani::any();
        let context = any_context(&context_bytes);
        let original: [u8; RECORD_LEN] = kani::any();
        let mut record = original;
        let mut entropy = AnyEntropy::new();
        let before = snapshots(&slots);
        let live = names_loaded(&before, &set) && names_loaded(&before, &parent);

        let result = slots.wrap(set, parent, context, &mut entropy, &mut record);
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a wrap changes no slot",
        );
        kani::assert(
            if context.is_empty() {
                result == Err(Error::InvalidContext)
            } else if !live {
                result == Err(Error::StaleHandle)
            } else if set.index == parent.index {
                result == Err(Error::SameKey)
            } else if entropy.failed {
                result == Err(Error::EntropyFailed)
            } else {
                result.is_ok()
                    || result == Err(Error::DerivationFailed)
                    || result == Err(Error::CipherFailed)
            },
            "a wrap refuses a bad context, a stale handle, a set wrapping itself and a failed \
             source",
        );
        kani::assert(
            if result.is_ok() {
                record[..12] == entropy.written[..12]
            } else {
                same(&record, &original)
            },
            "a wrap writes the record only when it succeeds, starting with the nonce",
        );
        kani::cover!(result.is_ok(), "a set is wrapped");
        kani::cover!(result == Err(Error::CipherFailed), "the cipher fails");
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "the derivation fails"
        );
    }
}
