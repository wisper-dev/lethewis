// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::{fmt, marker::PhantomData};

use crate::{
    derive::{
        Branch, Hedged, KeyId, derive_key_id, derive_layer_key, derive_lock_key, derive_wrap_key,
        wipe_cipher_stack, wipe_stack,
    },
    entropy::{Entropy, EntropyError},
    epoch::{Epoch, Erasure, Root, RootFailed},
    error::Error,
    key::{Key, KeyBytes, KeyLength, wipe},
    keyset::{self, Header, MEMBERS, Position, Refused, Stages},
    record::{
        AssociatedData, LAYER_LEN, LOCK_RECORD_LEN, PLAINTEXT_LEN, Purpose, RECORD_LEN, Status,
    },
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
    /// The set is a key from a secret the caller holds: it is never wrapped, and wraps only stored
    /// keys for wrapping.
    unlocks: bool,
    generation: u64,
    occupancy: Occupancy,
    /// The set has changed in this epoch.
    changed: bool,
    /// The set is wrapped in the next epoch, and has not changed since.
    sealed: bool,
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
            unlocks: false,
            generation: 0,
            occupancy: Occupancy::Free,
            changed: false,
            sealed: false,
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
        self.changed = false;
        self.sealed = false;
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

    fn key(&self, at: Position) -> &Key {
        let [first, second, third] = &self.keys;
        match at {
            Position::First => first,
            Position::Second => second,
            Position::Third => third,
        }
    }

    fn member(&mut self, at: Position) -> (&mut Key, &mut KeyId) {
        let [first, second, third] = &mut self.keys;
        let [first_id, second_id, third_id] = &mut self.ids;
        match at {
            Position::First => (first, first_id),
            Position::Second => (second, second_id),
            Position::Third => (third, third_id),
        }
    }

    /// The key of a set for wrapping, which holds it alone at the first position, and its
    /// identifier.
    fn wrapping_key(&self) -> (&Key, &KeyId) {
        let [first, ..] = &self.keys;
        let [first_id, ..] = &self.ids;
        (first, first_id)
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
/// and cannot outlive the memory of its slots and epoch. It may outlive the `Slots` itself:
///
/// ```
/// use lethewis_core::{Epoch, Purpose, Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 1];
/// let mut epoch = Epoch::empty();
/// let handle;
/// {
///     let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
///     handle = slots.import32(Purpose::Wrap, &mut [7; 32])?;
/// }
/// let _ = handle;
/// # Ok::<(), lethewis_core::Error>(())
/// ```
///
/// The same code with the memory gone before the handle does not compile:
///
/// ```compile_fail
/// use lethewis_core::{Epoch, Purpose, Slot, Slots};
///
/// let handle;
/// {
///     let mut memory = [const { Slot::empty() }; 1];
///     let mut epoch = Epoch::empty();
///     let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
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
/// A key goes in, and only a handle to its set comes out: no call returns a key itself except
/// [`Slots::reveal32`], and only a key for external data. A key is held in one place only,
/// whatever its purpose: a load that would hold a key these slots already hold is refused.
/// Creating and dropping `Slots` wipes every key in its slots and its epoch, and dropping it
/// discards every change no epoch has saved; a change of epoch under way is to be abandoned first,
/// so that its root is erased. A `Slots` leaked instead of dropped, for example through
/// [`core::mem::forget`], [`core::mem::ManuallyDrop`] or `Box::leak`, skips that wipe, and its keys
/// stay in memory until the next `Slots` over the same memory.
///
/// ```
/// use lethewis_core::{Epoch, Purpose, Slot, Slots};
///
/// let mut memory = [const { Slot::empty() }; 4];
/// let mut epoch = Epoch::empty();
/// let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
///
/// let mut secret = [7; 32];
/// let handle = slots.import32(Purpose::Wrap, &mut secret)?;
/// assert_eq!(secret, [0; 32]);
///
/// slots.release(handle)?;
/// # Ok::<(), lethewis_core::Error>(())
/// ```
pub struct Slots<'a> {
    memory: &'a mut [Slot],
    epoch: &'a mut Epoch,
}

/// What opens a sealed plaintext of `N` bytes: AES-256-GCM-SIV, or a model of it in the proofs.
trait Open<const N: usize>:
    FnMut(
    &[u8; CIPHER_KEY_LEN],
    &[u8; NONCE_LEN],
    &[u8],
    &mut [u8; N],
    &[u8; TAG_LEN],
) -> Result<(), Rejected>
{
}

impl<F, const N: usize> Open<N> for F where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8; N],
        &[u8; TAG_LEN],
    ) -> Result<(), Rejected>
{
}

/// Where a wrap writes: the record of a set for external data, or the lock record of a stored key
/// for wrapping.
enum Out<'r> {
    Record(&'r mut [u8; RECORD_LEN]),
    Lock(&'r mut [u8; LOCK_RECORD_LEN]),
}

impl<'a> Slots<'a> {
    /// Keeps key sets in `slots`, in the epoch numbered `number`, whose key it takes from `key`
    /// into `epoch` and then wipes. A key left in `slots` or `epoch` earlier is wiped first.
    #[must_use]
    pub fn new(
        slots: &'a mut [Slot],
        epoch: &'a mut Epoch,
        number: u64,
        key: &mut [u8; 32],
    ) -> Self {
        epoch.wipe();
        epoch.number = number;
        epoch.key.copy32(key);
        wipe(key);
        let mut this = Self {
            memory: slots,
            epoch,
        };
        this.unload_all();
        this
    }

    /// Takes a 32-byte key for `purpose` from `source` into a free slot, as a set of one whose key
    /// is the primary, and wipes `source`.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier, and the whole load, are
    /// each followed by a wipe of 8 KiB, or 64 KiB, below them. A build that optimises this crate
    /// but not the hash code it calls has to set that flag.
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
        let secret = purpose == Purpose::Wrap;
        let handle = self.load_new(purpose, KeyLength::Bytes32, secret, |first, _| {
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
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier, and the whole load, are
    /// each followed by a wipe of 8 KiB, or 64 KiB, below them. A build that optimises this crate
    /// but not the hash code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongLength`] if `purpose` takes no 64-byte key, [`Error::NoFreeSlot`] if no slot
    /// is free, [`Error::DerivationFailed`] if the identifier of the key cannot be derived, and
    /// [`Error::DuplicateKey`] if these slots hold the key already. `source` is then left as it
    /// was, and no slot changes.
    pub fn import64(
        &mut self,
        purpose: Purpose,
        source: &mut [u8; 64],
    ) -> Result<Handle<'a>, Error> {
        let secret = purpose == Purpose::Wrap;
        let handle = self.load_new(purpose, KeyLength::Bytes64, secret, |first, _| {
            first.copy64(source);
            Ok(())
        })?;
        wipe(source);
        Ok(handle)
    }

    /// Creates a key for `purpose` of `length` random bytes from `entropy` in a free slot, as a set
    /// of one whose key is the primary. The bytes are hedged with the key of the epoch, as RFC 8937
    /// has it, and the key derived from them is written straight into the slot; the bytes `entropy`
    /// gave are wiped, and so is the stack the derivations used. `entropy` is asked once, and only
    /// when `purpose` takes `length` and a slot is free.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the hedge, the derivation of the key's identifier, and the
    /// whole load, are each followed by a wipe of 8 KiB, or 64 KiB, below them. A build that
    /// optimises this crate but not the hash code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongLength`] if `purpose` takes no key of `length`, [`Error::NoFreeSlot`] if no
    /// slot is free, [`Error::EntropyFailed`] if `entropy` fails, [`Error::DerivationFailed`] if
    /// the key or its identifier cannot be derived, and [`Error::DuplicateKey`] if these slots hold
    /// the key already. No slot changes then.
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
        self.load_new(purpose, length, false, |first, epoch| {
            hedged_fill(first, length, entropy, epoch)
        })
    }

    /// Fills `dest` from `entropy`, the platform's source, hedged with the key of this epoch under
    /// `branch`.
    pub(crate) fn draw(
        &mut self,
        entropy: &mut (impl Entropy + ?Sized),
        branch: Branch,
        dest: &mut [u8],
    ) -> Result<(), Error> {
        let Epoch { key, drawn, .. } = &mut *self.epoch;
        hedged_draw(entropy, key, drawn, branch, dest)
    }

    /// Loads a key of `length` for `purpose` whose bytes `source` derives, from a password or from
    /// words, as a set of one: not hedged, so that the same input gives the same key.
    pub(crate) fn load_derived(
        &mut self,
        purpose: Purpose,
        length: KeyLength,
        source: &mut (impl Entropy + ?Sized),
    ) -> Result<Handle<'a>, Error> {
        self.load_new(purpose, length, purpose == Purpose::Wrap, |first, _| {
            first
                .fill(length, source)
                .map_err(|EntropyError| Error::EntropyFailed)
        })
    }

    /// Writes the enabled key at `at` of the set that `set` refers to into `out`, if the set serves
    /// `purpose` and keys of `purpose` leave the library: only [`Purpose::ExternalData`] does. The
    /// copy in `out` is the caller's to wipe. The set is to be wrapped and its record stored before
    /// an engine uses the key; otherwise the key is lost with the slots.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the call is followed by a wipe of 8 KiB, or 64 KiB, below it,
    /// whether it succeeded or not.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set serves another purpose than `purpose` or keys of
    /// `purpose` never leave the library, and [`Error::WrongStage`] if `at` does not hold an
    /// enabled key. `out` is then left as it was.
    pub fn reveal32(
        &self,
        set: Handle<'a>,
        at: Position,
        purpose: Purpose,
        out: &mut [u8; 32],
    ) -> Result<(), Error> {
        let revealed = self.reveal_on_stack(set, at, purpose, out);
        wipe_stack();
        revealed
    }

    /// The reveal itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn reveal_on_stack(
        &self,
        set: Handle<'a>,
        at: Position,
        purpose: Purpose,
        out: &mut [u8; 32],
    ) -> Result<(), Error> {
        let slot = self
            .memory
            .get(self.loaded(set)?)
            .ok_or(Error::StaleHandle)?;
        if purpose != Purpose::ExternalData || slot.purpose != purpose {
            return Err(Error::WrongPurpose);
        }
        if slot.stages.stage(at.index()) != Some(Status::Enabled) {
            return Err(Error::WrongStage);
        }
        let key = slot
            .key(at)
            .material()
            .and_then(|key| <&[u8; 32]>::try_from(key).ok())
            .ok_or(Error::WrongLength)?;
        *out = *key;
        Ok(())
    }

    /// Wraps the set for external data that `set` refers to under the stored key for wrapping that
    /// `parent` refers to and writes the record into `record`, in this epoch, or in the next while
    /// a change to it is under way. The record holds every key of the set, its stage and which key
    /// is the primary, and opens only with that key and the same `context`, which names the place
    /// the record is kept, from 1 to 255 bytes. The nonce comes from `entropy`, hedged with the key
    /// of the epoch the record is wrapped in.
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
    /// [`Error::SameKey`] if both refer to the same set, [`Error::WrongPurpose`] if the set
    /// `parent` refers to does not serve [`Purpose::Wrap`], [`Error::WrongLevel`] if the set `set`
    /// refers to serves it, or `parent` refers to a key from a secret, [`Error::Unsaved`] if the
    /// set `set` refers to has changed in this epoch and no change to the next is under way,
    /// [`Error::EntropyFailed`] if `entropy` fails,
    /// [`Error::DerivationFailed`] if the nonce cannot be hedged or the key that encrypts the record
    /// cannot be derived, and
    /// [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails. `record`
    /// is then left as it was.
    pub fn wrap(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; RECORD_LEN],
    ) -> Result<(), Error> {
        let wrapped = lethewis_dit::with(|| {
            self.wrap_on_stack(set, parent, context, entropy, Out::Record(record))
        });
        wipe_cipher_stack();
        wrapped
    }

    /// Locks the stored key for wrapping that `set` refers to under the key from a secret that
    /// `parent` refers to, and writes the lock record into `record`, in this epoch, or in the next
    /// while a change to it is under way. The record has two layers, both bound to `context`, from
    /// 1 to 255 bytes, for good. The inner one opens only with the key from a secret, whatever the
    /// epoch; the outer one only with the key of the epoch, which [`Slots::carry`] moves on to the
    /// next without the key from a secret. The nonces come from `entropy`, hedged with the key of
    /// the epoch the record is written in.
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
    /// [`Error::SameKey`] if both refer to the same set, [`Error::WrongPurpose`] if the set
    /// `parent` refers to does not serve [`Purpose::Wrap`], [`Error::WrongLevel`] if `set` does not
    /// refer to a stored key for wrapping or `parent` to a key from a secret,
    /// [`Error::EntropyFailed`] if `entropy` fails, [`Error::DerivationFailed`] if a nonce cannot
    /// be hedged or a key that encrypts a layer cannot be derived, and [`Error::CipherFailed`] if
    /// the cipher gives a known input a wrong answer or fails. `record` is then left as it was.
    pub fn lock(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; LOCK_RECORD_LEN],
    ) -> Result<(), Error> {
        let locked = lethewis_dit::with(|| {
            self.wrap_on_stack(set, parent, context, entropy, Out::Lock(record))
        });
        wipe_cipher_stack();
        locked
    }

    /// The wrap or the lock itself, in a frame of its own: the wipe that follows starts where this
    /// frame starts.
    #[inline(never)]
    fn wrap_on_stack(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        out: Out<'_>,
    ) -> Result<(), Error> {
        let lock = matches!(out, Out::Lock(_));
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let (index, wrapping) = (self.loaded(set)?, self.loaded(parent)?);
        if index == wrapping {
            return Err(Error::SameKey);
        }
        let (Some(child), Some(wrapping)) = (self.memory.get(index), self.memory.get(wrapping))
        else {
            return Err(Error::StaleHandle);
        };
        if wrapping.purpose != Purpose::Wrap {
            return Err(Error::WrongPurpose);
        }
        if child.unlocks || (child.purpose == Purpose::Wrap) != lock || wrapping.unlocks != lock {
            return Err(Error::WrongLevel);
        }
        if child.changed && !self.epoch.changing {
            return Err(Error::Unsaved);
        }
        let Epoch {
            number,
            key,
            next,
            changing,
            drawn,
        } = &mut *self.epoch;
        let (epoch, epoch_key) = if *changing {
            (number.checked_add(1).ok_or(Error::EpochExhausted)?, &*next)
        } else {
            (*number, &*key)
        };
        let (parent_key, parent_id) = wrapping.wrapping_key();
        let mut nonce = [0; NONCE_LEN];
        hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, &mut nonce)?;
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        let derived = if lock {
            derive_lock_key(parent_key, &mut cipher_key)
        } else {
            derive_wrap_key(parent_key, epoch_key, &mut cipher_key)
        };
        if derived.is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let header = Header {
            purpose: child.purpose,
            parent: parent_id.bytes(),
            epoch: if lock { 0 } else { epoch },
        };
        let [first, second, third] = &child.keys;
        let mut sealed = [0; PLAINTEXT_LEN];
        keyset::build(&header, &child.stages, [first, second, third], &mut sealed);
        let tag = seal::seal(&cipher_key, &nonce, associated.bytes(), &mut sealed);
        wipe(&mut cipher_key);
        let tag = tag.map_err(|_| Error::CipherFailed)?;
        match out {
            Out::Record(record) => write_record(record, &nonce, &sealed, &tag),
            Out::Lock(record) => {
                let mut inner = [0; RECORD_LEN];
                write_record(&mut inner, &nonce, &sealed, &tag);
                wipe(&mut sealed);
                let layered = seal_layer(
                    (epoch_key, epoch),
                    entropy,
                    drawn,
                    associated.bytes(),
                    &inner,
                    record,
                );
                wipe(&mut inner);
                layered?;
            }
        }
        if self.epoch.changing
            && let Some(child) = self.memory.get_mut(index)
        {
            child.sealed = true;
        }
        Ok(())
    }

    /// Unwraps `record` with the stored key for wrapping that `parent` refers to and the `context`
    /// it was wrapped for, into a free slot. The set comes out with the purpose, keys, stages and
    /// primary the record holds.
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
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::Wrap`], [`Error::WrongLevel`]
    /// if it is a key from a secret, [`Error::NoFreeSlot`] if no slot is free,
    /// [`Error::DerivationFailed`] if a value cannot be derived from a key,
    /// [`Error::RecordRejected`] if the record does not open with the key of the parent, this
    /// context and the key of this epoch, names a key other than the one that opens it or another
    /// epoch, or holds a set for wrapping or a plaintext this version of the library cannot read,
    /// and [`Error::DuplicateKey`] if these slots hold a key of the set already or the set holds
    /// one key twice. No slot changes then.
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
        mut open: impl Open<PLAINTEXT_LEN>,
    ) -> Result<Handle<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.parent(parent, false)?;
        self.take(index, associated.bytes(), record, false, &mut open)
    }

    /// Unlocks the lock record `record` with the key from a secret that `parent` refers to and the
    /// `context` it was locked for, into a free slot: the stored key for wrapping it holds comes
    /// out as a set of one.
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
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::Wrap`], [`Error::WrongLevel`]
    /// if it is not a key from a secret, [`Error::NoFreeSlot`] if no slot is free,
    /// [`Error::DerivationFailed`] if a value cannot be derived from a key,
    /// [`Error::StaleRecord`] if the record does not open in this epoch for this context: it was
    /// not locked or carried into this epoch, or it was changed, [`Error::RecordRejected`] if it
    /// does not open with the key of the parent, names a key other than the one that opens it, or
    /// holds a plaintext this version of the library cannot read, and [`Error::DuplicateKey`] if
    /// these slots hold its key already. No slot changes then.
    pub fn unlock(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; LOCK_RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let unlocked = lethewis_dit::with(|| {
            self.unlock_on_stack(parent, context, record, seal::open, seal::open)
        });
        wipe_cipher_stack();
        unlocked
    }

    /// The unlock itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn unlock_on_stack(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; LOCK_RECORD_LEN],
        mut open_layer_with: impl Open<LAYER_LEN>,
        mut open: impl Open<PLAINTEXT_LEN>,
    ) -> Result<Handle<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.parent(parent, true)?;
        let mut inner = [0; RECORD_LEN];
        let unlocked = open_layer(
            (&self.epoch.key, self.epoch.number),
            associated.bytes(),
            record,
            &mut inner,
            &mut open_layer_with,
        )
        .and_then(|()| self.take(index, associated.bytes(), &inner, true, &mut open));
        wipe(&mut inner);
        unlocked
    }

    /// The slot of the set `parent` refers to, if it serves [`Purpose::Wrap`], is a key from a
    /// secret exactly when `secret` says so, and a slot is free.
    fn parent(&self, parent: Handle<'a>, secret: bool) -> Result<usize, Error> {
        let index = self.loaded(parent)?;
        let set = self.memory.get(index).ok_or(Error::StaleHandle)?;
        if set.purpose != Purpose::Wrap {
            return Err(Error::WrongPurpose);
        }
        if set.unlocks != secret {
            return Err(Error::WrongLevel);
        }
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        Ok(index)
    }

    /// Opens `record` under the key of the set in slot `parent`, a key from a secret when `lock`
    /// says so, and loads the set it holds.
    fn take(
        &mut self,
        parent: usize,
        aad: &[u8],
        record: &[u8; RECORD_LEN],
        lock: bool,
        open: &mut impl Open<PLAINTEXT_LEN>,
    ) -> Result<Handle<'a>, Error> {
        let mut plaintext = [0; PLAINTEXT_LEN];
        let admitted = self
            .open_under(parent, aad, record, &mut plaintext, open, lock)
            .and_then(|()| self.admit(&plaintext, lock));
        wipe(&mut plaintext);
        admitted
    }

    /// Opens `record` under the key of the set in slot `parent`, a key from a secret when `lock`
    /// says so, and keeps the plaintext in `found` if it names that key's identifier as the
    /// parent's.
    fn open_under(
        &self,
        parent: usize,
        aad: &[u8],
        record: &[u8; RECORD_LEN],
        found: &mut [u8; PLAINTEXT_LEN],
        open: &mut impl Open<PLAINTEXT_LEN>,
        lock: bool,
    ) -> Result<(), Error> {
        let (key, id) = self
            .memory
            .get(parent)
            .ok_or(Error::StaleHandle)?
            .wrapping_key();
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        let derived = if lock {
            derive_lock_key(key, &mut cipher_key)
        } else {
            derive_wrap_key(key, &self.epoch.key, &mut cipher_key)
        };
        if derived.is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let (nonce, mut sealed, tag) = split_record(record);
        let opened = open(&cipher_key, &nonce, aad, &mut sealed, &tag).is_ok();
        wipe(&mut cipher_key);
        let named = opened && id.is(keyset::parent_of(&sealed));
        if named {
            *found = sealed;
        }
        wipe(&mut sealed);
        if named {
            Ok(())
        } else {
            Err(Error::RecordRejected)
        }
    }

    /// Loads the key set a record's plaintext holds into a free slot, if one is and the plaintext
    /// parses: a set of external data from a record of this epoch, or, from a lock record, a set
    /// of one stored key for wrapping.
    fn admit(&mut self, plaintext: &[u8; PLAINTEXT_LEN], lock: bool) -> Result<Handle<'a>, Error> {
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        let (header, stages, keys) = keyset::parse(plaintext).map_err(|_| Error::RecordRejected)?;
        let epoch = if lock { 0 } else { self.epoch.number };
        if header.epoch != epoch
            || (header.purpose == Purpose::Wrap) != lock
            || (header.purpose == Purpose::Wrap && !stages.is_one())
        {
            return Err(Error::RecordRejected);
        }
        self.load(
            header.purpose,
            stages,
            false,
            |[first, second, third], _| {
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
            },
        )
    }

    /// Carries the lock record `from` into the next epoch while a change to it is under way, and
    /// writes it into `to`: the same stored key for wrapping under the same key from a secret, for
    /// the same `context`, without that key. The nonce comes from `entropy`, hedged with the key
    /// of the next epoch. A lock record not carried opens no more once the change is committed, so
    /// a change that leaves one behind revokes that way in; until the commit, and while the
    /// platform keeps the old root, a copy of it still opens.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::NoEpochChange`] if no change to the next epoch is under way,
    /// [`Error::DerivationFailed`] if a key that encrypts a layer cannot be derived or the nonce
    /// cannot be hedged, [`Error::StaleRecord`] if `from` does not open in this epoch for this
    /// context, [`Error::EntropyFailed`] if `entropy` fails, and [`Error::CipherFailed`] if the
    /// cipher gives a known input a wrong answer or fails. `to` is then left as it was.
    pub fn carry(
        &mut self,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        from: &[u8; LOCK_RECORD_LEN],
        to: &mut [u8; LOCK_RECORD_LEN],
    ) -> Result<(), Error> {
        let carried =
            lethewis_dit::with(|| self.carry_on_stack(context, entropy, from, to, seal::open));
        wipe_cipher_stack();
        carried
    }

    /// The carry itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    fn carry_on_stack(
        &mut self,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        from: &[u8; LOCK_RECORD_LEN],
        to: &mut [u8; LOCK_RECORD_LEN],
        mut open: impl Open<LAYER_LEN>,
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let Epoch {
            number,
            key,
            next,
            changing,
            drawn,
        } = &mut *self.epoch;
        if !*changing {
            return Err(Error::NoEpochChange);
        }
        let following = number.checked_add(1).ok_or(Error::EpochExhausted)?;
        let mut inner = [0; RECORD_LEN];
        let carried = open_layer(
            (&*key, *number),
            associated.bytes(),
            from,
            &mut inner,
            &mut open,
        )
        .and_then(|()| {
            seal_layer(
                (&*next, following),
                entropy,
                drawn,
                associated.bytes(),
                &inner,
                to,
            )
        });
        wipe(&mut inner);
        carried
    }

    pub(crate) fn has_free(&self) -> bool {
        self.memory
            .iter()
            .any(|slot| slot.occupancy == Occupancy::Free)
    }

    /// The index of the slot `handle` refers to, if it is loaded with the handle's generation.
    fn loaded(&self, handle: Handle<'a>) -> Result<usize, Error> {
        if handle.slots != self.id() {
            return Err(Error::StaleHandle);
        }
        self.memory
            .get(handle.index)
            .filter(|slot| {
                slot.occupancy == Occupancy::Loaded && slot.generation == handle.generation
            })
            .map(|_| handle.index)
            .ok_or(Error::StaleHandle)
    }

    /// Puts one key of `length` for `purpose` into the first free slot with `fill`, as a set of one
    /// whose key is the primary, a key from a secret if `secret` says so, if `purpose` takes
    /// `length`.
    fn load_new(
        &mut self,
        purpose: Purpose,
        length: KeyLength,
        secret: bool,
        fill: impl FnOnce(&mut Key, &mut Epoch) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        if !purpose.takes(length) {
            return Err(Error::WrongLength);
        }
        self.load(purpose, Stages::one(), secret, |[first, ..], epoch| {
            fill(first, epoch)
        })
    }

    /// Puts the keys of a set for `purpose` with `stages` into the first free slot with `fill`,
    /// derives their identifiers, and issues a handle if that succeeds, no key is held already and
    /// none twice, with data-independent timing on. On failure the slot is left free and wiped.
    /// The stack the load used is wiped after it.
    fn load(
        &mut self,
        purpose: Purpose,
        stages: Stages,
        secret: bool,
        fill: impl FnOnce(&mut [Key; MEMBERS], &mut Epoch) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        // The copy of the key and the checks after its derivation run above the derivation's wipe.
        let loaded = lethewis_dit::with(|| self.load_in_slot(purpose, stages, secret, fill));
        wipe_stack();
        loaded
    }

    fn load_in_slot(
        &mut self,
        purpose: Purpose,
        stages: Stages,
        secret: bool,
        fill: impl FnOnce(&mut [Key; MEMBERS], &mut Epoch) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        let slots = self.id();
        let index = self
            .memory
            .iter()
            .position(|slot| slot.occupancy == Occupancy::Free)
            .ok_or(Error::NoFreeSlot)?;
        let filled = self
            .memory
            .get_mut(index)
            .map_or(Err(Error::NoFreeSlot), |slot| {
                fill(&mut slot.keys, &mut *self.epoch)
            });
        let identified = filled.and_then(|()| self.identify(index, &stages));
        let slot = self.memory.get_mut(index).ok_or(Error::NoFreeSlot)?;
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
        slot.unlocks = secret;
        slot.occupancy = Occupancy::Loaded;
        Ok(Handle {
            slots,
            index,
            generation: slot.generation,
            memory: PhantomData,
        })
    }

    /// The identifiers of the keys `stages` places in the free slot `index`. A key that a loaded
    /// slot holds, for any purpose, or that the set holds twice, is refused.
    // Derived into local buffers and copied in at once: the derivation writes byte by byte, and
    // each write through a reference to a slot chosen at run time multiplies the proofs' work.
    fn identify(&self, index: usize, stages: &Stages) -> Result<[KeyId; MEMBERS], Error> {
        let slot = self.memory.get(index).ok_or(Error::NoFreeSlot)?;
        let derive = |position: usize, key: &Key, id: &mut KeyId| -> Result<(), Error> {
            if stages.stage(position).is_some() {
                derive_key_id(key, id).map_err(|_| Error::DerivationFailed)?;
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
        let held = |id: &KeyId| self.memory.iter().any(|other| other.holds(id));
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

    /// Takes a 32-byte key from `source` into the first empty position of the set that `set` refers
    /// to, enabled and not the primary, and wipes `source`. Returns the position.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation of the key's identifier, and the whole
    /// addition, are each followed by a wipe of 8 KiB, or 64 KiB, below them. A build that optimises
    /// this crate but not the hash code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set serves [`Purpose::Wrap`], which takes no changes,
    /// [`Error::EpochChanging`] if a change to the next epoch is under way, [`Error::Unsaved`] if
    /// the set has changed in this epoch, [`Error::SetFull`] if every position holds a key,
    /// [`Error::SetExhausted`] if the set has changed as many times as its counter holds,
    /// [`Error::DerivationFailed`] if the identifier of the key cannot be derived, and
    /// [`Error::DuplicateKey`] if these slots hold the key already. `source` is then left as it
    /// was, and nothing changes.
    pub fn add32(&mut self, set: Handle<'a>, source: &mut [u8; 32]) -> Result<Position, Error> {
        let at = self.add(set, KeyLength::Bytes32, |key, _| {
            key.copy32(source);
            Ok(())
        })?;
        wipe(source);
        Ok(at)
    }

    /// Creates a key of `length` random bytes from `entropy` in the first empty position of the set
    /// that `set` refers to, enabled and not the primary, and returns the position. The bytes are
    /// hedged with the key of the epoch, as RFC 8937 has it, and the key derived from them is
    /// written straight into the slot. `entropy` is asked once, and only when the set's purpose
    /// takes `length` and a position is empty.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the hedge, the derivation of the key's identifier, and the
    /// whole addition, are each followed by a wipe of 8 KiB, or 64 KiB, below them. A build that
    /// optimises this crate but not the hash code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set serves [`Purpose::Wrap`], which takes no changes,
    /// [`Error::EpochChanging`] if a change to the next epoch is under way, [`Error::Unsaved`] if
    /// the set has changed in this epoch, [`Error::WrongLength`] if its purpose takes no key of
    /// `length`, [`Error::SetFull`] if every position holds a key,
    /// [`Error::SetExhausted`] if the set has changed as many times as its counter holds,
    /// [`Error::EntropyFailed`] if `entropy` fails, [`Error::DerivationFailed`] if the key or its
    /// identifier cannot be derived, and [`Error::DuplicateKey`] if these slots hold the key
    /// already. No slot changes then.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and the position stays empty and wiped.
    pub fn add_generated(
        &mut self,
        set: Handle<'a>,
        length: KeyLength,
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<Position, Error> {
        self.add(set, length, |key, epoch| {
            hedged_fill(key, length, entropy, epoch)
        })
    }

    /// Makes the enabled key at `at` the primary of the set that `set` refers to. The former primary
    /// stays enabled.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set serves [`Purpose::Wrap`], which takes no changes,
    /// [`Error::EpochChanging`] if a change to the next epoch is under way, [`Error::Unsaved`] if
    /// the set has changed in this epoch, [`Error::PrimaryKey`] if the key at `at` is the primary
    /// already, [`Error::WrongStage`] if `at` does not hold an enabled key, and
    /// [`Error::SetExhausted`] if the set has changed as many times as its counter holds. Nothing
    /// changes then.
    pub fn promote(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        self.change(set, at, Stages::promote).map(|_| ())
    }

    /// Disables the enabled key at `at` of the set that `set` refers to: it is not revealed until it
    /// is enabled again.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set serves [`Purpose::Wrap`], which takes no changes,
    /// [`Error::EpochChanging`] if a change to the next epoch is under way, [`Error::Unsaved`] if
    /// the set has changed in this epoch, [`Error::PrimaryKey`] if the key at `at` is the primary,
    /// [`Error::WrongStage`] if `at` does not hold an enabled key, and [`Error::SetExhausted`] if
    /// the set has changed as many times as its counter holds. Nothing changes then.
    pub fn disable(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        self.change(set, at, Stages::disable).map(|_| ())
    }

    /// Enables the disabled key at `at` of the set that `set` refers to again.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set serves [`Purpose::Wrap`], which takes no changes,
    /// [`Error::EpochChanging`] if a change to the next epoch is under way, [`Error::Unsaved`] if
    /// the set has changed in this epoch, [`Error::PrimaryKey`] if `at` is the primary position,
    /// [`Error::WrongStage`] if `at` does not hold a disabled key, and [`Error::SetExhausted`] if
    /// the set has changed as many times as its counter holds. Nothing changes then.
    pub fn enable(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        self.change(set, at, Stages::enable).map(|_| ())
    }

    /// Wipes the disabled key at `at` of the set that `set` refers to, with its identifier, and
    /// empties the position. A record of the set wrapped afterwards does not hold the key. The
    /// destruction is saved only by the commit of the next epoch, and a record wrapped before stays
    /// readable until then; dropping these slots first discards it.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set serves [`Purpose::Wrap`], which takes no changes,
    /// [`Error::EpochChanging`] if a change to the next epoch is under way, [`Error::Unsaved`] if
    /// the set has changed in this epoch, [`Error::PrimaryKey`] if `at` is the primary position,
    /// [`Error::WrongStage`] if `at` does not hold a disabled key, and [`Error::SetExhausted`] if
    /// the set has changed as many times as its counter holds. Nothing changes then.
    pub fn destroy(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        let (key, id) = self.change(set, at, Stages::destroy)?.member(at);
        key.wipe();
        id.wipe();
        Ok(())
    }

    /// Applies `transition` at `at` to the stages of the set that `set` refers to, and returns its
    /// slot if it applies.
    fn change(
        &mut self,
        set: Handle<'a>,
        at: Position,
        transition: impl FnOnce(&mut Stages, usize) -> Result<(), Refused>,
    ) -> Result<&mut Slot, Error> {
        let index = self.loaded(set)?;
        if self.memory.get(index).map(|slot| slot.purpose) == Some(Purpose::Wrap) {
            return Err(Error::WrongPurpose);
        }
        if self.epoch.changing {
            return Err(Error::EpochChanging);
        }
        let slot = self.memory.get_mut(index).ok_or(Error::StaleHandle)?;
        if slot.changed {
            return Err(Error::Unsaved);
        }
        let mut stages = slot.stages;
        transition(&mut stages, at.index())?;
        slot.stages = stages;
        slot.changed = true;
        slot.sealed = false;
        Ok(slot)
    }

    /// Puts a key of `length` into the first empty position of the set that `set` refers to with
    /// `fill`, derives its identifier, and keeps the key enabled if the set's purpose takes
    /// `length` and these slots do not hold the key already, with data-independent timing on. On
    /// failure the position is left empty and wiped. The stack the addition used is wiped after it.
    fn add(
        &mut self,
        set: Handle<'a>,
        length: KeyLength,
        fill: impl FnOnce(&mut Key, &mut Epoch) -> Result<(), Error>,
    ) -> Result<Position, Error> {
        let added = lethewis_dit::with(|| self.add_in_slot(set, length, fill));
        wipe_stack();
        added
    }

    fn add_in_slot(
        &mut self,
        set: Handle<'a>,
        length: KeyLength,
        fill: impl FnOnce(&mut Key, &mut Epoch) -> Result<(), Error>,
    ) -> Result<Position, Error> {
        let index = self.loaded(set)?;
        if self.memory.get(index).map(|slot| slot.purpose) == Some(Purpose::Wrap) {
            return Err(Error::WrongPurpose);
        }
        if self.epoch.changing {
            return Err(Error::EpochChanging);
        }
        let slot = self.memory.get_mut(index).ok_or(Error::StaleHandle)?;
        if slot.changed {
            return Err(Error::Unsaved);
        }
        if !slot.purpose.takes(length) {
            return Err(Error::WrongLength);
        }
        let mut stages = slot.stages;
        let at = Position::at(stages.add()?).ok_or(Error::SetFull)?;
        let filled = fill(slot.member(at).0, &mut *self.epoch);
        let mut id = KeyId::empty();
        let identified = filled.and_then(|()| {
            let key = self.memory.get(index).ok_or(Error::StaleHandle)?.key(at);
            derive_key_id(key, &mut id).map_err(|_| Error::DerivationFailed)?;
            if self.memory.iter().any(|other| other.holds(&id)) {
                return Err(Error::DuplicateKey);
            }
            Ok(())
        });
        let slot = self.memory.get_mut(index).ok_or(Error::StaleHandle)?;
        let (key, held) = slot.member(at);
        if let Err(error) = identified {
            key.wipe();
            return Err(error);
        }
        held.take(&mut id);
        slot.stages = stages;
        slot.changed = true;
        slot.sealed = false;
        Ok(at)
    }

    /// Begins the change to the next epoch, whose key it takes from `key` and then wipes. Until the
    /// change is committed or abandoned, records are wrapped in the next epoch and unwrapped in
    /// this one. `key` comes from the platform with the root of the next epoch, and is never used
    /// again.
    ///
    /// # Errors
    ///
    /// [`Error::EpochChanging`] if a change has begun already, and [`Error::EpochExhausted`] if
    /// this is the last epoch the counter holds. `key` is then left as it was.
    pub fn begin_epoch(&mut self, key: &mut [u8; 32]) -> Result<(), Error> {
        if self.epoch.changing {
            return Err(Error::EpochChanging);
        }
        if self.epoch.number == u64::MAX {
            return Err(Error::EpochExhausted);
        }
        self.epoch.next.copy32(key);
        wipe(key);
        self.epoch.changing = true;
        Ok(())
    }

    /// Abandons the change to the next epoch: wipes its key, and has `root` erase the root made for
    /// it, so that no record wrapped for it opens. Returns how surely that root is gone. A set that
    /// has changed in this epoch stays unsaved.
    ///
    /// # Errors
    ///
    /// [`Error::NoEpochChange`] if no change has begun. Nothing changes then.
    pub fn abandon_epoch(&mut self, root: &mut (impl Root + ?Sized)) -> Result<Erasure, Error> {
        if !self.epoch.changing {
            return Err(Error::NoEpochChange);
        }
        let next = self
            .epoch
            .number
            .checked_add(1)
            .ok_or(Error::EpochExhausted)?;
        self.epoch.next.wipe();
        self.epoch.changing = false;
        for slot in self.memory.iter_mut() {
            slot.sealed = false;
        }
        Ok(root.erase(next))
    }

    /// Commits the change to the next epoch: `root` makes the root of the next epoch the current
    /// one, the key of this epoch is wiped, and `root` erases its root. Returns how surely the root
    /// is gone. Only then are the keys destroyed in this epoch out of reach of the records wrapped
    /// before. Before the commit, every record of the next epoch is to be stored, and the records
    /// of this epoch kept until it returns: a record of the next epoch opens only after it, and a
    /// record of this epoch not wrapped or carried again opens no more. Should the platform stop between
    /// switching the root and erasing the old one, it erases the old one at its next start.
    ///
    /// # Errors
    ///
    /// [`Error::NoEpochChange`] if no change has begun, [`Error::Unsaved`] if a set that has
    /// changed in this epoch has not been wrapped in the next since, and [`Error::RootFailed`] if
    /// `root` does not switch the root. Nothing changes then.
    pub fn commit_epoch(&mut self, root: &mut (impl Root + ?Sized)) -> Result<Erasure, Error> {
        if !self.epoch.changing {
            return Err(Error::NoEpochChange);
        }
        let next = self
            .epoch
            .number
            .checked_add(1)
            .ok_or(Error::EpochExhausted)?;
        if self
            .memory
            .iter()
            .any(|slot| slot.occupancy == Occupancy::Loaded && slot.changed && !slot.sealed)
        {
            return Err(Error::Unsaved);
        }
        let next_key = self
            .epoch
            .next
            .material()
            .and_then(<[u8]>::first_chunk::<32>)
            .ok_or(Error::NoEpochChange)?;
        root.switch(next).map_err(|RootFailed| Error::RootFailed)?;
        let old = self.epoch.number;
        self.epoch.key.copy32(next_key);
        self.epoch.next.wipe();
        self.epoch.number = next;
        self.epoch.changing = false;
        for slot in self.memory.iter_mut() {
            slot.changed = false;
            slot.sealed = false;
        }
        Ok(root.erase(old))
    }

    /// Wipes every key of the set that `handle` refers to and frees its slot.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if `handle` does not refer to a set held here now, and
    /// [`Error::Unsaved`] if the set has changed in this epoch. Nothing changes then.
    pub fn release(&mut self, handle: Handle<'a>) -> Result<(), Error> {
        let index = self.loaded(handle)?;
        let slot = self.memory.get_mut(index).ok_or(Error::StaleHandle)?;
        if slot.changed {
            return Err(Error::Unsaved);
        }
        slot.unload();
        Ok(())
    }

    /// Marks every set saved, as a new epoch would: for tests of the stages alone.
    #[cfg(test)]
    pub(crate) fn settle(&mut self) {
        for slot in self.memory.iter_mut() {
            slot.changed = false;
        }
    }

    /// Makes the key for wrapping `handle` refers to a stored one, as an unlock gives it: for tests
    /// of what a stored key does, without a lock record.
    #[cfg(test)]
    pub(crate) fn store(&mut self, handle: Handle<'a>) -> Handle<'a> {
        if let Some(slot) = self.memory.get_mut(handle.index) {
            slot.unlocks = false;
        }
        handle
    }

    /// Tells apart two `Slots` alive at once: their memory does not overlap, so neither do the
    /// addresses. Empty ones may share an address, but they issue no handles. A handle keeps its
    /// memory borrowed, so no other `Slots` can take that memory over while the handle exists.
    fn id(&self) -> usize {
        self.memory.as_ptr().addr()
    }

    /// Wipes every key and identifier in every slot, loaded or not, and frees the loaded ones.
    fn unload_all(&mut self) {
        for slot in self.memory.iter_mut() {
            if slot.occupancy == Occupancy::Loaded {
                slot.unload();
            } else {
                slot.wipe_keys();
            }
        }
    }
}

/// Fills `key` with `length` bytes from `entropy`, the platform's source, hedged with the key of
/// `epoch`. A failed hedge is `DerivationFailed`, a failed source `EntropyFailed`.
fn hedged_fill(
    key: &mut Key,
    length: KeyLength,
    entropy: &mut (impl Entropy + ?Sized),
    epoch: &mut Epoch,
) -> Result<(), Error> {
    let Epoch {
        key: epoch_key,
        drawn,
        ..
    } = epoch;
    let mut hedged = Hedged {
        source: entropy,
        epoch: epoch_key,
        drawn,
        branch: Branch::HedgeKey,
        failed: false,
    };
    key.fill(length, &mut hedged).map_err(|EntropyError| {
        if hedged.failed {
            Error::DerivationFailed
        } else {
            Error::EntropyFailed
        }
    })
}

/// Fills `dest` from `entropy`, the platform's source, hedged with `epoch` under `branch` and the
/// next count of `drawn`. A failed hedge is `DerivationFailed`, a failed source `EntropyFailed`.
fn hedged_draw(
    entropy: &mut (impl Entropy + ?Sized),
    epoch: &Key,
    drawn: &mut u64,
    branch: Branch,
    dest: &mut [u8],
) -> Result<(), Error> {
    let mut hedged = Hedged {
        source: entropy,
        epoch,
        drawn,
        branch,
        failed: false,
    };
    hedged.fill(dest).map_err(|EntropyError| {
        if hedged.failed {
            Error::DerivationFailed
        } else {
            Error::EntropyFailed
        }
    })
}

/// Seals `inner`, the record of a stored key for wrapping, with the number of an epoch under that
/// epoch's key, given in `epoch`, into the lock record `out`; the nonce comes from `entropy`, hedged
/// with that key. `out` is written only when this succeeds.
fn seal_layer(
    (epoch_key, number): (&Key, u64),
    entropy: &mut (impl Entropy + ?Sized),
    drawn: &mut u64,
    aad: &[u8],
    inner: &[u8; RECORD_LEN],
    out: &mut [u8; LOCK_RECORD_LEN],
) -> Result<(), Error> {
    let mut nonce = [0; NONCE_LEN];
    hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, &mut nonce)?;
    let mut layer_key = [0; CIPHER_KEY_LEN];
    if derive_layer_key(epoch_key, &mut layer_key).is_err() {
        wipe(&mut layer_key);
        return Err(Error::DerivationFailed);
    }
    let mut layer = [0; LAYER_LEN];
    if let Some((head, rest)) = layer.split_first_chunk_mut::<8>()
        && let Ok(record) = <&mut [u8; RECORD_LEN]>::try_from(rest)
    {
        *head = number.to_le_bytes();
        *record = *inner;
    }
    let tag = seal::seal(&layer_key, &nonce, aad, &mut layer);
    wipe(&mut layer_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    if let Some((nonce_out, rest)) = out.split_first_chunk_mut::<NONCE_LEN>()
        && let Some((layer_out, tag_out)) = rest.split_first_chunk_mut::<LAYER_LEN>()
    {
        *nonce_out = nonce;
        *layer_out = layer;
        tag_out.copy_from_slice(&tag);
    }
    Ok(())
}

/// Opens the lock record `record` under the key of an epoch, given in `epoch` with its number, and
/// keeps the record it holds in `inner` if it names that number; otherwise `StaleRecord`, and
/// `inner` is left as it was.
fn open_layer(
    (epoch_key, number): (&Key, u64),
    aad: &[u8],
    record: &[u8; LOCK_RECORD_LEN],
    inner: &mut [u8; RECORD_LEN],
    open: &mut impl Open<LAYER_LEN>,
) -> Result<(), Error> {
    let mut layer_key = [0; CIPHER_KEY_LEN];
    if derive_layer_key(epoch_key, &mut layer_key).is_err() {
        wipe(&mut layer_key);
        return Err(Error::DerivationFailed);
    }
    let mut parts = ([0; NONCE_LEN], [0; LAYER_LEN], [0; TAG_LEN]);
    if let Some((nonce, rest)) = record.split_first_chunk::<NONCE_LEN>()
        && let Some((layer, tag)) = rest.split_first_chunk::<LAYER_LEN>()
        && let Ok(tag) = <[u8; TAG_LEN]>::try_from(tag)
    {
        parts = (*nonce, *layer, tag);
    }
    let (nonce, mut layer, tag) = parts;
    let opened = open(&layer_key, &nonce, aad, &mut layer, &tag).is_ok();
    wipe(&mut layer_key);
    let mut current = false;
    if opened
        && let Some((head, rest)) = layer.split_first_chunk::<8>()
        && let Ok(record) = <&[u8; RECORD_LEN]>::try_from(rest)
        && u64::from_le_bytes(*head) == number
    {
        *inner = *record;
        current = true;
    }
    wipe(&mut layer);
    if current {
        Ok(())
    } else {
        Err(Error::StaleRecord)
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
        self.epoch.wipe();
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
        AssociatedData, CIPHER_KEY_LEN, Entropy, EntropyError, Epoch, Erasure, Error, Handle,
        Header, KeyLength, LAYER_LEN, LOCK_RECORD_LEN, MEMBERS, Occupancy, PLAINTEXT_LEN, Position,
        Purpose, RECORD_LEN, Root, RootFailed, Slot, Slots, Stages, Status, derive_layer_key,
        derive_lock_key, derive_wrap_key, keyset, seal, write_record,
    };
    use crate::derive::{CIPHER_STACK_WIPE, KeyId, STACK_WIPE, derive_key_id};
    use crate::key::{
        Key,
        tests::{
            Counting, Failing, Panicking, Random, Recording, counted, from_environment, padded,
        },
    };
    use crate::record::MAX_CONTEXT;

    pub(super) const EPOCH: u64 = 1;

    pub(super) fn epoch_key() -> [u8; 32] {
        flipped_epoch_key(0)
    }

    /// The key of the test epoch with every bit of `flip` flipped in each byte; its bytes vary, so
    /// that the tests of residue look for it.
    pub(super) fn flipped_epoch_key(flip: u8) -> [u8; 32] {
        core::array::from_fn(|at| {
            u8::try_from(at)
                .unwrap()
                .wrapping_mul(29)
                .wrapping_add(0xe5)
                ^ flip
        })
    }

    pub(super) fn epoch() -> Key {
        flipped_epoch(0)
    }

    pub(super) fn flipped_epoch(flip: u8) -> Key {
        let mut key = Key::empty();
        key.load32(&mut flipped_epoch_key(flip));
        key
    }

    assert_not_impl!(Slot: Clone, PartialEq, Default);
    assert_not_impl!(Epoch: Clone, PartialEq, Default);

    /// Every import, generation, wrap, unwrap, lock, unlock and carry derives, and every call on
    /// words reads and writes them, with data-independent timing on, where the processor and the
    /// operating system offer it.
    #[test]
    fn every_call_that_derives_holds_data_independent_timing() {
        use crate::derive::timing::seen;
        assert!(!lethewis_dit::active(), "the mode is off before the work");
        let _ = seen();
        let mut memory = [const { Slot::empty() }; 7];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = slots.import64(Purpose::Wrap, &mut [7; 64]).unwrap();
        let parent = slots.store(parent);
        assert_eq!(seen(), Some(true));
        let key = slots.import32(Purpose::ExternalData, &mut [9; 32]).unwrap();
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
        let set = slots.unwrap(parent, b"context", &record).unwrap();
        assert_eq!(seen(), Some(true));
        slots.add32(set, &mut [3; 32]).unwrap();
        assert_eq!(seen(), Some(true));
        slots.settle();
        slots.release(set).unwrap();
        let set = slots.import32(Purpose::ExternalData, &mut [5; 32]).unwrap();
        let _ = seen();
        slots
            .add_generated(set, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        assert_eq!(seen(), Some(true));
        slots.settle();
        slots.release(set).unwrap();
        let mut words = [[0; 8]; 12];
        let set = slots.generate_words(&mut Counting, &mut words).unwrap();
        assert_eq!(seen(), Some(true));
        slots.release(set).unwrap();
        slots.derive_from_words(&mut words).unwrap();
        assert_eq!(seen(), Some(true));
        let secret = slots.import32(Purpose::Wrap, &mut [6; 32]).unwrap();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let _ = seen();
        let mut locked = [0; LOCK_RECORD_LEN];
        slots
            .lock(stored, secret, b"context", &mut Counting, &mut locked)
            .unwrap();
        assert_eq!(seen(), Some(true));
        slots.release(stored).unwrap();
        slots.unlock(secret, b"context", &locked).unwrap();
        assert_eq!(seen(), Some(true));
        slots.begin_epoch(&mut [8; 32]).unwrap();
        let mut carried = [0; LOCK_RECORD_LEN];
        slots
            .carry(b"context", &mut Counting, &locked, &mut carried)
            .unwrap();
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

    /// The documentation of each import, generation, addition, reveal, wrap, unwrap, lock, unlock
    /// and carry states the stack it needs and the depth of the wipe after it, and those depths are
    /// the library's.
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
            ("add32", loads),
            ("add_generated", loads),
            ("reveal32", loads),
            ("wrap", wraps),
            ("unwrap", wraps),
            ("lock", wraps),
            ("unlock", wraps),
            ("carry", wraps),
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

    #[test]
    fn keys_are_added_enabled_in_the_first_empty_position() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots
            .import32(Purpose::ExternalData, &mut secret())
            .unwrap();
        let mut short = [5; 32];
        assert_eq!(slots.add32(set, &mut short), Ok(Position::Second));
        assert_eq!(short, [0; 32]);
        slots.settle();
        let added = slots.add_generated(set, KeyLength::Bytes32, &mut Counting);
        assert_eq!(added, Ok(Position::Third));
        slots.settle();
        let generated = hedged(0, b"hedge key", &counted::<32>(), 32);
        assert_holds(
            &slots,
            set,
            [
                Some((Status::Enabled, &secret())),
                Some((Status::Enabled, &[5; 32])),
                Some((Status::Enabled, &generated)),
            ],
            0,
        );
        let mut more = [6; 32];
        assert_eq!(slots.add32(set, &mut more), Err(Error::SetFull));
        assert_eq!(more, [6; 32]);
    }

    /// A generated key is the hedge of the source's bytes, in its position: the source writes into a
    /// buffer of the library's, not into the slot.
    #[test]
    fn a_generated_key_is_the_hedge_of_the_source_in_its_position() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots
            .import32(Purpose::ExternalData, &mut secret())
            .unwrap();
        let mut source = Recording::default();
        let added = slots.add_generated(set, KeyLength::Bytes32, &mut source);
        assert_eq!(added, Ok(Position::Second));
        assert_eq!((source.calls, source.asked), (1, 32));
        assert_ne!(source.at, slots.memory[0].keys[1].bytes().as_ptr().addr());
        assert_eq!(
            slots.memory[0].keys[1].bytes()[..32],
            hedged(0, b"hedge key", &[3; 32], 32)[..]
        );
        let mut full = Recording::default();
        slots.settle();
        slots
            .add_generated(set, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        slots.settle();
        let refused = slots.add_generated(set, KeyLength::Bytes32, &mut full);
        assert_eq!((refused, full.calls), (Err(Error::SetFull), 0));
    }

    #[test]
    fn a_key_held_anywhere_is_not_added() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let first = slots.import32(Purpose::Wrap, &mut [1; 32]).unwrap();
        let second = slots.import32(Purpose::ExternalData, &mut [2; 32]).unwrap();
        for bytes in [[1; 32], [2; 32]] {
            let mut source = bytes;
            assert_eq!(slots.add32(second, &mut source), Err(Error::DuplicateKey));
            assert_eq!(source, bytes);
        }
        assert_holds_for(
            &slots,
            first,
            [Some((Status::Enabled, &[1; 32])), None, None],
            0,
            Purpose::Wrap,
        );
        assert_holds(
            &slots,
            second,
            [Some((Status::Enabled, &[2; 32])), None, None],
            0,
        );
    }

    #[test]
    fn a_failed_addition_leaves_the_position_empty_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots
            .import32(Purpose::ExternalData, &mut secret())
            .unwrap();
        let failed = slots.add_generated(set, KeyLength::Bytes32, &mut Failing);
        assert_eq!(failed, Err(Error::EntropyFailed));
        assert_holds(
            &slots,
            set,
            [Some((Status::Enabled, &secret())), None, None],
            0,
        );
    }

    #[test]
    fn the_stages_change_only_as_the_set_allows() {
        use Position::{First, Second, Third};
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots.import32(Purpose::ExternalData, &mut [1; 32]).unwrap();
        assert_eq!(slots.promote(set, Second), Err(Error::WrongStage));
        assert_eq!(slots.add32(set, &mut [2; 32]), Ok(Second));
        slots.settle();
        assert_eq!(slots.promote(set, First), Err(Error::PrimaryKey));
        assert_eq!(slots.disable(set, First), Err(Error::PrimaryKey));
        assert_eq!(slots.destroy(set, Second), Err(Error::WrongStage));
        assert_eq!(slots.promote(set, Second), Ok(()));
        slots.settle();
        assert_eq!(slots.disable(set, First), Ok(()));
        slots.settle();
        assert_eq!(slots.disable(set, First), Err(Error::WrongStage));
        assert_eq!(slots.enable(set, First), Ok(()));
        slots.settle();
        assert_eq!(slots.disable(set, First), Ok(()));
        slots.settle();
        assert_holds(
            &slots,
            set,
            [
                Some((Status::Disabled, &[1; 32])),
                Some((Status::Enabled, &[2; 32])),
                None,
            ],
            1,
        );
        assert_eq!(slots.destroy(set, Second), Err(Error::PrimaryKey));
        assert_eq!(slots.destroy(set, Third), Err(Error::WrongStage));
        assert_eq!(slots.destroy(set, First), Ok(()));
        slots.settle();
        assert_eq!(slots.destroy(set, First), Err(Error::WrongStage));
        assert_holds(
            &slots,
            set,
            [None, Some((Status::Enabled, &[2; 32])), None],
            1,
        );
        assert_eq!(slots.add32(set, &mut [3; 32]), Ok(First));
        slots.settle();
    }

    #[test]
    fn an_exhausted_set_changes_no_more() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots.import32(Purpose::ExternalData, &mut [1; 32]).unwrap();
        slots.add32(set, &mut [2; 32]).unwrap();
        slots.settle();
        let members = [Some(Status::Enabled), Some(Status::Enabled), None];
        slots.memory[0].stages = Stages::from_parts(members, 0, u64::MAX);
        let mut source = [3; 32];
        assert_eq!(slots.add32(set, &mut source), Err(Error::SetExhausted));
        assert_eq!(source, [3; 32]);
        let added = slots.add_generated(set, KeyLength::Bytes32, &mut Untouched);
        assert_eq!(added, Err(Error::SetExhausted));
        assert_eq!(
            slots.promote(set, Position::Second),
            Err(Error::SetExhausted)
        );
        assert_eq!(
            slots.disable(set, Position::Second),
            Err(Error::SetExhausted)
        );
        assert_holds(
            &slots,
            set,
            [
                Some((Status::Enabled, &[1; 32])),
                Some((Status::Enabled, &[2; 32])),
                None,
            ],
            0,
        );
    }

    #[test]
    fn a_panic_in_the_source_of_an_addition_leaves_the_position_empty_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots.import32(Purpose::ExternalData, &mut [1; 32]).unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = slots.add_generated(set, KeyLength::Bytes32, &mut Panicking);
        }));
        assert!(outcome.is_err());
        assert_holds(
            &slots,
            set,
            [Some((Status::Enabled, &[1; 32])), None, None],
            0,
        );
    }

    #[test]
    fn a_stale_handle_changes_nothing() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots.import32(Purpose::ExternalData, &mut [1; 32]).unwrap();
        slots.release(set).unwrap();
        let mut source = [2; 32];
        assert_eq!(slots.add32(set, &mut source), Err(Error::StaleHandle));
        assert_eq!(source, [2; 32]);
        assert_eq!(slots.promote(set, Position::First), Err(Error::StaleHandle));
        assert_eq!(
            slots.disable(set, Position::Second),
            Err(Error::StaleHandle)
        );
        assert_eq!(slots.enable(set, Position::Second), Err(Error::StaleHandle));
        assert_eq!(
            slots.destroy(set, Position::Second),
            Err(Error::StaleHandle)
        );
        let added = slots.add_generated(set, KeyLength::Bytes32, &mut Untouched);
        assert_eq!(added, Err(Error::StaleHandle));
        assert_eq!(slots.memory[0].occupancy, Occupancy::Free);
    }

    /// A set for wrapping holds its one key and never changes: every change of stage and every
    /// addition is refused before anything else, the source is not asked, and nothing changes.
    #[test]
    fn a_wrapping_set_takes_no_changes() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots.import32(Purpose::Wrap, &mut [1; 32]).unwrap();
        slots.begin_epoch(&mut [5; 32]).unwrap();
        let before = holdings(&slots);
        let mut source = [2; 32];
        assert_eq!(slots.add32(set, &mut source), Err(Error::WrongPurpose));
        assert_eq!(source, [2; 32]);
        let added = slots.add_generated(set, KeyLength::Bytes32, &mut Untouched);
        assert_eq!(added, Err(Error::WrongPurpose));
        for refused in [
            slots.promote(set, Position::First),
            slots.disable(set, Position::Second),
            slots.enable(set, Position::Second),
            slots.destroy(set, Position::Second),
        ] {
            assert_eq!(refused, Err(Error::WrongPurpose));
        }
        assert_eq!(holdings(&slots), before);
        assert!(!slots.memory[0].changed);
    }

    /// A platform that records what it is asked, and switches the root unless told to fail.
    #[derive(Default)]
    struct Platform {
        switched: Vec<u64>,
        erased: Vec<u64>,
        fail: bool,
    }

    impl Root for Platform {
        fn switch(&mut self, next: u64) -> Result<(), RootFailed> {
            if self.fail {
                return Err(RootFailed);
            }
            self.switched.push(next);
            Ok(())
        }

        fn erase(&mut self, old: u64) -> Erasure {
            self.erased.push(old);
            Erasure::Guaranteed
        }
    }

    /// Saves the change of `set` by a new epoch whose key is all `byte`: wraps `set` under `root`
    /// into `record`.
    fn save<'a>(
        slots: &mut Slots<'a>,
        platform: &mut Platform,
        (root, set): (Handle<'a>, Handle<'a>),
        record: &mut [u8; RECORD_LEN],
        byte: u8,
    ) {
        slots.begin_epoch(&mut [byte; 32]).unwrap();
        slots
            .wrap(set, root, b"set", &mut Counting, record)
            .unwrap();
        assert_eq!(slots.commit_epoch(platform), Ok(Erasure::Guaranteed));
    }

    /// A key goes from added to destroyed, each change saved by a new epoch. The copy of the set
    /// that holds the destroyed key does not reach the last epoch, and no copy of an epoch past
    /// opens.
    #[test]
    fn keys_rotate_from_added_to_destroyed() {
        use Position::{First, Second};
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut platform = Platform::default();
        let root = slots.import64(Purpose::Wrap, &mut [9; 64]).unwrap();
        let root = slots.store(root);
        let set = slots.import32(Purpose::ExternalData, &mut [1; 32]).unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"set", &mut Counting, &mut record)
            .unwrap();
        let first = record;
        slots.add32(set, &mut [2; 32]).unwrap();
        save(&mut slots, &mut platform, (root, set), &mut record, 2);
        slots.promote(set, Second).unwrap();
        save(&mut slots, &mut platform, (root, set), &mut record, 3);
        slots.disable(set, First).unwrap();
        save(&mut slots, &mut platform, (root, set), &mut record, 4);
        let with_disabled = record;
        slots.destroy(set, First).unwrap();
        slots.begin_epoch(&mut [5; 32]).unwrap();
        assert_eq!(
            slots.unwrap(root, b"set", &with_disabled),
            Err(Error::DuplicateKey)
        );
        slots
            .wrap(set, root, b"set", &mut Counting, &mut record)
            .unwrap();
        assert_eq!(slots.commit_epoch(&mut platform), Ok(Erasure::Guaranteed));
        assert_eq!(platform.switched, [2, 3, 4, 5]);
        assert_eq!(platform.erased, [1, 2, 3, 4]);
        slots.release(set).unwrap();
        let back = slots.unwrap(root, b"set", &record).unwrap();
        assert_holds(
            &slots,
            back,
            [None, Some((Status::Enabled, &[2; 32])), None],
            1,
        );
        slots.release(back).unwrap();
        for old in [first, with_disabled] {
            assert_eq!(slots.unwrap(root, b"set", &old), Err(Error::RecordRejected));
        }
    }

    /// A set changes once in an epoch, and is neither released nor wrapped in it after the
    /// change; the change is saved by committing a new epoch the set is wrapped in. Calls out of
    /// order are refused and change nothing.
    #[test]
    fn an_epoch_changes_only_in_order() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut platform = Platform::default();
        assert_eq!(slots.commit_epoch(&mut platform), Err(Error::NoEpochChange));
        let root = slots.import32(Purpose::Wrap, &mut [1; 32]).unwrap();
        let root = slots.store(root);
        let set = slots.import32(Purpose::ExternalData, &mut [2; 32]).unwrap();
        slots.add32(set, &mut [3; 32]).unwrap();
        let mut more = [4; 32];
        assert_eq!(slots.add32(set, &mut more), Err(Error::Unsaved));
        assert_eq!(more, [4; 32]);
        assert_eq!(slots.promote(set, Position::Second), Err(Error::Unsaved));
        assert_eq!(slots.release(set), Err(Error::Unsaved));
        let mut record = [0; RECORD_LEN];
        let wrapped = slots.wrap(set, root, b"set", &mut Counting, &mut record);
        assert_eq!((wrapped, record), (Err(Error::Unsaved), [0; RECORD_LEN]));
        let mut key = [5; 32];
        slots.begin_epoch(&mut key).unwrap();
        assert_eq!(key, [0; 32]);
        let mut again = [6; 32];
        assert_eq!(slots.begin_epoch(&mut again), Err(Error::EpochChanging));
        assert_eq!(again, [6; 32]);
        assert_eq!(slots.commit_epoch(&mut platform), Err(Error::Unsaved));
        slots
            .wrap(set, root, b"set", &mut Counting, &mut record)
            .unwrap();
        platform.fail = true;
        assert_eq!(slots.commit_epoch(&mut platform), Err(Error::RootFailed));
        assert_eq!(slots.release(set), Err(Error::Unsaved));
        platform.fail = false;
        assert_eq!(slots.commit_epoch(&mut platform), Ok(Erasure::Guaranteed));
        assert_eq!(
            (platform.switched, platform.erased),
            ([2].into(), [1].into())
        );
        slots.release(set).unwrap();
        let back = slots.unwrap(root, b"set", &record).unwrap();
        assert_holds(
            &slots,
            back,
            [
                Some((Status::Enabled, &[2; 32])),
                Some((Status::Enabled, &[3; 32])),
                None,
            ],
            0,
        );
    }

    /// An abandoned change leaves the epoch as it was: a record wrapped for the next epoch does not
    /// open, and a change stays unsaved until a later epoch the set is wrapped in.
    #[test]
    fn an_abandoned_epoch_change_leaves_the_epoch_as_it_was() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut platform = Platform::default();
        let root = slots.import32(Purpose::Wrap, &mut [1; 32]).unwrap();
        let root = slots.store(root);
        let set = slots.import32(Purpose::ExternalData, &mut [2; 32]).unwrap();
        slots.add32(set, &mut [3; 32]).unwrap();
        slots.begin_epoch(&mut [5; 32]).unwrap();
        let mut abandoned = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"set", &mut Counting, &mut abandoned)
            .unwrap();
        assert_eq!(slots.abandon_epoch(&mut platform), Ok(Erasure::Guaranteed));
        assert_eq!(platform.erased, [EPOCH + 1]);
        assert_eq!(
            slots.abandon_epoch(&mut platform),
            Err(Error::NoEpochChange)
        );
        assert_eq!(slots.commit_epoch(&mut platform), Err(Error::NoEpochChange));
        assert_eq!(slots.release(set), Err(Error::Unsaved));
        slots.begin_epoch(&mut [6; 32]).unwrap();
        assert_eq!(slots.commit_epoch(&mut platform), Err(Error::Unsaved));
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"set", &mut Counting, &mut record)
            .unwrap();
        assert_eq!(slots.commit_epoch(&mut platform), Ok(Erasure::Guaranteed));
        slots.release(set).unwrap();
        assert_eq!(
            slots.unwrap(root, b"set", &abandoned),
            Err(Error::RecordRejected)
        );
        assert!(slots.unwrap(root, b"set", &record).is_ok());
    }

    #[test]
    fn dropping_the_slots_wipes_the_epoch() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        {
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
            slots.begin_epoch(&mut [5; 32]).unwrap();
        }
        assert_eq!(*epoch_memory.key.bytes(), [0; 64]);
        assert_eq!(*epoch_memory.next.bytes(), [0; 64]);
        assert!(!epoch_memory.changing);
    }

    /// No set changes while a change of epoch is under way: a set wrapped for the next epoch could
    /// otherwise change after, and leave that record of the next epoch holding a destroyed key.
    #[test]
    fn a_set_does_not_change_during_an_epoch_change() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let root = slots.import32(Purpose::Wrap, &mut [1; 32]).unwrap();
        let root = slots.store(root);
        let set = slots.import32(Purpose::ExternalData, &mut [2; 32]).unwrap();
        slots.add32(set, &mut [3; 32]).unwrap();
        slots.settle();
        slots.disable(set, Position::Second).unwrap();
        slots.settle();
        slots.begin_epoch(&mut [5; 32]).unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"set", &mut Counting, &mut record)
            .unwrap();
        let mut source = [4; 32];
        assert_eq!(slots.add32(set, &mut source), Err(Error::EpochChanging));
        assert_eq!(source, [4; 32]);
        for refused in [
            slots.destroy(set, Position::Second),
            slots.enable(set, Position::Second),
            slots.promote(set, Position::Second),
            slots.disable(set, Position::First),
        ] {
            assert_eq!(refused, Err(Error::EpochChanging));
        }
        assert_holds(
            &slots,
            set,
            [
                Some((Status::Enabled, &[2; 32])),
                Some((Status::Disabled, &[3; 32])),
                None,
            ],
            0,
        );
    }

    /// A record opens only in the epoch it was wrapped in: with another key of the epoch it does
    /// not open, and with the same key under another number it is refused.
    #[test]
    fn a_record_opens_only_in_its_epoch() {
        let wrapped = |epoch, key: [u8; 32]| {
            let mut memory = [const { Slot::empty() }; 2];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, epoch, &mut key.clone());
            let parent = slots.import32(Purpose::Wrap, &mut [1; 32]).unwrap();
            let parent = slots.store(parent);
            let set = slots.import32(Purpose::ExternalData, &mut [2; 32]).unwrap();
            let mut record = [0; RECORD_LEN];
            slots
                .wrap(set, parent, b"set", &mut Counting, &mut record)
                .unwrap();
            record
        };
        let opened = |epoch, key: [u8; 32], record: &[u8; RECORD_LEN]| {
            let mut memory = [const { Slot::empty() }; 2];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, epoch, &mut key.clone());
            let parent = slots.import32(Purpose::Wrap, &mut [1; 32]).unwrap();
            let parent = slots.store(parent);
            slots.unwrap(parent, b"set", record).map(|_| ())
        };
        let record = wrapped(EPOCH, epoch_key());
        assert_eq!(opened(EPOCH, epoch_key(), &record), Ok(()));
        assert_eq!(
            opened(EPOCH, [0xe6; 32], &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            opened(EPOCH + 1, epoch_key(), &record),
            Err(Error::RecordRejected)
        );
    }

    #[test]
    fn the_last_epoch_does_not_change() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, u64::MAX, &mut epoch_key());
        let mut key = [5; 32];
        assert_eq!(slots.begin_epoch(&mut key), Err(Error::EpochExhausted));
        assert_eq!(key, [5; 32]);
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
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut source = secret();
        let handle = slots.import32(Purpose::Wrap, &mut source).unwrap();
        assert_eq!((handle.index, handle.generation), (0, 0));
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&secret()));
        assert_eq!(slots.memory[0].keys[0].length(), KeyLength::Bytes32);
        assert_eq!(slots.memory[0].occupancy, Occupancy::Loaded);
        assert_eq!(source, [0; 32]);
    }

    #[test]
    fn import64_loads_the_key_and_wipes_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut source = [5; 64];
        slots.import64(Purpose::Wrap, &mut source).unwrap();
        assert_eq!(slots.memory[0].keys[0].bytes(), &[5; 64]);
        assert_eq!(slots.memory[0].keys[0].length(), KeyLength::Bytes64);
        assert_eq!(slots.memory[0].occupancy, Occupancy::Loaded);
        assert_eq!(source, [0; 64]);
    }

    #[test]
    fn generate_writes_random_bytes_into_the_slot() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let short = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let long = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
        assert_eq!((short.index, long.index), (0, 1));
        assert_eq!(
            slots.memory[0].keys[0].bytes(),
            &padded(&hedged(0, b"hedge key", &counted::<32>(), 32))
        );
        assert_eq!(slots.memory[0].keys[0].length(), KeyLength::Bytes32);
        assert_eq!(
            slots.memory[1].keys[0].bytes()[..],
            hedged(1, b"hedge key", &counted::<64>(), 64)[..]
        );
        assert_eq!(slots.memory[1].keys[0].length(), KeyLength::Bytes64);
        assert_eq!(slots.memory[1].occupancy, Occupancy::Loaded);
    }

    #[test]
    fn a_failed_generate_leaves_the_slot_free_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        assert_eq!(
            slots.generate(Purpose::Wrap, KeyLength::Bytes64, &mut Failing),
            Err(Error::EntropyFailed)
        );
        assert_eq!(slots.memory[0].occupancy, Occupancy::Free);
        assert_eq!(slots.memory[0].generation, 0);
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&[]));
    }

    #[test]
    fn generate_asks_the_source_once_for_the_length() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut source = Recording::default();
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut source)
            .unwrap();
        assert_eq!((source.calls, source.asked), (1, 64));
        assert_ne!(source.at, slots.memory[0].keys[0].bytes().as_ptr().addr());
    }

    #[test]
    fn generate_takes_a_source_behind_a_trait_object() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let source: &mut dyn Entropy = &mut Counting;
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, source)
            .unwrap();
        assert_eq!(
            slots.memory[0].keys[0].bytes(),
            &padded(&hedged(0, b"hedge key", &counted::<32>(), 32))
        );
    }

    #[test]
    fn a_panic_in_the_source_leaves_the_slot_free_and_wiped() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = slots.generate(Purpose::Wrap, KeyLength::Bytes64, &mut Panicking);
        }));
        assert!(outcome.is_err());
        assert_eq!(slots.memory[0].occupancy, Occupancy::Free);
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&[]));
        assert!(
            slots
                .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
                .is_ok()
        );
    }

    #[test]
    fn generate_without_a_free_slot_asks_for_no_bytes() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_eq!(
            slots.generate(Purpose::Wrap, KeyLength::Bytes32, &mut Untouched),
            Err(Error::NoFreeSlot)
        );
    }

    fn id_of(key: &Key) -> KeyId {
        let mut id = KeyId::empty();
        derive_key_id(key, &mut id).unwrap();
        id
    }

    #[test]
    fn a_load_keeps_the_purpose_and_the_identifier_of_the_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
        let mut short = Key::empty();
        short.load32(&mut secret());
        let mut long = Key::empty();
        long.load64(
            &mut hedged(0, b"hedge key", &counted::<64>(), 64)
                .try_into()
                .unwrap(),
        );
        assert_eq!(slots.memory[0].purpose, Purpose::Wrap);
        assert_eq!(slots.memory[1].purpose, Purpose::Wrap);
        assert_eq!(slots.memory[0].stages.stage(0), Some(Status::Enabled));
        assert_eq!(slots.memory[1].stages.stage(0), Some(Status::Enabled));
        assert_eq!(slots.memory[0].ids[0], id_of(&short));
        assert_eq!(slots.memory[1].ids[0], id_of(&long));
        assert_ne!(slots.memory[0].ids[0], slots.memory[1].ids[0]);
    }

    #[test]
    fn release_wipes_the_identifier() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_ne!(slots.memory[0].ids[0], KeyId::empty());
        slots.release(handle).unwrap();
        assert_eq!(slots.memory[0].ids[0], KeyId::empty());
    }

    #[test]
    fn new_slots_wipe_an_identifier_left_behind() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut key = Key::empty();
        key.load32(&mut secret());
        memory[0].ids[0] = id_of(&key);
        let mut epoch_memory = Epoch::empty();
        let slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        assert_eq!(slots.memory[0].ids[0], KeyId::empty());
    }

    #[test]
    fn import_takes_the_first_free_slot() {
        let mut memory = [const { Slot::empty() }; 3];
        memory[1].occupancy = Occupancy::Retired;
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        let handle = slots.import64(Purpose::Wrap, &mut [5; 64]).unwrap();
        assert_eq!(handle.index, 2);
    }

    #[test]
    fn import_without_a_free_slot_keeps_the_source() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
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
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        let second = slots.import64(Purpose::Wrap, &mut [5; 64]).unwrap();
        slots.release(second).unwrap();
        assert_eq!(slots.memory[1].keys[0].bytes(), &padded(&[]));
        assert_eq!(slots.memory[1].keys[0].length(), KeyLength::Bytes32);
        assert_eq!(slots.memory[1].occupancy, Occupancy::Free);
        assert_eq!(slots.memory[1].generation, 1);
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&secret()));
        assert_eq!(slots.memory[0].occupancy, Occupancy::Loaded);
    }

    #[test]
    fn a_released_handle_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
    }

    #[test]
    fn an_old_handle_does_not_reach_a_new_key_in_the_same_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
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
        let mut epoch_memory = Epoch::empty();
        let mut first = Slots::new(
            &mut first_memory,
            &mut epoch_memory,
            EPOCH,
            &mut epoch_key(),
        );
        let mut epoch_memory = Epoch::empty();
        let mut second = Slots::new(
            &mut second_memory,
            &mut epoch_memory,
            EPOCH,
            &mut epoch_key(),
        );
        let handle = first.import32(Purpose::Wrap, &mut secret()).unwrap();
        second.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_eq!(second.release(handle), Err(Error::StaleHandle));
        assert_eq!(second.memory[0].keys[0].bytes(), &padded(&secret()));
    }

    #[test]
    fn a_handle_outside_the_slots_is_stale() {
        let mut memory = [const { Slot::empty() }; 1];
        let id = memory.as_ptr().addr();
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        let outside = Handle {
            slots: id,
            index: 1,
            generation: 0,
            memory: PhantomData,
        };
        assert_eq!(slots.release(outside), Err(Error::StaleHandle));
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&secret()));
    }

    #[test]
    fn a_slot_whose_generation_runs_out_is_retired() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].generation = u64::MAX;
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        slots.release(handle).unwrap();
        assert_eq!(
            slots.import32(Purpose::Wrap, &mut secret()),
            Err(Error::NoFreeSlot)
        );
        assert_eq!(slots.release(handle), Err(Error::StaleHandle));
        assert_eq!(slots.memory[0].occupancy, Occupancy::Retired);
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&[]));
    }

    #[test]
    fn dropping_the_slots_wipes_every_key() {
        let mut memory = [const { Slot::empty() }; 2];
        {
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
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
        let mut epoch_memory = Epoch::empty();
        let slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&[]));
        assert_eq!(slots.memory[0].occupancy, Occupancy::Free);
    }

    #[test]
    fn new_slots_wipe_bytes_left_in_a_free_slot() {
        let mut memory = [const { Slot::empty() }; 1];
        memory[0].keys[0].load64(&mut [5; 64]);
        let mut epoch_memory = Epoch::empty();
        let slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        assert_eq!(slots.memory[0].keys[0].bytes(), &padded(&[]));
        assert_eq!(
            (slots.memory[0].occupancy, slots.memory[0].generation),
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

    /// What the slots make of `drawn`, the bytes a source gave, at `count` draws since they were
    /// created, for the use `name`: HKDF-SHA-256 called directly, with the key of the test epoch as
    /// the salt and the label written out by hand.
    pub(super) fn hedged(count: u64, name: &[u8], drawn: &[u8], length: usize) -> Vec<u8> {
        crate::derive::direct::hedged_directly(&epoch_key(), count, name, drawn, length)
    }

    fn hex(text: &str) -> [u8; RECORD_LEN] {
        core::array::from_fn(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
    }

    /// Records computed by an implementation independent of this library, in epoch `EPOCH` with the
    /// key `epoch_key()`, of sets for external data: under a 32-byte parent, a set of one key in
    /// "chat 7"; under a 64-byte parent, a set of one key in "chat 8"; and under the 32-byte parent,
    /// in "archive", a full set at revision 9: a disabled key, an enabled key, and the primary, an
    /// enabled key. They are wrapped in this order in one set of slots, the nonce `NONCE` the
    /// source gave each hedged as the next draw.
    const KNOWN_RECORDS: [&str; 3] = [
        concat!(
            "c7a1550603080bf1aa1c51924a6d5d642a6be55972bad74c1f1853ffffd3f2b6",
            "87a3db11f39ee38c96dd1b88f187b7947c74e104117dae2f0839925604a70f42",
            "136a1504e135d2df44843a0151d54fdc5448bb1d12dbd697955817baf260bfb0",
            "c65cc712c3cb3dfac9453e5da727d5c867d3c450b1c5ee07670856a7904003de",
            "85ea07617ceaf7793c998afb52974cc920a9b3f2411b7b206d81c3227c78103a",
            "06d5e1e4de8ff1531a959d6263b93943ccc49c44b46f0624c9d2dda70ea6a3af",
            "650b7418a669bdd26bfb4f16be562faa9c758f09086397456e405ca8d3ddf4cd",
            "5ef8162e01b9a27569c34d7ee96bf6e9af1907bc0393da7fa5ea14d702c0b279",
            "a7e3eb7be7",
        ),
        concat!(
            "2d7fafac78ba33a2056ef2ae5455cae3d7fdb82cbbbf51f1222c1472afc6c4de",
            "ad42046c5440e60d9fa207baec952179ee31580ff66dd9b66838e3f0c7ec9a50",
            "74d27413582decd1b4d69046ca3207fb4a57ad1be9bedb216246b923ff300d50",
            "e7ba44bf501e5c4d7c0c05bd69bd2d285ca3ad35bc9f2a63b765c21e250e3cad",
            "e82f2730f0f24e7dc31803e8bcde5af92a02da96af8cdf785df977ad0cc26383",
            "2642b27e135801595183c6f3bf4563c6d4fe7371563f6d849bdd4765386a7d25",
            "7298a8bf60a67610af91c3bd96e3da969c17b2a64270b4902c0ce93916591de8",
            "df1b8cdfdcca9429c254fd60ead1174a20f86d1a05eb7e18b6707518d210c1c7",
            "ef827ac01a",
        ),
        concat!(
            "27bae2fc323c379d396cc79bd5267624a92673d4a5922e04131e647e01cb6ee2",
            "0e3a9f03774451ccad997c3c206b6735e9f01afa797f67fc5d4cb86f9d9e6828",
            "a88d2d8ffb0f4615acc84e4dcda93b156d9ac1ebdda06befb7752d19f8491ed8",
            "56b959f216ee2c192241587ef1e5d675df0cb2b03ae3d0e1a7c7167d0cabff9e",
            "4eafbe6382f73e213ae345b401f2990b5aba7833a0239f6ad4e35f2bdf985d6a",
            "213bada052007a23fe7ef1aa4ef849cb214c22f77c22fd72d1d017563f44e6fb",
            "2e0600e2b44e53cec455f1871378c58af221c96a6bf16f2ed6ce9bb60f344c8b",
            "647b719d659ec6f538d5afcba724a57f498ef11b0cfd16ca88476a1a95827e9a",
            "573514f847",
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
    /// empty position, for external data.
    fn assert_holds(
        slots: &Slots<'_>,
        handle: Handle<'_>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
    ) {
        assert_holds_for(slots, handle, members, primary, Purpose::ExternalData);
    }

    /// The same, for `purpose`.
    fn assert_holds_for(
        slots: &Slots<'_>,
        handle: Handle<'_>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
        purpose: Purpose,
    ) {
        let slot = &slots.memory[handle.index];
        assert_eq!(slot.occupancy, Occupancy::Loaded);
        assert_eq!((slot.stages.primary(), slot.purpose), (primary, purpose));
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
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let short_parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let short_parent = slots.store(short_parent);
        let first = slots
            .import32(Purpose::ExternalData, &mut pattern(59, 201))
            .unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(
                first,
                short_parent,
                b"chat 7",
                &mut Fixed(&NONCE),
                &mut record,
            )
            .unwrap();
        assert_eq!(record, hex(KNOWN_RECORDS[0]));

        let long_parent = slots.import64(Purpose::Wrap, &mut pattern(97, 13)).unwrap();

        let long_parent = slots.store(long_parent);
        let second = slots
            .import32(Purpose::ExternalData, &mut pattern(31, 7))
            .unwrap();
        slots
            .wrap(
                second,
                long_parent,
                b"chat 8",
                &mut Fixed(&NONCE),
                &mut record,
            )
            .unwrap();
        assert_eq!(record, hex(KNOWN_RECORDS[1]));

        slots.release(first).unwrap();
        slots.release(second).unwrap();
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
        let first = pattern::<32>(59, 201);
        let middle = pattern::<32>(31, 7);
        let last = pattern::<32>(83, 111);
        let cases: [Case<'_>; 3] = [
            (
                &short_parent,
                b"chat 7",
                [Some((Status::Enabled, &first)), None, None],
                0,
            ),
            (
                &long_parent,
                b"chat 8",
                [Some((Status::Enabled, &middle)), None, None],
                0,
            ),
            (
                &short_parent,
                b"archive",
                [
                    Some((Status::Disabled, &first)),
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
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
            let parent = match parent_bytes.len() {
                32 => slots.import32(Purpose::Wrap, &mut parent_bytes.try_into().unwrap()),
                _ => slots.import64(Purpose::Wrap, &mut parent_bytes.try_into().unwrap()),
            }
            .unwrap();
            let parent = slots.store(parent);
            let set = slots.unwrap(parent, context, &hex(known)).unwrap();
            assert_holds(&slots, set, members, primary);
        }
    }

    /// Two slots holding a parent and a key, and the record of the key under the parent.
    fn wrapped<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
    ) -> (Slots<'a>, Handle<'a>, [u8; RECORD_LEN]) {
        let mut slots = Slots::new(memory, epoch, EPOCH, &mut epoch_key());
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let parent = slots.store(parent);
        let key = slots
            .import32(Purpose::ExternalData, &mut pattern(59, 201))
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
        let mut epoch_memory = Epoch::empty();
        let (mut slots, parent, record) = wrapped(&mut memory, &mut epoch_memory);
        for bit in 0..RECORD_LEN * 8 {
            let mut changed = record;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                slots.unwrap(parent, b"chat 7", &changed),
                Err(Error::RecordRejected),
                "bit {bit}"
            );
            assert_eq!(slots.memory[1].occupancy, Occupancy::Free);
            assert_eq!(slots.memory[1].keys[0].bytes(), &padded(&[]));
        }
        assert!(slots.unwrap(parent, b"chat 7", &record).is_ok());
    }

    #[test]
    fn a_record_opens_only_with_its_parent_and_context() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let (mut slots, parent, record) = wrapped(&mut memory, &mut epoch_memory);
        let other = slots.import32(Purpose::Wrap, &mut pattern(97, 14)).unwrap();
        let other = slots.store(other);
        assert_eq!(
            slots.unwrap(other, b"chat 7", &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            slots.unwrap(parent, b"chat 8", &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(slots.memory[2].occupancy, Occupancy::Free);
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
        derive_wrap_key(sealer, &epoch(), &mut cipher_key).unwrap();
        let associated = AssociatedData::new(context).unwrap();
        let mut encrypted = *plaintext;
        let tag = seal::seal(&cipher_key, nonce, associated.bytes(), &mut encrypted).unwrap();
        let mut record = [0; RECORD_LEN];
        write_record(&mut record, nonce, &encrypted, &tag);
        record
    }

    /// The plaintext of the set `members` for external data with `primary`, naming `named` as its
    /// parent, built without `wrap`.
    fn set_plaintext(
        members: [Member<'_>; MEMBERS],
        primary: usize,
        named: [u8; 16],
    ) -> [u8; PLAINTEXT_LEN] {
        set_plaintext_for(members, primary, named, Purpose::ExternalData)
    }

    /// The same, for `purpose`.
    fn set_plaintext_for(
        members: [Member<'_>; MEMBERS],
        primary: usize,
        named: [u8; 16],
        purpose: Purpose,
    ) -> [u8; PLAINTEXT_LEN] {
        let keys =
            members.map(|member| member.map_or_else(Key::empty, |(_, bytes)| key_from(bytes)));
        let stages = Stages::from_parts(
            members.map(|member| member.map(|(stage, _)| stage)),
            primary,
            0,
        );
        let header = Header {
            purpose,
            parent: named,
            epoch: EPOCH,
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

    /// The record of the set `members` with `primary`, sealed under the key of the set `parent`
    /// refers to and naming that key, for `context`.
    fn sealed_under(
        slots: &Slots<'_>,
        parent: Handle<'_>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
        context: &[u8],
    ) -> [u8; RECORD_LEN] {
        let slot = &slots.memory[parent.index];
        let plaintext = set_plaintext(members, primary, slot.ids[0].bytes());
        seal_plaintext(&slot.keys[0], &plaintext, context, &NONCE)
    }

    /// A record opens with one trial, under the key of its parent; naming that parent but sealed under
    /// another key, it is refused, and nothing is loaded.
    #[test]
    fn a_record_opens_under_the_key_of_its_parent_alone() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let parent = slots.store(parent);
        let child = pattern::<32>(13, 5);
        let only = [Some((Status::Enabled, &child[..])), None, None];
        let plaintext = set_plaintext(only, 0, slots.memory[parent.index].ids[0].bytes());
        for (sealer, expected) in [
            (pattern::<32>(3, 1), Ok(())),
            (pattern::<32>(3, 2), Err(Error::RecordRejected)),
        ] {
            let record = seal_plaintext(&key_from(&sealer), &plaintext, b"chat 7", &NONCE);
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
            assert_eq!((tried, result.map(|_| ())), (1, expected));
            if let Ok(handle) = result {
                assert_holds(&slots, handle, only, 0);
                slots.release(handle).unwrap();
            }
            assert_eq!(slots.memory[1].occupancy, Occupancy::Free);
            assert_eq!(slots.memory[1].keys[0].bytes(), &padded(&[]));
        }
    }

    /// `plaintext`, the record of a stored key for wrapping, locked under the key from a secret
    /// `sealer` and then, with the number of the epoch `epoch` names, under the key of that epoch,
    /// for `context`: the inner layer with the first nonce, the outer with the second. Built
    /// without `lock`.
    fn lock_plaintext(
        sealer: &Key,
        plaintext: &[u8; PLAINTEXT_LEN],
        (epoch_key, epoch): (&Key, u64),
        context: &[u8],
        nonces: [&[u8; 12]; 2],
    ) -> [u8; LOCK_RECORD_LEN] {
        let associated = AssociatedData::new(context).unwrap();
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        derive_lock_key(sealer, &mut cipher_key).unwrap();
        let mut encrypted = *plaintext;
        let tag = seal::seal(&cipher_key, nonces[0], associated.bytes(), &mut encrypted).unwrap();
        let mut inner = [0; RECORD_LEN];
        write_record(&mut inner, nonces[0], &encrypted, &tag);
        let mut layer_key = [0; CIPHER_KEY_LEN];
        derive_layer_key(epoch_key, &mut layer_key).unwrap();
        let mut layer = [0; LAYER_LEN];
        layer[..8].copy_from_slice(&epoch.to_le_bytes());
        layer[8..].copy_from_slice(&inner);
        let tag = seal::seal(&layer_key, nonces[1], associated.bytes(), &mut layer).unwrap();
        let mut record = [0; LOCK_RECORD_LEN];
        record[..12].copy_from_slice(nonces[1]);
        record[12..12 + LAYER_LEN].copy_from_slice(&layer);
        record[12 + LAYER_LEN..].copy_from_slice(&tag);
        record
    }

    /// `plaintext` naming epoch zero, as the plaintext of a lock record does.
    fn of_epoch_zero(mut plaintext: [u8; PLAINTEXT_LEN]) -> [u8; PLAINTEXT_LEN] {
        plaintext[19..27].copy_from_slice(&[0; 8]);
        plaintext
    }

    /// The plaintext of the set `members` for wrapping, naming `named` as its parent, as a lock
    /// record holds it: in epoch zero.
    fn lock_set_plaintext(
        members: [Member<'_>; MEMBERS],
        primary: usize,
        named: [u8; 16],
    ) -> [u8; PLAINTEXT_LEN] {
        let mut plaintext = set_plaintext_for(members, primary, named, Purpose::Wrap);
        plaintext[19..27].copy_from_slice(&[0; 8]);
        plaintext
    }

    /// A record holds a set for wrapping only in a lock record, and there only a set of one that has
    /// never changed: a plain record of one, a lock record of a set for external data, of more
    /// keys, of a changed set or of an epoch, are refused although they open.
    #[test]
    fn a_set_for_wrapping_comes_back_only_from_a_lock_record_of_one_key() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let stored = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let stored = slots.store(stored);
        let named = slots.memory[stored.index].ids[0].bytes();
        let (first, second) = (pattern::<32>(5, 2), pattern::<64>(7, 3));
        let one = [Some((Status::Enabled, &first[..])), None, None];
        let plain = set_plaintext_for(one, 0, named, Purpose::Wrap);
        let record = seal_plaintext(&key_from(&pattern::<32>(3, 1)), &plain, b"set", &NONCE);
        assert_eq!(
            slots.unwrap(stored, b"set", &record),
            Err(Error::RecordRejected)
        );

        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 4)).unwrap();
        let named = slots.memory[secret.index].ids[0].bytes();
        let sealer = key_from(&pattern::<32>(3, 4));
        let epoch = (&epoch(), EPOCH);
        let lock = |plaintext: &[u8; PLAINTEXT_LEN]| {
            lock_plaintext(&sealer, plaintext, epoch, b"set", [&NONCE, &NONCE])
        };
        let mut changed = lock_set_plaintext(one, 0, named);
        changed[27] = 1;
        let mut of_an_epoch = lock_set_plaintext(one, 0, named);
        of_an_epoch[19] = 1;
        let two = [
            Some((Status::Enabled, &first[..])),
            Some((Status::Enabled, &second[..])),
            None,
        ];
        let elsewhere = [None, Some((Status::Enabled, &second[..])), None];
        let refused = [
            lock(&of_epoch_zero(set_plaintext(one, 0, named))),
            lock(&lock_set_plaintext(two, 0, named)),
            lock(&lock_set_plaintext(elsewhere, 1, named)),
            lock(&changed),
            lock(&of_an_epoch),
        ];
        let accepted = lock(&lock_set_plaintext(one, 0, named));
        for record in refused {
            assert_eq!(
                slots.unlock(secret, b"set", &record),
                Err(Error::RecordRejected)
            );
            assert_eq!(slots.memory[2].occupancy, Occupancy::Free);
        }
        let set = slots.unlock(secret, b"set", &accepted).unwrap();
        assert_holds_for(&slots, set, one, 0, Purpose::Wrap);
        assert!(!slots.memory[set.index].unlocks);
    }

    /// A stored key for wrapping comes back from its lock record under the key from a secret it was
    /// locked under, as the stored key it was, and wraps keys for external data.
    #[test]
    fn a_stored_key_comes_back_from_its_lock_record() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
        let mut record = [0; LOCK_RECORD_LEN];
        slots
            .lock(stored, secret, b"profile", &mut Counting, &mut record)
            .unwrap();
        slots.release(stored).unwrap();
        let back = slots.unlock(secret, b"profile", &record).unwrap();
        let generated = hedged(0, b"hedge key", &counted::<64>(), 64);
        let only = [Some((Status::Enabled, &generated[..])), None, None];
        assert_holds_for(&slots, back, only, 0, Purpose::Wrap);
        assert!(slots.memory[secret.index].unlocks && !slots.memory[back.index].unlocks);
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(5, 2))
            .unwrap();
        let mut plain = [0; RECORD_LEN];
        slots
            .wrap(data, back, b"chat", &mut Counting, &mut plain)
            .unwrap();
    }

    /// Each key wraps and unwraps only at its level: a key from a secret only stored keys for
    /// wrapping, in lock records, and a stored key only keys for external data, in plain records.
    /// Every other pairing is refused as `WrongLevel`, writes nothing and changes no slot.
    #[test]
    fn every_key_wraps_only_at_its_level() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let other_secret = slots.import64(Purpose::Wrap, &mut pattern(3, 2)).unwrap();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let other_stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
            .unwrap();
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(5, 2))
            .unwrap();
        let before = holdings(&slots);
        let mut plain = [0x55; RECORD_LEN];
        for (set, parent) in [
            (data, secret),
            (stored, other_stored),
            (secret, other_stored),
        ] {
            assert_eq!(
                slots.wrap(set, parent, b"x", &mut Untouched, &mut plain),
                Err(Error::WrongLevel)
            );
        }
        let mut locked = [0x55; LOCK_RECORD_LEN];
        for (set, parent) in [
            (data, secret),
            (other_secret, secret),
            (stored, other_stored),
        ] {
            assert_eq!(
                slots.lock(set, parent, b"x", &mut Untouched, &mut locked),
                Err(Error::WrongLevel)
            );
        }
        assert_eq!(slots.unwrap(secret, b"x", &plain), Err(Error::WrongLevel));
        assert_eq!(slots.unlock(stored, b"x", &locked), Err(Error::WrongLevel));
        assert_eq!(
            (plain, locked, holdings(&slots)),
            ([0x55; RECORD_LEN], [0x55; LOCK_RECORD_LEN], before)
        );
        slots
            .wrap(data, stored, b"x", &mut Counting, &mut plain)
            .unwrap();
        slots
            .lock(stored, secret, b"x", &mut Counting, &mut locked)
            .unwrap();
    }

    /// A lock record opens only with its key from a secret and its context, and every changed bit
    /// of it is refused, loading nothing: under another key from a secret it is `RecordRejected`,
    /// for another context or changed `StaleRecord`.
    #[test]
    fn a_lock_record_opens_only_with_its_secret_and_context() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let other = slots.import32(Purpose::Wrap, &mut pattern(3, 2)).unwrap();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let mut record = [0; LOCK_RECORD_LEN];
        slots
            .lock(stored, secret, b"profile", &mut Counting, &mut record)
            .unwrap();
        slots.release(stored).unwrap();
        assert_eq!(
            slots.unlock(other, b"profile", &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            slots.unlock(secret, b"profile 2", &record),
            Err(Error::StaleRecord)
        );
        for bit in 0..LOCK_RECORD_LEN * 8 {
            let mut changed = record;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                slots.unlock(secret, b"profile", &changed),
                Err(Error::StaleRecord),
                "bit {bit}"
            );
        }
        assert_eq!(slots.memory[2].occupancy, Occupancy::Free);
        assert!(slots.unlock(secret, b"profile", &record).is_ok());
    }

    /// A lock record is carried into the next epoch without its key from a secret, which no slot
    /// then holds. After the commit the carried copy opens and the old one does not, nor does a
    /// record left behind: so a way in is revoked. A carry needs a change under way, the record's
    /// context and a record of this epoch, and writes nothing otherwise.
    #[test]
    fn a_lock_record_is_carried_into_the_next_epoch_without_its_secret() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut platform = Platform::default();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let (mut kept, mut left) = ([0; LOCK_RECORD_LEN], [0; LOCK_RECORD_LEN]);
        for (bytes, record) in [(pattern(3, 1), &mut kept), (pattern(3, 2), &mut left)] {
            let secret = slots.import32(Purpose::Wrap, &mut bytes.clone()).unwrap();
            slots
                .lock(stored, secret, b"profile", &mut Counting, record)
                .unwrap();
            slots.release(secret).unwrap();
        }
        slots.release(stored).unwrap();
        let mut carried = [0x55; LOCK_RECORD_LEN];
        assert_eq!(
            slots.carry(b"profile", &mut Untouched, &kept, &mut carried),
            Err(Error::NoEpochChange)
        );
        slots.begin_epoch(&mut flipped_epoch_key(0xff)).unwrap();
        assert_eq!(
            slots.carry(b"other", &mut Untouched, &kept, &mut carried),
            Err(Error::StaleRecord)
        );
        assert_eq!(carried, [0x55; LOCK_RECORD_LEN]);
        slots
            .carry(b"profile", &mut Counting, &kept, &mut carried)
            .unwrap();
        let mut again = [0x55; LOCK_RECORD_LEN];
        assert_eq!(
            slots.carry(b"profile", &mut Untouched, &carried, &mut again),
            Err(Error::StaleRecord)
        );
        assert_eq!(slots.commit_epoch(&mut platform), Ok(Erasure::Guaranteed));
        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        assert_eq!(
            slots.unlock(secret, b"profile", &kept),
            Err(Error::StaleRecord)
        );
        let back = slots.unlock(secret, b"profile", &carried).unwrap();
        slots.release(back).unwrap();
        let revoked = slots.import32(Purpose::Wrap, &mut pattern(3, 2)).unwrap();
        assert_eq!(
            slots.unlock(revoked, b"profile", &left),
            Err(Error::StaleRecord)
        );
    }

    /// A lock record made during a change of epoch is of the next epoch: it opens only once the
    /// change is committed, and never if the change is abandoned.
    #[test]
    fn a_lock_during_a_change_is_of_the_next_epoch() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut platform = Platform::default();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let (mut abandoned, mut committed) = ([0; LOCK_RECORD_LEN], [0; LOCK_RECORD_LEN]);
        slots.begin_epoch(&mut flipped_epoch_key(0x0f)).unwrap();
        slots
            .lock(stored, secret, b"profile", &mut Counting, &mut abandoned)
            .unwrap();
        assert_eq!(slots.abandon_epoch(&mut platform), Ok(Erasure::Guaranteed));
        slots.begin_epoch(&mut flipped_epoch_key(0xff)).unwrap();
        slots
            .lock(stored, secret, b"profile", &mut Counting, &mut committed)
            .unwrap();
        slots.release(stored).unwrap();
        assert_eq!(
            slots.unlock(secret, b"profile", &committed),
            Err(Error::StaleRecord)
        );
        assert_eq!(slots.commit_epoch(&mut platform), Ok(Erasure::Guaranteed));
        assert_eq!(
            slots.unlock(secret, b"profile", &abandoned),
            Err(Error::StaleRecord)
        );
        let back = slots.unlock(secret, b"profile", &committed).unwrap();
        slots.release(back).unwrap();
    }

    /// A lock record and the same record carried into the next epoch, computed by an implementation
    /// independent of this library: a 64-byte stored key under a 32-byte key from a secret, in
    /// "profile", the nonce `NONCE` the source gave each hedged as the next draw, the inner one
    /// first; the next epoch's key is the key of the test epoch with every bit flipped.
    const KNOWN_LOCK: &str = concat!(
        "2d7fafac78ba33a2056ef2ae3f24eeb2ce9eb701f1b749b053ca457729fa13cf",
        "9c420772e867b9a831a0d611dca35747abee9a63e482baf4e4881c1a967e7984",
        "b955d24cdc33545ed73767926871082de098a0f878c2492683138014ba490069",
        "2559b87e53295bdb6efc67082430feaa96df3cf86e2ac8156158a46fb616dc3d",
        "551bbf103b63e057eefd519d23e9df2ce4e83020e017943665ff8fc70afc90ca",
        "11de5d9bb76d4cbecd0916c3eae31589f459328c2f843aeeb45183aca3454aea",
        "ef565d2a95cca038a56bea795f436e81113cd99a6df3e78f787dab6936f1a927",
        "abe4696cd15dd73196b28f512c424a862d1285905b8cede0c8b3449d75e32599",
        "9444629fc37233caeba54c034c9ed738293e4be39acb99f7e2075beb440e1768",
        "4cffa1962d553e77e7",
    );
    const KNOWN_CARRIED: &str = concat!(
        "0bae0f1cf9c58c7fc766995bb27c08d9b917b6837aac371e7bfe8e1fab9cb011",
        "fc4f2071c9e9b5c1f99f0de028b4d2fcda1b881703d2f58aa30875fb10913203",
        "3b7483a2f4f320c988f279ab244e394269c356051e483c48457c2a715e4f7c25",
        "44bf09614a7d8e890a77ea1d2cbdb91dd9126b76f8e0f2b4d19f497cc2328ac4",
        "3e487530e938956349dc50914cf706cdbfe15f68c090f1288f075792534d3358",
        "02e72c78b20870397fb4570eedc7a1a10b5d9666ce85e4481476e5d220de0197",
        "9da5a02ba0e900b714213e30e5399bcd0fa94e0f410411f158b3eb51d9d42c40",
        "5dc072cffd439eae3ef797cefc62a3388164dd849a6fe8887ad7fea89fe440fc",
        "f45bcbfeb1c3e94f5e97c45c6fec3647c97e5bba3589884a6e2103159e150f12",
        "b94577fad3ecce52fa",
    );

    fn lock_hex(text: &str) -> [u8; LOCK_RECORD_LEN] {
        core::array::from_fn(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
    }

    #[test]
    fn lock_records_match_ones_computed_independently() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let secret = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let stored = slots
            .import64(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        let stored = slots.store(stored);
        let mut record = [0; LOCK_RECORD_LEN];
        slots
            .lock(stored, secret, b"profile", &mut Fixed(&NONCE), &mut record)
            .unwrap();
        assert_eq!(record, lock_hex(KNOWN_LOCK));
        slots.release(stored).unwrap();
        let back = slots.unlock(secret, b"profile", &record).unwrap();
        let key = pattern::<64>(59, 201);
        let only = [Some((Status::Enabled, &key[..])), None, None];
        assert_holds_for(&slots, back, only, 0, Purpose::Wrap);
        slots.begin_epoch(&mut flipped_epoch_key(0xff)).unwrap();
        let mut carried = [0; LOCK_RECORD_LEN];
        slots
            .carry(b"profile", &mut Fixed(&NONCE), &record, &mut carried)
            .unwrap();
        assert_eq!(carried, lock_hex(KNOWN_CARRIED));
    }

    /// A key is held in one place only: an import of a key held here, and a set that holds such a
    /// key or one key twice, are refused, and leave the source and every slot as they were.
    #[test]
    fn a_key_is_held_in_one_place_only() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let held = pattern::<32>(97, 13);
        let mut source = held;
        let root = slots.import32(Purpose::Wrap, &mut source).unwrap();
        let root = slots.store(root);
        let mut again = held;
        assert_eq!(
            slots.import32(Purpose::Wrap, &mut again),
            Err(Error::DuplicateKey)
        );
        assert_eq!(again, held);
        let other = pattern::<32>(5, 6);
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
            let record = sealed_under(&slots, root, members, 0, b"chat 7");
            let before = holdings(&slots);
            assert_eq!(
                slots.unwrap(root, b"chat 7", &record),
                Err(Error::DuplicateKey)
            );
            assert_eq!(holdings(&slots), before);
        }
        let mut source = other;
        let set = slots.import32(Purpose::ExternalData, &mut source).unwrap();
        slots.release(set).unwrap();
        let mut source = other;
        assert!(slots.import32(Purpose::ExternalData, &mut source).is_ok());
    }

    #[test]
    fn a_set_cannot_wrap_itself() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let mut record = [0x55; RECORD_LEN];
        assert_eq!(
            slots.wrap(set, set, b"chat 7", &mut Counting, &mut record),
            Err(Error::SameKey)
        );
        assert_eq!(record, [0x55; RECORD_LEN]);
    }

    /// Only a key for wrapping wraps and unwraps: a parent of another purpose is refused, and
    /// nothing changes.
    #[test]
    fn only_a_wrapping_key_wraps_and_unwraps() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(97, 13))
            .unwrap();
        let set = slots
            .import32(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        let set = slots.store(set);
        let mut record = [0x55; RECORD_LEN];
        let before = holdings(&slots);
        assert_eq!(
            slots.wrap(set, data, b"chat 7", &mut Counting, &mut record),
            Err(Error::WrongPurpose)
        );
        assert_eq!(record, [0x55; RECORD_LEN]);
        assert_eq!(
            slots.unwrap(data, b"chat 7", &hex(KNOWN_RECORDS[0])),
            Err(Error::WrongPurpose)
        );
        assert_eq!(holdings(&slots), before);
        slots
            .wrap(data, set, b"chat 9", &mut Counting, &mut record)
            .unwrap();
    }

    /// A key for external data is 32 bytes: a longer one is refused by every load and addition
    /// before anything else happens, and a record that holds one does not open.
    #[test]
    fn a_purpose_takes_only_its_key_lengths() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let mut long = pattern::<64>(5, 2);
        assert_eq!(
            slots.import64(Purpose::ExternalData, &mut long),
            Err(Error::WrongLength)
        );
        assert_eq!(long, pattern::<64>(5, 2));
        let mut source = Recording {
            calls: 0,
            asked: 0,
            at: 0,
        };
        assert_eq!(
            slots.generate(Purpose::ExternalData, KeyLength::Bytes64, &mut source),
            Err(Error::WrongLength)
        );
        assert_eq!(source.calls, 0, "the source is not asked");
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(97, 13))
            .unwrap();
        let before = holdings(&slots);
        assert_eq!(
            slots.add_generated(data, KeyLength::Bytes64, &mut source),
            Err(Error::WrongLength)
        );
        assert_eq!(source.calls, 0, "the source is not asked");
        assert_eq!(holdings(&slots), before);
        assert!(slots.add32(data, &mut pattern(11, 4)).is_ok());

        let root = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();

        let root = slots.store(root);
        let named = slots.memory[root.index].ids[0].bytes();
        let plaintext = set_plaintext([Some((Status::Enabled, &long)), None, None], 0, named);
        let record = seal_plaintext(&slots.memory[root.index].keys[0], &plaintext, b"x", &NONCE);
        slots.settle();
        let before = holdings(&slots);
        assert_eq!(
            slots.unwrap(root, b"x", &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(holdings(&slots), before);
    }

    /// The same bytes are one key whatever they serve: a load or an addition of a key held for
    /// another purpose is refused.
    #[test]
    fn a_key_is_held_once_across_purposes() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let wrapping = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let mut source = pattern::<32>(97, 13);
        assert_eq!(
            slots.import32(Purpose::ExternalData, &mut source),
            Err(Error::DuplicateKey)
        );
        assert_eq!(source, pattern::<32>(97, 13));
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(59, 201))
            .unwrap();
        assert_eq!(
            slots.add32(data, &mut pattern(97, 13)),
            Err(Error::DuplicateKey)
        );
        assert_eq!(
            slots.import32(Purpose::Wrap, &mut pattern(59, 201)),
            Err(Error::DuplicateKey)
        );
        slots.release(wrapping).unwrap();
        assert!(slots.add32(data, &mut pattern(97, 13)).is_ok());
    }

    /// A key for external data comes out only to a call that names its purpose, from an enabled
    /// position; no other key ever does, and a refusal leaves the output as it was.
    #[test]
    fn only_an_enabled_key_for_external_data_is_revealed() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(97, 13))
            .unwrap();
        let at = slots.add32(data, &mut pattern(59, 201)).unwrap();
        slots.settle();
        let mut out = [0x55; 32];
        slots
            .reveal32(data, Position::First, Purpose::ExternalData, &mut out)
            .unwrap();
        assert_eq!(out, pattern::<32>(97, 13));
        slots
            .reveal32(data, at, Purpose::ExternalData, &mut out)
            .unwrap();
        assert_eq!(out, pattern::<32>(59, 201));

        let wrapping = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let mut out = [0x55; 32];
        for (set, purpose) in [
            (wrapping, Purpose::Wrap),
            (wrapping, Purpose::ExternalData),
            (data, Purpose::Wrap),
        ] {
            assert_eq!(
                slots.reveal32(set, Position::First, purpose, &mut out),
                Err(Error::WrongPurpose)
            );
        }
        assert_eq!(
            slots.reveal32(data, Position::Third, Purpose::ExternalData, &mut out),
            Err(Error::WrongStage)
        );
        slots.disable(data, at).unwrap();
        assert_eq!(
            slots.reveal32(data, at, Purpose::ExternalData, &mut out),
            Err(Error::WrongStage)
        );
        assert_eq!(out, [0x55; 32]);
        slots.settle();
        slots.release(data).unwrap();
        assert_eq!(
            slots.reveal32(data, Position::First, Purpose::ExternalData, &mut out),
            Err(Error::StaleHandle)
        );
        assert_eq!(out, [0x55; 32]);
    }

    /// A set for external data comes back from its record for external data: its key is revealed,
    /// and it wraps nothing.
    #[test]
    fn a_set_for_external_data_comes_back_for_external_data() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let root = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let root = slots.store(root);
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(59, 201))
            .unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(data, root, b"chat 9", &mut Counting, &mut record)
            .unwrap();
        slots.release(data).unwrap();
        let back = slots.unwrap(root, b"chat 9", &record).unwrap();
        assert_eq!(slots.memory[back.index].purpose, Purpose::ExternalData);
        let mut out = [0; 32];
        slots
            .reveal32(back, Position::First, Purpose::ExternalData, &mut out)
            .unwrap();
        assert_eq!(out, pattern::<32>(59, 201));
        assert_eq!(
            slots.wrap(root, back, b"x", &mut Counting, &mut record),
            Err(Error::WrongPurpose)
        );
    }

    /// A set keeps the stage of each key and its primary through an unwrap and a wrap.
    #[test]
    fn a_set_comes_out_of_a_wrap_as_it_went_in() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let root = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let root = slots.store(root);
        let (first, third) = (pattern::<32>(5, 2), pattern::<32>(11, 4));
        let members = [
            Some((Status::Enabled, &first[..])),
            None,
            Some((Status::Disabled, &third[..])),
        ];
        let record = sealed_under(&slots, root, members, 0, b"chat 7");
        let set = slots.unwrap(root, b"chat 7", &record).unwrap();
        assert_holds(&slots, set, members, 0);
        let mut out = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"chat 7", &mut Fixed(&NONCE), &mut out)
            .unwrap();
        let slot = &slots.memory[root.index];
        let plaintext = set_plaintext(members, 0, slot.ids[0].bytes());
        let nonce = hedged(0, b"hedge nonce", &NONCE, 12).try_into().unwrap();
        assert_eq!(
            out,
            seal_plaintext(&slot.keys[0], &plaintext, b"chat 7", &nonce)
        );
    }

    /// During a change of epoch the nonce of a record, and of the outer layer of a lock record, is
    /// hedged with the key of the next epoch, the key the record is wrapped in.
    #[test]
    fn a_nonce_during_a_change_is_hedged_with_the_next_key() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let root = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let root = slots.store(root);
        let set = slots
            .import32(Purpose::ExternalData, &mut pattern(5, 2))
            .unwrap();
        let next = flipped_epoch_key(0x5a);
        slots.begin_epoch(&mut next.clone()).unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"x", &mut Fixed(&NONCE), &mut record)
            .unwrap();
        let nonce = crate::derive::direct::hedged_directly(&next, 0, b"hedge nonce", &NONCE, 12);
        assert_eq!(record[..12], nonce[..]);
        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 4)).unwrap();
        let stored = slots.import32(Purpose::Wrap, &mut pattern(3, 5)).unwrap();
        let stored = slots.store(stored);
        let mut locked = [0; LOCK_RECORD_LEN];
        slots
            .lock(stored, secret, b"x", &mut Fixed(&NONCE), &mut locked)
            .unwrap();
        let outer = crate::derive::direct::hedged_directly(&next, 2, b"hedge nonce", &NONCE, 12);
        assert_eq!(locked[..12], outer[..]);
    }

    /// The count of draws moves by one with each draw the source answers, and neither with a failed
    /// draw nor with an import, a release, an unwrap or a change of epoch, begun, committed or
    /// abandoned.
    #[test]
    fn the_count_moves_only_with_answered_draws() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let root = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let root = slots.store(root);
        let set = slots
            .generate(Purpose::ExternalData, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        assert_eq!(slots.epoch.drawn, 1);
        let failed = slots.generate(Purpose::Wrap, KeyLength::Bytes32, &mut Failing);
        assert_eq!(failed, Err(Error::EntropyFailed));
        assert_eq!(slots.epoch.drawn, 1);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, root, b"x", &mut Counting, &mut record)
            .unwrap();
        assert_eq!(slots.epoch.drawn, 2);
        slots.release(set).unwrap();
        let set = slots.unwrap(root, b"x", &record).unwrap();
        slots.begin_epoch(&mut flipped_epoch_key(1)).unwrap();
        assert_eq!(slots.epoch.drawn, 2);
        slots
            .wrap(set, root, b"x", &mut Counting, &mut record)
            .unwrap();
        let _ = slots.commit_epoch(&mut Platform::default()).unwrap();
        assert_eq!(slots.epoch.drawn, 3);
        slots.begin_epoch(&mut flipped_epoch_key(2)).unwrap();
        let _ = slots.abandon_epoch(&mut Platform::default()).unwrap();
        assert_eq!(slots.epoch.drawn, 3);
    }

    /// A source that gives the same bytes every time still gives different keys, words and nonces:
    /// each draw is hedged with its own count.
    #[test]
    fn a_source_that_repeats_itself_gives_different_bytes() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let first = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let second = slots
            .generate(Purpose::ExternalData, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        assert_ne!(
            slots.memory[first.index].keys[0].bytes(),
            slots.memory[second.index].keys[0].bytes()
        );
        let (mut one, mut two) = ([0; RECORD_LEN], [0; RECORD_LEN]);
        slots
            .wrap(second, first, b"x", &mut Counting, &mut one)
            .unwrap();
        slots
            .wrap(second, first, b"x", &mut Counting, &mut two)
            .unwrap();
        assert_ne!(one[..12], two[..12]);
        let (mut words, mut more) = ([[0; 8]; 12], [[0; 8]; 12]);
        slots.generate_words(&mut Counting, &mut words).unwrap();
        slots.generate_words(&mut Counting, &mut more).unwrap();
        assert_ne!(words, more);
    }

    #[test]
    fn a_record_that_names_another_parent_or_is_malformed_is_rejected() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let parent = slots.store(parent);
        let child = pattern::<32>(59, 201);
        let members = [Some((Status::Enabled, &child[..])), None, None];
        let parent_id = slots.memory[0].ids[0].bytes();
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
            assert_eq!(slots.memory[1].occupancy, Occupancy::Free);
        }
        let record = seal_plaintext(&parent_key, &good, b"chat 7", &NONCE);
        assert!(slots.unwrap(parent, b"chat 7", &record).is_ok());
    }

    #[test]
    fn a_failed_wrap_leaves_the_record_as_it_was() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let parent = slots.store(parent);
        let key = slots
            .import32(Purpose::ExternalData, &mut pattern(59, 201))
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
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let parent = slots.store(parent);
        let mut key = slots
            .import32(Purpose::ExternalData, &mut pattern(59, 201))
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
        let mut epoch_memory = Epoch::empty();
        let (mut slots, parent, record) = wrapped(&mut memory, &mut epoch_memory);
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
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let handle = slots.import32(Purpose::Wrap, &mut secret()).unwrap();
        assert_eq!(format!("{handle:?}"), "Handle { .. }");
        assert_eq!(format!("{:?}", slots.memory[0]), "Slot { .. }");
        assert_eq!(format!("{slots:?}"), "Slots { .. }");
        assert_eq!(format!("{:?}", slots.epoch), "Epoch { .. }");
    }

    impl Random {
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
            .memory
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
            .memory
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

    /// The parent of a round: a key imported as a set of one, among other sets and released slots.
    fn random_parent<'a>(slots: &mut Slots<'a>, random: &mut Random) -> Handle<'a> {
        let parent = match random.key().len() {
            32 => slots.import32(Purpose::Wrap, &mut random.bytes()),
            _ => slots.import64(Purpose::Wrap, &mut random.bytes()),
        }
        .unwrap();
        let parent = slots.store(parent);
        for _ in 0..random.below(3) {
            let filler = slots.import64(Purpose::Wrap, &mut random.bytes()).unwrap();
            if random.below(2) == 0 {
                slots.release(filler).unwrap();
            }
        }
        parent
    }

    /// The plaintext of a random set for either purpose at a random revision naming `named`, at
    /// times with a key held in `held` or one key twice, left as built, wholly random or with one
    /// byte changed. A set of external data mostly holds 32-byte keys, as it has to, and one for
    /// wrapping is half the time a set of one that has never changed, as it has to be.
    fn random_plaintext(
        random: &mut Random,
        named: [u8; 16],
        held: &[Vec<u8>],
    ) -> [u8; PLAINTEXT_LEN] {
        let purpose = if random.below(2) == 0 {
            Purpose::Wrap
        } else {
            Purpose::ExternalData
        };
        let one = purpose == Purpose::Wrap && random.below(2) == 0;
        let (stages, primary) = if one {
            ([Some(Status::Enabled), None, None], 0)
        } else {
            random_stages(random)
        };
        let mut keys: Vec<Vec<u8>> = (0..MEMBERS).map(|_| random.key()).collect();
        if purpose == Purpose::ExternalData && random.below(4) != 0 {
            for key in &mut keys {
                key.truncate(32);
            }
        }
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
        let mut plaintext = set_plaintext_for(members, primary, named, purpose);
        if !one {
            plaintext[27..35].copy_from_slice(&random.bytes::<8>());
        }
        match random.below(4) {
            0 => plaintext = random.bytes(),
            1 => plaintext[random.below(PLAINTEXT_LEN)] ^= random.bytes::<1>()[0] | 1,
            _ => {}
        }
        plaintext
    }

    /// The keys of `plaintext` by position, if slots in the epoch `EPOCH` accept it: version 1,
    /// purpose 1 or 2, that epoch, each position zero throughout or stage 1 or 2 with length 32 or
    /// 64, only 32 for purpose 2, and zeros past the key, and an enabled key at the primary
    /// position, and purpose 2: a plain record holds no set for wrapping. Read from the layout, not
    /// by the parser.
    fn accepted_keys(plaintext: &[u8; PLAINTEXT_LEN]) -> Option<[Option<Vec<u8>>; MEMBERS]> {
        let primary = usize::from(plaintext[2]);
        if plaintext[0] != 1
            || !(plaintext[1] == 1 || plaintext[1] == 2)
            || plaintext[19..27] != EPOCH.to_le_bytes()
            || primary >= MEMBERS
            || plaintext[35 + 66 * primary] != 1
        {
            return None;
        }
        let mut keys: [Option<Vec<u8>>; MEMBERS] = Default::default();
        for (at, key) in keys.iter_mut().enumerate() {
            let position = &plaintext[35 + 66 * at..35 + 66 * (at + 1)];
            let length = usize::from(position[1]);
            match position[0] {
                0 if position.iter().all(|&byte| byte == 0) => {}
                1 | 2
                    if (length == 32 || (length == 64 && plaintext[1] == 1))
                        && position[2 + length..].iter().all(|&byte| byte == 0) =>
                {
                    *key = Some(position[2..2 + length].to_vec());
                }
                _ => return None,
            }
        }
        (plaintext[1] == 2).then_some(keys)
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
        if plaintext[1] == 2 {
            holding.6 = Purpose::ExternalData;
        }
        holding
    }

    /// Records sealed through the real derivation and cipher under the key of a random parent or
    /// under a key outside it, with random sets, keys held elsewhere, contexts of 0 to 300 bytes,
    /// and random changes to the plaintext, the record or the context: unwrapping never panics,
    /// refuses exactly what it should, with the error it should, loads the set the plaintext holds
    /// into the first free slot with that slot's generation when it accepts, and changes no other
    /// slot, or none when it refuses.
    fn unwrap_random_records(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        for round in 0..rounds {
            let mut memory = [const { Slot::empty() }; 4];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
            let parent = random_parent(&mut slots, &mut random);
            let parent_slot = &slots.memory[parent.index];
            let parent_key = &parent_slot.keys[0];
            let outsider = key_from(&random.key());
            let by_parent = random.below(8) != 0;
            let sealer = key_from(if by_parent {
                &parent_key.bytes()[..parent_key.length().bytes()]
            } else {
                &outsider.bytes()[..outsider.length().bytes()]
            });
            let sealer_id = id_of(&sealer).bytes();
            let named = if random.below(8) == 0 {
                random.bytes()
            } else {
                sealer_id
            };
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
            let opens = !changed && !other_context && by_parent && plaintext[3..19] == sealer_id;
            let parsed = accepted_keys(&plaintext)
                .map(|keys| keys.into_iter().flatten().collect::<Vec<Vec<u8>>>());
            let expected = if !valid_context {
                Err(Error::InvalidContext)
            } else if first_free.is_none() {
                Err(Error::NoFreeSlot)
            } else if !opens {
                Err(Error::RecordRejected)
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
        unwrap_random_records(
            from_environment("LETHEWIS_RANDOM_ROUNDS", 100_000),
            from_environment("LETHEWIS_RANDOM_SEED", 2),
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
    //! What wrapping, unwrapping and revealing leave on the stack, read back from the memory of this
    //! process.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use aes::Aes256;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    use super::tests::{
        EPOCH, LOAD_NEEDS, WRAP_NEEDS, epoch_key, flipped_epoch, flipped_epoch_key,
    };
    use super::{
        Entropy, EntropyError, Epoch, Error, Handle, Header, LAYER_LEN, LOCK_RECORD_LEN, MEMBERS,
        Out, Position, Purpose, RECORD_LEN, Slot, Slots, Stages, Status, keyset, write_record,
    };
    use crate::derive::{
        Branch, CIPHER_STACK_WIPE, SALT, STACK_WIPE, derive_layer_key, derive_lock_key,
        derive_wrap_key, stack::secrets,
    };
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

    /// The key of the parent, which wraps the child set: 64 bytes.
    fn parent_bytes(flip: u8) -> [u8; 64] {
        pattern(43, 9, 64, flip).try_into().unwrap()
    }

    /// The keys of the child set, for external data.
    fn child_keys(flip: u8) -> [Vec<u8>; MEMBERS] {
        [
            pattern(29, 101, 32, flip),
            pattern(31, 103, 32, flip),
            pattern(37, 107, 32, flip),
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
        keystream_of(enc_key, tag, PLAINTEXT_LEN)
    }

    /// The same, `length` bytes long.
    fn keystream_of(enc_key: &[u8; 32], tag: &[u8; 16], length: usize) -> Vec<u8> {
        let mut block = *tag;
        block[15] |= 0x80;
        let first = u32::from_le_bytes(block[..4].try_into().unwrap());
        let blocks = u32::try_from(length.div_ceil(16)).unwrap();
        (0..blocks)
            .flat_map(|step| {
                block[..4].copy_from_slice(&first.wrapping_add(step).to_le_bytes());
                encrypt(enc_key, block)
            })
            .collect()
    }

    /// Loads, under the key `parent` refers to, the set of `keys` for external data with `stages`
    /// and `primary`, by unwrapping a record of it.
    fn loaded_set(
        slots: &mut Slots<'_>,
        parent: Handle<'static>,
        keys: &[Vec<u8>; MEMBERS],
        stages: [Option<Status>; MEMBERS],
        primary: usize,
    ) -> Handle<'static> {
        let keys = keys.each_ref().map(|bytes| key_from(bytes));
        let header = Header {
            purpose: Purpose::ExternalData,
            parent: slots.memory[parent.index].ids[0].bytes(),
            epoch: EPOCH,
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
            &slots.memory[parent.index].keys[0],
            &slots.epoch.key,
            &mut cipher_key,
        )
        .unwrap();
        let associated = AssociatedData::new(SET_CONTEXT).unwrap();
        let tag = seal::seal(&cipher_key, &NONCE, associated.bytes(), &mut plaintext).unwrap();
        let mut record = [0; RECORD_LEN];
        write_record(&mut record, &NONCE, &plaintext, &tag);
        widen(slots.unwrap(parent, SET_CONTEXT, &record).unwrap())
    }

    /// The parent, and the child set, whose first key is disabled and whose third is the primary,
    /// all made from `flip`ped patterns.
    fn sets(slots: &mut Slots<'_>, flip: u8) -> (Handle<'static>, Handle<'static>) {
        let parent = slots
            .import64(Purpose::Wrap, &mut parent_bytes(flip))
            .unwrap();
        let parent = widen(slots.store(parent));
        let (enabled, disabled) = (Some(Status::Enabled), Some(Status::Disabled));
        let child = loaded_set(
            slots,
            parent,
            &child_keys(flip),
            [disabled, enabled, enabled],
            2,
        );
        (parent, child)
    }

    /// What is measured: a wrap, the trial of an unwrap whose record the key does not open, or a
    /// whole unwrap.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Work {
        Wrap,
        Trial,
        Unwrap,
    }

    /// The secrets the work handles on the sets made from `flip`ped patterns: the key of the
    /// parent, the derivation of the cipher key from it, the cipher key, the message keys, the
    /// round keys of the cipher key and of the message encryption key in the layout of FIPS 197,
    /// the keystream, and the plaintext. For a whole unwrap, also the derivations of the
    /// identifiers of the child's keys.
    fn handled(flip: u8, work: Work) -> Vec<Vec<u8>> {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(
            &mut memory,
            &mut epoch_memory,
            EPOCH,
            &mut flipped_epoch_key(flip),
        );
        let (parent, child) = sets(&mut slots, flip);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(child, parent, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        let nonce: [u8; 12] = record[..NONCE.len()].try_into().unwrap();
        let tag: [u8; 16] = record[NONCE.len() + PLAINTEXT_LEN..].try_into().unwrap();
        let ciphertext = &record[NONCE.len()..NONCE.len() + PLAINTEXT_LEN];
        let bytes = parent_bytes(flip);
        let key = key_from(&bytes);
        let mut cipher_key = [0; 32];
        derive_wrap_key(&key, &flipped_epoch(flip), &mut cipher_key).unwrap();
        let (mac_key, enc_key) = message_keys(&cipher_key, &nonce);
        let stream = keystream(&enc_key, &tag);
        let decrypted = ciphertext.iter().zip(&stream).map(|(c, k)| c ^ k).collect();
        let mut handled = secrets(
            &bytes,
            &flipped_epoch_key(flip),
            key.length(),
            Branch::WrapKey,
        );
        handled.extend([
            bytes.to_vec(),
            cipher_key.to_vec(),
            mac_key.to_vec(),
            enc_key.to_vec(),
            stream,
            decrypted,
        ]);
        handled.extend(round_keys(&cipher_key));
        handled.extend(round_keys(&enc_key));
        if work == Work::Unwrap {
            for bytes in child_keys(flip) {
                handled.extend(secrets(
                    &bytes,
                    SALT,
                    key_from(&bytes).length(),
                    Branch::KeyId,
                ));
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
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (parent, child) = sets(&mut slots, 0);
        let mut record = [0; RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .wrap_on_stack(child, parent, CONTEXT, &mut Fixed, Out::Record(&mut record))
                .unwrap();
            black_box(&record);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn a_wrap_leaves_no_residue() {
        let pieces = pieces(Work::Wrap);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
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
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (parent, record) = wrapped(&mut slots);
        assert_clean(&pieces, || {
            black_box(slots.unwrap(parent, CONTEXT, &record).unwrap());
        });
    }

    /// A record whose ciphertext was changed is decrypted under the key of the parent before the tag
    /// fails. This is also the unwrap that shows the test sees residue: after a successful one,
    /// the wipes that follow the derivations of the new keys' identifiers already cover the frames
    /// the cipher used.
    #[test]
    fn a_rejected_unwrap_leaves_no_residue() {
        let pieces = pieces(Work::Trial);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
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

    /// The key from a secret of the lock tests, and the stored key it locks: 32 and 64 bytes.
    fn secret_bytes(flip: u8) -> [u8; 32] {
        pattern(61, 13, 32, flip).try_into().unwrap()
    }

    fn stored_bytes(flip: u8) -> [u8; 64] {
        pattern(67, 17, 64, flip).try_into().unwrap()
    }

    /// What the cipher works with under `cipher_key` for a record whose nonce, encrypted part and
    /// tag are given: the cipher key, the message keys, their round keys, the keystream and what
    /// the record decrypts to, which it returns as well.
    fn cipher_secrets(
        cipher_key: &[u8; 32],
        nonce: &[u8; 12],
        sealed: &[u8],
        tag: &[u8; 16],
    ) -> (Vec<Vec<u8>>, Vec<u8>) {
        let (mac_key, enc_key) = message_keys(cipher_key, nonce);
        let stream = keystream_of(&enc_key, tag, sealed.len());
        let decrypted: Vec<u8> = sealed.iter().zip(&stream).map(|(c, k)| c ^ k).collect();
        let mut found = std::vec![
            cipher_key.to_vec(),
            mac_key.to_vec(),
            enc_key.to_vec(),
            stream,
            decrypted.clone(),
        ];
        found.extend(round_keys(cipher_key));
        found.extend(round_keys(&enc_key));
        (found, decrypted)
    }

    /// The outer layer of a lock record, under the key of the epoch `epoch`: the secrets of the
    /// derivation of its key and of the cipher, and what it decrypts to.
    fn layer_secrets(epoch: &[u8; 32], record: &[u8; LOCK_RECORD_LEN]) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut layer_key = [0; 32];
        derive_layer_key(&key_from(epoch), &mut layer_key).unwrap();
        let nonce: [u8; 12] = record[..12].try_into().unwrap();
        let tag: [u8; 16] = record[12 + LAYER_LEN..].try_into().unwrap();
        let (mut found, layer) =
            cipher_secrets(&layer_key, &nonce, &record[12..12 + LAYER_LEN], &tag);
        found.extend(secrets(epoch, SALT, KeyLength::Bytes32, Branch::EpochLayer));
        (found, layer)
    }

    /// What is measured with lock records.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Locking {
        Lock,
        Unlock,
        Carry,
    }

    /// The slots of the lock tests, made from `flip`ped patterns: a key from a secret, the stored
    /// key it locks, and their lock record.
    fn locked(
        slots: &mut Slots<'_>,
        flip: u8,
    ) -> (Handle<'static>, Handle<'static>, [u8; LOCK_RECORD_LEN]) {
        let secret = widen(
            slots
                .import32(Purpose::Wrap, &mut secret_bytes(flip))
                .unwrap(),
        );
        let stored = slots
            .import64(Purpose::Wrap, &mut stored_bytes(flip))
            .unwrap();
        let stored = widen(slots.store(stored));
        let mut record = [0; LOCK_RECORD_LEN];
        slots
            .lock(stored, secret, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        (secret, stored, record)
    }

    /// The key of the next epoch in the lock tests.
    fn next_key(flip: u8) -> [u8; 32] {
        flipped_epoch_key(flip ^ 0x5a)
    }

    /// The secrets the work with lock records handles on keys made from `flip`ped patterns: both
    /// layers' derivations, cipher keys, message keys, round keys and keystreams, the record the
    /// outer layer holds and the plaintext of the inner, both keys, and for an unlock the
    /// derivation of the stored key's identifier, for a carry the new outer layer.
    fn lock_handled(flip: u8, work: Locking) -> Vec<Vec<u8>> {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(
            &mut memory,
            &mut epoch_memory,
            EPOCH,
            &mut flipped_epoch_key(flip),
        );
        let (_, _, record) = locked(&mut slots, flip);
        let (mut handled, layer) = layer_secrets(&flipped_epoch_key(flip), &record);
        let inner = &layer[8..];
        let mut lock_key = [0; 32];
        derive_lock_key(&key_from(&secret_bytes(flip)), &mut lock_key).unwrap();
        let nonce: [u8; 12] = inner[..12].try_into().unwrap();
        let tag: [u8; 16] = inner[12 + PLAINTEXT_LEN..].try_into().unwrap();
        let (found, _) = cipher_secrets(&lock_key, &nonce, &inner[12..12 + PLAINTEXT_LEN], &tag);
        handled.extend(found);
        handled.extend(secrets(
            &secret_bytes(flip),
            SALT,
            KeyLength::Bytes32,
            Branch::LockKey,
        ));
        handled.extend([
            inner.to_vec(),
            secret_bytes(flip).to_vec(),
            stored_bytes(flip).to_vec(),
        ]);
        match work {
            Locking::Lock => {}
            Locking::Unlock => handled.extend(secrets(
                &stored_bytes(flip),
                SALT,
                KeyLength::Bytes64,
                Branch::KeyId,
            )),
            Locking::Carry => {
                slots.begin_epoch(&mut next_key(flip)).unwrap();
                let mut carried = [0; LOCK_RECORD_LEN];
                slots
                    .carry(CONTEXT, &mut Fixed, &record, &mut carried)
                    .unwrap();
                handled.extend(layer_secrets(&next_key(flip), &carried).0);
            }
        }
        handled
    }

    fn lock_pieces(work: Locking) -> Vec<Vec<u8>> {
        key_dependent(&lock_handled(0, work), &lock_handled(0xff, work))
    }

    #[test]
    fn a_lock_without_the_wipe_leaves_residue() {
        let pieces = lock_pieces(Locking::Lock);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (secret, stored, _) = locked(&mut slots, 0);
        let mut record = [0; LOCK_RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .wrap_on_stack(stored, secret, CONTEXT, &mut Fixed, Out::Lock(&mut record))
                .unwrap();
            black_box(&record);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn a_lock_leaves_no_residue() {
        let pieces = lock_pieces(Locking::Lock);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (secret, stored, _) = locked(&mut slots, 0);
        let mut record = [0; LOCK_RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .lock(stored, secret, CONTEXT, &mut Fixed, &mut record)
                .unwrap();
            black_box(&record);
        });
    }

    #[test]
    fn an_unlock_leaves_no_residue() {
        let pieces = lock_pieces(Locking::Unlock);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (secret, stored, record) = locked(&mut slots, 0);
        slots.release(stored).unwrap();
        assert_clean(&pieces, || {
            black_box(slots.unlock(secret, CONTEXT, &record).unwrap());
        });
    }

    /// An unlock under another key from a secret decrypts the outer layer and fails at the inner:
    /// the record of the outer layer and the secrets of both trials are left on the stack without
    /// the wipe, and none with it.
    #[test]
    fn a_rejected_unlock_leaves_no_residue() {
        let handled = |flip| {
            let mut memory = [const { Slot::empty() }; 4];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(
                &mut memory,
                &mut epoch_memory,
                EPOCH,
                &mut flipped_epoch_key(flip),
            );
            let (_, _, record) = locked(&mut slots, flip);
            let (mut handled, layer) = layer_secrets(&flipped_epoch_key(flip), &record);
            handled.push(layer[8..].to_vec());
            handled
        };
        let pieces = key_dependent(&handled(0), &handled(0xff));
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (_, stored, record) = locked(&mut slots, 0);
        slots.release(stored).unwrap();
        let other = slots
            .import32(
                Purpose::Wrap,
                &mut pattern(89, 3, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        let range = below_pad(false, || {
            let refused = slots.unlock_on_stack(other, CONTEXT, &record, seal::open, seal::open);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        });
        assert!(residue(range, &pieces) > 0);
        assert_clean(&pieces, || {
            let refused = slots.unlock(other, CONTEXT, &record);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        });
    }

    #[test]
    fn a_carry_without_the_wipe_leaves_residue() {
        let pieces = lock_pieces(Locking::Carry);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (_, _, record) = locked(&mut slots, 0);
        slots.begin_epoch(&mut next_key(0)).unwrap();
        let mut carried = [0; LOCK_RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .carry_on_stack(CONTEXT, &mut Fixed, &record, &mut carried, seal::open)
                .unwrap();
            black_box(&carried);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn a_carry_leaves_no_residue() {
        let pieces = lock_pieces(Locking::Carry);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (_, _, record) = locked(&mut slots, 0);
        slots.begin_epoch(&mut next_key(0)).unwrap();
        let mut carried = [0; LOCK_RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .carry(CONTEXT, &mut Fixed, &record, &mut carried)
                .unwrap();
            black_box(&carried);
        });
    }

    /// A reveal writes the key into the caller's buffer and leaves no piece of it on the stack;
    /// without the wipe after it, a build without optimisation leaves the key there.
    #[test]
    fn a_reveal_leaves_no_residue() {
        let key = pattern(37, 11, 32, 0);
        let pieces = key_dependent(core::slice::from_ref(&key), &[pattern(37, 11, 32, 0x5a)]);
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots
            .import32(Purpose::ExternalData, &mut key.clone().try_into().unwrap())
            .unwrap();
        let mut out = [0; 32];
        let range = below_pad(false, || {
            slots
                .reveal_on_stack(set, Position::First, Purpose::ExternalData, &mut out)
                .unwrap();
        });
        if cfg!(lethewis_unoptimised) {
            assert!(residue(range, &pieces) > 0);
        }
        assert_clean(&pieces, || {
            slots
                .reveal32(set, Position::First, Purpose::ExternalData, &mut out)
                .unwrap();
        });
        assert_eq!(out[..], key[..]);
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

    /// The wipes that follow a wrap, an unwrap and a reveal reach as deep as they are meant to, also
    /// when the call fails, and no call reaches deeper than its documentation says it needs.
    #[test]
    fn wraps_unwraps_and_loads_wipe_and_need_the_stack_documented() {
        let mut memory = [const { Slot::empty() }; 12];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
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
            .import32(
                Purpose::ExternalData,
                &mut pattern(5, 5, 32, 0).try_into().unwrap(),
            )
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
            depth_changed(|| {
                let mut short: [u8; 32] = pattern(11, 11, 32, 0).try_into().unwrap();
                black_box(slots.add32(key, &mut short).unwrap());
            }),
            depth_changed(|| {
                slots.settle();
                let added = slots.add_generated(key, KeyLength::Bytes32, &mut Counting);
                black_box(added.unwrap());
            }),
        ];
        for depth in loads {
            assert!(depth <= LOAD_STACK, "{depth} bytes reached");
        }
        let data = slots
            .import32(
                Purpose::ExternalData,
                &mut pattern(13, 13, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        let mut revealed = [0; 32];
        let reveals = [
            depth_changed(|| {
                slots
                    .reveal32(data, Position::First, Purpose::ExternalData, &mut revealed)
                    .unwrap();
                black_box(&revealed);
            }),
            depth_changed(|| {
                let refused =
                    slots.reveal32(data, Position::Third, Purpose::ExternalData, &mut revealed);
                assert_eq!(black_box(refused), Err(Error::WrongStage));
            }),
        ];
        for depth in reveals {
            assert!(depth >= STACK_WIPE, "{depth} bytes wiped after a reveal");
            assert!(depth <= LOAD_STACK, "{depth} bytes reached");
        }
    }

    /// The wipes that follow a lock, an unlock and a carry reach as deep as those after a wrap, also
    /// when the call fails, and no call reaches deeper than its documentation says it needs.
    #[test]
    fn lock_records_wipe_and_need_the_stack_documented() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let secret = slots.import32(Purpose::Wrap, &mut [3; 32]).unwrap();
        let stored = slots.import32(Purpose::Wrap, &mut [4; 32]).unwrap();
        let stored = slots.store(stored);
        let mut locked = [0; LOCK_RECORD_LEN];
        let mut depths = Vec::new();
        depths.push(depth_changed(|| {
            slots
                .lock(stored, secret, CONTEXT, &mut Fixed, &mut locked)
                .unwrap();
            black_box(&locked);
        }));
        depths.push(depth_changed(|| {
            let failed = slots.lock(stored, secret, CONTEXT, &mut Failing, &mut locked);
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        slots.release(stored).unwrap();
        let mut changed = locked;
        changed[40] ^= 1;
        depths.push(depth_changed(|| {
            black_box(slots.unlock(secret, CONTEXT, &locked).unwrap());
        }));
        depths.push(depth_changed(|| {
            assert_eq!(
                black_box(slots.unlock(secret, CONTEXT, &changed)),
                Err(Error::StaleRecord)
            );
        }));
        slots.begin_epoch(&mut [5; 32]).unwrap();
        let mut carried = [0; LOCK_RECORD_LEN];
        depths.push(depth_changed(|| {
            slots
                .carry(CONTEXT, &mut Fixed, &locked, &mut carried)
                .unwrap();
            black_box(&carried);
        }));
        depths.push(depth_changed(|| {
            let refused = slots.carry(CONTEXT, &mut Fixed, &changed, &mut carried);
            assert_eq!(black_box(refused), Err(Error::StaleRecord));
        }));
        for depth in depths {
            assert!(depth >= CIPHER_STACK_WIPE, "{depth} bytes wiped");
            assert!(depth <= WRAP_STACK, "{depth} bytes reached");
        }
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs {
    use core::marker::PhantomData;

    use super::{
        CIPHER_KEY_LEN, Entropy, EntropyError, Epoch, Erasure, Error, Handle, Key, KeyId,
        KeyLength, LAYER_LEN, LOCK_RECORD_LEN, MEMBERS, NONCE_LEN, Occupancy, Out, PLAINTEXT_LEN,
        Position, Purpose, RECORD_LEN, Rejected, Root, RootFailed, Slot, Slots, Stages, Status,
        TAG_LEN,
    };
    use crate::derive::{
        Branch,
        model::{any_failed, failed, id_bytes, id_from_bytes},
        proofs::{
            expected_hedge, expected_key_id, expected_layer_key, expected_lock_key,
            expected_words_key, expected_wrap_key,
        },
    };
    use crate::keyset::proofs::{allowed, any_purpose, any_whole_stages};
    use crate::password::{MemoryBlock, model::argon2_failed, proofs::any_params};
    use crate::record::ID_LEN;
    use crate::words::{
        Words, bits_of,
        proofs::{any_list, expected_words},
    };

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
        unlocks: bool,
        changed: bool,
        sealed: bool,
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
            unlocks: slot.unlocks,
            changed: slot.changed,
            sealed: slot.sealed,
        }
    }

    // Kani 0.68.0 reports spurious failures when a key buffer is read through a symbolic index, so
    // the reads below take every element and then pick one, with no check left behind a branch.

    fn slot_at<'s>(slots: &'s Slots<'_>, index: usize) -> &'s Slot {
        let (first, second) = (&slots.memory[0], &slots.memory[1]);
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
        same_bytes(a, b)
    }

    /// The same for two slices of one length.
    fn same_bytes(a: &[u8], b: &[u8]) -> bool {
        a.chunks(64).zip(b.chunks(64)).all(|(x, y)| x == y)
    }

    fn snapshots(slots: &Slots<'_>) -> [Snapshot; 2] {
        [snapshot(&slots.memory[0]), snapshot(&slots.memory[1])]
    }

    /// Every slot but `changed` matches its snapshot.
    fn unchanged_except(slots: &Slots<'_>, before: &[Snapshot; 2], changed: usize) -> bool {
        (0..2).all(|index| index == changed || snapshot(&slots.memory[index]) == before[index])
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

    /// A slot in any state, for either purpose, with any generation and any stages whose primary is
    /// enabled; when loaded, holding a key of a length its purpose takes and any identifier at each
    /// position the stages fill, a set of one if it is for wrapping, from a secret or stored, and
    /// changed and wrapped for the next epoch or not. A free or retired slot keeps the purpose of
    /// the set it last held. Every load, addition and unwrap keeps a key's length one its purpose
    /// takes, every load and unwrap makes a set for wrapping a set of one, and no change or
    /// addition takes one, as their proofs show.
    fn any_slot() -> Slot {
        any_slot_in(any_occupancy())
    }

    fn any_occupancy() -> Occupancy {
        match kani::any::<u8>() % 3 {
            0 => Occupancy::Free,
            1 => Occupancy::Loaded,
            _ => Occupancy::Retired,
        }
    }

    fn any_slot_in(occupancy: Occupancy) -> Slot {
        let mut slot = Slot::empty();
        slot.generation = kani::any();
        slot.occupancy = occupancy;
        let purpose = any_purpose();
        slot.purpose = purpose;
        slot.stages = if purpose == Purpose::Wrap && occupancy == Occupancy::Loaded {
            Stages::one()
        } else {
            any_whole_stages()
        };
        slot.unlocks = purpose == Purpose::Wrap && kani::any();
        if slot.occupancy == Occupancy::Loaded {
            slot.changed = kani::any();
            slot.sealed = kani::any();
            let stages = slot.stages;
            let fill = |position: usize, key: &mut Key, id: &mut KeyId| {
                if stages.stage(position).is_some() {
                    any_key(key);
                    kani::assume(allowed(purpose, key.length()));
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

    /// Any epoch with any key and any count of draws, and, if `changing`, with a change to the next
    /// under way and any key for it.
    fn any_epoch(changing: bool) -> Epoch {
        let mut epoch = Epoch::empty();
        epoch.number = kani::any();
        epoch.key.load32(&mut kani::any());
        if changing {
            epoch.next.load32(&mut kani::any());
        }
        epoch.changing = changing;
        epoch.drawn = kani::any();
        epoch
    }

    /// The first 32 bytes of `key`.
    fn first_half(key: &Key) -> [u8; 32] {
        let mut half = [0; 32];
        half.copy_from_slice(&key.bytes()[..32]);
        half
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

    /// Whether a loaded slot of `before` for a purpose other than `purpose` holds a key with the
    /// identifier `id`.
    fn held_for_another(before: &[Snapshot; 2], id: &Id, purpose: Purpose) -> bool {
        before.iter().any(|snapshot| {
            snapshot.occupancy == Occupancy::Loaded
                && snapshot.purpose != purpose
                && (0..MEMBERS).any(|position| {
                    snapshot.stages.stage(position).is_some()
                        && pick(&snapshot.ids, position) == *id
                })
        })
    }

    /// A platform source that writes any bytes and then either succeeds or fails, as a real one
    /// may fail after writing part of its output. It remembers how often and for how many bytes it
    /// was asked, how often it answered, and what it wrote.
    struct AnyEntropy {
        written: Bytes,
        calls: u8,
        answered: u8,
        requested: usize,
        at: usize,
        failed: bool,
    }

    impl AnyEntropy {
        fn new() -> Self {
            Self {
                written: [0; 64],
                calls: 0,
                answered: 0,
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
                return Err(EntropyError);
            }
            self.answered = self.answered.saturating_add(1);
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

    /// Imports one key of either length with any bytes for `purpose`. Returns the outcome and, on
    /// success, the bytes and length the slot must now hold.
    fn import_any(
        slots: &mut Slots<'_>,
        purpose: Purpose,
    ) -> (Result<Handle<'static>, Error>, Bytes, KeyLength) {
        let (result, expected, length) = if kani::any() {
            let mut source: [u8; 32] = kani::any();
            let original = source;
            let result = slots.import32(purpose, &mut source);
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
            let result = slots.import64(purpose, &mut source);
            kani::assert(
                source == if result.is_ok() { [0; 64] } else { original },
                "an import wipes its source exactly when it succeeds",
            );
            (result, original, KeyLength::Bytes64)
        };
        (result.map(widen), expected, length)
    }

    /// Loads one key by any of the three ways, with any key and length, for `purpose`. Returns the
    /// outcome, the bytes and length the slot must hold on success, whether a platform source was
    /// asked and failed, and whether the key was imported.
    fn load_any(
        slots: &mut Slots<'_>,
        purpose: Purpose,
    ) -> (Result<Handle<'static>, Error>, Bytes, KeyLength, bool, bool) {
        if kani::any() {
            let (result, expected, length) = import_any(slots, purpose);
            return (result, expected, length, false, true);
        }
        let mut entropy = AnyEntropy::new();
        let length = any_length();
        let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
        let result = slots.generate(purpose, length, &mut entropy);
        let unasked = result == Err(Error::NoFreeSlot) || result == Err(Error::WrongLength);
        kani::assert(
            if unasked {
                entropy.calls == 0
            } else {
                entropy.calls == 1 && entropy.requested == length.bytes()
            },
            "a length the purpose does not take and a full set ask the source for nothing, and \
             otherwise it is asked once, for the length of the key",
        );
        kani::assert(
            unasked || (result == Err(Error::EntropyFailed)) == entropy.failed,
            "a generation fails with EntropyFailed exactly when the source fails",
        );
        kani::assert(
            slots.epoch.drawn
                == if unasked || entropy.failed {
                    count
                } else {
                    count.wrapping_add(1)
                },
            "a draw the source answers is counted once",
        );
        if let Ok(handle) = result {
            let buffer = slot_at(slots, handle.index).keys[0].bytes().as_ptr().addr();
            kani::assert(
                entropy.at != buffer,
                "the source writes into a buffer of the library's, not into the slot",
            );
        }
        // What the slot must hold: the hedge of what the source wrote, worked out from the model.
        let mut hedged = [0; 64];
        if length == KeyLength::Bytes32 {
            let mut drawn = [0; 32];
            drawn.copy_from_slice(&entropy.written[..32]);
            hedged[..32].copy_from_slice(&expected_hedge(
                &epoch_key,
                count,
                Branch::HedgeKey,
                &drawn,
            ));
        } else {
            hedged = expected_hedge(&epoch_key, count, Branch::HedgeKey, &entropy.written);
        }
        kani::cover!(
            result == Err(Error::EntropyFailed),
            "the platform source fails"
        );
        kani::cover!(
            entropy.failed && entropy.written.iter().any(|&byte| byte != 0),
            "the source fails after writing bytes"
        );
        kani::cover!(
            result.is_ok() && length == KeyLength::Bytes32,
            "a short key is generated"
        );
        kani::cover!(
            result.is_ok() && length == KeyLength::Bytes64,
            "a long key is generated"
        );
        kani::cover!(
            result.is_ok() && slots.epoch.changing,
            "a key is generated during a change of epoch"
        );
        (result.map(widen), hedged, length, entropy.failed, false)
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
        let mut epoch = any_epoch(false);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let tracked = track(&slots, id);
        let (result, issued, issued_length) = import_any(&mut slots, any_purpose());
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
    /// handle wipes every key and identifier of its set at once, unless the set has changed in
    /// this epoch, and any other is refused.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_step_by_a_release() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut epoch = any_epoch(kani::any());
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let tracked = track(&slots, id);
        let target = if kani::any() {
            tracked.handle
        } else {
            forged(id)
        };
        let target_live = live(&slots, id, &target);
        let target_changed = target_live && slot_at(&slots, target.index).changed;
        let result = slots.release(target);
        let released =
            target_live && !target_changed && tracked.live && target.index == tracked.handle.index;
        kani::assert(
            if target_changed {
                result == Err(Error::Unsaved)
            } else if target_live {
                result == Ok(()) && wiped(slot_at(&slots, target.index))
            } else {
                result == Err(Error::StaleHandle)
            },
            "a live handle releases its set, whose keys and identifiers are zero at once, unless \
             the set has changed in this epoch, and any other is refused",
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
        let mut epoch = any_epoch(false);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
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
    /// length and any identifiers at every position, loaded or not, and changed or not if loaded.
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
        if slot.occupancy == Occupancy::Loaded {
            slot.changed = kani::any();
            slot.sealed = kani::any();
        }
        slot
    }

    /// From any state of two slots, with any bytes left in any buffer, creating `Slots` wipes every
    /// key and identifier, loads no slot and leaves none changed, and takes the epoch and its key.
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
        let epoch = kani::any();
        let mut epoch_key: [u8; 32] = kani::any();
        let original = epoch_key;
        let mut epoch_memory = any_epoch(kani::any());
        epoch_memory.key.fill_any();
        let slots = Slots::new(&mut memory, &mut epoch_memory, epoch, &mut epoch_key);
        kani::assert(
            slots.epoch.number == epoch
                && first_half(&slots.epoch.key) == original
                && slots.epoch.key.bytes()[32..] == [0; 32]
                && slots.epoch.key.length() == KeyLength::Bytes32
                && *slots.epoch.next.bytes() == [0; 64]
                && epoch_key == [0; 32]
                && !slots.epoch.changing,
            "creating slots takes the epoch and its key, wipes the source, and leaves nothing else \
             in the memory of the epoch",
        );
        for slot in slots.memory.iter() {
            kani::assert(
                slot.occupancy != Occupancy::Loaded,
                "creating slots loads no slot",
            );
            kani::assert(wiped(slot), "creating slots wipes every key and identifier");
            kani::assert(
                !slot.changed && !slot.sealed,
                "creating slots leaves no set changed",
            );
        }
    }

    /// A load by import or from the platform source for either purpose, from `memory`: it takes
    /// the first free slot, issues that slot's generation, keeps it in the slot and leaves a set of
    /// one there: exactly the expected bytes at the first position, zero past the key's length,
    /// enabled and the primary, with the purpose given and the identifier derived from those bytes
    /// and their length alone, and nothing at the other positions; it fails with `WrongLength`
    /// first for a length the purpose does not take, then with `NoFreeSlot` without a free slot,
    /// with `EntropyFailed` when the source fails, with `DerivationFailed` when the derivation
    /// fails, and with `DuplicateKey` exactly when a loaded slot holds a key with that identifier,
    /// for any purpose; a failed load changes no slot, and neither a refused length nor a full set
    /// asks the source; no load panics or overflows. Returns the outcome, and whether a slot for
    /// another purpose holds the key.
    fn load_from(mut memory: [Slot; 2]) -> (Result<Handle<'static>, Error>, bool) {
        let mut epoch = any_epoch(kani::any());
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let first_free = first_free(&before);
        let purpose = any_purpose();
        let (result, expected, length, source_failed, imported) = load_any(&mut slots, purpose);
        let id = expected_key_id(&expected, length);
        kani::assert(
            if !allowed(purpose, length) {
                result == Err(Error::WrongLength)
            } else if first_free.is_none() {
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
            "a load fails with WrongLength for a length its purpose does not take, then with \
             NoFreeSlot without a free slot, with EntropyFailed when the source fails, with \
             DerivationFailed when the derivation fails, with DuplicateKey when the key is held, \
             and otherwise succeeds",
        );
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "a load fails to derive the identifier"
        );
        kani::cover!(
            result == Err(Error::WrongLength),
            "a key too long for its purpose is refused"
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
                    && now.purpose == purpose
                    && now.unlocks == (imported && purpose == Purpose::Wrap),
                "the slot keeps the purpose, a set of one and the identifier derived from its key; an \
                 imported key for wrapping is a key from a secret, a generated one is stored",
            );
            kani::assert(
                unchanged_except(&slots, &before, index),
                "a load changes no other slot",
            );
            kani::cover!(length == KeyLength::Bytes32, "a short key is loaded");
            kani::cover!(length == KeyLength::Bytes64, "a long key is loaded");
            kani::cover!(
                purpose == Purpose::ExternalData,
                "a key for external data is loaded"
            );
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a failed load changes no slot",
            );
        }
        (result, held_for_another(&before, &id, purpose))
    }

    /// A load with the first slot free; with the next two, any state of two slots.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_load_into_the_first_slot() {
        let (result, elsewhere) = into_the_first(load_from);
        kani::cover!(
            result == Err(Error::DuplicateKey) && elsewhere,
            "a load finds its key held for another purpose"
        );
    }

    /// A load with the first slot loaded.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_load_past_a_loaded_slot() {
        let (result, elsewhere) = past_a(Occupancy::Loaded, load_from);
        kani::cover!(
            result == Err(Error::DuplicateKey) && elsewhere,
            "a load finds its key held for another purpose"
        );
        kani::cover!(
            result == Err(Error::DuplicateKey) && !elsewhere,
            "a load finds its key held for its own purpose"
        );
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// A load with the first slot retired, where no key is held beside a free slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_load_past_a_retired_slot() {
        let (result, _) = past_a(Occupancy::Retired, load_from);
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// A derivation from a password, from `memory`, with any parameters within the bounds, any
    /// password of up to two bytes and any working memory: an empty password, and memory too small
    /// for the parameters, are refused before anything else; a failing Argon2 is `DerivationFailed`,
    /// never the failure of a platform source; the password is wiped exactly when the derivation
    /// succeeds; a failed derivation changes no slot, and one that succeeds loads the first free
    /// slot with a 32-byte key and the identifier derived from it. The rest is the load of a
    /// generation, proven above for a source that writes any bytes and may fail.
    fn derivation_from(mut memory: [Slot; 2]) -> Result<Handle<'static>, Error> {
        let mut epoch = any_epoch(false);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let params = any_params();
        let mut password: [u8; 2] = kani::any();
        let original = password;
        let length: usize = kani::any();
        kani::assume(length <= 2);
        let mut blocks = [MemoryBlock; 2_097_152];
        let count: usize = kani::any();
        kani::assume(count <= blocks.len());
        let result =
            slots.derive_from_password(&mut password[..length], &params, &mut blocks[..count]);
        kani::assert(
            if length == 0 {
                result == Err(Error::InvalidPassword)
            } else if count < params.memory_blocks() {
                result == Err(Error::NotEnoughMemory)
            } else {
                result != Err(Error::EntropyFailed)
            },
            "an empty password and too little memory are refused first, and Argon2 never \
             fails as a platform source does",
        );
        kani::assert(
            !argon2_failed() || result == Err(Error::DerivationFailed),
            "a failure of Argon2id is DerivationFailed",
        );
        let wiped: [u8; 2] = core::array::from_fn(|at| if at < length { 0 } else { original[at] });
        kani::assert(
            password == if result.is_ok() { wiped } else { original },
            "the password is wiped exactly when the derivation succeeds",
        );
        if let Ok(handle) = result {
            let now = snapshot(slot_at(&slots, handle.index));
            kani::assert(
                first_free(&before) == Some(handle.index)
                    && now.occupancy == Occupancy::Loaded
                    && now.lengths[0] == KeyLength::Bytes32
                    && now.keys.0[32..] == [0; 32]
                    && now.ids.0 == expected_key_id(&now.keys.0, KeyLength::Bytes32)
                    && now.stages == Stages::one()
                    && now.purpose == Purpose::Wrap
                    && now.unlocks,
                "the first free slot holds a 32-byte key from a secret and its identifier",
            );
            kani::assert(
                unchanged_except(&slots, &before, handle.index),
                "a derivation changes no other slot",
            );
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a failed derivation changes no slot",
            );
        }
        kani::cover!(result.is_ok(), "a key is derived from a password");
        kani::cover!(result == Err(Error::InvalidPassword), "an empty password");
        kani::cover!(result == Err(Error::NotEnoughMemory), "too little memory");
        kani::cover!(argon2_failed(), "Argon2 fails");
        result.map(widen)
    }

    /// A derivation from a password with the first slot free.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_derivation_from_a_password_into_the_first_slot() {
        let _ = into_the_first(derivation_from);
    }

    /// A derivation from a password with the first slot loaded.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_derivation_from_a_password_past_a_loaded_slot() {
        let result = past_a(Occupancy::Loaded, derivation_from);
        kani::cover!(
            result == Err(Error::DuplicateKey),
            "a derivation finds its key held"
        );
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// A derivation from a password with the first slot retired, where no key is held beside a
    /// free slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_derivation_from_a_password_past_a_retired_slot() {
        let result = past_a(Occupancy::Retired, derivation_from);
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// A derivation from any bytes that twelve words stand for, from `memory`: a failure of a
    /// derivation is `DerivationFailed`, and nothing else is, never the failure of a platform
    /// source; a failed derivation changes no slot, and one that succeeds loads the first free slot
    /// with the 32-byte key derived from the bytes and the identifier derived from it. The rest is
    /// the load of a generation, proven above for a source that writes any bytes and may fail.
    fn derivation_from_words(mut memory: [Slot; 2]) -> Result<Handle<'static>, Error> {
        let mut epoch = any_epoch(false);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let bytes: [u8; 16] = kani::any();
        let result = slots.derive_into(&bytes);
        kani::assert(
            (result == Err(Error::DerivationFailed)) == any_failed(),
            "a failure of a derivation is DerivationFailed, and nothing else is",
        );
        if let Ok(handle) = result {
            let now = snapshot(slot_at(&slots, handle.index));
            let key = expected_words_key(&bytes);
            kani::assert(
                first_free(&before) == Some(handle.index)
                    && now.occupancy == Occupancy::Loaded
                    && now.lengths[0] == KeyLength::Bytes32
                    && now.keys.0[..32] == key
                    && now.keys.0[32..] == [0; 32]
                    && now.ids.0 == expected_key_id(&now.keys.0, KeyLength::Bytes32)
                    && now.stages == Stages::one()
                    && now.purpose == Purpose::Wrap
                    && now.unlocks,
                "the first free slot holds the key from a secret of the bytes and the identifier \
                 derived from it",
            );
            kani::assert(
                unchanged_except(&slots, &before, handle.index),
                "a derivation changes no other slot",
            );
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a failed derivation changes no slot",
            );
        }
        kani::cover!(result.is_ok(), "a key is derived from words");
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "the derivation fails"
        );
        result.map(widen)
    }

    /// A derivation from words with the first slot free.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_derivation_from_words_into_the_first_slot() {
        let _ = into_the_first(derivation_from_words);
    }

    /// A derivation from words with the first slot loaded.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_derivation_from_words_past_a_loaded_slot() {
        let result = past_a(Occupancy::Loaded, derivation_from_words);
        kani::cover!(
            result == Err(Error::DuplicateKey),
            "a derivation finds its key held"
        );
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// A derivation from words with the first slot retired.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_derivation_from_words_past_a_retired_slot() {
        let result = past_a(Occupancy::Retired, derivation_from_words);
        kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    }

    /// Whether two sets of words are the same, compared word by word.
    fn same_words(a: &Words, b: &Words) -> bool {
        a.iter().zip(b).all(|(x, y)| x == y)
    }

    /// Any twelve words of any list of three, with the first slot free: words the list refuses
    /// change no slot and derive nothing; the words are wiped exactly when the derivation succeeds;
    /// a failure of the platform source is never reported; a failed derivation changes no slot.
    /// Where the key goes, the derivations from words above prove.
    #[kani::proof]
    #[kani::unwind(65)]
    fn words_are_wiped_exactly_when_their_key_is_derived() {
        into_the_first(|mut memory| {
            let mut epoch = any_epoch(false);
            let mut slots = Slots {
                memory: &mut memory,
                epoch: &mut epoch,
            };
            let before = snapshots(&slots);
            let list = any_list();
            let mut words: Words = kani::any();
            let original = words;
            let result = slots.derive_from_words_in(&list, &mut words);
            let refused = matches!(result, Err(Error::UnknownWord | Error::InvalidChecksum));
            kani::assert(!refused || !any_failed(), "refused words derive nothing");
            kani::assert(
                result != Err(Error::EntropyFailed),
                "no platform source is asked",
            );
            kani::assert(
                same_words(
                    &words,
                    &if result.is_ok() {
                        [[0; 8]; 12]
                    } else {
                        original
                    },
                ),
                "the words are wiped exactly when the derivation succeeds",
            );
            if result.is_ok() {
                let numbers: [u16; 12] = core::array::from_fn(|at| {
                    let word = u64::from_le_bytes(original[at]);
                    if word == list[1] {
                        1
                    } else if word == list[2] {
                        2
                    } else {
                        0
                    }
                });
                let (read, _) = bits_of(&numbers);
                kani::assert(
                    snapshot(&slots.memory[0]).keys.0[..32] == expected_words_key(&read),
                    "the key in the slot is the one the bytes the words stand for derive",
                );
            } else {
                kani::assert(
                    unchanged_except(&slots, &before, 2),
                    "a failed derivation changes no slot",
                );
            }
            kani::cover!(result.is_ok(), "a key is derived from words");
            kani::cover!(result == Err(Error::UnknownWord), "an unknown word");
            kani::cover!(
                result == Err(Error::InvalidChecksum),
                "a checksum that does not hold"
            );
            kani::cover!(
                result == Err(Error::DuplicateKey),
                "valid words whose key is held"
            );
            kani::cover!(
                result == Err(Error::DerivationFailed),
                "valid words whose derivation fails"
            );
        });
    }

    /// Generation with any list of three, with the first slot free: the source is asked once for
    /// 16 bytes, its failure is `EntropyFailed`, the count of draws grows exactly when it answers,
    /// and the words of its bytes hedged with the key of this epoch are written exactly when the key
    /// is derived; a failed generation changes neither the words nor any slot. During a change of
    /// epoch or not.
    #[kani::proof]
    #[kani::unwind(65)]
    fn words_are_written_exactly_when_their_key_is_generated() {
        into_the_first(|mut memory| {
            let mut epoch = any_epoch(kani::any());
            let mut slots = Slots {
                memory: &mut memory,
                epoch: &mut epoch,
            };
            let before = snapshots(&slots);
            let list = any_list();
            let mut source = AnyEntropy::new();
            let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
            let mut words: Words = kani::any();
            let original = words;
            let result = slots.generate_words_from(&list, &mut source, &mut words);
            kani::assert(
                source.calls == 1 && source.requested == 16,
                "the source is asked once for 16 bytes",
            );
            kani::assert(
                source.failed == (result == Err(Error::EntropyFailed)),
                "a failure of the source is EntropyFailed, and nothing else is",
            );
            kani::assert(
                slots.epoch.drawn == count.wrapping_add(u64::from(!source.failed)),
                "the count of draws grows by one exactly when the source answers",
            );
            let mut drawn = [0; 16];
            drawn.copy_from_slice(&source.written[..16]);
            let bytes = expected_hedge(&epoch_key, count, Branch::HedgeWords, &drawn);
            let expected = if result.is_ok() {
                expected_words(&list, &bytes)
            } else {
                original
            };
            kani::assert(
                same_words(&words, &expected),
                "the words of the hedged bytes are written exactly when the key is derived",
            );
            if result.is_ok() {
                let now = snapshot(&slots.memory[0]);
                kani::assert(
                    now.keys.0[..32] == expected_words_key(&bytes) && now.unlocks,
                    "the key in the slot is the one the hedged bytes derive, a key from a secret",
                );
            } else {
                kani::assert(
                    unchanged_except(&slots, &before, 2),
                    "a failed generation changes no slot",
                );
            }
            kani::cover!(result.is_ok(), "words are generated");
            kani::cover!(
                result.is_ok() && slots.epoch.changing,
                "words are generated during a change of epoch"
            );
            kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
            kani::cover!(
                result == Err(Error::DuplicateKey),
                "the key generated is held"
            );
            kani::cover!(
                result == Err(Error::DerivationFailed),
                "the derivation fails"
            );
        });
    }

    /// Without a free slot, from `memory`, generation asks nothing of the source and changes
    /// neither the words nor any slot.
    fn generation_without_a_free_slot(mut memory: [Slot; 2]) {
        let mut epoch = any_epoch(kani::any());
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let mut source = AnyEntropy::new();
        let mut words: Words = kani::any();
        let original = words;
        let result = slots.generate_words_from(&any_list(), &mut source, &mut words);
        kani::assert(
            result == Err(Error::NoFreeSlot) && source.calls == 0,
            "without a free slot nothing is asked",
        );
        kani::assert(
            same_words(&words, &original) && unchanged_except(&slots, &before, 2),
            "nothing changes",
        );
    }

    /// The same in each of the four ways two slots can be taken.
    #[kani::proof]
    #[kani::unwind(65)]
    fn no_words_are_generated_without_a_free_slot() {
        let (loaded, retired) = (Occupancy::Loaded, Occupancy::Retired);
        let layout = kani::any::<u8>() % 4;
        match layout {
            0 => generation_without_a_free_slot([any_slot_in(loaded), any_slot_in(loaded)]),
            1 => generation_without_a_free_slot([any_slot_in(loaded), any_slot_in(retired)]),
            2 => generation_without_a_free_slot([any_slot_in(retired), any_slot_in(loaded)]),
            _ => generation_without_a_free_slot([any_slot_in(retired), any_slot_in(retired)]),
        }
        kani::cover!(layout == 3, "both slots retired");
    }

    /// From any state of two slots and any generation, which includes every state a load leaves: a
    /// handle of this set naming any slot and generation releases a set only if that slot is
    /// loaded with that generation and unchanged in this epoch, and otherwise is refused and changes
    /// nothing; a release wipes
    /// every key and identifier of the set and advances the generation by one, or retires the slot
    /// when the generation runs out; no release panics or overflows.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_handle_releases_only_a_matching_loaded_slot() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut epoch = any_epoch(kani::any());
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };

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
        if target.is_some_and(|named| named.changed) {
            kani::assert(
                result == Err(Error::Unsaved) && unchanged_except(&slots, &before, 2),
                "a set changed in this epoch is not released, and no slot changes",
            );
            kani::cover!(true, "a changed set is kept");
        } else if let Some(named) = target {
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

    /// From any state of two slots, for a handle of this set naming any slot and generation, any
    /// position and either purpose named: revealing writes exactly the 32-byte key at that position
    /// into the output when the handle is live, the set and the call both name external data and
    /// the position holds an enabled key; otherwise it is refused as `StaleHandle`, `WrongPurpose`
    /// or `WrongStage`, in that order, and the output is left as it was. No slot changes either
    /// way.
    #[kani::proof]
    #[kani::unwind(65)]
    fn only_an_enabled_key_for_external_data_is_revealed() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut epoch = any_epoch(false);
        let slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let handle = forged(id);
        let position = any_position();
        let purpose = any_purpose();
        let before = snapshots(&slots);
        let original: [u8; 32] = kani::any();
        let mut out = original;
        let result = slots.reveal32(handle, position, purpose, &mut out);

        let named = snapshot_at(&before, handle.index);
        let at_position = position.index();
        let stage = at(
            &[
                named.stages.stage(0),
                named.stages.stage(1),
                named.stages.stage(2),
            ],
            at_position,
        );
        let expected = if !names_loaded(&before, &handle) {
            Err(Error::StaleHandle)
        } else if purpose != Purpose::ExternalData || named.purpose != purpose {
            Err(Error::WrongPurpose)
        } else if stage != Some(Status::Enabled) {
            Err(Error::WrongStage)
        } else {
            Ok(())
        };
        kani::assert(
            result == expected,
            "a reveal succeeds exactly for an enabled key of a live set for external data, named so \
             by the call, and is otherwise refused for the first reason",
        );
        kani::assert(
            if result.is_ok() {
                out[..] == pick(&named.keys, at_position)[..32]
                    && at_length(&named.lengths, at_position) == KeyLength::Bytes32
            } else {
                out == original
            },
            "a reveal writes exactly the 32-byte key at the position, or nothing",
        );
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a reveal changes no slot",
        );
        kani::cover!(result.is_ok(), "a key is revealed");
        kani::cover!(
            result.is_ok() && at_position == 2,
            "the key at the last position is revealed"
        );
        kani::cover!(
            result == Err(Error::WrongPurpose) && named.purpose == Purpose::Wrap,
            "a key for wrapping is not revealed"
        );
        kani::cover!(
            result == Err(Error::WrongPurpose) && named.purpose == Purpose::ExternalData,
            "a call that does not name external data reveals nothing"
        );
        kani::cover!(
            result == Err(Error::WrongStage) && stage == Some(Status::Disabled),
            "a disabled key is not revealed"
        );
        kani::cover!(
            result == Err(Error::WrongStage) && stage.is_none(),
            "an empty position reveals nothing"
        );
        kani::cover!(
            result == Err(Error::StaleHandle)
                && handle.index < 2
                && named.occupancy == Occupancy::Loaded,
            "a handle of another generation is refused"
        );
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
    /// identifier derived from it, nothing at the others, and the purpose, primary and revision
    /// the plaintext states, unchanged in this epoch, and a stored set. From a plain record, a
    /// plaintext of another epoch or of a set for wrapping is refused as `RecordRejected`; from a
    /// lock record, a plaintext of an epoch other than zero, of a set for external data, or of a
    /// set for wrapping other than a set of one that has never changed. Otherwise no slot changes, and the failure is `NoFreeSlot`,
    /// `RecordRejected`, `DerivationFailed` or `DuplicateKey`, in that order. The offsets are written
    /// from the layout, independently of the parser.
    fn admit_from(mut memory: [Slot; 2]) {
        let id = memory.as_ptr().addr();
        let changing = kani::any();
        let mut epoch = any_epoch(changing);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let plaintext: [u8; PLAINTEXT_LEN] = kani::any();
        let lock: bool = kani::any();
        let before = snapshots(&slots);
        let first_free = first_free(&before);
        let result = slots.admit(&plaintext, lock);
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
        let mut named_epoch = [0; 8];
        named_epoch.copy_from_slice(&plaintext[19..27]);
        let other_epoch =
            u64::from_le_bytes(named_epoch) != if lock { 0 } else { slots.epoch.number };
        let members = [0, 1, 2].map(|position| plaintext_key(&plaintext, position));
        let ids = members.map(|(key, length)| expected_key_id(&key, length));
        let filled = [0, 1, 2].map(|position| plaintext[35 + 66 * position] != 0);
        let mut revision = [0; 8];
        revision.copy_from_slice(&plaintext[27..35]);
        let wrapping = plaintext[1] == 1;
        let one = filled == [true, false, false]
            && plaintext[35] == 1
            && plaintext[2] == 0
            && revision == [0; 8];
        let repeated = (0..MEMBERS).any(|position| {
            at(&filled, position)
                && (held(&before, &at(&ids, position))
                    || (0..position).any(|earlier| {
                        at(&filled, earlier) && at(&ids, earlier) == at(&ids, position)
                    }))
        });
        kani::assert(
            if parsed.is_err() || other_epoch || wrapping != lock || (wrapping && !one) {
                result == Err(Error::RecordRejected)
            } else if any_failed() {
                result == Err(Error::DerivationFailed)
            } else if repeated {
                result == Err(Error::DuplicateKey)
            } else {
                result.is_ok()
            },
            "a plaintext is admitted exactly when it parses, names its epoch, is for wrapping exactly \
             when it comes from a lock record and then holds one key, finds a free slot, its keys' \
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
            let purpose = if plaintext[1] == 1 {
                Purpose::Wrap
            } else {
                Purpose::ExternalData
            };
            kani::assert(
                now.stages == stages
                    && now.stages.primary() == usize::from(plaintext[2])
                    && now.purpose == purpose
                    && !now.unlocks
                    && !now.changed,
                "the slot keeps the primary, the revision and the purpose the plaintext states, a \
                 stored set, unchanged in this epoch",
            );
            kani::assert(
                unchanged_except(&slots, &before, index),
                "admitting changes no other slot",
            );
            kani::cover!(
                filled == [true, true, true] && plaintext[35] == 2,
                "a full set with a disabled key is admitted"
            );
            kani::cover!(
                purpose == Purpose::ExternalData,
                "a set of external data is admitted"
            );
            kani::cover!(purpose == Purpose::Wrap, "a set for wrapping is admitted");
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a refused plaintext changes no slot",
            );
        }
        kani::cover!(parsed.is_err(), "a malformed plaintext is refused");
        kani::cover!(
            parsed.is_ok() && other_epoch,
            "a plaintext of another epoch is refused"
        );
        kani::cover!(
            parsed.is_ok() && !other_epoch && wrapping && !one && filled == [true, false, false],
            "a set for wrapping that has changed is refused"
        );
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

    /// Stands in for the cipher of `N` bytes: writes any bytes, accepts or rejects at will, and
    /// remembers how often it was called, and the key and nonce it was given, what it wrote and
    /// whether it accepted.
    struct AnyCipher<const N: usize> {
        calls: usize,
        key: [u8; CIPHER_KEY_LEN],
        nonce: [u8; NONCE_LEN],
        given: [u8; N],
        tag: [u8; TAG_LEN],
        written: [u8; N],
        accepted: bool,
    }

    impl<const N: usize> AnyCipher<N> {
        fn new() -> Self {
            Self {
                calls: 0,
                key: [0; CIPHER_KEY_LEN],
                nonce: [0; NONCE_LEN],
                given: [0; N],
                tag: [0; TAG_LEN],
                written: [0; N],
                accepted: false,
            }
        }

        fn open(
            &mut self,
            key: &[u8; CIPHER_KEY_LEN],
            nonce: &[u8; NONCE_LEN],
            buffer: &mut [u8; N],
            tag: &[u8; TAG_LEN],
        ) -> Result<(), Rejected> {
            let written: [u8; N] = kani::any();
            let accepted: bool = kani::any();
            (self.given, self.tag) = (*buffer, *tag);
            *buffer = written;
            (self.key, self.nonce, self.written, self.accepted) = (*key, *nonce, written, accepted);
            self.calls = self.calls.saturating_add(1);
            if accepted { Ok(()) } else { Err(Rejected) }
        }
    }

    /// For a loaded set for wrapping in any state, any 261-byte record, any associated data of up to
    /// two bytes and any behaviour of the cipher its interface allows: opening tries the key of the
    /// set, once, with the cipher key derived from it and the key of this epoch, or from it alone for
    /// a lock record, and not at all when that derivation fails, which is `DerivationFailed`; it
    /// leaves in the output the plaintext the cipher wrote when the cipher accepts it and it names
    /// that key's identifier as its parent, and otherwise fails with `RecordRejected` and leaves the
    /// output as it was.
    #[kani::proof]
    #[kani::unwind(65)]
    fn opening_uses_the_key_of_the_parent() {
        let mut memory = [any_slot_in(Occupancy::Loaded)];
        kani::assume(memory[0].purpose == Purpose::Wrap);
        let changing = kani::any();
        let mut epoch = any_epoch(changing);
        let slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let record: [u8; RECORD_LEN] = kani::any();
        let aad: [u8; 2] = kani::any();
        let before = snapshot(&slots.memory[0]);
        let epoch_key = first_half(&slots.epoch.key);
        let mut cipher = AnyCipher::<PLAINTEXT_LEN>::new();
        let original: [u8; PLAINTEXT_LEN] = kani::any();
        let mut found = original;
        let lock: bool = kani::any();

        let result = slots.open_under(
            0,
            &aad,
            &record,
            &mut found,
            &mut |key, nonce, _, buffer, tag| cipher.open(key, nonce, buffer, tag),
            lock,
        );
        kani::assert(
            cipher.calls == usize::from(!any_failed()),
            "the key is tried once, unless its derivation fails",
        );
        let expected = if lock {
            expected_lock_key(&before.keys.0, before.lengths[0])
        } else {
            expected_wrap_key(&before.keys.0, before.lengths[0], &epoch_key)
        };
        kani::assert(
            any_failed() || (cipher.key == expected && cipher.nonce[..] == record[..NONCE_LEN]),
            "the trial uses the cipher key derived from the key, and the record's nonce",
        );
        let named = cipher.accepted && cipher.written[3..19] == before.ids.0;
        kani::assert(
            if any_failed() {
                result == Err(Error::DerivationFailed) && same(&found, &original)
            } else if named {
                result == Ok(()) && same(&found, &cipher.written)
            } else {
                result == Err(Error::RecordRejected) && same(&found, &original)
            },
            "opening keeps the plaintext exactly when the cipher accepts it and it names the key, \
             and otherwise leaves the output as it was",
        );
        kani::cover!(
            result.is_ok() && lock,
            "the key from a secret opens the record"
        );
        kani::cover!(result.is_ok() && !lock, "the stored key opens the record");
        kani::cover!(
            result == Err(Error::RecordRejected) && cipher.accepted,
            "the key opens the record but is not named in it"
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

    /// Unwrapping or unlocking in `memory`, for a handle of this set naming any slot and generation,
    /// any record or lock record and any context of up to two bytes, whatever the cipher does: an
    /// empty context, a stale parent, a parent not for wrapping, one of the other level and a full
    /// set are refused, in that order, before anything is decrypted. An unlock opens the outer
    /// layer once, under the key derived from the key of this epoch, and refuses it as
    /// `StaleRecord`, decrypting nothing more, unless the cipher accepts it and it names this
    /// epoch; the inner record it then opens is the one the outer layer holds. A refused call
    /// changes no slot, and one that succeeds changes only the first free slot, and needs every
    /// trial the cipher accepts and every derivation to succeed. What the trial of the parent's
    /// key gives, `opening_uses_the_key_of_the_parent` proves. Returns the outcome and whether it
    /// was an unlock.
    fn unwrap_from(mut memory: [Slot; 2]) -> (Result<(), Error>, bool) {
        let id = memory.as_ptr().addr();
        let mut epoch = any_epoch(kani::any());
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let parent = forged(id);
        let lock: bool = kani::any();
        let context_bytes: [u8; 2] = kani::any();
        let context = any_context(&context_bytes);
        let before = snapshots(&slots);
        let parent_live = names_loaded(&before, &parent);
        let named = snapshot_at(&before, parent.index);
        let wrapping = parent_live && named.purpose == Purpose::Wrap;
        let level = wrapping && named.unlocks == lock;
        let first_free = first_free(&before);
        let (epoch_key, number) = (first_half(&slots.epoch.key), slots.epoch.number);
        let mut layer = AnyCipher::<LAYER_LEN>::new();
        let mut cipher = AnyCipher::<PLAINTEXT_LEN>::new();

        let result = if lock {
            let record: [u8; LOCK_RECORD_LEN] = kani::any();
            slots.unlock_on_stack(
                parent,
                context,
                &record,
                |key, nonce, _, buffer, tag| layer.open(key, nonce, buffer, tag),
                |key, nonce, _, buffer, tag| cipher.open(key, nonce, buffer, tag),
            )
        } else {
            let record: [u8; RECORD_LEN] = kani::any();
            slots.unwrap_on_stack(parent, context, &record, |key, nonce, _, buffer, tag| {
                cipher.open(key, nonce, buffer, tag)
            })
        };
        let refused_before = context.is_empty() || !level || first_free.is_none();
        kani::assert(
            if context.is_empty() {
                result == Err(Error::InvalidContext)
            } else if !parent_live {
                result == Err(Error::StaleHandle)
            } else if !wrapping {
                result == Err(Error::WrongPurpose)
            } else if !level {
                result == Err(Error::WrongLevel)
            } else if first_free.is_none() {
                result == Err(Error::NoFreeSlot)
            } else {
                true
            },
            "an unwrap and an unlock refuse a bad context, a stale parent, a parent not for \
             wrapping, a parent of the other level and a full set",
        );
        kani::cover!(
            result == Err(Error::WrongPurpose),
            "a parent for external data is refused"
        );
        kani::cover!(
            result == Err(Error::WrongLevel) && lock,
            "a stored key unlocks nothing"
        );
        kani::cover!(
            result == Err(Error::WrongLevel) && !lock,
            "a key from a secret unwraps nothing"
        );
        kani::assert(
            !refused_before || (cipher.calls == 0 && layer.calls == 0),
            "those refusals come before any decryption",
        );
        let current = layer.accepted && layer.written[..8] == number.to_le_bytes();
        let layer_key = expected_layer_key(&epoch_key);
        let mut inner = [0; RECORD_LEN];
        inner.copy_from_slice(&layer.written[8..]);
        let held = cipher.nonce[..] == inner[..NONCE_LEN]
            && same_bytes(&cipher.given, &inner[NONCE_LEN..NONCE_LEN + PLAINTEXT_LEN])
            && cipher.tag[..] == inner[NONCE_LEN + PLAINTEXT_LEN..];
        kani::assert(
            !lock
                || refused_before
                || (any_failed()
                    && layer.calls == 0
                    && cipher.calls == 0
                    && result == Err(Error::DerivationFailed))
                || (layer.calls == 1
                    && layer.key == layer_key
                    && (current || (result == Err(Error::StaleRecord) && cipher.calls == 0))),
            "an unlock opens the outer layer once, under the key of this epoch, and refuses it as \
             StaleRecord, decrypting nothing more, unless it opens and names this epoch",
        );
        kani::assert(
            !lock || cipher.calls == 0 || held,
            "the inner record is the one the outer layer holds: its nonce, encrypted part and tag",
        );
        kani::assert(
            result.is_err() || (cipher.accepted && !any_failed() && (!lock || current)),
            "a set is loaded only after the trials the cipher accepts and when every derivation \
             succeeds",
        );
        kani::assert(
            refused_before || !any_failed() || result == Err(Error::DerivationFailed),
            "a call that a derivation fails fails with DerivationFailed",
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
            "a refused call changes no slot, and one that succeeds only the first free slot, whose \
             handle names these slots and that slot's generation",
        );
        (result.map(|_| ()), lock)
    }

    /// The outcomes of an unwrap or an unlock that decrypts.
    fn every_outcome((result, lock): (Result<(), Error>, bool)) {
        kani::cover!(result.is_ok() && !lock, "a record is unwrapped");
        kani::cover!(result.is_ok() && lock, "a lock record is unlocked");
        kani::cover!(result == Err(Error::RecordRejected), "a record is rejected");
        kani::cover!(
            result == Err(Error::StaleRecord),
            "a lock record not of this epoch is refused"
        );
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
        let (result, _) = past_a(Occupancy::Retired, unwrap_from);
        kani::cover!(
            result == Err(Error::NoFreeSlot),
            "a live parent leaves no slot free"
        );
    }

    /// From any state of two slots and of the epoch, with a change to the next under way or not,
    /// for handles of this set naming any slots and generations, any context of up to two bytes
    /// and any record buffer, whatever the platform's source and the cipher do: a wrap, or a lock
    /// when `lock` says so, changes no key, stage or epoch, and marks the set wrapped for the next
    /// epoch only when it succeeds during a change; it writes the record only when it succeeds,
    /// starting with the nonce the source gave last, hedged with the key the record is wrapped in
    /// at its count; it refuses an empty context, a stale handle, a set wrapped under itself, a
    /// parent that does not serve wrapping, a set or a parent of the wrong level, a set changed in
    /// this epoch outside a change, and a failed source. Each draw the source answers is counted
    /// once. Returns the outcome.
    fn wrap_from(lock: bool) -> Result<(), Error> {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let changing = kani::any();
        let mut epoch = any_epoch(changing);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let epoch = slots.epoch.number;
        let (set, parent) = (forged(id), forged(id));
        let context_bytes: [u8; 2] = kani::any();
        let context = any_context(&context_bytes);
        let original: [u8; LOCK_RECORD_LEN] = kani::any();
        let mut record = original;
        let mut entropy = AnyEntropy::new();
        let before = snapshots(&slots);
        let live = names_loaded(&before, &set) && names_loaded(&before, &parent);
        let (child, wrapping) = (
            snapshot_at(&before, set.index),
            snapshot_at(&before, parent.index),
        );

        let (epoch_key, next_key) = (*slots.epoch.key.bytes(), *slots.epoch.next.bytes());
        let count = slots.epoch.drawn;
        let result = if lock {
            slots.wrap_on_stack(set, parent, context, &mut entropy, Out::Lock(&mut record))
        } else {
            let mut plain: [u8; RECORD_LEN] = original[..RECORD_LEN].try_into().unwrap();
            let result =
                slots.wrap_on_stack(set, parent, context, &mut entropy, Out::Record(&mut plain));
            record[..RECORD_LEN].copy_from_slice(&plain);
            result
        };
        let sealing = result.is_ok() && changing;
        kani::assert(
            if sealing {
                unchanged_except(&slots, &before, set.index)
                    && snapshot(slot_at(&slots, set.index)) == marked(child, child.changed, true)
            } else {
                unchanged_except(&slots, &before, 2)
            },
            "a wrap changes no key or stage, and marks the set wrapped for the next epoch only when \
             it succeeds during a change",
        );
        kani::assert(
            slots.epoch.number == epoch
                && slots.epoch.changing == changing
                && *slots.epoch.key.bytes() == epoch_key
                && *slots.epoch.next.bytes() == next_key,
            "a wrap changes no epoch and no key of one",
        );
        kani::assert(
            slots.epoch.drawn == count.wrapping_add(u64::from(entropy.answered)),
            "a draw the source answers is counted once",
        );
        let level =
            !child.unlocks && (child.purpose == Purpose::Wrap) == lock && wrapping.unlocks == lock;
        kani::assert(
            if context.is_empty() {
                result == Err(Error::InvalidContext)
            } else if !live {
                result == Err(Error::StaleHandle)
            } else if set.index == parent.index {
                result == Err(Error::SameKey)
            } else if wrapping.purpose != Purpose::Wrap {
                result == Err(Error::WrongPurpose)
            } else if !level {
                result == Err(Error::WrongLevel)
            } else if child.changed && !changing {
                result == Err(Error::Unsaved)
            } else if changing && epoch == u64::MAX {
                result == Err(Error::EpochExhausted)
            } else if entropy.failed {
                result == Err(Error::EntropyFailed)
            } else {
                result.is_ok()
                    || result == Err(Error::DerivationFailed)
                    || result == Err(Error::CipherFailed)
            },
            "a wrap refuses a bad context, a stale handle, a set wrapping itself, a parent not for \
             wrapping, a set or a parent of the wrong level, an unsaved set outside a change and a \
             failed source",
        );
        kani::cover!(
            result == Err(Error::WrongPurpose),
            "a parent for external data is refused"
        );
        kani::cover!(
            result == Err(Error::WrongLevel),
            "a set of the wrong level is refused"
        );
        let written = if lock { LOCK_RECORD_LEN } else { RECORD_LEN };
        kani::assert(
            if result.is_ok() {
                let mut drawn = [0; 12];
                drawn.copy_from_slice(&entropy.written[..12]);
                let mut salt = [0; 32];
                salt.copy_from_slice(&if changing { next_key } else { epoch_key }[..32]);
                let last = count
                    .wrapping_add(u64::from(entropy.answered))
                    .wrapping_sub(1);
                record[..12] == expected_hedge(&salt, last, Branch::HedgeNonce, &drawn)
            } else {
                same_bytes(&record[..written], &original[..written])
            },
            "a wrap writes the record only when it succeeds, starting with the nonce hedged from \
             the source's last bytes",
        );
        kani::assert(
            !any_failed() || result == Err(Error::DerivationFailed),
            "a wrap that a derivation fails fails with DerivationFailed",
        );
        kani::cover!(result.is_ok(), "a set is wrapped");
        kani::cover!(
            sealing && child.changed,
            "a changed set is wrapped for the next epoch"
        );
        kani::cover!(
            entropy.failed && entropy.written.iter().any(|&byte| byte != 0),
            "the source fails after writing bytes"
        );
        kani::cover!(result == Err(Error::CipherFailed), "the cipher fails");
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "the derivation fails"
        );
        result
    }

    /// The wrap of a set for external data.
    #[kani::proof]
    #[kani::unwind(234)]
    fn a_wrap_changes_no_slot_and_writes_only_when_it_succeeds() {
        let result = wrap_from(false);
        kani::cover!(
            result == Err(Error::Unsaved),
            "a changed set is not wrapped in its epoch"
        );
    }

    /// The lock of a stored key for wrapping.
    #[kani::proof]
    #[kani::unwind(270)]
    fn a_lock_changes_no_slot_and_writes_only_when_it_succeeds() {
        let result = wrap_from(true);
        kani::cover!(result.is_ok(), "a stored key is locked");
    }

    /// From any state of two slots and of the epoch, with a change to the next under way or not,
    /// for any lock record, any output buffer and any context of up to two bytes, whatever the
    /// platform's source and the cipher do: a carry changes no slot and no epoch but its count of
    /// draws. It refuses an empty context and a missing change before it decrypts, then opens the
    /// record once, under the key derived from the key of this epoch and with the record's nonce,
    /// and refuses it as `StaleRecord`, asking the source nothing, unless the cipher accepts it
    /// and it names this epoch. It writes the output only when it succeeds, starting with the nonce
    /// the source gave, hedged with the key of the next epoch.
    #[kani::proof]
    #[kani::unwind(270)]
    fn a_carry_changes_no_slot_and_writes_only_when_it_succeeds() {
        let mut memory = [any_slot(), any_slot()];
        let changing = kani::any();
        let mut epoch = any_epoch(changing);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let (number, epoch_key, next_key) = (
            slots.epoch.number,
            first_half(&slots.epoch.key),
            first_half(&slots.epoch.next),
        );
        let count = slots.epoch.drawn;
        let context_bytes: [u8; 2] = kani::any();
        let context = any_context(&context_bytes);
        let from: [u8; LOCK_RECORD_LEN] = kani::any();
        let original: [u8; LOCK_RECORD_LEN] = kani::any();
        let mut to = original;
        let mut entropy = AnyEntropy::new();
        let mut layer = AnyCipher::<LAYER_LEN>::new();
        let before = snapshots(&slots);

        let result = slots.carry_on_stack(
            context,
            &mut entropy,
            &from,
            &mut to,
            |key, nonce, _, buffer, tag| layer.open(key, nonce, buffer, tag),
        );
        kani::assert(
            unchanged_except(&slots, &before, 2)
                && slots.epoch.number == number
                && slots.epoch.changing == changing
                && first_half(&slots.epoch.key) == epoch_key
                && first_half(&slots.epoch.next) == next_key
                && slots.epoch.drawn == count.wrapping_add(u64::from(entropy.answered)),
            "a carry changes no slot and no epoch, and counts once each draw the source answers",
        );
        let current = layer.accepted && layer.written[..8] == number.to_le_bytes();
        kani::assert(
            if context.is_empty() {
                result == Err(Error::InvalidContext) && layer.calls == 0
            } else if !changing {
                result == Err(Error::NoEpochChange) && layer.calls == 0
            } else if number == u64::MAX {
                result == Err(Error::EpochExhausted) && layer.calls == 0
            } else if layer.calls == 0 {
                result == Err(Error::DerivationFailed) && any_failed()
            } else if !current {
                result == Err(Error::StaleRecord) && entropy.calls == 0
            } else if entropy.failed {
                result == Err(Error::EntropyFailed)
            } else {
                result.is_ok()
                    || result == Err(Error::DerivationFailed)
                    || result == Err(Error::CipherFailed)
            },
            "a carry refuses a bad context and a missing change, a failed derivation, a record that \
             does not open in this epoch and a failed source",
        );
        kani::assert(
            !any_failed() || result == Err(Error::DerivationFailed),
            "a carry that a derivation fails fails with DerivationFailed",
        );
        kani::assert(
            layer.calls <= 1
                && (layer.calls == 0
                    || (layer.key == expected_layer_key(&epoch_key)
                        && layer.nonce[..] == from[..NONCE_LEN])),
            "the record is opened once, under the key of this epoch and with its own nonce",
        );
        kani::assert(
            if result.is_ok() {
                let mut drawn = [0; 12];
                drawn.copy_from_slice(&entropy.written[..12]);
                to[..12] == expected_hedge(&next_key, count, Branch::HedgeNonce, &drawn)
            } else {
                same(&to, &original)
            },
            "a carry writes its output only when it succeeds, starting with the nonce hedged with \
             the key of the next epoch",
        );
        kani::cover!(result.is_ok(), "a lock record is carried");
        kani::cover!(
            result == Err(Error::StaleRecord) && layer.accepted,
            "a lock record of another epoch is refused"
        );
        kani::cover!(
            result == Err(Error::NoEpochChange),
            "nothing is carried outside a change"
        );
        kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
    }

    fn any_position() -> Position {
        match kani::any::<u8>() % 3 {
            0 => Position::First,
            1 => Position::Second,
            _ => Position::Third,
        }
    }

    /// Promotes, disables, enables or destroys the key at any position through `handle`, and returns
    /// what the call gave, what the transition of the stages gave, and whether it destroyed.
    fn any_change(
        slots: &mut Slots<'_>,
        handle: Handle<'static>,
        chosen: Position,
        expected: &mut Stages,
    ) -> (Result<(), Error>, Result<(), Error>, bool) {
        let destroying = kani::any::<u8>() % 4 == 3;
        let (result, outcome) = match kani::any::<u8>() % 3 {
            _ if destroying => (
                slots.destroy(handle, chosen),
                expected.destroy(chosen.index()),
            ),
            0 => (
                slots.promote(handle, chosen),
                expected.promote(chosen.index()),
            ),
            1 => (
                slots.disable(handle, chosen),
                expected.disable(chosen.index()),
            ),
            _ => (
                slots.enable(handle, chosen),
                expected.enable(chosen.index()),
            ),
        };
        (result, outcome.map_err(Error::from), destroying)
    }

    /// From `memory`, with the slot `index` loaded and any position: promoting, disabling, enabling
    /// and destroying through the live handle of that slot are refused as `WrongPurpose` for a set
    /// for wrapping, then as `EpochChanging` during a change of epoch, then as `Unsaved` if the set
    /// has changed in this epoch, and otherwise
    /// change its stages exactly as the transition of the stages gives, marking the set changed and
    /// not wrapped for the next epoch; a refusal changes nothing; a destroy wipes the key and the
    /// identifier at the position and leaves every other key as it was; the slot keeps its
    /// generation and purpose, and no other slot changes.
    fn change_in(mut memory: [Slot; 2], index: usize) {
        let id = memory.as_ptr().addr();
        let changing = kani::any();
        let mut epoch = any_epoch(changing);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let named = snapshot_at(&before, index);
        let handle = Handle {
            slots: id,
            index,
            generation: named.generation,
            memory: PhantomData,
        };
        let chosen = any_position();
        let mut expected = named.stages;
        let (result, outcome, destroying) = any_change(&mut slots, handle, chosen, &mut expected);
        let wrapping = named.purpose == Purpose::Wrap;
        let refused = wrapping || changing || named.changed;
        kani::assert(
            result
                == if wrapping {
                    Err(Error::WrongPurpose)
                } else if changing {
                    Err(Error::EpochChanging)
                } else if named.changed {
                    Err(Error::Unsaved)
                } else {
                    outcome
                },
            "a change of a set for wrapping, during a change of epoch, or of a set changed in this \
             epoch is refused, and otherwise succeeds exactly when the transition of the stages \
             does, or fails as it does",
        );
        let applied = result.is_ok();
        let now = snapshot(slot_at(&slots, index));
        kani::assert(
            now.stages == if refused { named.stages } else { expected }
                && now.occupancy == Occupancy::Loaded
                && now.generation == named.generation
                && now.purpose == named.purpose
                && now.changed == (named.changed || applied)
                && now.sealed == (named.sealed && !applied),
            "the set keeps its slot, generation and purpose, its stages change as the transition \
             gives, and a change marks it changed and not wrapped for the next epoch",
        );
        let wiped = destroying && applied;
        for position in 0..MEMBERS {
            kani::assert(
                if wiped && position == chosen.index() {
                    pick(&now.keys, position) == [0; 64]
                        && at(&now.lengths, position) == KeyLength::Bytes32
                        && pick(&now.ids, position) == [0; ID_LEN]
                } else {
                    pick(&now.keys, position) == pick(&named.keys, position)
                        && at(&now.lengths, position) == at(&named.lengths, position)
                        && pick(&now.ids, position) == pick(&named.ids, position)
                },
                "a destroy wipes the key and identifier at its position, and no other key changes",
            );
        }
        kani::assert(
            unchanged_except(&slots, &before, index),
            "a change touches no other slot",
        );
        kani::cover!(
            wiped && chosen == Position::Third,
            "a key at the last position is destroyed"
        );
        kani::cover!(
            !destroying && result.is_ok() && now.stages.primary() == chosen.index(),
            "a key is promoted"
        );
        kani::cover!(
            result == Err(Error::PrimaryKey),
            "a change is refused for the primary"
        );
        kani::cover!(
            result == Err(Error::WrongStage),
            "a change finds the wrong stage"
        );
        kani::cover!(
            result == Err(Error::Unsaved),
            "a set changes once in an epoch"
        );
        kani::cover!(
            result == Err(Error::EpochChanging),
            "no set changes during a change of epoch"
        );
        kani::cover!(
            result == Err(Error::WrongPurpose),
            "a set for wrapping takes no change"
        );
    }

    /// A change through the first slot; with the next, through either slot of two in any state.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_change_of_stage_in_the_first_slot() {
        change_in([any_slot_in(Occupancy::Loaded), any_slot()], 0);
    }

    /// A change through the second slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_change_of_stage_in_the_second_slot() {
        change_in([any_slot(), any_slot_in(Occupancy::Loaded)], 1);
    }

    /// From any state of two slots, a handle of this set that names no loaded slot with its
    /// generation is refused by every change of stage, at any position, and no slot changes.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_change_of_stage_with_a_stale_handle_changes_nothing() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let changing = kani::any();
        let mut epoch = any_epoch(changing);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let handle = forged(id);
        kani::assume(!live(&slots, id, &handle));
        let before = snapshots(&slots);
        let (result, _, _) = any_change(&mut slots, handle, any_position(), &mut Stages::one());
        let mut source: [u8; 32] = kani::any();
        let original = source;
        let added = slots.add32(handle, &mut source);
        kani::assert(
            result == Err(Error::StaleHandle)
                && added == Err(Error::StaleHandle)
                && source == original
                && unchanged_except(&slots, &before, 2),
            "a stale handle is refused by every change and addition, and changes nothing",
        );
        kani::cover!(
            handle.index < 2 && slot_at(&slots, handle.index).occupancy == Occupancy::Loaded,
            "the stale handle names a loaded slot"
        );
    }

    /// From `memory`, with the slot `index` loaded and no change of epoch under way: adding a key
    /// of 32 bytes, any bytes, through its live handle puts it into the first empty position of
    /// the set, enabled, with the identifier derived from its bytes and its length alone, marks the
    /// set changed and not wrapped for the next epoch, and changes nothing else; it fails as
    /// `WrongPurpose` for a set for wrapping, as `Unsaved` if the set has changed in this epoch, as
    /// the transition of the stages does when no position is empty or the set is exhausted, and
    /// otherwise with DerivationFailed when the derivation fails and with DuplicateKey exactly when
    /// a loaded slot holds a key with that identifier, for any purpose; the source is wiped exactly
    /// when the addition succeeds, and a failed addition changes no slot. A generation fills a key
    /// as a load does, which the proofs of a load cover. Returns the outcome and the set's purpose.
    fn add_in(mut memory: [Slot; 2], index: usize) -> (Result<Position, Error>, Purpose) {
        let id = memory.as_ptr().addr();
        let mut epoch = any_epoch(false);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let named = snapshot_at(&before, index);
        let handle = Handle {
            slots: id,
            index,
            generation: named.generation,
            memory: PhantomData,
        };
        let mut expected = named.stages;
        let position = expected.add();
        let mut source: [u8; 32] = kani::any();
        let original = source;
        let result = slots.add32(handle, &mut source);
        kani::assert(
            source == if result.is_ok() { [0; 32] } else { original },
            "an addition wipes its source exactly when it succeeds",
        );
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&original);
        let length = KeyLength::Bytes32;
        let key_id = expected_key_id(&bytes, length);
        kani::assert(
            match position {
                _ if named.purpose == Purpose::Wrap => result == Err(Error::WrongPurpose),
                _ if named.changed => result == Err(Error::Unsaved),
                Err(refused) => result == Err(Error::from(refused)),
                Ok(at) => {
                    if failed() {
                        result == Err(Error::DerivationFailed)
                    } else if held(&before, &key_id) {
                        result == Err(Error::DuplicateKey)
                    } else {
                        result.ok() == Position::at(at)
                    }
                }
            },
            "an addition fails as WrongPurpose for a set for wrapping, as Unsaved for a set changed \
             in this epoch, as the stages refuse it, then with DerivationFailed when the derivation \
             fails, with DuplicateKey when the key is held, and otherwise succeeds at the first \
             empty position",
        );
        if let (Ok(added), Ok(at)) = (result, position) {
            let now = snapshot(slot_at(&slots, index));
            kani::assert(
                added.index() == at
                    && now.stages == expected
                    && now.occupancy == Occupancy::Loaded
                    && now.generation == named.generation
                    && now.purpose == named.purpose
                    && now.changed
                    && !now.sealed,
                "the set keeps its slot, generation and purpose, its stages gain the key, and it is \
                 marked changed and not wrapped for the next epoch",
            );
            for position in 0..MEMBERS {
                kani::assert(
                    if position == at {
                        pick(&now.keys, position) == bytes
                            && at_length(&now.lengths, position) == length
                            && pick(&now.ids, position) == key_id
                    } else {
                        pick(&now.keys, position) == pick(&named.keys, position)
                            && at_length(&now.lengths, position)
                                == at_length(&named.lengths, position)
                            && pick(&now.ids, position) == pick(&named.ids, position)
                    },
                    "the added key and its identifier are at its position, and no other key changes",
                );
            }
            kani::assert(
                unchanged_except(&slots, &before, index),
                "an addition touches no other slot",
            );
            kani::cover!(at == 2, "a key is added last");
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a failed addition changes no slot",
            );
        }
        kani::cover!(result == Err(Error::DuplicateKey), "the added key is held");
        kani::cover!(
            result == Err(Error::Unsaved),
            "a set changed in this epoch takes no key"
        );
        kani::cover!(result == Err(Error::SetFull), "the set is full");
        kani::cover!(
            result == Err(Error::WrongPurpose),
            "a set for wrapping takes no key"
        );
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "the derivation fails"
        );
        (result, named.purpose)
    }

    /// Stands in for the platform: switches the root or fails, as chosen when made, erases with any
    /// outcome, and remembers what it was asked.
    struct AnyRoot {
        switches: bool,
        answer: Erasure,
        switched: Option<u64>,
        erased: Option<u64>,
    }

    impl Root for AnyRoot {
        fn switch(&mut self, next: u64) -> Result<(), RootFailed> {
            self.switched = Some(next);
            if self.switches {
                Ok(())
            } else {
                Err(RootFailed)
            }
        }

        fn erase(&mut self, old: u64) -> Erasure {
            self.erased = Some(old);
            self.answer
        }
    }

    fn any_root() -> AnyRoot {
        AnyRoot {
            switches: kani::any(),
            answer: match kani::any::<u8>() % 3 {
                0 => Erasure::Guaranteed,
                1 => Erasure::BestEffort,
                _ => Erasure::NotErased,
            },
            switched: None,
            erased: None,
        }
    }

    /// `snapshot` with its marks of a change set to `changed` and `sealed`.
    fn marked(snapshot: Snapshot, changed: bool, sealed: bool) -> Snapshot {
        let mut marked = snapshot;
        marked.changed = changed;
        marked.sealed = sealed;
        marked
    }

    /// From any state of two slots and of the epoch, with a change to the next under way or not:
    /// beginning a change is refused while one is under way and in the last epoch, and otherwise
    /// takes the key of the next epoch and wipes its source; abandoning, only while a change is
    /// under way, wipes that key, has the platform erase the root made for it and forgets which
    /// sets were wrapped for the next epoch; committing is refused without a change, while
    /// a set changed in this epoch has not been wrapped for the next since, and when the platform
    /// does not switch the root, and then changes nothing and asks the platform nothing more;
    /// otherwise the next epoch with its key becomes this one, the old key is gone, every set
    /// counts as saved and keeps its keys and stages, the platform is asked to switch to the next
    /// epoch and then to erase the old, and its answer is returned.
    #[kani::proof]
    #[kani::unwind(65)]
    fn an_epoch_changes_only_in_order() {
        let mut memory = [any_slot(), any_slot()];
        let changing = kani::any();
        let mut epoch = any_epoch(changing);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let (epoch, epoch_key, next_key) = (
            slots.epoch.number,
            *slots.epoch.key.bytes(),
            *slots.epoch.next.bytes(),
        );
        let unchanged = |slots: &Slots<'_>| {
            unchanged_except(slots, &before, 2)
                && slots.epoch.number == epoch
                && *slots.epoch.key.bytes() == epoch_key
                && *slots.epoch.next.bytes() == next_key
                && slots.epoch.changing == changing
        };
        match kani::any::<u8>() % 3 {
            0 => {
                let mut source: [u8; 32] = kani::any();
                let original = source;
                let result = slots.begin_epoch(&mut source);
                kani::assert(
                    if changing {
                        result == Err(Error::EpochChanging)
                    } else if epoch == u64::MAX {
                        result == Err(Error::EpochExhausted)
                    } else {
                        result.is_ok()
                    },
                    "a change begins unless one is under way or this is the last epoch",
                );
                kani::assert(
                    if result.is_ok() {
                        slots.epoch.changing
                            && first_half(&slots.epoch.next) == original
                            && slots.epoch.next.length() == KeyLength::Bytes32
                            && source == [0; 32]
                            && unchanged_except(&slots, &before, 2)
                            && slots.epoch.number == epoch
                            && *slots.epoch.key.bytes() == epoch_key
                    } else {
                        source == original && unchanged(&slots)
                    },
                    "a change takes the key of the next epoch and wipes its source, and a refused \
                     one changes nothing",
                );
                kani::cover!(result.is_ok(), "a change begins");
            }
            1 => {
                let mut root = any_root();
                let result = slots.abandon_epoch(&mut root);
                let next = epoch.checked_add(1);
                kani::assert(
                    if !changing {
                        result == Err(Error::NoEpochChange)
                    } else if next.is_none() {
                        result == Err(Error::EpochExhausted)
                    } else {
                        result == Ok(root.answer)
                    },
                    "a change is abandoned only while under way, returning how surely its root is \
                     erased",
                );
                kani::assert(
                    if result.is_ok() {
                        !slots.epoch.changing
                            && *slots.epoch.next.bytes() == [0; 64]
                            && slots.epoch.number == epoch
                            && *slots.epoch.key.bytes() == epoch_key
                            && root.erased == next
                            && root.switched.is_none()
                            && (0..2).all(|index| {
                                snapshot(&slots.memory[index])
                                    == marked(before[index], before[index].changed, false)
                            })
                    } else {
                        unchanged(&slots) && root.erased.is_none()
                    },
                    "abandoning wipes the key of the next epoch, has the platform erase its root, \
                     forgets what was wrapped for it, and keeps this epoch and every set; a refusal \
                     changes nothing",
                );
                kani::cover!(result.is_ok(), "a change is abandoned");
            }
            _ => {
                let mut root = any_root();
                let unsaved = before.iter().any(|snapshot| {
                    snapshot.occupancy == Occupancy::Loaded && snapshot.changed && !snapshot.sealed
                });
                let result = slots.commit_epoch(&mut root);
                let next = epoch.checked_add(1);
                kani::assert(
                    if !changing {
                        result == Err(Error::NoEpochChange) && root.switched.is_none()
                    } else if next.is_none() {
                        result == Err(Error::EpochExhausted) && root.switched.is_none()
                    } else if unsaved {
                        result == Err(Error::Unsaved) && root.switched.is_none()
                    } else if !root.switches {
                        result == Err(Error::RootFailed) && root.switched == next
                    } else {
                        result == Ok(root.answer)
                    },
                    "a commit is refused without a change, with a set unsaved, and when the root \
                     is not switched, and otherwise returns how surely the old root is erased",
                );
                if result.is_ok() {
                    kani::assert(
                        root.switched == next
                            && root.erased == Some(epoch)
                            && next == Some(slots.epoch.number)
                            && *slots.epoch.key.bytes() == next_key
                            && *slots.epoch.next.bytes() == [0; 64]
                            && !slots.epoch.changing
                            && (0..2).all(|index| {
                                snapshot(&slots.memory[index])
                                    == marked(before[index], false, false)
                            }),
                        "a commit switches the root to the next epoch, erases the old, makes the \
                         next epoch and its key this one's, and saves every set as it is",
                    );
                } else {
                    kani::assert(
                        unchanged(&slots) && root.erased.is_none(),
                        "a refused commit changes nothing and erases nothing",
                    );
                }
                kani::cover!(
                    result.is_ok() && before.iter().any(|snapshot| snapshot.changed),
                    "a change of a set is saved"
                );
                kani::cover!(result == Err(Error::Unsaved), "a set is not yet wrapped");
                kani::cover!(result == Err(Error::RootFailed), "the root is not switched");
            }
        }
    }

    fn at_length(lengths: &[KeyLength; MEMBERS], position: usize) -> KeyLength {
        at(lengths, position)
    }

    /// An addition through the first slot; with the next, an addition through either slot of two in
    /// any state.
    #[kani::proof]
    #[kani::unwind(65)]
    fn an_addition_in_the_first_slot() {
        let (result, purpose) = add_in([any_slot_in(Occupancy::Loaded), any_slot()], 0);
        kani::cover!(
            result.is_ok() && purpose == Purpose::ExternalData,
            "a key is added to a set of external data"
        );
    }

    /// An addition through the second slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn an_addition_in_the_second_slot() {
        let (result, purpose) = add_in([any_slot(), any_slot_in(Occupancy::Loaded)], 1);
        kani::cover!(
            result.is_ok() && purpose == Purpose::ExternalData,
            "a key is added to a set of external data"
        );
    }

    /// With the first of two slots loaded, the second in any state and no change of epoch under way:
    /// an addition of a key of either length, any bytes, through the live handle of the first, by
    /// the code every addition runs, is refused as `WrongPurpose` for a set for wrapping, as
    /// `Unsaved` for a set changed in this epoch, and then as `WrongLength` exactly for a length its
    /// purpose does not take, changing nothing. No purpose takes an addition of 64 bytes.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_long_addition_in_the_first_slot() {
        let mut memory = [any_slot_in(Occupancy::Loaded), any_slot()];
        let id = memory.as_ptr().addr();
        let mut epoch = any_epoch(false);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let handle = Handle {
            slots: id,
            index: 0,
            generation: before[0].generation,
            memory: PhantomData,
        };
        let length = any_length();
        let mut source = AnyEntropy::new();
        let result = slots.add(handle, length, |key, _| {
            key.fill(length, &mut source)
                .map_err(|EntropyError| Error::EntropyFailed)
        });
        let refusal = if before[0].purpose == Purpose::Wrap {
            Some(Error::WrongPurpose)
        } else if before[0].changed {
            Some(Error::Unsaved)
        } else if !allowed(before[0].purpose, length) {
            Some(Error::WrongLength)
        } else {
            None
        };
        kani::assert(
            match refusal {
                Some(refusal) => result == Err(refusal) && unchanged_except(&slots, &before, 2),
                None => result != Err(Error::WrongLength),
            },
            "an addition is refused for the first reason, a length its purpose does not take among \
             them, and then changes nothing",
        );
        kani::cover!(
            result == Err(Error::WrongLength),
            "a set of external data refuses a long key"
        );
        kani::cover!(
            refusal.is_none() && result.is_ok(),
            "a key of a length its purpose takes is added"
        );
        kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
    }

    /// From any state of two slots during a change of epoch, for a handle of this set naming any
    /// slot and generation: every change of stage and an addition are refused, as `StaleHandle` if
    /// the handle is not live, as `WrongPurpose` for a set for wrapping, and as `EpochChanging`
    /// otherwise; the source is left as it was, and nothing changes. A generated key goes through
    /// the same code as the addition, which refuses before it fills the slot.
    #[kani::proof]
    #[kani::unwind(65)]
    fn no_set_changes_during_a_change_of_epoch() {
        let mut memory = [any_slot(), any_slot()];
        let id = memory.as_ptr().addr();
        let mut epoch = any_epoch(true);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let handle = forged(id);
        let live = live(&slots, id, &handle);
        let before = snapshots(&slots);
        let wrapping = live && snapshot_at(&before, handle.index).purpose == Purpose::Wrap;
        let (result, _, _) = any_change(&mut slots, handle, any_position(), &mut Stages::one());
        let mut source: [u8; 32] = kani::any();
        let original = source;
        let added = slots.add32(handle, &mut source);
        let refusal = if !live {
            Error::StaleHandle
        } else if wrapping {
            Error::WrongPurpose
        } else {
            Error::EpochChanging
        };
        kani::assert(
            result == Err(refusal)
                && added == Err(refusal)
                && source == original
                && unchanged_except(&slots, &before, 2)
                && slots.epoch.changing,
            "during a change of epoch no set changes or takes a key, and nothing changes",
        );
        kani::cover!(live && !wrapping, "a live set is refused");
    }
}
