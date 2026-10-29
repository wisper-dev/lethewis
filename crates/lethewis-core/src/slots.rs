// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::{fmt, marker::PhantomData};

use crate::{
    derive::{
        Branch, DerivationFailed, Hedged, KeyId, SECRET_LEN, derive_archive_key, derive_challenge,
        derive_combined, derive_export_key, derive_from_secret, derive_key_id, derive_layer_key,
        derive_lock_key, derive_wrap_key, wipe_cipher_stack, wipe_stack,
    },
    entropy::{Entropy, EntropyError},
    epoch::{Epoch, Erasure, Root, RootFailed},
    error::Error,
    key::{Key, KeyBytes, KeyLength, wipe},
    keyset::{self, Header, MEMBERS, Position, Refused, Stages},
    record::{
        AssociatedData, END_LABEL, END_RECORD_LEN, EXPORT_LABEL, LAYER_LEN, LOCK_RECORD_LEN,
        PLAINTEXT_LEN, Purpose, RECORD_LEN, Status,
    },
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, NONCE_LEN, Rejected, SealFailed, TAG_LEN},
};

mod archive;
mod archived;
mod batch;
mod carry;
mod data;
mod table;

use table::{Index, Table};

pub use archived::ArchivePublic;
pub use carry::{Exporting, Receipt, Receiving};
pub use data::{Opening, Sealing};

/// Memory for one key set of up to three keys, provided by the caller.
///
/// It holds keys only while a [`Slots`] over it is alive, so moving it afterwards copies no key.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the kind of a set and its marks for the epoch are independent"
)]
pub struct Slot {
    keys: [Key; MEMBERS],
    ids: [KeyId; MEMBERS],
    stages: Stages,
    purpose: Purpose,
    /// A key from a secret the caller holds: it is never wrapped, and wraps only stored keys.
    unlocks: bool,
    generation: u64,
    occupancy: Occupancy,
    /// The set has changed in this epoch.
    changed: bool,
    /// The set is wrapped in the next epoch, and has not changed since.
    sealed: bool,
    /// The set came from a record of this epoch, or was wrapped into one since it last changed.
    /// What its keys encrypt then outlives the slots while that record is kept.
    recorded: bool,
    /// The slot and generation of the key for transfers the set came under, until that transfer
    /// ends.
    pending: Option<(Index, u64)>,
    /// For a key for transfers: the tag of the last element of its export, or zero before the
    /// first.
    chain: [u8; TAG_LEN],
    direction: Direction,
}

/// Which way the records of a key for transfers go until the end of its export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Idle,
    Out,
    In,
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
            recorded: false,
            pending: None,
            chain: [0; TAG_LEN],
            direction: Direction::Idle,
        }
    }

    // Each position is named, not iterated or reached through an array of references. Under the
    // proofs either costs many times a field access.
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
        self.recorded = false;
        self.pending = None;
        self.chain = [0; TAG_LEN];
        self.direction = Direction::Idle;
        match self.generation.checked_add(1) {
            Some(next) => {
                self.generation = next;
                self.occupancy = Occupancy::Free;
            }
            None => self.occupancy = Occupancy::Retired,
        }
    }

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

    fn may_go(&self, way: Direction) -> Result<(), Error> {
        if self.direction == Direction::Idle || self.direction == way {
            Ok(())
        } else {
            Err(Error::Unfinished)
        }
    }

    fn may_end(&self, way: Direction) -> Result<(), Error> {
        if self.direction == way {
            Ok(())
        } else if self.direction == Direction::Idle {
            Err(Error::NoTransfer)
        } else {
            Err(Error::Unfinished)
        }
    }

    /// A set for wrapping holds its key alone at the first position.
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

/// Refers to a key set held in the [`Slots`] that issued it, until the set is released. It may
/// outlive that `Slots`, but not its memory; the second example does not compile.
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
    index: Index,
    generation: u64,
    memory: PhantomData<&'a [Slot]>,
}

impl fmt::Debug for Handle<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle").finish_non_exhaustive()
    }
}

/// Key sets in slots provided by the caller, reached only through handles; only
/// [`Slots::reveal32`] gives a key out. Dropping it wipes every key and discards unsaved changes,
/// so abandon an epoch change first; leaking it skips the wipe.
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
    memory: Table<'a>,
    epoch: &'a mut Epoch,
}

/// Opens a sealed plaintext of `N` bytes: AES-256-GCM-SIV, or a model of it in proofs and tests.
trait Open<const N: usize> {
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected>;
}

impl<const N: usize> Open<N> for seal::Aes {
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        seal::open(key, nonce, aad, buffer, tag)
    }
}

#[cfg(any(test, kani))]
impl<F, const N: usize> Open<N> for F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8; N],
        &[u8; TAG_LEN],
    ) -> Result<(), Rejected>,
{
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        self(key, nonce, aad, buffer, tag)
    }
}

/// Seals a plaintext of `N` bytes: AES-256-GCM-SIV, or a model of it in proofs and tests.
trait Seal<const N: usize> {
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed>;
}

impl<const N: usize> Seal<N> for seal::Aes {
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        seal::seal(key, nonce, aad, buffer)
    }
}

#[cfg(any(test, kani))]
impl<F, const N: usize> Seal<N> for F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed>,
{
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        self(key, nonce, aad, buffer)
    }
}

#[cfg(any(test, kani))]
fn opening<F, const N: usize>(open: F) -> F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8; N],
        &[u8; TAG_LEN],
    ) -> Result<(), Rejected>,
{
    open
}

enum Out<'r> {
    Record(&'r mut [u8; RECORD_LEN]),
    Lock(&'r mut [u8; LOCK_RECORD_LEN]),
    Export(&'r mut [u8; RECORD_LEN]),
}

impl Out<'_> {
    const fn kind(&self) -> Kind {
        match self {
            Self::Record(_) => Kind::Record,
            Self::Lock(_) => Kind::Lock,
            Self::Export(_) => Kind::Export,
        }
    }
}

/// `Lock` and `ArchiveKey` are the inner records of a lock record and of the record of an archive
/// key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Record,
    Lock,
    Export,
    ArchiveKey,
}

impl Kind {
    const fn holds(self, purpose: Purpose) -> bool {
        match self {
            Self::Record => matches!(
                purpose,
                Purpose::ExternalData | Purpose::Transfer | Purpose::ArchiveSeal | Purpose::Data
            ),
            Self::Lock => matches!(purpose, Purpose::Wrap | Purpose::ArchiveWrap),
            Self::Export => matches!(purpose, Purpose::ExternalData),
            Self::ArchiveKey => matches!(purpose, Purpose::Archive),
        }
    }

    const fn parent_purpose(self) -> Purpose {
        match self {
            Self::Record | Self::Lock => Purpose::Wrap,
            Self::Export => Purpose::Transfer,
            Self::ArchiveKey => Purpose::ArchiveWrap,
        }
    }
}

impl<'a> Slots<'a> {
    /// Keeps key sets in `slots`, in the epoch numbered `number`, whose key it takes from `key` and
    /// wipes. Any key left in `slots` or `epoch` is wiped first; each profile needs an epoch of its
    /// own.
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
            memory: Table::new(slots),
            epoch,
        };
        this.unload_all();
        this
    }

    /// Takes a 32-byte key for `purpose` from `source` into a free slot as a set of one, and wipes
    /// `source`. Keys of the archive and for data are refused: only the library creates them.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::WrongPurpose`], [`Error::NoFreeSlot`], [`Error::DerivationFailed`] or
    /// [`Error::DuplicateKey`], and then leaves `source` and the slots as they were.
    pub fn import32(
        &mut self,
        purpose: Purpose,
        source: &mut [u8; 32],
    ) -> Result<Handle<'a>, Error> {
        if !purpose.imported() {
            return Err(Error::WrongPurpose);
        }
        let secret = purpose == Purpose::Wrap;
        let handle = self.load_new(purpose, KeyLength::Bytes32, secret, |first, _| {
            first.copy32(source);
            Ok(())
        })?;
        wipe(source);
        Ok(handle)
    }

    /// Takes a 64-byte key for `purpose` from `source` into a free slot as a set of one, and wipes
    /// `source`. Keys of the archive and for data are refused: only the library creates them.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::WrongPurpose`], [`Error::WrongLength`], [`Error::NoFreeSlot`],
    /// [`Error::DerivationFailed`] or [`Error::DuplicateKey`], and then leaves `source` and the
    /// slots as they were.
    pub fn import64(
        &mut self,
        purpose: Purpose,
        source: &mut [u8; 64],
    ) -> Result<Handle<'a>, Error> {
        if !purpose.imported() {
            return Err(Error::WrongPurpose);
        }
        let secret = purpose == Purpose::Wrap;
        let handle = self.load_new(purpose, KeyLength::Bytes64, secret, |first, _| {
            first.copy64(source);
            Ok(())
        })?;
        wipe(source);
        Ok(handle)
    }

    /// Creates a key for `purpose` of `length` bytes in a free slot, from `entropy` hedged with the
    /// epoch key. `entropy` is asked once, after the purpose, the length and a free slot are
    /// checked.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::WrongPurpose`], [`Error::WrongLength`], [`Error::NoFreeSlot`],
    /// [`Error::EntropyFailed`], [`Error::DerivationFailed`] or [`Error::DuplicateKey`], and then
    /// changes no slot.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; the slot then stays free and wiped.
    pub fn generate(
        &mut self,
        purpose: Purpose,
        length: KeyLength,
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<Handle<'a>, Error> {
        if !purpose.generated() {
            return Err(Error::WrongPurpose);
        }
        self.load_new(purpose, length, false, |first, epoch| {
            hedged_fill(first, length, entropy, epoch)
        })
    }

    pub(crate) fn draw(
        &mut self,
        entropy: &mut (impl Entropy + ?Sized),
        branch: Branch,
        dest: &mut [u8],
    ) -> Result<(), Error> {
        let Epoch { key, drawn, .. } = &mut *self.epoch;
        hedged_draw(entropy, key, drawn, branch, dest)
    }

    /// Not hedged, so that the same password or words give the same key.
    pub(crate) fn load_derived(
        &mut self,
        purpose: Purpose,
        length: KeyLength,
        source: &mut (impl Entropy + ?Sized),
    ) -> Result<Handle<'a>, Error> {
        if !purpose.imported() {
            return Err(Error::WrongPurpose);
        }
        self.load_new(purpose, length, purpose == Purpose::Wrap, |first, _| {
            first
                .fill(length, source)
                .map_err(|EntropyError| Error::EntropyFailed)
        })
    }

    /// `secret` holds the bytes that twelve words or two shares stand for.
    pub(crate) fn derive_into(
        &mut self,
        secret: &[u8; SECRET_LEN],
        purpose: Purpose,
        branch: Branch,
    ) -> Result<Handle<'a>, Error> {
        self.load_derived(
            purpose,
            KeyLength::Bytes32,
            &mut FromSecret {
                secret,
                purpose,
                branch,
            },
        )
        .map_err(|error| match error {
            Error::EntropyFailed => Error::DerivationFailed,
            other => other,
        })
    }

    /// Copies the enabled key at `at` of `set` into `out`, if both the set and `purpose` are
    /// [`Purpose::ExternalData`]. The copy is the caller's to wipe; wrap and store the set first,
    /// or the key dies with the slots.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::Unfinished`] or
    /// [`Error::WrongStage`], and then leaves `out` as it was.
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
        if slot.pending.is_some() {
            return Err(Error::Unfinished);
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

    /// Combines the keys from a secret `key` and `salt` by HKDF, the 32-byte `salt` as the salt,
    /// and releases both. With a password key and the chip's answer to its [`Slots::challenge`],
    /// the new key needs both.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::SameKey`], [`Error::WrongPurpose`],
    /// [`Error::WrongLevel`], [`Error::WrongLength`], [`Error::NoFreeSlot`],
    /// [`Error::DerivationFailed`] or [`Error::DuplicateKey`], and then changes no slot.
    pub fn combine(&mut self, key: Handle<'a>, salt: Handle<'a>) -> Result<Handle<'a>, Error> {
        let combined = crate::timing::with(|| self.combine_on_stack(key, salt));
        wipe_stack();
        combined
    }

    #[inline(never)]
    fn combine_on_stack(&mut self, key: Handle<'a>, salt: Handle<'a>) -> Result<Handle<'a>, Error> {
        let (first, second) = self.combinable(key, salt)?;
        let (Some(input), Some(salting)) = (self.memory.get(first), self.memory.get(second)) else {
            return Err(Error::StaleHandle);
        };
        let (input_key, salt_key) = (input.wrapping_key().0, salting.wrapping_key().0);
        let mut combined = [0; 32];
        if derive_combined(input_key, salt_key, &mut combined).is_err() {
            wipe(&mut combined);
            return Err(Error::DerivationFailed);
        }
        let loaded = self.load_new(Purpose::Wrap, KeyLength::Bytes32, true, |slot_key, _| {
            slot_key.copy32(&combined);
            Ok(())
        });
        wipe(&mut combined);
        let handle = loaded?;
        for index in [first, second] {
            if let Some(slot) = self.memory.get_mut(index) {
                slot.unload();
            }
        }
        Ok(handle)
    }

    fn combinable(&self, key: Handle<'a>, salt: Handle<'a>) -> Result<(Index, Index), Error> {
        let (first, second) = (self.loaded(key)?, self.loaded(salt)?);
        if first == second {
            return Err(Error::SameKey);
        }
        let (Some(input), Some(salting)) = (self.memory.get(first), self.memory.get(second)) else {
            return Err(Error::StaleHandle);
        };
        if input.purpose != Purpose::Wrap || salting.purpose != Purpose::Wrap {
            return Err(Error::WrongPurpose);
        }
        if !input.unlocks || !salting.unlocks {
            return Err(Error::WrongLevel);
        }
        if salting.wrapping_key().0.length() != KeyLength::Bytes32 {
            return Err(Error::WrongLength);
        }
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        Ok((first, second))
    }

    /// Writes into `out` the chip's challenge from the key from a secret `set`; the answer is
    /// [`Slots::combine`]'s salt. It lets guesses at the secret be tested without the chip: wipe
    /// it, and give it to the chip alone.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::WrongLevel`] or
    /// [`Error::DerivationFailed`], and then leaves `out` as it was.
    pub fn challenge(&self, set: Handle<'a>, out: &mut [u8; 32]) -> Result<(), Error> {
        let challenged = crate::timing::with(|| self.challenge_on_stack(set, out));
        wipe_stack();
        challenged
    }

    #[inline(never)]
    fn challenge_on_stack(&self, set: Handle<'a>, out: &mut [u8; 32]) -> Result<(), Error> {
        let slot = self
            .memory
            .get(self.loaded(set)?)
            .ok_or(Error::StaleHandle)?;
        if slot.purpose != Purpose::Wrap {
            return Err(Error::WrongPurpose);
        }
        if !slot.unlocks {
            return Err(Error::WrongLevel);
        }
        let mut derived = [0; 32];
        let challenged = derive_challenge(slot.wrapping_key().0, &mut derived);
        if challenged.is_ok() {
            *out = derived;
        }
        wipe(&mut derived);
        challenged.map_err(|_| Error::DerivationFailed)
    }

    /// Wraps `set` under the stored wrapping key `parent` into `record`, in this epoch or, during a
    /// change, the next. The record opens only with that key and the same `context` of 1 to 255
    /// bytes.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::SameKey`],
    /// [`Error::WrongPurpose`], [`Error::WrongLevel`], [`Error::Unfinished`], [`Error::Unsaved`],
    /// [`Error::EntropyFailed`], [`Error::DerivationFailed`] or [`Error::CipherFailed`], and then
    /// leaves `record` as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; `record` is then left as it was.
    pub fn wrap(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; RECORD_LEN],
    ) -> Result<(), Error> {
        let wrapped = crate::timing::with(|| {
            self.wrap_on_stack(set, parent, context, entropy, Out::Record(record))
        });
        wipe_cipher_stack();
        wrapped
    }

    /// Locks the stored key `set` under the key from a secret `parent` into `record`, for this
    /// epoch or the next. It opens with that key, the same `context` and the epoch key;
    /// [`Slots::carry`] moves it on without the secret.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::SameKey`],
    /// [`Error::WrongPurpose`], [`Error::WrongLevel`], [`Error::EntropyFailed`],
    /// [`Error::DerivationFailed`] or [`Error::CipherFailed`], and then leaves `record` as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; `record` is then left as it was.
    pub fn lock(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; LOCK_RECORD_LEN],
    ) -> Result<(), Error> {
        let locked = crate::timing::with(|| {
            self.wrap_on_stack(set, parent, context, entropy, Out::Lock(record))
        });
        wipe_cipher_stack();
        locked
    }

    fn wrappable(&self, index: Index, parent: Index, kind: Kind) -> Result<(), Error> {
        if index == parent {
            return Err(Error::SameKey);
        }
        let (Some(child), Some(wrapping)) = (self.memory.get(index), self.memory.get(parent))
        else {
            return Err(Error::StaleHandle);
        };
        if wrapping.purpose != kind.parent_purpose() {
            return Err(Error::WrongPurpose);
        }
        let level = match kind {
            Kind::Record => kind.holds(child.purpose) && !wrapping.unlocks,
            Kind::Lock => kind.holds(child.purpose) && !child.unlocks && wrapping.unlocks,
            Kind::Export | Kind::ArchiveKey => kind.holds(child.purpose),
        };
        if !level {
            return Err(Error::WrongLevel);
        }
        if child.pending.is_some() {
            return Err(Error::Unfinished);
        }
        if kind == Kind::Export {
            wrapping.may_go(Direction::Out)?;
        } else if child.changed && !self.epoch.changing {
            return Err(Error::Unsaved);
        }
        Ok(())
    }

    /// Writes `set`, for external data, into `record` as the next record of the export under
    /// `transfer`. It opens in any epoch with that key, the same `context` and all before it; early
    /// release abandons it.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::SameKey`],
    /// [`Error::WrongPurpose`], [`Error::WrongLevel`], [`Error::Unfinished`],
    /// [`Error::EntropyFailed`], [`Error::DerivationFailed`] or [`Error::CipherFailed`]. `record`
    /// and the export then stay as they were.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; `record` and the export are then left as they were.
    pub fn export(
        &mut self,
        set: Handle<'a>,
        transfer: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; RECORD_LEN],
    ) -> Result<(), Error> {
        let exported = crate::timing::with(|| {
            self.wrap_on_stack(set, transfer, context, entropy, Out::Export(record))
        });
        wipe_cipher_stack();
        exported
    }

    /// Ends the export under `transfer`, writing into `end` what opens only after its elements, in
    /// order, for the same `context`. The next record or block under the key begins a new export.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::WrongPurpose`],
    /// [`Error::NoTransfer`], [`Error::Unfinished`], [`Error::EntropyFailed`],
    /// [`Error::DerivationFailed`] or [`Error::CipherFailed`]. `end` and the export then stay as
    /// they were.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; `end` and the export are then left as they were.
    pub fn end_export(
        &mut self,
        transfer: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        end: &mut [u8; END_RECORD_LEN],
    ) -> Result<(), Error> {
        let ended =
            crate::timing::with(|| self.end_export_on_stack(transfer, context, entropy, end));
        wipe_cipher_stack();
        ended
    }

    #[inline(never)]
    fn end_export_on_stack(
        &mut self,
        transfer: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        end: &mut [u8; END_RECORD_LEN],
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.serving(transfer, Purpose::Transfer)?;
        let slot = self.memory.get(index).ok_or(Error::StaleHandle)?;
        slot.may_end(Direction::Out)?;
        let associated = associated.chained(END_LABEL, &slot.chain);
        let Epoch { key, drawn, .. } = &mut *self.epoch;
        let mut nonce = [0; NONCE_LEN];
        hedged_draw(entropy, key, drawn, Branch::HedgeNonce, &mut nonce)?;
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        if derive_export_key(slot.wrapping_key().0, &mut cipher_key).is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let tag = seal::seal(&cipher_key, &nonce, associated.bytes(), &mut []);
        wipe(&mut cipher_key);
        let tag = tag.map_err(|_| Error::CipherFailed)?;
        if let Some((nonce_out, tag_out)) = end.split_first_chunk_mut::<NONCE_LEN>() {
            *nonce_out = nonce;
            tag_out.copy_from_slice(&tag);
        }
        if let Some(slot) = self.memory.get_mut(index) {
            slot.chain = [0; TAG_LEN];
            slot.direction = Direction::Idle;
        }
        Ok(())
    }

    #[inline(never)]
    fn wrap_on_stack(
        &mut self,
        set: Handle<'a>,
        parent: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        out: Out<'_>,
    ) -> Result<(), Error> {
        let kind = out.kind();
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let (index, parent_index) = (self.loaded(set)?, self.loaded(parent)?);
        self.wrappable(index, parent_index, kind)?;
        let (Some(child), Some(wrapping)) = (self.memory.get(index), self.memory.get(parent_index))
        else {
            return Err(Error::StaleHandle);
        };
        let in_epoch = kind != Kind::Export;
        let Epoch {
            number,
            key,
            next,
            changing,
            drawn,
        } = &mut *self.epoch;
        let (epoch, epoch_key) = if in_epoch && *changing {
            (number.checked_add(1).ok_or(Error::EpochExhausted)?, &*next)
        } else {
            (*number, &*key)
        };
        let (parent_key, parent_id) = wrapping.wrapping_key();
        let (mut nonce, mut outer) = ([0; NONCE_LEN], [0; NONCE_LEN]);
        hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, &mut nonce)?;
        if kind == Kind::Lock {
            hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, &mut outer)?;
        }
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        let derived = derive_record_key(kind, parent_key, epoch_key, &mut cipher_key);
        if derived.is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let header = Header {
            purpose: child.purpose,
            parent: parent_id.bytes(),
            epoch: if kind == Kind::Record { epoch } else { 0 },
        };
        let associated = if kind == Kind::Export {
            associated.chained(EXPORT_LABEL, &wrapping.chain)
        } else {
            associated
        };
        let [first, second, third] = &child.keys;
        let mut sealed = [0; PLAINTEXT_LEN];
        keyset::build(&header, &child.stages, [first, second, third], &mut sealed);
        let tag = seal::seal(&cipher_key, &nonce, associated.bytes(), &mut sealed);
        wipe(&mut cipher_key);
        let tag = tag.map_err(|_| Error::CipherFailed)?;
        match out {
            Out::Record(record) | Out::Export(record) => {
                write_record(record, &nonce, &sealed, &tag);
            }
            Out::Lock(record) => {
                let mut inner = [0; RECORD_LEN];
                write_record(&mut inner, &nonce, &sealed, &tag);
                wipe(&mut sealed);
                let layered = seal_layer(
                    (epoch_key, epoch),
                    &outer,
                    associated.bytes(),
                    &inner,
                    record,
                );
                wipe(&mut inner);
                layered?;
            }
        }
        if kind == Kind::Export {
            if let Some(wrapping) = self.memory.get_mut(parent_index) {
                wrapping.chain = tag;
                wrapping.direction = Direction::Out;
            }
        } else if let Some(child) = self.memory.get_mut(index) {
            if self.epoch.changing {
                child.sealed = true;
            } else if kind == Kind::Record {
                child.recorded = true;
            }
        }
        Ok(())
    }

    /// Unwraps `record` with the stored wrapping key `parent` and its `context` into a free slot.
    /// The set comes out with the purpose, keys, stages and primary the record holds.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::WrongPurpose`],
    /// [`Error::WrongLevel`], [`Error::NoFreeSlot`], [`Error::DerivationFailed`],
    /// [`Error::RecordRejected`] or [`Error::DuplicateKey`], and then changes no slot.
    pub fn unwrap(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let unwrapped =
            crate::timing::with(|| self.unwrap_on_stack(parent, context, record, seal::Aes));
        wipe_cipher_stack();
        unwrapped
    }

    #[inline(never)]
    fn unwrap_on_stack(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; RECORD_LEN],
        mut open: impl Open<PLAINTEXT_LEN>,
    ) -> Result<Handle<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.parent(parent, Kind::Record)?;
        self.take(index, associated.bytes(), record, Kind::Record, &mut open)
    }

    /// Receives `record`, the next record of the export under `transfer`, for its `context` into a
    /// free slot. The set is not revealed, wrapped, exported or changed until
    /// [`Slots::end_receive`]; releasing the key first abandons the export.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::WrongPurpose`],
    /// [`Error::NoFreeSlot`], [`Error::Unfinished`], [`Error::DerivationFailed`],
    /// [`Error::RecordRejected`] or [`Error::DuplicateKey`]. No slot then changes, and the export
    /// stays as it was.
    pub fn receive(
        &mut self,
        transfer: Handle<'a>,
        context: &[u8],
        record: &[u8; RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let received =
            crate::timing::with(|| self.receive_on_stack(transfer, context, record, seal::Aes));
        wipe_cipher_stack();
        received
    }

    #[inline(never)]
    fn receive_on_stack(
        &mut self,
        transfer: Handle<'a>,
        context: &[u8],
        record: &[u8; RECORD_LEN],
        mut open: impl Open<PLAINTEXT_LEN>,
    ) -> Result<Handle<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.parent(transfer, Kind::Export)?;
        let slot = self.memory.get(index).ok_or(Error::StaleHandle)?;
        slot.may_go(Direction::In)?;
        let (associated, generation) = (
            associated.chained(EXPORT_LABEL, &slot.chain),
            slot.generation,
        );
        let handle = self.take(index, associated.bytes(), record, Kind::Export, &mut open)?;
        let taken = self.loaded(handle)?;
        if let Some(received) = self.memory.get_mut(taken) {
            received.pending = Some((index, generation));
        }
        if let (Some(slot), Some(tag)) = (self.memory.get_mut(index), record.last_chunk()) {
            slot.chain = *tag;
            slot.direction = Direction::In;
        }
        Ok(handle)
    }

    /// Receives `end`, the end of the export under `transfer`, for its `context`, after all its
    /// elements. The sets it brought are then free to use, and the next element begins a new
    /// export.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::WrongPurpose`],
    /// [`Error::NoTransfer`], [`Error::Unfinished`], [`Error::DerivationFailed`] or
    /// [`Error::RecordRejected`]. No slot then changes, and the export stays as it was.
    pub fn end_receive(
        &mut self,
        transfer: Handle<'a>,
        context: &[u8],
        end: &[u8; END_RECORD_LEN],
    ) -> Result<(), Error> {
        let ended =
            crate::timing::with(|| self.end_receive_on_stack(transfer, context, end, seal::Aes));
        wipe_cipher_stack();
        ended
    }

    #[inline(never)]
    fn end_receive_on_stack(
        &mut self,
        transfer: Handle<'a>,
        context: &[u8],
        end: &[u8; END_RECORD_LEN],
        mut open: impl Open<0>,
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let index = self.serving(transfer, Purpose::Transfer)?;
        let slot = self.memory.get(index).ok_or(Error::StaleHandle)?;
        slot.may_end(Direction::In)?;
        let (associated, generation) =
            (associated.chained(END_LABEL, &slot.chain), slot.generation);
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        if derive_export_key(slot.wrapping_key().0, &mut cipher_key).is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let (mut nonce, mut tag) = ([0; NONCE_LEN], [0; TAG_LEN]);
        if let Some((given_nonce, given_tag)) = end.split_first_chunk::<NONCE_LEN>()
            && let Ok(given_tag) = <[u8; TAG_LEN]>::try_from(given_tag)
        {
            (nonce, tag) = (*given_nonce, given_tag);
        }
        let opened = open
            .open(&cipher_key, &nonce, associated.bytes(), &mut [], &tag)
            .is_ok();
        wipe(&mut cipher_key);
        if !opened {
            return Err(Error::RecordRejected);
        }
        self.memory.each(|slot| {
            if slot.pending == Some((index, generation)) {
                slot.pending = None;
            }
        });
        if let Some(slot) = self.memory.get_mut(index) {
            slot.chain = [0; TAG_LEN];
            slot.direction = Direction::Idle;
        }
        Ok(())
    }

    /// Unlocks the lock record `record` with the key from a secret `parent` and its `context`. Its
    /// stored key comes out in a free slot as a set of one.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::StaleHandle`], [`Error::WrongPurpose`],
    /// [`Error::WrongLevel`], [`Error::NoFreeSlot`], [`Error::DerivationFailed`],
    /// [`Error::StaleRecord`], [`Error::RecordRejected`] or [`Error::DuplicateKey`], and then
    /// changes no slot.
    pub fn unlock(
        &mut self,
        parent: Handle<'a>,
        context: &[u8],
        record: &[u8; LOCK_RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let unlocked = crate::timing::with(|| {
            self.unlock_on_stack(parent, context, record, seal::Aes, seal::Aes)
        });
        wipe_cipher_stack();
        unlocked
    }

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
        let index = self.parent(parent, Kind::Lock)?;
        let mut inner = [0; RECORD_LEN];
        let unlocked = open_layer(
            (&self.epoch.key, self.epoch.number),
            associated.bytes(),
            record,
            &mut inner,
            &mut open_layer_with,
        )
        .and_then(|()| self.take(index, associated.bytes(), &inner, Kind::Lock, &mut open));
        wipe(&mut inner);
        unlocked
    }

    fn serving(&self, handle: Handle<'a>, purpose: Purpose) -> Result<Index, Error> {
        let index = self.loaded(handle)?;
        let set = self.memory.get(index).ok_or(Error::StaleHandle)?;
        if set.purpose != purpose {
            return Err(Error::WrongPurpose);
        }
        Ok(index)
    }

    fn parent(&self, parent: Handle<'a>, kind: Kind) -> Result<Index, Error> {
        let index = self.serving(parent, kind.parent_purpose())?;
        let set = self.memory.get(index).ok_or(Error::StaleHandle)?;
        if set.unlocks != (kind == Kind::Lock) {
            return Err(Error::WrongLevel);
        }
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        Ok(index)
    }

    fn take(
        &mut self,
        parent: Index,
        aad: &[u8],
        record: &[u8; RECORD_LEN],
        kind: Kind,
        open: &mut impl Open<PLAINTEXT_LEN>,
    ) -> Result<Handle<'a>, Error> {
        let mut plaintext = [0; PLAINTEXT_LEN];
        let admitted = self
            .open_under(parent, aad, record, &mut plaintext, open, kind)
            .and_then(|()| self.admit(&plaintext, kind));
        wipe(&mut plaintext);
        admitted
    }

    fn open_under(
        &self,
        parent: Index,
        aad: &[u8],
        record: &[u8; RECORD_LEN],
        found: &mut [u8; PLAINTEXT_LEN],
        open: &mut impl Open<PLAINTEXT_LEN>,
        kind: Kind,
    ) -> Result<(), Error> {
        let (key, id) = self
            .memory
            .get(parent)
            .ok_or(Error::StaleHandle)?
            .wrapping_key();
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        let derived = derive_record_key(kind, key, &self.epoch.key, &mut cipher_key);
        if derived.is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let (nonce, mut sealed, tag) = split_record(record);
        let opened = open
            .open(&cipher_key, &nonce, aad, &mut sealed, &tag)
            .is_ok();
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

    fn admit(&mut self, plaintext: &[u8; PLAINTEXT_LEN], kind: Kind) -> Result<Handle<'a>, Error> {
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        let (header, stages, keys) = keyset::parse(plaintext).map_err(|_| Error::RecordRejected)?;
        let epoch = if kind == Kind::Record {
            self.epoch.number
        } else {
            0
        };
        if header.epoch != epoch
            || !kind.holds(header.purpose)
            || (!header.purpose.staged() && !stages.is_one())
        {
            return Err(Error::RecordRejected);
        }
        self.load(
            header.purpose,
            stages,
            false,
            kind == Kind::Record,
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

    /// Carries the lock record `from` into the next epoch during a change, without its key from a
    /// secret, into `to`. A lock record not carried opens no more once the change is committed.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when unoptimised, and wipes 24 KiB, or 64 KiB, below
    /// itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidContext`], [`Error::NoEpochChange`],
    /// [`Error::EpochExhausted`], [`Error::EntropyFailed`], [`Error::DerivationFailed`],
    /// [`Error::StaleRecord`] or [`Error::CipherFailed`], and then leaves `to` as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; `to` is then left as it was.
    pub fn carry(
        &mut self,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        from: &[u8; LOCK_RECORD_LEN],
        to: &mut [u8; LOCK_RECORD_LEN],
    ) -> Result<(), Error> {
        let carried =
            crate::timing::with(|| self.carry_on_stack(context, entropy, from, to, seal::Aes));
        wipe_cipher_stack();
        carried
    }

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
        let mut nonce = [0; NONCE_LEN];
        hedged_draw(entropy, next, drawn, Branch::HedgeNonce, &mut nonce)?;
        let mut inner = [0; RECORD_LEN];
        let carried = open_layer(
            (&*key, *number),
            associated.bytes(),
            from,
            &mut inner,
            &mut open,
        )
        .and_then(|()| seal_layer((&*next, following), &nonce, associated.bytes(), &inner, to));
        wipe(&mut inner);
        carried
    }

    pub(crate) fn has_free(&self) -> bool {
        self.memory.any(|slot| slot.occupancy == Occupancy::Free)
    }

    fn loaded(&self, handle: Handle<'a>) -> Result<Index, Error> {
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
        self.load(
            purpose,
            Stages::one(),
            secret,
            false,
            |[first, ..], epoch| fill(first, epoch),
        )
    }

    /// On failure the slot is left free and wiped.
    fn load(
        &mut self,
        purpose: Purpose,
        stages: Stages,
        secret: bool,
        recorded: bool,
        fill: impl FnOnce(&mut [Key; MEMBERS], &mut Epoch) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        // The copy of the key and the checks after its derivation run above the derivation's wipe.
        let loaded =
            crate::timing::with(|| self.load_in_slot(purpose, stages, secret, recorded, fill));
        wipe_stack();
        loaded
    }

    fn load_in_slot(
        &mut self,
        purpose: Purpose,
        stages: Stages,
        secret: bool,
        recorded: bool,
        fill: impl FnOnce(&mut [Key; MEMBERS], &mut Epoch) -> Result<(), Error>,
    ) -> Result<Handle<'a>, Error> {
        let slots = self.id();
        let index = self
            .memory
            .find(|slot| slot.occupancy == Occupancy::Free)
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
        slot.recorded = recorded;
        slot.occupancy = Occupancy::Loaded;
        Ok(Handle {
            slots,
            index,
            generation: slot.generation,
            memory: PhantomData,
        })
    }

    // Derived into local buffers and copied in at once: the derivation writes byte by byte. Each
    // write through a reference to a slot chosen at run time multiplies the proofs' work.
    fn identify(&self, index: Index, stages: &Stages) -> Result<[KeyId; MEMBERS], Error> {
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
        let held = |id: &KeyId| self.memory.any(|other| other.holds(id));
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

    /// Takes a 32-byte key from `source` as an enabled key into the first empty position of `set`,
    /// and wipes `source`. Returns the position; only a set for external data takes a key the
    /// caller gives.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::EpochChanging`],
    /// [`Error::Unfinished`], [`Error::Unsaved`], [`Error::SetFull`], [`Error::SetExhausted`],
    /// [`Error::DerivationFailed`] or [`Error::DuplicateKey`]. `source` and the slots then stay as
    /// they were.
    pub fn add32(&mut self, set: Handle<'a>, source: &mut [u8; 32]) -> Result<Position, Error> {
        let at = self.add(set, KeyLength::Bytes32, true, |key, _| {
            key.copy32(source);
            Ok(())
        })?;
        wipe(source);
        Ok(at)
    }

    /// Creates an enabled key of `length` bytes from hedged `entropy` in the first empty position
    /// of `set`. Returns the position; `entropy` is asked once, after the purpose, the length and
    /// an empty position are checked.
    ///
    /// Needs 9 KiB of stack, or 68 KiB when unoptimised, and wipes 8 KiB, or 64 KiB, below itself.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::EpochChanging`],
    /// [`Error::Unfinished`], [`Error::Unsaved`], [`Error::WrongLength`], [`Error::SetFull`],
    /// [`Error::SetExhausted`], [`Error::EntropyFailed`], [`Error::DerivationFailed`] or
    /// [`Error::DuplicateKey`], and then changes no slot.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics; the position then stays empty and wiped.
    pub fn add_generated(
        &mut self,
        set: Handle<'a>,
        length: KeyLength,
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<Position, Error> {
        self.add(set, length, false, |key, epoch| {
            hedged_fill(key, length, entropy, epoch)
        })
    }

    /// Makes the enabled key at `at` the primary of the set `set` refers to; the former primary
    /// stays enabled. Only sets for external data and for data change.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::EpochChanging`],
    /// [`Error::Unfinished`], [`Error::Unsaved`], [`Error::PrimaryKey`], [`Error::WrongStage`] or
    /// [`Error::SetExhausted`], and then changes nothing.
    pub fn promote(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        self.change(set, at, Stages::promote).map(|_| ())
    }

    /// Disables the enabled key at `at` of `set`, which is then not revealed until it is enabled
    /// again. Only sets for external data and for data change.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::EpochChanging`],
    /// [`Error::Unfinished`], [`Error::Unsaved`], [`Error::PrimaryKey`], [`Error::WrongStage`] or
    /// [`Error::SetExhausted`], and then changes nothing.
    pub fn disable(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        self.change(set, at, Stages::disable).map(|_| ())
    }

    /// Enables the disabled key at `at` of the set `set` refers to again. Only sets for external
    /// data and for data change.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::EpochChanging`],
    /// [`Error::Unfinished`], [`Error::Unsaved`], [`Error::PrimaryKey`], [`Error::WrongStage`] or
    /// [`Error::SetExhausted`], and then changes nothing.
    pub fn enable(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        self.change(set, at, Stages::enable).map(|_| ())
    }

    /// Wipes the disabled key at `at` of `set` and empties the position. Until the next epoch is
    /// committed, a record wrapped before still opens, and dropping the slots undoes it.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`], [`Error::WrongPurpose`], [`Error::EpochChanging`],
    /// [`Error::Unfinished`], [`Error::Unsaved`], [`Error::PrimaryKey`], [`Error::WrongStage`] or
    /// [`Error::SetExhausted`], and then changes nothing.
    pub fn destroy(&mut self, set: Handle<'a>, at: Position) -> Result<(), Error> {
        let (key, id) = self.change(set, at, Stages::destroy)?.member(at);
        key.wipe();
        id.wipe();
        Ok(())
    }

    fn change(
        &mut self,
        set: Handle<'a>,
        at: Position,
        transition: impl FnOnce(&mut Stages, usize) -> Result<(), Refused>,
    ) -> Result<&mut Slot, Error> {
        let index = self.loaded(set)?;
        if !self
            .memory
            .get(index)
            .is_some_and(|slot| slot.purpose.staged())
        {
            return Err(Error::WrongPurpose);
        }
        if self.epoch.changing {
            return Err(Error::EpochChanging);
        }
        let slot = self.memory.get_mut(index).ok_or(Error::StaleHandle)?;
        if slot.pending.is_some() {
            return Err(Error::Unfinished);
        }
        if slot.changed {
            return Err(Error::Unsaved);
        }
        let mut stages = slot.stages;
        transition(&mut stages, at.index())?;
        slot.stages = stages;
        slot.changed = true;
        slot.sealed = false;
        slot.recorded = false;
        Ok(slot)
    }

    /// On failure the position is left empty and wiped.
    fn add(
        &mut self,
        set: Handle<'a>,
        length: KeyLength,
        given: bool,
        fill: impl FnOnce(&mut Key, &mut Epoch) -> Result<(), Error>,
    ) -> Result<Position, Error> {
        let added = crate::timing::with(|| self.add_in_slot(set, length, given, fill));
        wipe_stack();
        added
    }

    fn add_in_slot(
        &mut self,
        set: Handle<'a>,
        length: KeyLength,
        given: bool,
        fill: impl FnOnce(&mut Key, &mut Epoch) -> Result<(), Error>,
    ) -> Result<Position, Error> {
        let index = self.loaded(set)?;
        let purpose = self.memory.get(index).map(|slot| slot.purpose);
        if !purpose.is_some_and(|purpose| purpose.staged() && (!given || purpose.imported())) {
            return Err(Error::WrongPurpose);
        }
        if self.epoch.changing {
            return Err(Error::EpochChanging);
        }
        let slot = self.memory.get_mut(index).ok_or(Error::StaleHandle)?;
        if slot.pending.is_some() {
            return Err(Error::Unfinished);
        }
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
            if self.memory.any(|other| other.holds(&id)) {
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
        slot.recorded = false;
        Ok(at)
    }

    /// Begins the change to the next epoch, taking its key from `key` and wiping it. Until the
    /// change ends, records are wrapped in the next epoch and unwrapped in this one.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::EpochChanging`] or [`Error::EpochExhausted`], and then leaves `key` as
    /// it was.
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

    /// Abandons the epoch change: wipes the next key, and `root` erases its root so its records
    /// open no more. Returns how surely that root is gone; a set changed in this epoch stays
    /// unsaved.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::NoEpochChange`], and then changes nothing.
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
        self.memory.each(|slot| slot.sealed = false);
        Ok(root.erase(next))
    }

    /// Commits the change to the next epoch and returns how surely `root` erased the old root.
    /// Store the next epoch's records before the call, and keep this epoch's until it returns.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::NoEpochChange`], [`Error::Unsaved`] or [`Error::RootFailed`], and then
    /// changes nothing.
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
        self.memory.each(|slot| {
            slot.recorded = slot.sealed;
            slot.changed = false;
            slot.sealed = false;
        });
        Ok(root.erase(old))
    }

    /// Wipes every key of the set `handle` refers to and frees its slot.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::StaleHandle`] or [`Error::Unsaved`], and then changes nothing.
    pub fn release(&mut self, handle: Handle<'a>) -> Result<(), Error> {
        let index = self.loaded(handle)?;
        let slot = self.memory.get_mut(index).ok_or(Error::StaleHandle)?;
        if slot.changed {
            return Err(Error::Unsaved);
        }
        slot.unload();
        Ok(())
    }

    /// Marks every set saved, as a new epoch would, for tests of the stages alone.
    #[cfg(test)]
    pub(crate) fn settle(&mut self) {
        for slot in self.memory.iter_mut() {
            slot.changed = false;
        }
    }

    /// Makes a key for wrapping a stored one, as an unlock gives it, for tests without a lock
    /// record.
    #[cfg(test)]
    pub(crate) fn store(&mut self, handle: Handle<'a>) -> Handle<'a> {
        if let Some(slot) = self.memory.get_mut(handle.index) {
            slot.unlocks = false;
        }
        handle
    }

    /// Two `Slots` alive at once never share memory, and a handle keeps its memory borrowed. Empty
    /// ones may share an address, but issue no handles.
    fn id(&self) -> usize {
        self.memory.id()
    }

    fn unload_all(&mut self) {
        self.memory.each(|slot| {
            if slot.occupancy == Occupancy::Loaded {
                slot.unload();
            } else {
                slot.wipe_keys();
            }
        });
    }
}

fn derive_record_key(
    kind: Kind,
    parent: &Key,
    epoch: &Key,
    out: &mut [u8; CIPHER_KEY_LEN],
) -> Result<(), DerivationFailed> {
    match kind {
        Kind::Record => derive_wrap_key(parent, epoch, out),
        Kind::Lock => derive_lock_key(parent, out),
        Kind::Export => derive_export_key(parent, out),
        Kind::ArchiveKey => derive_archive_key(parent, out),
    }
}

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

struct FromSecret<'b> {
    secret: &'b [u8; SECRET_LEN],
    purpose: Purpose,
    branch: Branch,
}

impl Entropy for FromSecret<'_> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        derive_from_secret(self.secret, Some(self.purpose), self.branch, dest)
            .map_err(|_| EntropyError)
    }
}

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

/// `out` is written only when this succeeds.
fn seal_layer(
    (epoch_key, number): (&Key, u64),
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    inner: &[u8; RECORD_LEN],
    out: &mut [u8; LOCK_RECORD_LEN],
) -> Result<(), Error> {
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
    let tag = seal::seal(&layer_key, nonce, aad, &mut layer);
    wipe(&mut layer_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    if let Some((nonce_out, rest)) = out.split_first_chunk_mut::<NONCE_LEN>()
        && let Some((layer_out, tag_out)) = rest.split_first_chunk_mut::<LAYER_LEN>()
    {
        *nonce_out = *nonce;
        *layer_out = layer;
        tag_out.copy_from_slice(&tag);
    }
    Ok(())
}

/// `inner` is written only when the layer opens and names the epoch `number`.
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
    let opened = open.open(&layer_key, &nonce, aad, &mut layer, &tag).is_ok();
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
        AssociatedData, CIPHER_KEY_LEN, END_RECORD_LEN, Entropy, EntropyError, Epoch, Erasure,
        Error, Handle, Header, Index, KeyLength, LAYER_LEN, LOCK_RECORD_LEN, MEMBERS, Occupancy,
        PLAINTEXT_LEN, Position, Purpose, RECORD_LEN, Root, RootFailed, Slot, Slots, Stages,
        Status, derive_layer_key, derive_lock_key, derive_wrap_key, keyset, opening, seal,
        write_record,
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

    /// Its bytes vary, so that the tests of residue look for it.
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

    #[test]
    fn every_call_that_derives_holds_data_independent_timing() {
        use crate::timing::timed;
        assert!(!lethewis_dit::active(), "the mode is off before the work");
        let mut memory = [const { Slot::empty() }; 7];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = timed(|| slots.import64(Purpose::Wrap, &mut [7; 64]).unwrap());
        let parent = slots.store(parent);
        let key = timed(|| slots.import32(Purpose::ExternalData, &mut [9; 32]).unwrap());
        timed(|| {
            slots
                .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Counting)
                .unwrap()
        });
        let mut record = [0; RECORD_LEN];
        timed(|| {
            slots
                .wrap(key, parent, b"context", &mut Counting, &mut record)
                .unwrap();
        });
        slots.release(key).unwrap();
        let set = timed(|| slots.unwrap(parent, b"context", &record).unwrap());
        timed(|| slots.add32(set, &mut [3; 32]).unwrap());
        slots.settle();
        slots.release(set).unwrap();
        let set = timed(|| slots.import32(Purpose::ExternalData, &mut [5; 32]).unwrap());
        timed(|| {
            slots
                .add_generated(set, KeyLength::Bytes32, &mut Counting)
                .unwrap();
        });
        slots.settle();
        slots.release(set).unwrap();
        let mut words = [[0; 8]; 12];
        let set = timed(|| slots.generate_words(&mut Counting, &mut words).unwrap());
        let mut kept = words;
        slots.release(set).unwrap();
        timed(|| slots.derive_from_words(&mut words).unwrap());
        let mut shares = [[0; crate::shares::SHARE_LEN]; crate::shares::SHARE_COUNT];
        let set = timed(|| slots.generate_shares(&mut Counting, &mut shares).unwrap());
        slots.release(set).unwrap();
        let mut written = [[0; 8]; crate::shares::SHARE_WORD_COUNT];
        timed(|| crate::shares::share_to_words(&shares[0], &mut written).unwrap());
        timed(|| assert_eq!(crate::shares::wrong_share_word(&written), None));
        timed(|| crate::shares::share_from_words(&mut written, &mut shares[0]).unwrap());
        let [first, _, third] = &mut shares;
        let set = timed(|| slots.derive_from_shares(third, first).unwrap());
        slots.release(set).unwrap();
        let secret = timed(|| slots.import32(Purpose::Wrap, &mut [6; 32]).unwrap());
        let stored = timed(|| {
            slots
                .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
                .unwrap()
        });
        let mut locked = [0; LOCK_RECORD_LEN];
        timed(|| {
            slots
                .lock(stored, secret, b"context", &mut Counting, &mut locked)
                .unwrap();
        });
        slots.release(stored).unwrap();
        timed(|| slots.unlock(secret, b"context", &locked).unwrap());
        let answer = timed(|| slots.import32(Purpose::Wrap, &mut [7; 32]).unwrap());
        let mut challenge = [0; 32];
        timed(|| slots.challenge(secret, &mut challenge).unwrap());
        let combined = timed(|| slots.combine(secret, answer).unwrap());
        slots.release(combined).unwrap();
        slots.begin_epoch(&mut [8; 32]).unwrap();
        let mut carried = [0; LOCK_RECORD_LEN];
        timed(|| {
            slots
                .carry(b"context", &mut Counting, &locked, &mut carried)
                .unwrap();
        });
        let transfer = timed(|| slots.import32(Purpose::Transfer, &mut [4; 32]).unwrap());
        let data = timed(|| slots.import32(Purpose::ExternalData, &mut [2; 32]).unwrap());
        let mut exported = [0; RECORD_LEN];
        timed(|| {
            slots
                .export(data, transfer, b"context", &mut Counting, &mut exported)
                .unwrap();
        });
        let mut end = [0; END_RECORD_LEN];
        timed(|| {
            slots
                .end_export(transfer, b"context", &mut Counting, &mut end)
                .unwrap();
        });
        slots.release(data).unwrap();
        timed(|| slots.receive(transfer, b"context", &exported).unwrap());
        timed(|| slots.end_receive(transfer, b"context", &end).unwrap());
        slots.release(transfer).unwrap();
        timed(|| slots.transfer_from_words(&mut kept).unwrap());
    }

    /// In KiB, for an optimised build and for one without optimisation.
    pub(super) const LOAD_NEEDS: [usize; 2] = [9, 68];
    pub(super) const WRAP_NEEDS: [usize; 2] = [25, 72];
    const LOAD_WIPES: [usize; 2] = [8, 64];
    const WRAP_WIPES: [usize; 2] = [24, 64];

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
            ("combine", loads),
            ("challenge", loads),
            ("wrap", wraps),
            ("unwrap", wraps),
            ("lock", wraps),
            ("unlock", wraps),
            ("carry", wraps),
            ("export", wraps),
            ("end_export", wraps),
            ("receive", wraps),
            ("end_receive", wraps),
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

    /// The inputs of the known answers of the derivations.
    fn counted_from(first: u8) -> [u8; 32] {
        core::array::from_fn(|i| first + u8::try_from(i).unwrap())
    }

    /// The expected keys come from an independent implementation of HKDF.
    #[test]
    fn two_keys_from_a_secret_combine_into_one_and_go() {
        for (long, expected) in [
            (
                false,
                "d3bcd5a6261170da7661346c8ee46c257579fd9ba0b4b5bfa08d25c372af1869",
            ),
            (
                true,
                "2e7a0e4937b3ceb87d5015a733a6c8b30e03778b65d404f57996887d4498e5b1",
            ),
        ] {
            let mut memory = [const { Slot::empty() }; 3];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
            let password = if long {
                let mut bytes = core::array::from_fn(|i| u8::try_from(i).unwrap());
                slots.import64(Purpose::Wrap, &mut bytes)
            } else {
                slots.import32(Purpose::Wrap, &mut counted_from(0))
            }
            .unwrap();
            let answer = slots
                .import32(Purpose::Wrap, &mut counted_from(64))
                .unwrap();
            let combined = slots.combine(password, answer).unwrap();
            let expected = unhex32(expected);
            let only = [Some((Status::Enabled, &expected[..])), None, None];
            assert_holds_for(&slots, combined, only, 0, Purpose::Wrap);
            assert!(slots.memory[combined.index.number()].unlocks);
            for (handle, at) in [(password, 0), (answer, 1)] {
                assert_eq!(slots.release(handle), Err(Error::StaleHandle));
                assert_eq!(slots.memory[at].occupancy, Occupancy::Free);
                assert_eq!(slots.memory[at].keys[0].bytes(), &padded(&[]));
            }
        }
    }

    fn unhex32(text: &str) -> [u8; 32] {
        core::array::from_fn(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
    }

    #[test]
    fn a_combination_takes_only_two_keys_from_a_secret() {
        let mut memory = [const { Slot::empty() }; 7];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let password = slots.import32(Purpose::Wrap, &mut counted_from(0)).unwrap();
        let answer = slots
            .import32(Purpose::Wrap, &mut counted_from(64))
            .unwrap();
        let long = slots.import64(Purpose::Wrap, &mut [7; 64]).unwrap();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(5, 2))
            .unwrap();
        let before = holdings(&slots);
        for (key, salt, refusal) in [
            (password, password, Error::SameKey),
            (password, data, Error::WrongPurpose),
            (data, answer, Error::WrongPurpose),
            (password, stored, Error::WrongLevel),
            (stored, answer, Error::WrongLevel),
            (password, long, Error::WrongLength),
        ] {
            assert_eq!(slots.combine(key, salt), Err(refusal));
        }
        assert_eq!(holdings(&slots), before);
        let fillers = [[3; 32], [4; 32]]
            .map(|mut bytes| slots.import32(Purpose::ExternalData, &mut bytes).unwrap());
        assert_eq!(slots.combine(password, answer), Err(Error::NoFreeSlot));
        for filler in fillers {
            slots.release(filler).unwrap();
        }
        let mut held = unhex32("d3bcd5a6261170da7661346c8ee46c257579fd9ba0b4b5bfa08d25c372af1869");
        let held = slots.import32(Purpose::ExternalData, &mut held).unwrap();
        let before = holdings(&slots);
        assert_eq!(slots.combine(password, answer), Err(Error::DuplicateKey));
        assert_eq!(holdings(&slots), before);
        slots.release(held).unwrap();
        slots.release(password).unwrap();
        assert_eq!(slots.combine(password, answer), Err(Error::StaleHandle));
    }

    /// The expected challenges come from an independent implementation of HKDF.
    #[test]
    fn a_challenge_comes_only_from_a_key_from_a_secret() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let secret = slots.import32(Purpose::Wrap, &mut counted_from(0)).unwrap();
        let mut out = [0x55; 32];
        slots.challenge(secret, &mut out).unwrap();
        assert_eq!(
            out,
            unhex32("0477373f3a3672a9f939bd9be82544eeccf23ab0b19b091e86b93ebb3ad348de")
        );
        slots.release(secret).unwrap();
        let mut bytes = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let long = slots.import64(Purpose::Wrap, &mut bytes).unwrap();
        slots.challenge(long, &mut out).unwrap();
        assert_eq!(
            out,
            unhex32("0a1efc3452f44c26f65ae4613543a29c077440e7568c05b06deee2a000463da8")
        );
        slots.release(long).unwrap();
        let secret = slots.import32(Purpose::Wrap, &mut counted_from(0)).unwrap();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(5, 2))
            .unwrap();
        let mut out = [0x55; 32];
        assert_eq!(slots.challenge(stored, &mut out), Err(Error::WrongLevel));
        assert_eq!(slots.challenge(data, &mut out), Err(Error::WrongPurpose));
        slots.release(secret).unwrap();
        assert_eq!(slots.challenge(secret, &mut out), Err(Error::StaleHandle));
        assert_eq!(out, [0x55; 32]);
    }

    #[derive(Default)]
    pub(super) struct Platform {
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

    /// Otherwise a set wrapped for the next epoch could change after, and leave that record
    /// holding a destroyed key.
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
        assert_eq!((handle.index, handle.generation), (Index::new(0), 0));
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
        assert_eq!((short.index, long.index), (Index::new(0), Index::new(1)));
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
        assert_eq!(handle.index, Index::new(2));
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
            index: Index::new(1),
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

    pub(super) fn pattern<const N: usize>(times: u8, plus: u8) -> [u8; N] {
        core::array::from_fn(|i| {
            u8::try_from(i % 256)
                .unwrap()
                .wrapping_mul(times)
                .wrapping_add(plus)
        })
    }

    /// The hedge of `drawn` at `count` draws for the use `name`, by HKDF-SHA-256 with the label
    /// written by hand.
    pub(super) fn hedged(count: u64, name: &[u8], drawn: &[u8], length: usize) -> Vec<u8> {
        crate::derive::direct::hedged_directly(&epoch_key(), count, name, drawn, length)
    }

    fn hex(text: &str) -> [u8; RECORD_LEN] {
        core::array::from_fn(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
    }

    /// Computed by an independent implementation, in the order the test wraps them. Each nonce is
    /// `NONCE` hedged as the next draw.
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

    fn assert_holds(
        slots: &Slots<'_>,
        handle: Handle<'_>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
    ) {
        assert_holds_for(slots, handle, members, primary, Purpose::ExternalData);
    }

    fn assert_holds_for(
        slots: &Slots<'_>,
        handle: Handle<'_>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
        purpose: Purpose,
    ) {
        let slot = &slots.memory[handle.index.number()];
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

    fn set_plaintext(
        members: [Member<'_>; MEMBERS],
        primary: usize,
        named: [u8; 16],
    ) -> [u8; PLAINTEXT_LEN] {
        set_plaintext_for(members, primary, named, Purpose::ExternalData)
    }

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

    fn sealed_under(
        slots: &Slots<'_>,
        parent: Handle<'_>,
        members: [Member<'_>; MEMBERS],
        primary: usize,
        context: &[u8],
    ) -> [u8; RECORD_LEN] {
        let slot = &slots.memory[parent.index.number()];
        let plaintext = set_plaintext(members, primary, slot.ids[0].bytes());
        seal_plaintext(&slot.keys[0], &plaintext, context, &NONCE)
    }

    #[test]
    fn a_record_opens_under_the_key_of_its_parent_alone() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let parent = slots.store(parent);
        let child = pattern::<32>(13, 5);
        let only = [Some((Status::Enabled, &child[..])), None, None];
        let plaintext = set_plaintext(only, 0, slots.memory[parent.index.number()].ids[0].bytes());
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
                opening(|key, nonce, aad, buffer, tag| {
                    tried += 1;
                    seal::open(key, nonce, aad, buffer, tag)
                }),
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

    fn lock_set_plaintext(
        members: [Member<'_>; MEMBERS],
        primary: usize,
        named: [u8; 16],
    ) -> [u8; PLAINTEXT_LEN] {
        let mut plaintext = set_plaintext_for(members, primary, named, Purpose::Wrap);
        plaintext[19..27].copy_from_slice(&[0; 8]);
        plaintext
    }

    #[test]
    fn a_set_for_wrapping_comes_back_only_from_a_lock_record_of_one_key() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let stored = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let stored = slots.store(stored);
        let named = slots.memory[stored.index.number()].ids[0].bytes();
        let (first, second) = (pattern::<32>(5, 2), pattern::<64>(7, 3));
        let one = [Some((Status::Enabled, &first[..])), None, None];
        let plain = set_plaintext_for(one, 0, named, Purpose::Wrap);
        let record = seal_plaintext(&key_from(&pattern::<32>(3, 1)), &plain, b"set", &NONCE);
        assert_eq!(
            slots.unwrap(stored, b"set", &record),
            Err(Error::RecordRejected)
        );

        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 4)).unwrap();
        let named = slots.memory[secret.index.number()].ids[0].bytes();
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
        assert!(!slots.memory[set.index.number()].unlocks);
    }

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
        assert!(
            slots.memory[secret.index.number()].unlocks
                && !slots.memory[back.index.number()].unlocks
        );
        let data = slots
            .import32(Purpose::ExternalData, &mut pattern(5, 2))
            .unwrap();
        let mut plain = [0; RECORD_LEN];
        slots
            .wrap(data, back, b"chat", &mut Counting, &mut plain)
            .unwrap();
    }

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

    #[test]
    fn the_keys_of_the_archive_lie_only_where_their_records_allow() {
        let mut memory = [const { Slot::empty() }; 5];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        for purpose in [Purpose::Archive, Purpose::ArchiveWrap, Purpose::ArchiveSeal] {
            let mut short = pattern(5, 1);
            assert_eq!(
                slots.import32(purpose, &mut short),
                Err(Error::WrongPurpose)
            );
            assert_eq!(short, pattern(5, 1));
            let mut long = [7; 64];
            assert_eq!(slots.import64(purpose, &mut long), Err(Error::WrongPurpose));
            assert_eq!(long, [7; 64]);
        }
        assert_eq!(
            slots.generate(Purpose::Archive, KeyLength::Bytes32, &mut Counting),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.generate(Purpose::ArchiveSeal, KeyLength::Bytes64, &mut Counting),
            Err(Error::WrongLength)
        );
        let secret = slots.import32(Purpose::Wrap, &mut pattern(3, 1)).unwrap();
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let archive = slots
            .generate(Purpose::ArchiveWrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let seal = slots
            .generate(Purpose::ArchiveSeal, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let mut record = [0; RECORD_LEN];
        assert_eq!(
            slots.wrap(archive, stored, b"archive", &mut Counting, &mut record),
            Err(Error::WrongLevel)
        );
        assert_eq!(
            slots.wrap(seal, archive, b"chat", &mut Counting, &mut record),
            Err(Error::WrongPurpose)
        );
        let mut lock = [0; LOCK_RECORD_LEN];
        assert_eq!(
            slots.lock(seal, secret, b"chat", &mut Counting, &mut lock),
            Err(Error::WrongLevel)
        );
        slots
            .wrap(seal, stored, b"chat", &mut Counting, &mut record)
            .unwrap();
        slots
            .lock(archive, secret, b"archive", &mut Counting, &mut lock)
            .unwrap();
        slots.release(seal).unwrap();
        slots.release(archive).unwrap();
        let seal = slots.unwrap(stored, b"chat", &record).unwrap();
        assert_eq!(
            slots.memory[seal.index.number()].purpose,
            Purpose::ArchiveSeal
        );
        let archive = slots.unlock(secret, b"archive", &lock).unwrap();
        assert_eq!(
            slots.memory[archive.index.number()].purpose,
            Purpose::ArchiveWrap
        );
        assert!(!slots.memory[archive.index.number()].unlocks);
        let mut out = [0; 32];
        assert_eq!(
            slots.reveal32(seal, Position::First, Purpose::ArchiveSeal, &mut out),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.reveal32(archive, Position::First, Purpose::ArchiveWrap, &mut out),
            Err(Error::WrongPurpose)
        );
        assert_eq!(out, [0; 32]);
        assert_eq!(
            slots.add32(seal, &mut pattern(9, 1)),
            Err(Error::WrongPurpose)
        );
        assert_eq!(slots.combine(archive, secret), Err(Error::WrongPurpose));
        assert_eq!(slots.challenge(archive, &mut out), Err(Error::WrongPurpose));
        slots.release(stored).unwrap();
        let transfer = slots
            .import32(Purpose::Transfer, &mut pattern(11, 2))
            .unwrap();
        assert_eq!(
            slots.export(seal, transfer, b"chat", &mut Counting, &mut record),
            Err(Error::WrongLevel)
        );
    }

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
            slots.carry(b"other", &mut Counting, &kept, &mut carried),
            Err(Error::StaleRecord)
        );
        assert_eq!(carried, [0x55; LOCK_RECORD_LEN]);
        slots
            .carry(b"profile", &mut Counting, &kept, &mut carried)
            .unwrap();
        let mut again = [0x55; LOCK_RECORD_LEN];
        assert_eq!(
            slots.carry(b"profile", &mut Counting, &carried, &mut again),
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

    /// A lock record and its carry into the next epoch, computed by an independent implementation.
    /// Each nonce is `NONCE` hedged as the next draw, the inner one first.
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

    /// An export of the sets of the first and third of `KNOWN_RECORDS`, ended by `KNOWN_END`,
    /// computed by an independent implementation. Each nonce is `NONCE` hedged as the next draw.
    const KNOWN_EXPORT: [&str; 2] = [
        concat!(
            "c7a1550603080bf1aa1c5192e380992e16666f44fc3fa7685aa5c7fb96716cdf",
            "daa6b90f28f5b29dce32de34dbdd3fd4cd5b51cf98e35276030b07af5b66a84f",
            "7fe896d0f964df415213e0995547491c378ee37601cbddcbd0c4bed5771eb5f5",
            "3f2edc8a5a0e996c12b067c098725d2c7ac3fabb740f843b1e011d910cbc56b5",
            "a91da5430d0f7e106554eb79d17848f52fa0ae94e8c5b092a8bdf77c981e514c",
            "8d1f579a0ed7e7659673b7f6dbdd1ed344df52db3fecd8807df054c1971233a7",
            "ffaf8f5ffdbc92558bda9c89b9c479b6ff4306836da1cb3f3caec998159ee96e",
            "f2fd9e740104de9660d96da5698afdb88e1267afbcb9fbf533db7147657818f5",
            "0ee89e2912",
        ),
        concat!(
            "2d7fafac78ba33a2056ef2ae28d1188b6aad91f3339e40faae10de2b51e166e6",
            "489c484db809f19bb4f363a2e4c45625de97d0dff3ed2bdca912aed482f2360d",
            "7a6ab58c8f49a926990bc990032b65c115bca46c3d85642beb30abf7412ffaf9",
            "0a50a38479abd381df6b4f0deac40199866f2b38a6b7434399eca70d3d0138ed",
            "6321eb55414fb0f0fec3343016067184f0edf50b3020c21ed61b67e9d0f6ce01",
            "a43c6b53ea025aa4a810551ade85a49fba7208ec9fa6e11ee03392ae4623a88f",
            "88b982cc27468a3d73f96b81567846a1d6431d5320874257cc338103a9894d81",
            "d388aba8141e4e597ab13038177893546ac129bbefce1b713797d275dc306a0c",
            "d15945a5a0",
        ),
    ];
    const KNOWN_END: &str = "27bae2fc323c379d396cc79b29c2a553399d4673ce2433fd8134dd4b";

    fn end_hex(text: &str) -> [u8; END_RECORD_LEN] {
        core::array::from_fn(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
    }

    #[test]
    fn exports_match_ones_computed_independently() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let parent = slots.store(parent);
        let transfer = slots
            .import32(Purpose::Transfer, &mut pattern(41, 3))
            .unwrap();
        let first = slots
            .import32(Purpose::ExternalData, &mut pattern(59, 201))
            .unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .export(first, transfer, b"move", &mut Fixed(&NONCE), &mut record)
            .unwrap();
        assert_eq!(record, hex(KNOWN_EXPORT[0]));
        slots.release(first).unwrap();
        let full = slots
            .unwrap(parent, b"archive", &hex(KNOWN_RECORDS[2]))
            .unwrap();
        slots
            .export(full, transfer, b"move", &mut Fixed(&NONCE), &mut record)
            .unwrap();
        assert_eq!(record, hex(KNOWN_EXPORT[1]));
        let mut end = [0; END_RECORD_LEN];
        slots
            .end_export(transfer, b"move", &mut Fixed(&NONCE), &mut end)
            .unwrap();
        assert_eq!(end, end_hex(KNOWN_END));
    }

    #[test]
    fn an_export_is_received_in_another_epoch() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, 9, &mut [0x3c; 32]);
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let transfer = slots
            .import32(Purpose::Transfer, &mut pattern(41, 3))
            .unwrap();
        let one = slots
            .receive(transfer, b"move", &hex(KNOWN_EXPORT[0]))
            .unwrap();
        let first = pattern::<32>(59, 201);
        let middle = pattern::<32>(31, 7);
        let last = pattern::<32>(83, 111);
        assert_holds(
            &slots,
            one,
            [Some((Status::Enabled, &first)), None, None],
            0,
        );
        let mut record = [0; RECORD_LEN];
        assert_eq!(
            slots.wrap(one, stored, b"chat", &mut Counting, &mut record),
            Err(Error::Unfinished)
        );
        // The full set holds the first key too, and a key is held in one place only.
        slots.release(one).unwrap();
        let full = slots
            .receive(transfer, b"move", &hex(KNOWN_EXPORT[1]))
            .unwrap();
        assert_holds(
            &slots,
            full,
            [
                Some((Status::Disabled, &first)),
                Some((Status::Enabled, &middle)),
                Some((Status::Enabled, &last)),
            ],
            2,
        );
        assert_eq!(
            slots.wrap(full, stored, b"chat", &mut Counting, &mut record),
            Err(Error::Unfinished)
        );
        slots
            .end_receive(transfer, b"move", &end_hex(KNOWN_END))
            .unwrap();
        slots
            .wrap(full, stored, b"chat", &mut Counting, &mut record)
            .unwrap();
    }

    struct Pair<'a> {
        from: Slots<'a>,
        to: Slots<'a>,
        sets: [Handle<'a>; 3],
        out: Handle<'a>,
        into: Handle<'a>,
        stored: Handle<'a>,
    }

    fn pair<'a>(
        (memory, epoch): (&'a mut [Slot], &'a mut Epoch),
        (other_memory, other_epoch): (&'a mut [Slot], &'a mut Epoch),
    ) -> Pair<'a> {
        let mut from = Slots::new(memory, epoch, EPOCH, &mut epoch_key());
        let mut to = Slots::new(other_memory, other_epoch, 4, &mut [0x5a; 32]);
        let sets = [1, 2, 3].map(|plus| {
            from.import32(Purpose::ExternalData, &mut pattern(19, plus))
                .unwrap()
        });
        let out = from
            .import32(Purpose::Transfer, &mut pattern(41, 3))
            .unwrap();
        let into = to.import32(Purpose::Transfer, &mut pattern(41, 3)).unwrap();
        let stored = to
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        Pair {
            from,
            to,
            sets,
            out,
            into,
            stored,
        }
    }

    fn exported(pair: &mut Pair<'_>) -> ([[u8; RECORD_LEN]; 3], [u8; END_RECORD_LEN]) {
        let mut records = [[0; RECORD_LEN]; 3];
        for (set, record) in pair.sets.into_iter().zip(&mut records) {
            pair.from
                .export(set, pair.out, b"move", &mut Counting, record)
                .unwrap();
        }
        let mut end = [0; END_RECORD_LEN];
        pair.from
            .end_export(pair.out, b"move", &mut Counting, &mut end)
            .unwrap();
        (records, end)
    }

    #[test]
    fn records_of_an_export_open_only_in_order() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 5], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let mut pair = pair(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let (records, end) = exported(&mut pair);
        let into = pair.into;
        let to = &mut pair.to;
        let other = to.import32(Purpose::Transfer, &mut pattern(41, 4)).unwrap();
        let before = holdings(to);
        assert_eq!(
            to.receive(into, b"move", &records[1]),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            to.receive(into, b"other", &records[0]),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            to.receive(other, b"move", &records[0]),
            Err(Error::RecordRejected)
        );
        assert_eq!(holdings(to), before);
        to.receive(into, b"move", &records[0]).unwrap();
        assert_eq!(
            to.receive(into, b"move", &records[0]),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            to.receive(into, b"move", &records[2]),
            Err(Error::RecordRejected)
        );
        to.receive(into, b"move", &records[1]).unwrap();
        assert_eq!(
            to.end_receive(into, b"move", &end),
            Err(Error::RecordRejected)
        );
        to.receive(into, b"move", &records[2]).unwrap();
        assert_eq!(
            to.end_receive(into, b"other", &end),
            Err(Error::RecordRejected)
        );
        assert_eq!(to.end_receive(other, b"move", &end), Err(Error::NoTransfer));
        to.end_receive(into, b"move", &end).unwrap();
    }

    #[test]
    fn sets_wait_for_the_end_of_their_own_export() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 8], Epoch::empty());
        let mut pair = pair(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let [first, second, third] = pair.sets;
        let (out, into, stored) = (pair.out, pair.into, pair.stored);
        let from = &mut pair.from;
        let out_too = from
            .import32(Purpose::Transfer, &mut pattern(41, 4))
            .unwrap();
        let mut records = [[0; RECORD_LEN]; 3];
        let (mut end, mut end_too) = ([0; END_RECORD_LEN], [0; END_RECORD_LEN]);
        from.export(first, out, b"move", &mut Counting, &mut records[0])
            .unwrap();
        from.export(third, out_too, b"move", &mut Counting, &mut records[2])
            .unwrap();
        from.export(second, out, b"move", &mut Counting, &mut records[1])
            .unwrap();
        from.end_export(out, b"move", &mut Counting, &mut end)
            .unwrap();
        from.end_export(out_too, b"move", &mut Counting, &mut end_too)
            .unwrap();

        let to = &mut pair.to;
        let into_too = to.import32(Purpose::Transfer, &mut pattern(41, 4)).unwrap();
        let first = to.receive(into, b"move", &records[0]).unwrap();
        let third = to.receive(into_too, b"move", &records[2]).unwrap();
        let mut record = [0x55; RECORD_LEN];
        assert_eq!(
            to.wrap(first, stored, b"chat", &mut Untouched, &mut record),
            Err(Error::Unfinished)
        );
        assert_eq!(
            to.export(first, into, b"move", &mut Untouched, &mut record),
            Err(Error::Unfinished)
        );
        assert_eq!(to.add32(first, &mut [8; 32]), Err(Error::Unfinished));
        assert_eq!(to.disable(first, Position::First), Err(Error::Unfinished));
        let mut revealed = [0x55; 32];
        assert_eq!(
            to.reveal32(first, Position::First, Purpose::ExternalData, &mut revealed),
            Err(Error::Unfinished)
        );
        assert_eq!((record, revealed), ([0x55; RECORD_LEN], [0x55; 32]));
        let second = to.receive(into, b"move", &records[1]).unwrap();
        let mut changed = end;
        changed[20] ^= 1;
        assert_eq!(
            to.end_receive(into, b"move", &changed),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            to.wrap(second, stored, b"chat", &mut Untouched, &mut record),
            Err(Error::Unfinished)
        );
        to.end_receive(into, b"move", &end).unwrap();
        for set in [first, second] {
            to.wrap(set, stored, b"chat", &mut Counting, &mut record)
                .unwrap();
        }
        assert_eq!(
            to.wrap(third, stored, b"chat", &mut Untouched, &mut record),
            Err(Error::Unfinished)
        );
        to.release(third).unwrap();
    }

    #[test]
    fn a_key_for_transfers_serves_transfers_alone() {
        let mut memory = [const { Slot::empty() }; 5];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        assert_eq!(
            slots.generate(Purpose::Transfer, KeyLength::Bytes32, &mut Untouched),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.import64(Purpose::Transfer, &mut [4; 64]),
            Err(Error::WrongLength)
        );
        let transfer = slots.import32(Purpose::Transfer, &mut [4; 32]).unwrap();
        let secret = slots.import32(Purpose::Wrap, &mut [5; 32]).unwrap();
        let data = slots.import32(Purpose::ExternalData, &mut [6; 32]).unwrap();
        let before = holdings(&slots);
        let mut out = [0x55; 32];
        assert_eq!(
            slots.reveal32(transfer, Position::First, Purpose::Transfer, &mut out),
            Err(Error::WrongPurpose)
        );
        let mut record = [0x55; RECORD_LEN];
        let mut locked = [0x55; LOCK_RECORD_LEN];
        assert_eq!(
            slots.wrap(data, transfer, b"x", &mut Untouched, &mut record),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.lock(transfer, secret, b"x", &mut Untouched, &mut locked),
            Err(Error::WrongLevel)
        );
        assert_eq!(
            slots.export(secret, transfer, b"x", &mut Untouched, &mut record),
            Err(Error::WrongLevel)
        );
        assert_eq!(
            slots.export(data, secret, b"x", &mut Untouched, &mut record),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.unwrap(transfer, b"x", &record),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.receive(secret, b"x", &record),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.add32(transfer, &mut [7; 32]),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.promote(transfer, Position::First),
            Err(Error::WrongPurpose)
        );
        assert_eq!(slots.combine(secret, transfer), Err(Error::WrongPurpose));
        assert_eq!(
            slots.challenge(transfer, &mut out),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            (out, record, locked, holdings(&slots)),
            (
                [0x55; 32],
                [0x55; RECORD_LEN],
                [0x55; LOCK_RECORD_LEN],
                before
            )
        );
    }

    #[test]
    fn a_key_for_transfers_is_stored_under_a_stored_key() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let bytes = pattern::<32>(41, 3);
        let transfer = slots
            .import32(Purpose::Transfer, &mut bytes.clone())
            .unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(transfer, stored, b"backup key", &mut Counting, &mut record)
            .unwrap();
        slots.release(transfer).unwrap();
        let transfer = slots.unwrap(stored, b"backup key", &record).unwrap();
        assert_holds_for(
            &slots,
            transfer,
            [Some((Status::Enabled, &bytes)), None, None],
            0,
            Purpose::Transfer,
        );
    }

    #[test]
    fn the_same_bytes_in_two_roles_open_neither_record() {
        let bytes = pattern::<32>(43, 5);
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 3], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 3], Epoch::empty());
        let mut stored_side = Slots::new(&mut memory, &mut epoch, EPOCH, &mut epoch_key());
        let mut transfer_side =
            Slots::new(&mut other_memory, &mut other_epoch, EPOCH, &mut epoch_key());
        let stored = stored_side
            .import32(Purpose::Wrap, &mut bytes.clone())
            .unwrap();
        let stored = stored_side.store(stored);
        let transfer = transfer_side
            .import32(Purpose::Transfer, &mut bytes.clone())
            .unwrap();
        let data = stored_side
            .import32(Purpose::ExternalData, &mut [6; 32])
            .unwrap();
        let mut wrapped = [0; RECORD_LEN];
        stored_side
            .wrap(data, stored, b"same", &mut Counting, &mut wrapped)
            .unwrap();
        assert_eq!(
            transfer_side.receive(transfer, b"same", &wrapped),
            Err(Error::RecordRejected)
        );
        let data = transfer_side
            .import32(Purpose::ExternalData, &mut [7; 32])
            .unwrap();
        let mut exported = [0; RECORD_LEN];
        transfer_side
            .export(data, transfer, b"same", &mut Counting, &mut exported)
            .unwrap();
        assert_eq!(
            stored_side.unwrap(stored, b"same", &exported),
            Err(Error::RecordRejected)
        );
    }

    #[test]
    fn a_key_for_transfers_carries_one_export_at_a_time() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 5], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let mut pair = pair(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let [first, second, _] = pair.sets;
        let (out, into) = (pair.out, pair.into);
        let mut end = [0x55; END_RECORD_LEN];
        assert_eq!(
            pair.from.end_export(out, b"move", &mut Untouched, &mut end),
            Err(Error::NoTransfer)
        );
        assert_eq!(
            pair.to.end_receive(into, b"move", &end),
            Err(Error::NoTransfer)
        );
        let mut records = [[0; RECORD_LEN]; 2];
        for (set, record) in [first, second].into_iter().zip(&mut records) {
            pair.from
                .export(set, out, b"move", &mut Counting, record)
                .unwrap();
        }
        assert_eq!(
            pair.from.receive(out, b"move", &records[0]),
            Err(Error::Unfinished)
        );
        assert_eq!(
            pair.from.end_receive(out, b"move", &end),
            Err(Error::Unfinished)
        );
        pair.from
            .end_export(out, b"move", &mut Counting, &mut end)
            .unwrap();

        let to = &mut pair.to;
        let own = to.import32(Purpose::ExternalData, &mut [9; 32]).unwrap();
        let received = to.receive(into, b"move", &records[0]).unwrap();
        let mut record = [0x55; RECORD_LEN];
        assert_eq!(
            to.export(own, into, b"move", &mut Untouched, &mut record),
            Err(Error::Unfinished)
        );
        assert_eq!(
            to.end_export(into, b"move", &mut Untouched, &mut end),
            Err(Error::Unfinished)
        );
        to.release(into).unwrap();
        let into = to.import32(Purpose::Transfer, &mut pattern(41, 3)).unwrap();
        assert_eq!(
            to.receive(into, b"move", &records[0]),
            Err(Error::DuplicateKey)
        );
        to.release(received).unwrap();
        for record in &records {
            to.receive(into, b"move", record).unwrap();
        }
        to.end_receive(into, b"move", &end).unwrap();
        to.export(own, into, b"move", &mut Counting, &mut record)
            .unwrap();
    }

    #[test]
    fn an_export_saves_nothing_and_outlives_the_epoch() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 5], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let mut pair = pair(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let [set, _, _] = pair.sets;
        let out = pair.out;
        let from = &mut pair.from;
        let stored = from
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        from.add32(set, &mut pattern(23, 9)).unwrap();
        let mut record = [0; RECORD_LEN];
        from.export(set, out, b"move", &mut Counting, &mut record)
            .unwrap();
        from.begin_epoch(&mut [0x77; 32]).unwrap();
        let mut again = [0; RECORD_LEN];
        from.end_export(out, b"move", &mut Counting, &mut [0; END_RECORD_LEN])
            .unwrap();
        from.export(set, out, b"move", &mut Counting, &mut again)
            .unwrap();
        let mut platform = Platform::default();
        assert_eq!(from.commit_epoch(&mut platform), Err(Error::Unsaved));
        let mut saved = [0; RECORD_LEN];
        from.wrap(set, stored, b"set", &mut Counting, &mut saved)
            .unwrap();
        assert_eq!(from.commit_epoch(&mut platform), Ok(Erasure::Guaranteed));
        let into = pair.into;
        let received = pair.to.receive(into, b"move", &record).unwrap();
        let added = pattern::<32>(23, 9);
        let first = pattern::<32>(19, 1);
        assert_holds(
            &pair.to,
            received,
            [
                Some((Status::Enabled, &first)),
                Some((Status::Enabled, &added)),
                None,
            ],
            0,
        );
    }

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
        let third = pattern::<32>(8, 9);
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
            [
                Some((Status::Enabled, &third[..])),
                Some((Status::Enabled, &other[..])),
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
        let named = slots.memory[root.index.number()].ids[0].bytes();
        let plaintext = set_plaintext([Some((Status::Enabled, &long)), None, None], 0, named);
        let record = seal_plaintext(
            &slots.memory[root.index.number()].keys[0],
            &plaintext,
            b"x",
            &NONCE,
        );
        slots.settle();
        let before = holdings(&slots);
        assert_eq!(
            slots.unwrap(root, b"x", &record),
            Err(Error::RecordRejected)
        );
        assert_eq!(holdings(&slots), before);
    }

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
        assert_eq!(
            slots.memory[back.index.number()].purpose,
            Purpose::ExternalData
        );
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
        let slot = &slots.memory[root.index.number()];
        let plaintext = set_plaintext(members, 0, slot.ids[0].bytes());
        let nonce = hedged(0, b"hedge nonce", &NONCE, 12).try_into().unwrap();
        assert_eq!(
            out,
            seal_plaintext(&slot.keys[0], &plaintext, b"chat 7", &nonce)
        );
    }

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

    /// Each draw is hedged with its own count.
    #[test]
    fn a_source_that_repeats_itself_gives_different_bytes() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let first = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let second = slots
            .generate(Purpose::ExternalData, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        assert_ne!(
            slots.memory[first.index.number()].keys[0].bytes(),
            slots.memory[second.index.number()].keys[0].bytes()
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
        let mut shares = [[0; crate::shares::SHARE_LEN]; crate::shares::SHARE_COUNT];
        let mut others = shares;
        slots.generate_shares(&mut Counting, &mut shares).unwrap();
        slots.generate_shares(&mut Counting, &mut others).unwrap();
        for (share, other) in shares.iter().zip(&others) {
            assert_ne!(share[1..], other[1..]);
        }
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

    /// Biased towards plaintexts the slots accept: mostly 32-byte keys outside sets for wrapping.
    /// Half the time it is a set of one that never changed, where the purpose has no stages.
    fn random_plaintext(
        random: &mut Random,
        named: [u8; 16],
        held: &[Vec<u8>],
    ) -> [u8; PLAINTEXT_LEN] {
        let purpose = [
            Purpose::Wrap,
            Purpose::ExternalData,
            Purpose::Transfer,
            Purpose::ArchiveSeal,
            Purpose::Data,
        ][random.below(5)];
        let one = !purpose.staged() && random.below(2) == 0;
        let (stages, primary) = if one {
            ([Some(Status::Enabled), None, None], 0)
        } else {
            random_stages(random)
        };
        let mut keys: Vec<Vec<u8>> = (0..MEMBERS).map(|_| random.key()).collect();
        if purpose != Purpose::Wrap && random.below(4) != 0 {
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

    /// The keys of `plaintext` by position, if slots in the epoch `EPOCH` accept it from a plain
    /// record. Read from the layout, not by the parser.
    fn accepted_keys(plaintext: &[u8; PLAINTEXT_LEN]) -> Option<[Option<Vec<u8>>; MEMBERS]> {
        let primary = usize::from(plaintext[2]);
        let purpose = plaintext[1];
        if plaintext[0] != 1
            || ![2, 3, 6, 7].contains(&purpose)
            || plaintext[19..27] != EPOCH.to_le_bytes()
            || primary >= MEMBERS
            || plaintext[35 + 66 * primary] != 1
        {
            return None;
        }
        let mut keys: [Option<Vec<u8>>; MEMBERS] = Default::default();
        for (at, key) in keys.iter_mut().enumerate() {
            let position = &plaintext[35 + 66 * at..35 + 66 * (at + 1)];
            match position[0] {
                0 if position.iter().all(|&byte| byte == 0) => {}
                1 | 2 if position[1] == 32 && position[34..].iter().all(|&byte| byte == 0) => {
                    *key = Some(position[2..34].to_vec());
                }
                _ => return None,
            }
        }
        let one = primary == 0
            && plaintext[35] == 1
            && keys[1..].iter().all(Option::is_none)
            && plaintext[27..35] == [0; 8];
        (purpose == 2 || purpose == 7 || one).then_some(keys)
    }

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
        holding.6 = Purpose::from_byte(plaintext[1]).unwrap();
        holding
    }

    fn unwrap_random_records(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        for round in 0..rounds {
            let mut memory = [const { Slot::empty() }; 4];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
            let parent = random_parent(&mut slots, &mut random);
            let parent_slot = &slots.memory[parent.index.number()];
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
                    (Index::new(at), before[at].1),
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
    //! What the calls leave on the stack, read back from the memory of this process.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use aes::Aes256;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    use super::tests::{
        EPOCH, LOAD_NEEDS, WRAP_NEEDS, epoch_key, flipped_epoch, flipped_epoch_key,
    };
    use super::{
        END_RECORD_LEN, Entropy, EntropyError, Epoch, Error, Handle, Header, LAYER_LEN,
        LOCK_RECORD_LEN, MEMBERS, Out, Position, Purpose, RECORD_LEN, Slot, Slots, Stages, Status,
        keyset, write_record,
    };
    use crate::derive::{
        Branch, CIPHER_STACK_WIPE, SALT, STACK_WIPE, derive_export_key, derive_layer_key,
        derive_lock_key, derive_wrap_key,
        stack::{hedge_secrets, secrets},
    };
    use crate::key::{
        Key, KeyLength,
        tests::{Counting, Failing},
    };
    use crate::record::{AssociatedData, PLAINTEXT_LEN};
    use crate::residue::{
        assert_clean, below_pad, depth_changed, key_dependent, panic_at, residue,
    };
    use crate::seal;

    const CONTEXT: &[u8] = b"chat 7";
    const SET_CONTEXT: &[u8] = b"set";
    const NONCE: [u8; 12] = [
        0x31, 0x9c, 0x07, 0xe2, 0x5d, 0xa8, 0x14, 0x6f, 0xc3, 0x2b, 0x90, 0x4e,
    ];

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

    fn parent_bytes(flip: u8) -> [u8; 64] {
        pattern(43, 9, 64, flip).try_into().unwrap()
    }

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

    /// The S-box at zero and at FIPS 197's example in section 5.1.1, and the key expansion of
    /// appendix A.3.
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

    /// What AES-256-GCM-SIV handles for a record of `length` sealed bytes, but its plaintext.
    pub(super) fn keying_secrets(
        key: &[u8; 32],
        nonce: &[u8; 12],
        tag: &[u8; 16],
        length: usize,
    ) -> Vec<Vec<u8>> {
        let (mac_key, enc_key) = message_keys(key, nonce);
        let mut secrets = std::vec![
            key.to_vec(),
            mac_key.to_vec(),
            enc_key.to_vec(),
            keystream_of(&enc_key, tag, length),
        ];
        secrets.extend(round_keys(key));
        secrets.extend(round_keys(&enc_key));
        secrets
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

    fn keystream(enc_key: &[u8; 32], tag: &[u8; 16]) -> Vec<u8> {
        keystream_of(enc_key, tag, PLAINTEXT_LEN)
    }

    /// Counter blocks from the tag with its top bit set, the first word counting up: RFC 8452,
    /// section 4.
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
            parent: slots.memory[parent.index.number()].ids[0].bytes(),
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
            &slots.memory[parent.index.number()].keys[0],
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

    /// `Trial` is an unwrap whose record the key does not open.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Work {
        Wrap,
        Trial,
        Unwrap,
    }

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

    /// Only a rejected unwrap shows that the test sees residue. After a successful one, the wipes
    /// after deriving the new identifiers already cover the cipher's frames.
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

    fn secret_bytes(flip: u8) -> [u8; 32] {
        pattern(61, 13, 32, flip).try_into().unwrap()
    }

    fn stored_bytes(flip: u8) -> [u8; 64] {
        pattern(67, 17, 64, flip).try_into().unwrap()
    }

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

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Locking {
        Lock,
        Unlock,
        Carry,
    }

    fn before_lock(slots: &mut Slots<'_>, flip: u8) -> (Handle<'static>, Handle<'static>) {
        let secret = widen(
            slots
                .import32(Purpose::Wrap, &mut secret_bytes(flip))
                .unwrap(),
        );
        let stored = slots
            .import64(Purpose::Wrap, &mut stored_bytes(flip))
            .unwrap();
        (secret, widen(slots.store(stored)))
    }

    fn locked(
        slots: &mut Slots<'_>,
        flip: u8,
    ) -> (Handle<'static>, Handle<'static>, [u8; LOCK_RECORD_LEN]) {
        let (secret, stored) = before_lock(slots, flip);
        let mut record = [0; LOCK_RECORD_LEN];
        slots
            .lock(stored, secret, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        (secret, stored, record)
    }

    fn next_key(flip: u8) -> [u8; 32] {
        flipped_epoch_key(flip ^ 0x5a)
    }

    /// The secrets the work handles, and the start of each outer layer.
    fn lock_handled(flip: u8, work: Locking) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
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
        let mut open = std::vec![layer[..20].to_vec()];
        let drawn = slots.epoch.drawn;
        for count in [drawn.wrapping_sub(2), drawn.wrapping_sub(1)] {
            handled.extend(hedge_secrets(
                &flipped_epoch_key(flip),
                count,
                Branch::HedgeNonce,
                &NONCE,
            ));
        }
        handled.push(flipped_epoch_key(flip).to_vec());
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
                let (found, layer) = layer_secrets(&next_key(flip), &carried);
                handled.extend(found);
                open.push(layer[..20].to_vec());
                handled.extend(hedge_secrets(
                    &next_key(flip),
                    slots.epoch.drawn.wrapping_sub(1),
                    Branch::HedgeNonce,
                    &NONCE,
                ));
                handled.push(next_key(flip).to_vec());
            }
        }
        (handled, open)
    }

    /// Leaves out the start of each outer layer: the epoch number and the inner nonce, which are
    /// public.
    fn lock_pieces(work: Locking) -> Vec<Vec<u8>> {
        let (handled, open) = lock_handled(0, work);
        let (mut others, _) = lock_handled(0xff, work);
        others.extend(open);
        key_dependent(&handled, &others)
    }

    #[test]
    fn a_lock_without_the_wipe_leaves_residue() {
        let pieces = lock_pieces(Locking::Lock);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (secret, stored) = before_lock(&mut slots, 0);
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
        let (secret, stored) = before_lock(&mut slots, 0);
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

    /// Another key from a secret still decrypts the outer layer, and fails only at the inner.
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

    /// Each runs from the state its test above runs it from, so it handles the same values until
    /// the panic.
    #[test]
    fn a_panicking_source_leaves_no_secret_of_a_lock_or_a_carry() {
        for (work, calls) in [(Locking::Lock, 2), (Locking::Carry, 1)] {
            let pieces = lock_pieces(work);
            for at in 1..=calls + 1 {
                let mut memory = [const { Slot::empty() }; 4];
                let mut epoch_memory = Epoch::empty();
                let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
                let mut written = [0; LOCK_RECORD_LEN];
                let reached = if work == Locking::Lock {
                    let (secret, stored) = before_lock(&mut slots, 0);
                    panic_at(&pieces, (Fixed, at), |source| {
                        slots
                            .lock(stored, secret, CONTEXT, source, &mut written)
                            .unwrap();
                    })
                } else {
                    let (_, _, record) = locked(&mut slots, 0);
                    slots.begin_epoch(&mut next_key(0)).unwrap();
                    panic_at(&pieces, (Fixed, at), |source| {
                        slots.carry(CONTEXT, source, &record, &mut written).unwrap();
                    })
                };
                assert_eq!(reached, at <= calls);
                assert_eq!(written == [0; LOCK_RECORD_LEN], reached);
            }
        }
    }

    fn combination_handled(flip: u8) -> Vec<Vec<u8>> {
        let key = pattern(71, 3, 32, flip);
        let salt = pattern(73, 5, 32, flip);
        let mut combined = [0; 32];
        crate::derive::derive_combined(&key_from(&key), &key_from(&salt), &mut combined).unwrap();
        let mut handled = secrets(&key, &salt, KeyLength::Bytes32, Branch::Combined);
        handled.extend(secrets(&combined, SALT, KeyLength::Bytes32, Branch::KeyId));
        handled.extend([key, salt, combined.to_vec()]);
        handled
    }

    #[test]
    fn a_combination_leaves_no_residue() {
        let pieces = key_dependent(&combination_handled(0), &combination_handled(0xff));
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let key = slots
            .import32(
                Purpose::Wrap,
                &mut pattern(71, 3, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        let salt = slots
            .import32(
                Purpose::Wrap,
                &mut pattern(73, 5, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        assert_clean(&pieces, || {
            black_box(slots.combine(key, salt).unwrap());
        });
    }

    #[test]
    fn a_challenge_leaves_no_residue() {
        let handled = |flip| {
            let key = pattern(79, 7, 32, flip);
            secrets(&key, SALT, KeyLength::Bytes32, Branch::Challenge)
        };
        let pieces = key_dependent(&handled(0), &handled(0xff));
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let key = slots
            .import32(
                Purpose::Wrap,
                &mut pattern(79, 7, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        let mut out = [0; 32];
        assert_clean(&pieces, || {
            slots.challenge(key, &mut out).unwrap();
        });
    }

    /// Without the wipe, only a build without optimisation leaves the key on the stack.
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

    fn transfer_bytes(flip: u8) -> [u8; 32] {
        pattern(71, 19, 32, flip).try_into().unwrap()
    }

    fn exported(
        slots: &mut Slots<'_>,
        flip: u8,
    ) -> (Handle<'static>, Handle<'static>, [u8; RECORD_LEN]) {
        let (_, child) = sets(slots, flip);
        let transfer = slots
            .import32(Purpose::Transfer, &mut transfer_bytes(flip))
            .unwrap();
        let transfer = widen(transfer);
        let mut record = [0; RECORD_LEN];
        slots
            .export(child, transfer, CONTEXT, &mut Fixed, &mut record)
            .unwrap();
        (child, transfer, record)
    }

    /// `Record` covers an export and the trial of a receipt the key does not open.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Transfer {
        Record,
        Receipt,
        End,
    }

    fn transfer_handled(flip: u8, work: Transfer) -> Vec<Vec<u8>> {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(
            &mut memory,
            &mut epoch_memory,
            EPOCH,
            &mut flipped_epoch_key(flip),
        );
        let (_, transfer, record) = exported(&mut slots, flip);
        let bytes = transfer_bytes(flip);
        let mut cipher_key = [0; 32];
        derive_export_key(&key_from(&bytes), &mut cipher_key).unwrap();
        let mut found = if work == Transfer::End {
            let mut end = [0; END_RECORD_LEN];
            slots
                .end_export(transfer, CONTEXT, &mut Fixed, &mut end)
                .unwrap();
            let tag: [u8; 16] = end[12..].try_into().unwrap();
            cipher_secrets(&cipher_key, &end[..12].try_into().unwrap(), &[], &tag).0
        } else {
            let tag: [u8; 16] = record[12 + PLAINTEXT_LEN..].try_into().unwrap();
            let sealed = &record[12..12 + PLAINTEXT_LEN];
            cipher_secrets(&cipher_key, &record[..12].try_into().unwrap(), sealed, &tag).0
        };
        found.extend(secrets(&bytes, SALT, KeyLength::Bytes32, Branch::ExportKey));
        found.push(bytes.to_vec());
        if work == Transfer::Receipt {
            for bytes in child_keys(flip) {
                found.extend(secrets(&bytes, SALT, KeyLength::Bytes32, Branch::KeyId));
            }
        }
        found
    }

    fn transfer_pieces(work: Transfer) -> Vec<Vec<u8>> {
        key_dependent(&transfer_handled(0, work), &transfer_handled(0xff, work))
    }

    #[test]
    fn an_export_without_the_wipe_leaves_residue() {
        let pieces = transfer_pieces(Transfer::Record);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (child, transfer, _) = exported(&mut slots, 0);
        let mut record = [0; RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .wrap_on_stack(
                    child,
                    transfer,
                    CONTEXT,
                    &mut Fixed,
                    Out::Export(&mut record),
                )
                .unwrap();
            black_box(&record);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn an_export_leaves_no_residue() {
        let pieces = transfer_pieces(Transfer::Record);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (child, transfer, _) = exported(&mut slots, 0);
        let mut end = [0; END_RECORD_LEN];
        slots
            .end_export(transfer, CONTEXT, &mut Fixed, &mut end)
            .unwrap();
        let mut record = [0; RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .export(child, transfer, CONTEXT, &mut Fixed, &mut record)
                .unwrap();
            black_box(&record);
        });
    }

    fn to_receive(slots: &mut Slots<'_>) -> (Handle<'static>, [u8; RECORD_LEN]) {
        let (child, transfer, record) = exported(slots, 0);
        slots
            .end_export(transfer, CONTEXT, &mut Fixed, &mut [0; END_RECORD_LEN])
            .unwrap();
        slots.release(child).unwrap();
        (transfer, record)
    }

    #[test]
    fn a_receipt_leaves_no_residue() {
        let pieces = transfer_pieces(Transfer::Receipt);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (transfer, record) = to_receive(&mut slots);
        assert_clean(&pieces, || {
            black_box(slots.receive(transfer, CONTEXT, &record).unwrap());
        });
    }

    /// A changed record is still decrypted before its tag fails.
    #[test]
    fn a_rejected_receipt_leaves_no_residue() {
        let pieces = transfer_pieces(Transfer::Record);
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (transfer, mut record) = to_receive(&mut slots);
        record[40] ^= 1;
        let range = below_pad(false, || {
            let refused = slots.receive_on_stack(transfer, CONTEXT, &record, seal::open);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        });
        assert!(residue(range, &pieces) > 0);
        assert_clean(&pieces, || {
            let refused = slots.receive(transfer, CONTEXT, &record);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        });
    }

    /// Each case runs in slots of its own, so the end has the nonce the secrets were worked out
    /// with.
    #[test]
    fn an_end_leaves_no_residue() {
        let pieces = transfer_pieces(Transfer::End);
        let mut end = [0; END_RECORD_LEN];
        for (wipe, receive) in [(false, false), (true, false), (true, true)] {
            let mut memory = [const { Slot::empty() }; 4];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
            let (child, transfer, record) = exported(&mut slots, 0);
            if receive {
                slots
                    .end_export(transfer, CONTEXT, &mut Fixed, &mut end)
                    .unwrap();
                slots.release(child).unwrap();
                slots.receive(transfer, CONTEXT, &record).unwrap();
                assert_clean(&pieces, || {
                    slots.end_receive(transfer, CONTEXT, &end).unwrap();
                });
            } else if wipe {
                assert_clean(&pieces, || {
                    slots
                        .end_export(transfer, CONTEXT, &mut Fixed, &mut end)
                        .unwrap();
                    black_box(&end);
                });
            } else {
                let range = below_pad(false, || {
                    slots
                        .end_export_on_stack(transfer, CONTEXT, &mut Fixed, &mut end)
                        .unwrap();
                    black_box(&end);
                });
                assert!(residue(range, &pieces) > 0);
            }
        }
    }

    #[test]
    fn transfers_wipe_and_need_the_stack_documented() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (child, transfer, _) = exported(&mut slots, 0);
        let (mut record, mut end) = ([0; RECORD_LEN], [0; END_RECORD_LEN]);
        let mut depths = Vec::new();
        depths.push(depth_changed(|| {
            let failed = slots.export(child, transfer, CONTEXT, &mut Failing, &mut record);
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        depths.push(depth_changed(|| {
            let failed = slots.end_export(transfer, CONTEXT, &mut Failing, &mut end);
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        slots
            .end_export(transfer, CONTEXT, &mut Fixed, &mut end)
            .unwrap();
        depths.push(depth_changed(|| {
            slots
                .export(child, transfer, CONTEXT, &mut Fixed, &mut record)
                .unwrap();
            black_box(&record);
        }));
        depths.push(depth_changed(|| {
            slots
                .end_export(transfer, CONTEXT, &mut Fixed, &mut end)
                .unwrap();
            black_box(&end);
        }));
        slots.release(child).unwrap();
        let mut changed = record;
        changed[40] ^= 1;
        depths.push(depth_changed(|| {
            let refused = slots.receive(transfer, CONTEXT, &changed);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        }));
        depths.push(depth_changed(|| {
            black_box(slots.receive(transfer, CONTEXT, &record).unwrap());
        }));
        let mut other = end;
        other[20] ^= 1;
        depths.push(depth_changed(|| {
            let refused = slots.end_receive(transfer, CONTEXT, &other);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        }));
        depths.push(depth_changed(|| {
            slots.end_receive(transfer, CONTEXT, &end).unwrap();
        }));
        for depth in depths {
            assert!(depth >= CIPHER_STACK_WIPE, "{depth} bytes wiped");
            assert!(depth <= WRAP_STACK, "{depth} bytes reached");
        }
    }

    /// The derivations a wrap and an unwrap run are measured with the derivation, and wiped after
    /// it besides.
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

    const WRAP_STACK: usize = 1024 * WRAP_NEEDS[if cfg!(lethewis_unoptimised) { 1 } else { 0 }];
    const LOAD_STACK: usize = 1024 * LOAD_NEEDS[if cfg!(lethewis_unoptimised) { 1 } else { 0 }];

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

    #[test]
    fn calls_on_keys_from_a_secret_wipe_and_need_the_stack_documented() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let data = slots
            .import32(
                Purpose::ExternalData,
                &mut pattern(13, 13, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        let password = slots
            .import32(
                Purpose::Wrap,
                &mut pattern(15, 15, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        let answer = slots
            .import32(
                Purpose::Wrap,
                &mut pattern(17, 17, 32, 0).try_into().unwrap(),
            )
            .unwrap();
        let mut challenge = [0; 32];
        let secrets = [
            depth_changed(|| {
                slots.challenge(password, &mut challenge).unwrap();
                black_box(&challenge);
            }),
            depth_changed(|| {
                let refused = slots.challenge(data, &mut challenge);
                assert_eq!(black_box(refused), Err(Error::WrongPurpose));
            }),
            depth_changed(|| {
                black_box(slots.combine(password, answer).unwrap());
            }),
        ];
        for depth in secrets {
            assert!(
                depth >= STACK_WIPE,
                "{depth} bytes wiped after a call on keys from a secret"
            );
            assert!(depth <= LOAD_STACK, "{depth} bytes reached");
        }
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;
