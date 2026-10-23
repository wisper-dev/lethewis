// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Blocks of data carried to another device or into a backup under a key for transfers: each chunk
//! is opened and sealed again in the library, so that no key for data leaves it. A carried block
//! is the next element of the export under that key, after its records, and its end covers it.

use super::data::{OpenChunk, Opening, SealChunk};
use super::{Direction, Handle, Slots, hedged_draw};
use crate::{
    block::{
        BLOCK_HEADER_LEN, CARRY_LABEL, CHECK_LEN, CHUNK_LEN, CHUNK_TAG_LEN, SALT_LEN, chunk_nonce,
        chunks_in, data_len_in, same_check,
    },
    derive::{
        Branch, derive_carry_check, derive_carry_chunk, derive_data_check, derive_data_chunk,
        wipe_cipher_stack, wipe_stack,
    },
    entropy::Entropy,
    epoch::Epoch,
    error::Error,
    key::{KeyLength, wipe},
    keyset::Position,
    record::{AssociatedData, Purpose},
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, Rejected, TAG_LEN},
};

/// A block of data being carried out under a key for transfers, from
/// [`Slots::begin_export_block`]: it reads the block under its set for data and writes it under the
/// key for transfers, and holds no key. It cannot be copied or cloned, and it stops working once
/// the set changes, the key turns to receiving or its chain moves on. One begun as the first
/// element of an export goes on as the first of the next, if that export ends between its chunks.
pub struct Exporting<'a> {
    pub(super) source: Opening<'a>,
    pub(super) transfer: Handle<'a>,
    pub(super) chain: [u8; TAG_LEN],
    pub(super) salt: [u8; SALT_LEN],
    pub(super) associated: AssociatedData,
}

/// A carried block whose header opened under a key for transfers, from [`Slots::begin_receive_block`],
/// before [`Slots::receive_into`] gives it a set for data to be written under.
pub struct Receipt<'a> {
    pub(super) transfer: Handle<'a>,
    pub(super) chain: [u8; TAG_LEN],
    pub(super) salt: [u8; SALT_LEN],
    pub(super) associated: AssociatedData,
    pub(super) chunks: u64,
    pub(super) last: u64,
}

/// A carried block being received, from [`Slots::receive_into`]: it reads the block under the key
/// for transfers and writes it under the primary key of a set for data that came in the same
/// transfer, and holds no key. It cannot be copied or cloned, and it stops working once another
/// record or block goes under the key for transfers, the end of that transfer is received, or the
/// set is released.
pub struct Receiving<'a> {
    pub(super) receipt: Receipt<'a>,
    pub(super) set: Handle<'a>,
    pub(super) at: Position,
    pub(super) salt: [u8; SALT_LEN],
    pub(super) associated: AssociatedData,
    pub(super) next: u64,
}

impl Receipt<'_> {
    /// How many chunks the block holds, one at least.
    #[must_use]
    pub const fn chunks(&self) -> u64 {
        self.chunks
    }

    /// How many bytes the last chunk holds: from 1 to [`CHUNK_LEN`], or none when the data are
    /// empty.
    #[must_use]
    pub const fn last_len(&self) -> u64 {
        self.last
    }
}

impl core::fmt::Debug for Exporting<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Exporting").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Receipt<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receipt").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Receiving<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receiving").finish_non_exhaustive()
    }
}

/// Where a chunk is carried from and to: the key, the nonce and the associated data of each side.
struct Passes<'k> {
    open_key: &'k [u8; CIPHER_KEY_LEN],
    open_aad: &'k [u8],
    seal_key: &'k [u8; CIPHER_KEY_LEN],
    seal_aad: &'k [u8],
    index: u64,
    last: bool,
}

/// Whether two chains of an export are the same. Compared as numbers: Kani 0.68.0 reads bytes from
/// before the latest write when it compares arrays whole.
fn same_chain(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    u128::from_ne_bytes(*a) == u128::from_ne_bytes(*b)
}

/// Opens `chunk` under `tag` and seals it again, in place, and gives the new tag: `RecordRejected`
/// if it does not open, `CipherFailed` if the seal fails. Either wipes the chunk.
fn reseal(
    passes: &Passes<'_>,
    chunk: &mut [u8],
    tag: &[u8; CHUNK_TAG_LEN],
    mut open_with: impl OpenChunk,
    mut seal_with: impl SealChunk,
) -> Result<[u8; CHUNK_TAG_LEN], Error> {
    let nonce = chunk_nonce(passes.index, passes.last);
    open_with
        .open(passes.open_key, &nonce, passes.open_aad, chunk, tag)
        .map_err(|Rejected| Error::RecordRejected)?;
    seal_with
        .seal(passes.seal_key, &nonce, passes.seal_aad, chunk)
        .map_err(|_| Error::CipherFailed)
}

impl<'a> Slots<'a> {
    /// Begins to carry the block `opening` reads, from its first chunk, as the next element of the
    /// export under the key for transfers that `transfer` refers to, for the export's `context`,
    /// from 1 to 255 bytes, and writes the header of the carried block into `header`: a salt from
    /// `entropy`, hedged with the key of this epoch, and a check derived from the key for transfers
    /// and the salt. The chunks follow with [`Slots::export_chunk`] and [`Slots::export_last`]; the
    /// carried block opens only with that key, the same `context` and the records and blocks before
    /// it, in any epoch: neither a change of epoch nor a destruction afterwards reaches it.
    ///
    /// Needs 12 KiB of stack, or 74 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the hedge, the derivation and the whole call are each followed
    /// by a wipe of 8 KiB, or 64 KiB, below them, whether it succeeded or not. A build that
    /// optimises this crate but not the hash code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if either handle does not refer to a set held here now or the set
    /// for data has changed since the block began to be read, [`Error::WrongPurpose`] if
    /// `transfer` does not serve [`Purpose::Transfer`], [`Error::Unfinished`] if the key for
    /// transfers receives an export, [`Error::WrongChunk`] if a chunk has been read from the block,
    /// [`Error::EntropyFailed`] if `entropy` fails, and [`Error::DerivationFailed`] if the salt
    /// cannot be hedged or the check cannot be derived. `header` is then left as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and `header` is left as it was.
    pub fn begin_export_block(
        &mut self,
        opening: Opening<'a>,
        transfer: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Result<Exporting<'a>, Error> {
        let begun = crate::timing::with(|| {
            self.begin_export_block_in(opening, transfer, context, entropy, header)
        });
        wipe_stack();
        begun
    }

    /// The beginning itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    pub(super) fn begin_export_block_in(
        &mut self,
        opening: Opening<'a>,
        transfer: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Result<Exporting<'a>, Error> {
        let associated = AssociatedData::of_data(context).map_err(|_| Error::InvalidContext)?;
        let index = self.loaded(opening.set)?;
        let source = self.memory.get(index).ok_or(Error::StaleHandle)?;
        if source.stages.revision() != opening.revision {
            return Err(Error::StaleHandle);
        }
        let transfer_index = self.serving(transfer, Purpose::Transfer)?;
        let Self { memory, epoch } = self;
        let carrier = memory.get(transfer_index).ok_or(Error::StaleHandle)?;
        carrier.may_go(Direction::Out)?;
        if opening.next != 0 {
            return Err(Error::WrongChunk);
        }
        let Epoch { key, drawn, .. } = &mut **epoch;
        let mut salt = [0; SALT_LEN];
        hedged_draw(entropy, key, drawn, Branch::HedgeSalt, &mut salt)?;
        let mut check = [0; CHECK_LEN];
        let derived = derive_carry_check(carrier.wrapping_key().0, &salt, &mut check);
        if derived.is_ok()
            && let Some((salt_out, check_out)) = header.split_first_chunk_mut::<SALT_LEN>()
        {
            *salt_out = salt;
            check_out.copy_from_slice(&check);
        }
        wipe(&mut check);
        derived.map_err(|_| Error::DerivationFailed)?;
        Ok(Exporting {
            source: opening,
            transfer,
            chain: carrier.chain,
            salt,
            associated: associated.chained(CARRY_LABEL, &carrier.chain),
        })
    }

    /// Carries `chunk`, the next chunk of the block `exporting` carries and not its last, in place:
    /// it opens under the set for data if `tag` is its tag, is sealed under the key for transfers,
    /// and its new tag goes into `out`.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongChunk`] if the last chunk is due, [`Error::StaleHandle`] if either set is not
    /// held here now, the set for data has changed since the block began to be read, or another
    /// record or block has gone under the key for transfers, [`Error::Unfinished`] if the key
    /// receives an export, [`Error::DerivationFailed`] if a key
    /// that encrypts the chunks cannot be derived, [`Error::RecordRejected`] if the chunk does not
    /// open as the next of the block, and [`Error::CipherFailed`] if the cipher gives a known input
    /// a wrong answer or fails, or the chunk does not open and seal again to the same tag and
    /// ciphertext. `chunk` is then wiped if the cipher ran, and left as it was if not, `out` is
    /// left as it was, and the block goes on as before the call: the caller keeps its own copy of
    /// the chunk until the call succeeds.
    pub fn export_chunk(
        &mut self,
        exporting: &mut Exporting<'a>,
        chunk: &mut [u8; CHUNK_LEN],
        tag: &[u8; CHUNK_TAG_LEN],
        out: &mut [u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let carried = crate::timing::with(|| {
            self.export_next_in(exporting, chunk, (tag, out), seal::Aes, seal::Aes)
        });
        wipe_cipher_stack();
        carried
    }

    /// A chunk carried out that is not the last.
    pub(super) fn export_next_in(
        &mut self,
        exporting: &mut Exporting<'a>,
        chunk: &mut [u8],
        tags: (&[u8; CHUNK_TAG_LEN], &mut [u8; CHUNK_TAG_LEN]),
        open_with: impl OpenChunk,
        seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        let source = &exporting.source;
        if source
            .next
            .checked_add(1)
            .is_none_or(|after| after >= source.chunks)
        {
            return Err(Error::WrongChunk);
        }
        self.export_chunk_on_stack(exporting, chunk, false, tags, open_with, seal_with)
    }

    /// Carries `chunk`, the last chunk of the block `exporting` carries, in place, as
    /// [`Slots::export_chunk`] does, and ends the block: the export under the key for transfers
    /// goes on after it.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongChunk`] if more chunks are due before the last, or `chunk` is not as long as
    /// the block's last chunk, and the errors of [`Slots::export_chunk`]. The block is then not
    /// carried.
    pub fn export_last(
        &mut self,
        mut exporting: Exporting<'a>,
        chunk: &mut [u8],
        tag: &[u8; CHUNK_TAG_LEN],
        out: &mut [u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let carried = crate::timing::with(|| {
            self.export_last_in(&mut exporting, chunk, (tag, out), seal::Aes, seal::Aes)
        });
        wipe_cipher_stack();
        carried
    }

    /// The last chunk carried out.
    pub(super) fn export_last_in(
        &mut self,
        exporting: &mut Exporting<'a>,
        chunk: &mut [u8],
        tags: (&[u8; CHUNK_TAG_LEN], &mut [u8; CHUNK_TAG_LEN]),
        open_with: impl OpenChunk,
        seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        let source = &exporting.source;
        let length = u64::try_from(chunk.len()).map_err(|_| Error::WrongChunk)?;
        if source.next.checked_add(1) != Some(source.chunks) || length != source.last {
            return Err(Error::WrongChunk);
        }
        self.export_chunk_on_stack(exporting, chunk, true, tags, open_with, seal_with)
    }

    /// The carriage of a chunk out itself, in a frame of its own: the wipe that follows starts
    /// where this frame starts. Every check and both derivations come before the cipher.
    #[inline(never)]
    pub(super) fn export_chunk_on_stack(
        &mut self,
        exporting: &mut Exporting<'a>,
        chunk: &mut [u8],
        last: bool,
        (tag, out): (&[u8; CHUNK_TAG_LEN], &mut [u8; CHUNK_TAG_LEN]),
        open_with: impl OpenChunk,
        seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        let source = &mut exporting.source;
        let index = self.loaded(source.set)?;
        let transfer_index = self.loaded(exporting.transfer)?;
        let (Some(slot), Some(carrier)) = (self.memory.get(index), self.memory.get(transfer_index))
        else {
            return Err(Error::StaleHandle);
        };
        if slot.stages.revision() != source.revision
            || !same_chain(&carrier.chain, &exporting.chain)
        {
            return Err(Error::StaleHandle);
        }
        carrier.may_go(Direction::Out)?;
        let mut open_key = [0; CIPHER_KEY_LEN];
        let mut seal_key = [0; CIPHER_KEY_LEN];
        let derived =
            derive_data_chunk(slot.key(source.at), &source.salt, &mut open_key).and_then(|()| {
                derive_carry_chunk(carrier.wrapping_key().0, &exporting.salt, &mut seal_key)
            });
        let resealed = derived.map_err(|_| Error::DerivationFailed).and_then(|()| {
            let passes = Passes {
                open_key: &open_key,
                open_aad: source.associated.bytes(),
                seal_key: &seal_key,
                seal_aad: exporting.associated.bytes(),
                index: source.next,
                last,
            };
            reseal(&passes, chunk, tag, open_with, seal_with)
        });
        wipe(&mut open_key);
        wipe(&mut seal_key);
        *out = resealed?;
        source.next = source.next.saturating_add(1);
        if last && let Some(carrier) = self.memory.get_mut(transfer_index) {
            carrier.chain = *out;
            carrier.direction = Direction::Out;
        }
        Ok(())
    }

    /// Begins to receive the carried block of `block` bytes whose header is `header`, the next
    /// element of the export under the key for transfers that `transfer` refers to, for the
    /// `context` it was exported for: the header's check is derived from that key and compared,
    /// and the block opens only after the records and blocks received under that key before it, in
    /// the order they were exported. [`Slots::receive_into`] then gives it a set to be written
    /// under.
    ///
    /// Needs 11 KiB of stack, or 70 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation and the whole call are each followed by a wipe
    /// of 8 KiB, or 64 KiB, below them. A build that optimises this crate but not the hash code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `transfer` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::Transfer`],
    /// [`Error::Unfinished`] if the key writes an export, [`Error::RecordRejected`] if no block is
    /// `block` bytes long, [`Error::DerivationFailed`] if the check cannot be derived, and
    /// [`Error::RecordRejected`] if the header does not name the key.
    pub fn begin_receive_block(
        &self,
        transfer: Handle<'a>,
        context: &[u8],
        header: &[u8; BLOCK_HEADER_LEN],
        block: u64,
    ) -> Result<Receipt<'a>, Error> {
        let begun = crate::timing::with(|| {
            self.begin_receive_block_in::<CHUNK_LEN>(transfer, context, header, block)
        });
        wipe_stack();
        begun
    }

    /// The beginning itself, for chunks of `C` bytes, in a frame of its own: the wipe that follows
    /// starts where this frame starts.
    #[inline(never)]
    pub(super) fn begin_receive_block_in<const C: usize>(
        &self,
        transfer: Handle<'a>,
        context: &[u8],
        header: &[u8; BLOCK_HEADER_LEN],
        block: u64,
    ) -> Result<Receipt<'a>, Error> {
        let associated = AssociatedData::of_data(context).map_err(|_| Error::InvalidContext)?;
        let index = self.serving(transfer, Purpose::Transfer)?;
        let carrier = self.memory.get(index).ok_or(Error::StaleHandle)?;
        carrier.may_go(Direction::In)?;
        let len = data_len_in::<C>(block).ok_or(Error::RecordRejected)?;
        let (chunks, last) = chunks_in::<C>(len);
        let (salt, kept) = super::data::split_header(header);
        let mut check = [0; CHECK_LEN];
        let derived = derive_carry_check(carrier.wrapping_key().0, &salt, &mut check);
        let found = derived.is_ok() && same_check(&check, &kept);
        wipe(&mut check);
        derived.map_err(|_| Error::DerivationFailed)?;
        if !found {
            return Err(Error::RecordRejected);
        }
        Ok(Receipt {
            transfer,
            chain: carrier.chain,
            salt,
            associated: associated.chained(CARRY_LABEL, &carrier.chain),
            chunks,
            last,
        })
    }

    /// Gives the carried block `receipt` begins a set for data to be written under, from its
    /// first chunk, bound to `context`, from 1 to 255 bytes, which names the place the block is
    /// kept, and writes the header of the block written into `header`, as [`Slots::begin_seal`]
    /// does. With `set` empty the set is a new one, of one key from `entropy`, hedged with the key
    /// of this epoch, in the first free slot; otherwise `set` is to refer to a set that came in this
    /// transfer, before its end. Such a set is neither wrapped, exported nor changed, and opens and
    /// writes no other block, until [`Slots::end_receive`] receives the end of the export: blocks
    /// of an export that does not end are lost with it. The chunks follow with
    /// [`Slots::receive_chunk`] and [`Slots::receive_last`].
    ///
    /// Needs 13 KiB of stack, or 77 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: each hedge, the load, the derivation and the whole call are
    /// each followed by a wipe of 8 KiB, or 64 KiB, below them, whether it succeeded or not. A
    /// build that optimises this crate but not the hash code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if a handle does not refer to a set held here now, or another record
    /// or block has gone under the key for transfers, [`Error::WrongPurpose`] if `set` does not
    /// serve [`Purpose::Data`], [`Error::NotReceived`] if it did not come in this transfer,
    /// [`Error::EntropyFailed`] if `entropy` fails, [`Error::NoFreeSlot`] if a new set finds no
    /// free slot, [`Error::DerivationFailed`] if the salt, a key, its identifier or the check
    /// cannot be derived, and [`Error::DuplicateKey`] if these slots hold the new key already. No
    /// other slot changes then, a new set is released, and `header` is left as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, no slot changes, and `header` is left as
    /// it was.
    pub fn receive_into(
        &mut self,
        receipt: Receipt<'a>,
        set: Option<Handle<'a>>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Result<(Receiving<'a>, Handle<'a>), Error> {
        let begun =
            crate::timing::with(|| self.receive_into_in(receipt, set, context, entropy, header));
        wipe_stack();
        begun
    }

    /// The beginning of the block written itself, in a frame of its own: the wipe that follows
    /// starts where this frame starts.
    #[inline(never)]
    pub(super) fn receive_into_in(
        &mut self,
        receipt: Receipt<'a>,
        set: Option<Handle<'a>>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Result<(Receiving<'a>, Handle<'a>), Error> {
        let associated = AssociatedData::of_data(context).map_err(|_| Error::InvalidContext)?;
        let transfer_index = self.loaded(receipt.transfer)?;
        let carrier = self.memory.get(transfer_index).ok_or(Error::StaleHandle)?;
        if !same_chain(&carrier.chain, &receipt.chain) {
            return Err(Error::StaleHandle);
        }
        let mark = Some((transfer_index, carrier.generation));
        if let Some(set) = set {
            let index = self.serving(set, Purpose::Data)?;
            if self.memory.get(index).map(|slot| slot.pending) != Some(mark) {
                return Err(Error::NotReceived);
            }
        }
        let Epoch { key, drawn, .. } = &mut *self.epoch;
        let mut salt = [0; SALT_LEN];
        hedged_draw(entropy, key, drawn, Branch::HedgeSalt, &mut salt)?;
        let (set, new) = match set {
            Some(set) => (set, false),
            None => (
                self.generate(Purpose::Data, KeyLength::Bytes32, entropy)?,
                true,
            ),
        };
        let begun = self.header_of_received(set, &salt, header);
        let index = set.index;
        match begun {
            Ok(at) => {
                if new && let Some(slot) = self.memory.get_mut(index) {
                    slot.pending = mark;
                }
                let receiving = Receiving {
                    receipt,
                    set,
                    at,
                    salt,
                    associated,
                    next: 0,
                };
                Ok((receiving, set))
            }
            Err(error) => {
                if new && let Some(slot) = self.memory.get_mut(index) {
                    slot.unload();
                }
                Err(error)
            }
        }
    }

    /// Writes into `header` the salt `salt` and the check of the primary key of the set at `set`,
    /// when the check is derived, and gives the position of that key.
    fn header_of_received(
        &self,
        set: Handle<'a>,
        salt: &[u8; SALT_LEN],
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Result<Position, Error> {
        let slot = self.memory.get(set.index).ok_or(Error::StaleHandle)?;
        let at = slot.stages.primary_position().ok_or(Error::StaleHandle)?;
        let mut check = [0; CHECK_LEN];
        let derived = derive_data_check(slot.key(at), salt, &mut check);
        if derived.is_ok()
            && let Some((salt_out, check_out)) = header.split_first_chunk_mut::<SALT_LEN>()
        {
            *salt_out = *salt;
            check_out.copy_from_slice(&check);
        }
        wipe(&mut check);
        derived.map_err(|_| Error::DerivationFailed)?;
        Ok(at)
    }

    /// Receives `chunk`, the next chunk of the carried block `receiving` receives and not its
    /// last, in place: it opens under the key for transfers if `tag` is its tag, is sealed under
    /// the set for data, and its new tag goes into `out`.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongChunk`] if the last chunk is due, [`Error::StaleHandle`] if either set is not
    /// held here now, the set for data no longer waits for the end of this transfer, or another
    /// record or block has gone under the key for transfers, [`Error::Unfinished`] if the key
    /// writes an export, [`Error::DerivationFailed`] if a key that encrypts the chunks cannot be
    /// derived,
    /// [`Error::RecordRejected`] if the chunk does not open as the next of the block, and
    /// [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails, or the
    /// chunk does not open and seal again to the same tag and ciphertext. `chunk` is then wiped if
    /// the cipher ran, and left as it was if not, `out` is left as it was, and the block goes on
    /// as before the call: the caller keeps its own copy of the chunk until the call succeeds.
    pub fn receive_chunk(
        &mut self,
        receiving: &mut Receiving<'a>,
        chunk: &mut [u8; CHUNK_LEN],
        tag: &[u8; CHUNK_TAG_LEN],
        out: &mut [u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let carried = crate::timing::with(|| {
            self.receive_next_in(receiving, chunk, (tag, out), seal::Aes, seal::Aes)
        });
        wipe_cipher_stack();
        carried
    }

    /// A chunk received that is not the last.
    pub(super) fn receive_next_in(
        &mut self,
        receiving: &mut Receiving<'a>,
        chunk: &mut [u8],
        tags: (&[u8; CHUNK_TAG_LEN], &mut [u8; CHUNK_TAG_LEN]),
        open_with: impl OpenChunk,
        seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        if receiving
            .next
            .checked_add(1)
            .is_none_or(|after| after >= receiving.receipt.chunks)
        {
            return Err(Error::WrongChunk);
        }
        self.receive_chunk_on_stack(receiving, chunk, false, tags, open_with, seal_with)
    }

    /// Receives `chunk`, the last chunk of the carried block `receiving` receives, in place, as
    /// [`Slots::receive_chunk`] does, and ends the block: the receipt of the export goes on after
    /// it.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongChunk`] if more chunks are due before the last, or `chunk` is not as long as
    /// [`Receipt::last_len`] says, and the errors of [`Slots::receive_chunk`]. The block is then
    /// not received.
    pub fn receive_last(
        &mut self,
        mut receiving: Receiving<'a>,
        chunk: &mut [u8],
        tag: &[u8; CHUNK_TAG_LEN],
        out: &mut [u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let carried = crate::timing::with(|| {
            self.receive_last_in(&mut receiving, chunk, (tag, out), seal::Aes, seal::Aes)
        });
        wipe_cipher_stack();
        carried
    }

    /// The last chunk received.
    pub(super) fn receive_last_in(
        &mut self,
        receiving: &mut Receiving<'a>,
        chunk: &mut [u8],
        tags: (&[u8; CHUNK_TAG_LEN], &mut [u8; CHUNK_TAG_LEN]),
        open_with: impl OpenChunk,
        seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        let length = u64::try_from(chunk.len()).map_err(|_| Error::WrongChunk)?;
        let receipt = &receiving.receipt;
        if receiving.next.checked_add(1) != Some(receipt.chunks) || length != receipt.last {
            return Err(Error::WrongChunk);
        }
        self.receive_chunk_on_stack(receiving, chunk, true, tags, open_with, seal_with)
    }

    /// The receipt of a chunk itself, in a frame of its own: the wipe that follows starts where
    /// this frame starts. Every check and both derivations come before the cipher.
    #[inline(never)]
    pub(super) fn receive_chunk_on_stack(
        &mut self,
        receiving: &mut Receiving<'a>,
        chunk: &mut [u8],
        last: bool,
        (tag, out): (&[u8; CHUNK_TAG_LEN], &mut [u8; CHUNK_TAG_LEN]),
        open_with: impl OpenChunk,
        seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        let receipt = &receiving.receipt;
        let transfer_index = self.loaded(receipt.transfer)?;
        let index = self.loaded(receiving.set)?;
        let (Some(carrier), Some(slot)) = (self.memory.get(transfer_index), self.memory.get(index))
        else {
            return Err(Error::StaleHandle);
        };
        if !same_chain(&carrier.chain, &receipt.chain)
            || slot.pending != Some((transfer_index, carrier.generation))
        {
            return Err(Error::StaleHandle);
        }
        carrier.may_go(Direction::In)?;
        let mut open_key = [0; CIPHER_KEY_LEN];
        let mut seal_key = [0; CIPHER_KEY_LEN];
        let derived = derive_carry_chunk(carrier.wrapping_key().0, &receipt.salt, &mut open_key)
            .and_then(|()| {
                derive_data_chunk(slot.key(receiving.at), &receiving.salt, &mut seal_key)
            });
        let resealed = derived.map_err(|_| Error::DerivationFailed).and_then(|()| {
            let passes = Passes {
                open_key: &open_key,
                open_aad: receipt.associated.bytes(),
                seal_key: &seal_key,
                seal_aad: receiving.associated.bytes(),
                index: receiving.next,
                last,
            };
            reseal(&passes, chunk, tag, open_with, seal_with)
        });
        wipe(&mut open_key);
        wipe(&mut seal_key);
        *out = resealed?;
        receiving.next = receiving.next.saturating_add(1);
        if last && let Some(carrier) = self.memory.get_mut(transfer_index) {
            carrier.chain = *tag;
            carrier.direction = Direction::In;
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "a test lays chunks out and picks bits"
)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use sha2::{Digest, Sha256};

    use super::super::data::tests::{
        Fixed, NONCE, open_block, pattern_of, recorded_set, seal_block,
    };
    use crate::block::{BLOCK_HEADER_LEN, CHUNK_LEN, CHUNK_TAG_LEN};
    use crate::entropy::Entropy;
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::tests::{Random, from_environment};
    use crate::record::{END_RECORD_LEN, Purpose, RECORD_LEN};
    use crate::seal;
    use crate::slots::tests::{EPOCH, epoch_key, pattern};
    use crate::slots::{Handle, Slot, Slots};
    use crate::timing::timed;

    /// The chunks of `block`, each with its tag, past the header, for a block of `chunks` chunks
    /// whose last holds `last` bytes.
    fn chunks_of(block: &[u8], chunks: u64, last: u64) -> Vec<(Vec<u8>, [u8; CHUNK_TAG_LEN])> {
        let mut at = BLOCK_HEADER_LEN;
        (0..chunks)
            .map(|index| {
                let len = if index + 1 == chunks {
                    usize::try_from(last).unwrap()
                } else {
                    CHUNK_LEN
                };
                let chunk = block[at..at + len].to_vec();
                let tag = block[at + len..at + len + CHUNK_TAG_LEN]
                    .try_into()
                    .unwrap();
                at += len + CHUNK_TAG_LEN;
                (chunk, tag)
            })
            .collect()
    }

    /// Carries `block`, read under `set` for `context`, under `transfer` for the export's
    /// `export`: the carried block.
    fn export_block<'a>(
        slots: &mut Slots<'a>,
        (set, context): (Handle<'a>, &[u8]),
        block: &[u8],
        (transfer, export): (Handle<'a>, &[u8]),
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<Vec<u8>, Error> {
        let header: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let opening =
            slots.begin_open(set, context, &header, u64::try_from(block.len()).unwrap())?;
        let (chunks, last) = (opening.chunks(), opening.last_len());
        let mut carried = [0; BLOCK_HEADER_LEN];
        let mut exporting =
            slots.begin_export_block(opening, transfer, export, entropy, &mut carried)?;
        let mut out = carried.to_vec();
        let pieces = chunks_of(block, chunks, last);
        let count = pieces.len();
        for (index, (mut chunk, tag)) in pieces.into_iter().enumerate() {
            let mut new_tag = [0; CHUNK_TAG_LEN];
            if index + 1 == count {
                slots.export_last(exporting, &mut chunk, &tag, &mut new_tag)?;
                out.extend_from_slice(&chunk);
                out.extend_from_slice(&new_tag);
                return Ok(out);
            }
            let full: &mut [u8; CHUNK_LEN] = (&mut chunk[..]).try_into().unwrap();
            slots.export_chunk(&mut exporting, full, &tag, &mut new_tag)?;
            out.extend_from_slice(&chunk);
            out.extend_from_slice(&new_tag);
        }
        unreachable!("the last chunk returns")
    }

    /// Receives the carried block `carried` under `transfer` for the export's `export`, into
    /// `set` or a new set, as a block for `context`: the block and the handle of its set.
    fn receive_block<'a>(
        slots: &mut Slots<'a>,
        (transfer, export): (Handle<'a>, &[u8]),
        carried: &[u8],
        (set, context): (Option<Handle<'a>>, &[u8]),
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<(Vec<u8>, Handle<'a>), Error> {
        let header: [u8; BLOCK_HEADER_LEN] = carried[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(carried.len()).unwrap();
        let receipt = slots.begin_receive_block(transfer, export, &header, length)?;
        let (chunks, last) = (receipt.chunks(), receipt.last_len());
        let mut local = [0; BLOCK_HEADER_LEN];
        let (mut receiving, set) =
            slots.receive_into(receipt, set, context, entropy, &mut local)?;
        let mut out = local.to_vec();
        let pieces = chunks_of(carried, chunks, last);
        let count = pieces.len();
        for (index, (mut chunk, tag)) in pieces.into_iter().enumerate() {
            let mut new_tag = [0; CHUNK_TAG_LEN];
            if index + 1 == count {
                slots.receive_last(receiving, &mut chunk, &tag, &mut new_tag)?;
                out.extend_from_slice(&chunk);
                out.extend_from_slice(&new_tag);
                return Ok((out, set));
            }
            let full: &mut [u8; CHUNK_LEN] = (&mut chunk[..]).try_into().unwrap();
            slots.receive_chunk(&mut receiving, full, &tag, &mut new_tag)?;
            out.extend_from_slice(&chunk);
            out.extend_from_slice(&new_tag);
        }
        unreachable!("the last chunk returns")
    }

    const LENGTHS: [usize; 5] = [0, 1, 33, CHUNK_LEN, CHUNK_LEN + 1];

    /// Blocks carried out in turn as one export, computed by an implementation independent of this
    /// library: the length of the data and of the carried block, and the block, or its SHA-256 when
    /// long.
    const KNOWN_CARRIED: [(usize, usize, &str); 5] = [
        (
            0,
            64,
            concat!(
                "5ec0693f3cab9fae3896278c3c5cae97111f12d58aa9e23facff4a77a9ce3fca",
                "159d1d8a9ab49728aad190d0cf47f4ffb6a9f2c1a52d7c0f1d1b602c4823546a",
            ),
        ),
        (
            1,
            65,
            concat!(
                "2ca072379a34ad8554ed6e7c424e4936b3881d32c9fc5f07bd0b1d8b6e54979c",
                "25f367cc50664196ced841937bf454ad0f941da80b9871705cc20528b5ee54ec",
                "ec",
            ),
        ),
        (
            33,
            97,
            concat!(
                "75db895f57d1f5c9521b756acfab9c275d4acce5420034327c709f1bbb272cfd",
                "6a2bdc4366379da350dd63543bb496e2b4207deb39c2d4f4e42ea57a69394515",
                "4b7f98c1f9a6b8f44238a77590341f45b09d4a7922cbb65223dc655be74b26e4",
                "4f",
            ),
        ),
        (
            65536,
            65600,
            "9df43ff9c905e091303059cedf678c3b923e50c182cfb344f2342b8a83ae7459",
        ),
        (
            65537,
            65617,
            "7e09b6b2fb56f5832119968e51094f34207e62a0a4e7476a328c8373d55aa82f",
        ),
    ];

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    /// Slots of one device with a recorded set for data and a key for transfers, and of another
    /// with the same key for transfers.
    fn devices<'a>(
        (memory, epoch): (&'a mut [Slot], &'a mut Epoch),
        (other_memory, other_epoch): (&'a mut [Slot], &'a mut Epoch),
    ) -> (Slots<'a>, Handle<'a>, Handle<'a>, Slots<'a>, Handle<'a>) {
        let mut from = Slots::new(memory, epoch, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut from);
        let out = from
            .import32(Purpose::Transfer, &mut pattern(41, 3))
            .unwrap();
        let mut to = Slots::new(other_memory, other_epoch, 4, &mut [0x5a; 32]);
        let into = to.import32(Purpose::Transfer, &mut pattern(41, 3)).unwrap();
        (from, set, out, to, into)
    }

    #[test]
    fn carried_blocks_match_ones_computed_independently() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut from, set, out, ..) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        for (data_len, carried_len, known) in KNOWN_CARRIED {
            let drawn = pattern::<16>(17, 5);
            let block = seal_block(
                &mut from,
                set,
                b"chat 7",
                &mut Fixed(&drawn),
                &pattern_of(data_len),
            )
            .unwrap();
            let carried = export_block(
                &mut from,
                (set, b"chat 7"),
                &block,
                (out, b"move"),
                &mut Fixed(&drawn),
            )
            .unwrap();
            assert_eq!(carried.len(), carried_len);
            if carried.len() <= 128 {
                assert_eq!(carried, unhex(known), "{data_len}");
            } else {
                assert_eq!(
                    Sha256::digest(&carried).to_vec(),
                    unhex(known),
                    "{data_len}"
                );
            }
        }
    }

    /// Blocks of every length carried out, received into one new set and opened once the end of
    /// the export is received: before the end the set opens and writes no block.
    #[test]
    fn carried_blocks_open_to_their_data_once_the_export_ends() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let mut carried = Vec::new();
        for len in LENGTHS {
            let block = seal_block(
                &mut from,
                set,
                b"chat 7",
                &mut Fixed(&NONCE),
                &pattern_of(len),
            )
            .unwrap();
            carried.push(
                export_block(
                    &mut from,
                    (set, b"chat 7"),
                    &block,
                    (out, b"move"),
                    &mut Fixed(&NONCE),
                )
                .unwrap(),
            );
        }
        let mut end = [0; END_RECORD_LEN];
        from.end_export(out, b"move", &mut Fixed(&NONCE), &mut end)
            .unwrap();
        let mut received = Vec::new();
        let mut new = None;
        for block in &carried {
            let (local, set) = receive_block(
                &mut to,
                (into, b"move"),
                block,
                (new, b"chat 9"),
                &mut Fixed(&pattern::<16>(3, 7)),
            )
            .unwrap();
            new = Some(set);
            received.push(local);
        }
        let new = new.unwrap();
        assert_eq!(
            open_block(&to, new, b"chat 9", &received[0]),
            Err(Error::Unfinished)
        );
        let mut header = [0; BLOCK_HEADER_LEN];
        assert_eq!(
            to.begin_seal(new, b"chat 9", &mut Fixed(&NONCE), &mut header)
                .err(),
            Some(Error::Unfinished)
        );
        to.end_receive(into, b"move", &end).unwrap();
        for (block, len) in received.iter().zip(LENGTHS) {
            assert_eq!(
                open_block(&to, new, b"chat 9", block).unwrap(),
                pattern_of(len)
            );
        }
    }

    /// A carried block opens only in its place in the export: one out of order, one given twice
    /// and one of another context are refused, and the end does not open after a block left out.
    /// A carried block is no local block and a local one no carried block.
    #[test]
    fn carried_blocks_open_only_in_order_and_as_what_they_are() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let blocks: Vec<Vec<u8>> = [1, 33, 2]
            .map(|len| {
                seal_block(
                    &mut from,
                    set,
                    b"chat 7",
                    &mut Fixed(&NONCE),
                    &pattern_of(len),
                )
                .unwrap()
            })
            .to_vec();
        let carried: Vec<Vec<u8>> = blocks
            .iter()
            .map(|block| {
                export_block(
                    &mut from,
                    (set, b"chat 7"),
                    block,
                    (out, b"move"),
                    &mut Fixed(&NONCE),
                )
                .unwrap()
            })
            .collect();
        let mut end = [0; END_RECORD_LEN];
        from.end_export(out, b"move", &mut Fixed(&NONCE), &mut end)
            .unwrap();
        let entropy = &mut Fixed(&pattern::<16>(3, 7));
        // The local block is no carried block, and the carried block no local one.
        let header: [u8; BLOCK_HEADER_LEN] = blocks[0][..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(blocks[0].len()).unwrap();
        assert_eq!(
            to.begin_receive_block(into, b"move", &header, length).err(),
            Some(Error::RecordRejected)
        );
        assert_eq!(
            open_block(&from, set, b"chat 7", &carried[0]),
            Err(Error::RecordRejected)
        );
        // Out of order, and in another context.
        let new = None;
        assert_eq!(
            receive_block(&mut to, (into, b"move"), &carried[1], (new, b"x"), entropy).err(),
            Some(Error::RecordRejected)
        );
        assert_eq!(
            receive_block(&mut to, (into, b"other"), &carried[0], (new, b"x"), entropy).err(),
            Some(Error::RecordRejected)
        );
        let (_, set_in) =
            receive_block(&mut to, (into, b"move"), &carried[0], (new, b"x"), entropy).unwrap();
        assert_eq!(
            receive_block(
                &mut to,
                (into, b"move"),
                &carried[0],
                (Some(set_in), b"x"),
                entropy
            )
            .err(),
            Some(Error::RecordRejected)
        );
        // The second block left out: the third does not open, nor does the end.
        assert_eq!(
            receive_block(
                &mut to,
                (into, b"move"),
                &carried[2],
                (Some(set_in), b"x"),
                entropy
            )
            .err(),
            Some(Error::RecordRejected)
        );
        assert_eq!(
            to.end_receive(into, b"move", &end),
            Err(Error::RecordRejected)
        );
        receive_block(
            &mut to,
            (into, b"move"),
            &carried[1],
            (Some(set_in), b"x"),
            entropy,
        )
        .unwrap();
        receive_block(
            &mut to,
            (into, b"move"),
            &carried[2],
            (Some(set_in), b"x"),
            entropy,
        )
        .unwrap();
        to.end_receive(into, b"move", &end).unwrap();
    }

    /// A block carried between records of the export takes its place among them, a record between
    /// two of its chunks breaks it, and a set that did not come in the transfer takes no block.
    #[test]
    fn a_carried_block_is_an_element_of_its_export() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 5], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let external = from
            .import32(Purpose::ExternalData, &mut pattern(19, 4))
            .unwrap();
        let mut first = [0; RECORD_LEN];
        from.export(external, out, b"move", &mut Fixed(&NONCE), &mut first)
            .unwrap();
        let long = seal_block(
            &mut from,
            set,
            b"chat 7",
            &mut Fixed(&NONCE),
            &pattern_of(CHUNK_LEN + 3),
        )
        .unwrap();
        // A record between two chunks of a block breaks the block.
        let header: [u8; BLOCK_HEADER_LEN] = long[..BLOCK_HEADER_LEN].try_into().unwrap();
        let opening = from
            .begin_open(set, b"chat 7", &header, u64::try_from(long.len()).unwrap())
            .unwrap();
        let mut carried_header = [0; BLOCK_HEADER_LEN];
        let mut exporting = from
            .begin_export_block(
                opening,
                out,
                b"move",
                &mut Fixed(&NONCE),
                &mut carried_header,
            )
            .unwrap();
        let pieces = chunks_of(&long, 2, 3);
        let mut chunk: [u8; CHUNK_LEN] = pieces[0].0[..].try_into().unwrap();
        let mut new_tag = [0; CHUNK_TAG_LEN];
        from.export_chunk(&mut exporting, &mut chunk, &pieces[0].1, &mut new_tag)
            .unwrap();
        let another = from
            .import32(Purpose::ExternalData, &mut pattern(19, 5))
            .unwrap();
        let mut second = [0; RECORD_LEN];
        from.export(another, out, b"move", &mut Fixed(&NONCE), &mut second)
            .unwrap();
        let mut last = pieces[1].0.clone();
        assert_eq!(
            from.export_last(exporting, &mut last, &pieces[1].1, &mut new_tag),
            Err(Error::StaleHandle)
        );
        let carried = export_block(
            &mut from,
            (set, b"chat 7"),
            &long,
            (out, b"move"),
            &mut Fixed(&NONCE),
        )
        .unwrap();
        let mut end = [0; END_RECORD_LEN];
        from.end_export(out, b"move", &mut Fixed(&NONCE), &mut end)
            .unwrap();
        let entropy = &mut Fixed(&pattern::<16>(3, 7));
        to.receive(into, b"move", &first).unwrap();
        to.receive(into, b"move", &second).unwrap();
        let (other, _) = recorded_set(&mut to);
        assert_eq!(
            receive_block(
                &mut to,
                (into, b"move"),
                &carried,
                (Some(other), b"x"),
                entropy
            )
            .err(),
            Some(Error::NotReceived)
        );
        receive_block(&mut to, (into, b"move"), &carried, (None, b"x"), entropy).unwrap();
        to.end_receive(into, b"move", &end).unwrap();
    }

    assert_not_impl!(super::Exporting<'static>: Clone, Copy);
    assert_not_impl!(super::Receipt<'static>: Clone, Copy);
    assert_not_impl!(super::Receiving<'static>: Clone, Copy);

    #[test]
    fn debug_shows_no_state_of_a_carried_block() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let block = seal_block(&mut from, set, b"chat 7", &mut Fixed(&NONCE), &[7]).unwrap();
        let header: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = from.begin_open(set, b"chat 7", &header, length).unwrap();
        let mut carried = [0; BLOCK_HEADER_LEN];
        let exporting = from
            .begin_export_block(opening, out, b"move", &mut Fixed(&NONCE), &mut carried)
            .unwrap();
        assert_eq!(std::format!("{exporting:?}"), "Exporting { .. }");
        let receipt = to
            .begin_receive_block(into, b"move", &carried, length)
            .unwrap();
        assert_eq!(std::format!("{receipt:?}"), "Receipt { .. }");
        let mut local = [0; BLOCK_HEADER_LEN];
        let (receiving, _) = to
            .receive_into(receipt, None, b"kept", &mut Fixed(&NONCE), &mut local)
            .unwrap();
        assert_eq!(std::format!("{receiving:?}"), "Receiving { .. }");
    }

    /// A chunk refused by the cipher is wiped, on the way out and in, and its block goes on from it.
    #[test]
    fn a_chunk_that_does_not_open_is_wiped() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let block = seal_block(&mut from, set, b"chat 7", &mut Fixed(&NONCE), &[7; 9]).unwrap();
        let header: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = from.begin_open(set, b"chat 7", &header, length).unwrap();
        let mut carried = [0; BLOCK_HEADER_LEN];
        let mut exporting = from
            .begin_export_block(opening, out, b"move", &mut Fixed(&NONCE), &mut carried)
            .unwrap();
        let tag: [u8; CHUNK_TAG_LEN] = block[BLOCK_HEADER_LEN + 9..].try_into().unwrap();
        let mut wrong = tag;
        wrong[0] ^= 1;
        let mut chunk = block[BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + 9].to_vec();
        let mut new_tag = [5; CHUNK_TAG_LEN];
        assert_eq!(
            from.export_chunk_on_stack(
                &mut exporting,
                &mut chunk,
                true,
                (&wrong, &mut new_tag),
                seal::Aes,
                seal::Aes
            ),
            Err(Error::RecordRejected)
        );
        assert_eq!((chunk, new_tag), (std::vec![0; 9], [5; CHUNK_TAG_LEN]));
        let mut chunk = block[BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + 9].to_vec();
        from.export_last(exporting, &mut chunk, &tag, &mut new_tag)
            .unwrap();
        let receipt = to
            .begin_receive_block(into, b"move", &carried, length)
            .unwrap();
        let mut local = [0; BLOCK_HEADER_LEN];
        let (mut receiving, _) = to
            .receive_into(receipt, None, b"kept", &mut Fixed(&NONCE), &mut local)
            .unwrap();
        let carried_chunk = chunk.clone();
        let mut wrong = new_tag;
        wrong[0] ^= 1;
        let mut kept = [5; CHUNK_TAG_LEN];
        assert_eq!(
            to.receive_chunk_on_stack(
                &mut receiving,
                &mut chunk,
                true,
                (&wrong, &mut kept),
                seal::Aes,
                seal::Aes
            ),
            Err(Error::RecordRejected)
        );
        assert_eq!((chunk, kept), (std::vec![0; 9], [5; CHUNK_TAG_LEN]));
        let mut chunk = carried_chunk;
        to.receive_last(receiving, &mut chunk, &new_tag, &mut kept)
            .unwrap();
    }

    /// A receipt stops at another element of the export between two of its chunks, and at an end
    /// of another export received under the same key, which lets its set go: a block begun as the
    /// first element of one export does not go on into another.
    #[test]
    fn a_receipt_stops_at_another_element_or_end() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let entropy = &mut Fixed(&pattern::<16>(3, 7));
        let long = seal_block(
            &mut from,
            set,
            b"chat 7",
            entropy,
            &pattern_of(CHUNK_LEN + 3),
        )
        .unwrap();
        // The first export: the long block alone, ended.
        let carried =
            export_block(&mut from, (set, b"chat 7"), &long, (out, b"move"), entropy).unwrap();
        let mut end = [0; END_RECORD_LEN];
        from.end_export(out, b"move", entropy, &mut end).unwrap();
        // The second export: one record, ended.
        let external = from
            .import32(Purpose::ExternalData, &mut pattern(19, 4))
            .unwrap();
        let mut record = [0; RECORD_LEN];
        from.export(external, out, b"move", entropy, &mut record)
            .unwrap();
        let mut other_end = [0; END_RECORD_LEN];
        from.end_export(out, b"move", entropy, &mut other_end)
            .unwrap();
        let length = u64::try_from(carried.len()).unwrap();
        let header: [u8; BLOCK_HEADER_LEN] = carried[..BLOCK_HEADER_LEN].try_into().unwrap();
        let receipt = to
            .begin_receive_block(into, b"move", &header, length)
            .unwrap();
        let mut local = [0; BLOCK_HEADER_LEN];
        let (mut receiving, new) = to
            .receive_into(receipt, None, b"kept", entropy, &mut local)
            .unwrap();
        let pieces = chunks_of(&carried, 2, 3);
        let mut first: [u8; CHUNK_LEN] = pieces[0].0[..].try_into().unwrap();
        let mut kept = [0; CHUNK_TAG_LEN];
        to.receive_chunk(&mut receiving, &mut first, &pieces[0].1, &mut kept)
            .unwrap();
        // Another export received whole under the same key between the chunks.
        to.receive(into, b"move", &record).unwrap();
        to.end_receive(into, b"move", &other_end).unwrap();
        let mut last = pieces[1].0.clone();
        assert_eq!(
            to.receive_last(receiving, &mut last, &pieces[1].1, &mut kept),
            Err(Error::StaleHandle)
        );
        assert_eq!(
            open_block(
                &to,
                new,
                b"kept",
                &[&local[..], &first[..], &kept[..]].concat()
            ),
            Err(Error::RecordRejected)
        );
        let _ = end;
    }

    /// Every call on a carried block derives and runs the cipher with data-independent timing on,
    /// where it is offered.
    #[test]
    fn every_call_on_a_carried_block_holds_data_independent_timing() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let block = seal_block(
            &mut from,
            set,
            b"chat 7",
            &mut Fixed(&NONCE),
            &pattern_of(CHUNK_LEN + 5),
        )
        .unwrap();
        let header: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = from.begin_open(set, b"chat 7", &header, length).unwrap();
        let mut carried = [0; BLOCK_HEADER_LEN];
        let mut exporting = timed(|| {
            from.begin_export_block(opening, out, b"move", &mut Fixed(&NONCE), &mut carried)
                .unwrap()
        });
        let pieces = chunks_of(&block, 2, 5);
        let (mut first, mut last) = (pieces[0].0.clone(), pieces[1].0.clone());
        let (mut first_tag, mut last_tag) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        timed(|| {
            let full: &mut [u8; CHUNK_LEN] = (&mut first[..]).try_into().unwrap();
            from.export_chunk(&mut exporting, full, &pieces[0].1, &mut first_tag)
                .unwrap();
        });
        timed(|| {
            from.export_last(exporting, &mut last, &pieces[1].1, &mut last_tag)
                .unwrap();
        });
        let receipt = timed(|| {
            to.begin_receive_block(into, b"move", &carried, length)
                .unwrap()
        });
        let mut local = [0; BLOCK_HEADER_LEN];
        let (mut receiving, _) = timed(|| {
            to.receive_into(receipt, None, b"kept", &mut Fixed(&NONCE), &mut local)
                .unwrap()
        });
        let mut tag = [0; CHUNK_TAG_LEN];
        timed(|| {
            let full: &mut [u8; CHUNK_LEN] = (&mut first[..]).try_into().unwrap();
            to.receive_chunk(&mut receiving, full, &first_tag, &mut tag)
                .unwrap();
        });
        timed(|| {
            to.receive_last(receiving, &mut last, &last_tag, &mut tag)
                .unwrap();
        });
    }

    /// A source of the next bytes of `random`.
    fn random_source(random: &mut Random) -> Fixed<'static> {
        Fixed(std::boxed::Box::leak(std::boxed::Box::new(
            random.bytes::<64>(),
        )))
    }

    /// Exports of one to four elements, each a set for external data or a block of a random length
    /// and context, carried out and received in order into one new set, with their end. One random
    /// element with one bit changed is refused in its place, and the export goes on with it whole;
    /// once the end is received, every block opens to its data.
    #[expect(
        clippy::too_many_lines,
        reason = "one round builds an export, changes it and receives it"
    )]
    fn random_exports(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        for round in 0..rounds {
            let (mut memory, mut epoch) = ([const { Slot::empty() }; 8], Epoch::empty());
            let (mut other_memory, mut other_epoch) =
                ([const { Slot::empty() }; 8], Epoch::empty());
            let (mut from, set, out, mut to, into) = devices(
                (&mut memory, &mut epoch),
                (&mut other_memory, &mut other_epoch),
            );
            let count = 1 + random.below(4);
            let mut elements = Vec::new();
            for _ in 0..count {
                if random.below(3) == 0 {
                    let external = from
                        .import32(Purpose::ExternalData, &mut random.bytes::<32>())
                        .unwrap();
                    let mut record = [0; RECORD_LEN];
                    from.export(
                        external,
                        out,
                        b"move",
                        &mut random_source(&mut random),
                        &mut record,
                    )
                    .unwrap();
                    elements.push((record.to_vec(), None));
                } else {
                    let length = match random.below(3) {
                        0 => random.below(64),
                        1 => random.below(CHUNK_LEN + 2),
                        _ => CHUNK_LEN * (1 + random.below(2)),
                    };
                    let context: Vec<u8> = (0..=random.below(20))
                        .map(|_| random.bytes::<1>()[0])
                        .collect();
                    let data: Vec<u8> = (0..length).map(|_| random.bytes::<1>()[0]).collect();
                    let block = seal_block(
                        &mut from,
                        set,
                        &context,
                        &mut random_source(&mut random),
                        &data,
                    )
                    .unwrap();
                    let carried = export_block(
                        &mut from,
                        (set, &context),
                        &block,
                        (out, b"move"),
                        &mut random_source(&mut random),
                    )
                    .unwrap();
                    elements.push((carried, Some((data, context))));
                }
            }
            let mut end = [0; END_RECORD_LEN];
            from.end_export(out, b"move", &mut random_source(&mut random), &mut end)
                .unwrap();
            let changed_at = random.below(count);
            let mut new = None;
            let mut received = Vec::new();
            for (at, (bytes, block)) in elements.iter().enumerate() {
                let entropy = &mut random_source(&mut random);
                if at == changed_at {
                    let mut changed = bytes.clone();
                    let byte = random.below(changed.len());
                    changed[byte] ^= 1 << random.below(8);
                    let refused = match block {
                        None => to
                            .receive(into, b"move", &changed[..].try_into().unwrap())
                            .err(),
                        Some((_, context)) => receive_block(
                            &mut to,
                            (into, b"move"),
                            &changed,
                            (new, context),
                            entropy,
                        )
                        .err(),
                    };
                    assert_eq!(
                        refused,
                        Some(Error::RecordRejected),
                        "round {round}, byte {byte}"
                    );
                }
                match block {
                    None => {
                        to.receive(into, b"move", &bytes[..].try_into().unwrap())
                            .unwrap();
                    }
                    Some((data, context)) => {
                        let (local, set) =
                            receive_block(&mut to, (into, b"move"), bytes, (new, context), entropy)
                                .unwrap();
                        new = Some(set);
                        received.push((local, data, context));
                    }
                }
            }
            to.end_receive(into, b"move", &end).unwrap();
            for (local, data, context) in received {
                assert_eq!(
                    open_block(&to, new.unwrap(), context, &local).unwrap(),
                    *data,
                    "round {round}"
                );
            }
        }
    }

    #[test]
    fn random_exports_open_to_their_data_and_refuse_a_changed_bit() {
        random_exports(8, 1);
    }

    /// The same over as many rounds and from the seed `LETHEWIS_RANDOM_ROUNDS` and
    /// `LETHEWIS_RANDOM_SEED` give.
    #[test]
    #[ignore = "long; the rounds and the seed come from the environment"]
    fn many_random_exports_open_to_their_data_and_refuse_a_changed_bit() {
        random_exports(
            from_environment("LETHEWIS_RANDOM_ROUNDS", 1_000),
            from_environment("LETHEWIS_RANDOM_SEED", 2),
        );
    }

    /// Every changed bit of a carried block is refused, at its header or at its chunk, and the block
    /// unchanged is received after them.
    #[test]
    fn every_bit_of_a_carried_block_is_bound() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 5], Epoch::empty());
        let (mut from, set, out, mut to, into) = devices(
            (&mut memory, &mut epoch),
            (&mut other_memory, &mut other_epoch),
        );
        let block = seal_block(
            &mut from,
            set,
            b"chat 7",
            &mut Fixed(&NONCE),
            &pattern_of(5),
        )
        .unwrap();
        let carried = export_block(
            &mut from,
            (set, b"chat 7"),
            &block,
            (out, b"move"),
            &mut Fixed(&NONCE),
        )
        .unwrap();
        let entropy = &mut Fixed(&pattern::<16>(3, 7));
        let length = u64::try_from(carried.len()).unwrap();
        let mut target = None;
        for at in 0..carried.len() * 8 {
            let mut changed = carried.clone();
            changed[at / 8] ^= 1 << (at % 8);
            let header: [u8; BLOCK_HEADER_LEN] = changed[..BLOCK_HEADER_LEN].try_into().unwrap();
            match to.begin_receive_block(into, b"move", &header, length) {
                Err(error) => assert_eq!(error, Error::RecordRejected, "bit {at}"),
                Ok(receipt) => {
                    assert!(at >= BLOCK_HEADER_LEN * 8, "bit {at}");
                    let mut local = [0; BLOCK_HEADER_LEN];
                    let (receiving, set) = to
                        .receive_into(receipt, target, b"x", entropy, &mut local)
                        .unwrap();
                    target = Some(set);
                    let mut chunk = changed[BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + 5].to_vec();
                    let tag = changed[BLOCK_HEADER_LEN + 5..].try_into().unwrap();
                    let mut new_tag = [0; CHUNK_TAG_LEN];
                    assert_eq!(
                        to.receive_last(receiving, &mut chunk, &tag, &mut new_tag),
                        Err(Error::RecordRejected),
                        "bit {at}"
                    );
                }
            }
        }
        receive_block(&mut to, (into, b"move"), &carried, (target, b"x"), entropy).unwrap();
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(clippy::arithmetic_side_effects, reason = "a test lays chunks out")]
mod stack {
    extern crate std;

    use core::hint::black_box;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use super::super::stack::keying_secrets;
    use super::{Exporting, Receiving};
    use crate::block::{BLOCK_HEADER_LEN, CHUNK_LEN, CHUNK_TAG_LEN, chunk_nonce};
    use crate::derive::stack::secrets_of;
    use crate::derive::{
        Branch, CIPHER_STACK_WIPE, STACK_WIPE, derive_carry_chunk, derive_data_chunk,
    };
    use crate::key::tests::Counting;
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::slots::tests::{EPOCH, WRAP_NEEDS, flipped_epoch_key, pattern};
    use crate::{Epoch, Handle, KeyLength, Position, Purpose, RECORD_LEN, Slot, Slots, seal};

    /// The stack each beginning needs, in KiB, in an optimised build and in one without
    /// optimisation: a beginning of a receipt reads as a beginning of a block does, one of an
    /// export also hedges, and one of the block received also loads a key.
    const EXPORT_NEEDS: [usize; 2] = [12, 74];
    const RECEIPT_NEEDS: [usize; 2] = [11, 70];
    const INTO_NEEDS: [usize; 2] = [13, 77];

    /// The documentation of the public call `name` in this file, its lines joined.
    fn documentation(name: &str) -> String {
        let source = include_str!("carry.rs");
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

    /// The documentation of each call on a carried block states the stack it needs and the depth
    /// of the wipe after it: a beginning derives, a chunk derives and runs the cipher.
    #[test]
    fn the_documentation_states_the_stack_calls_need() {
        for (call, needs, wipes) in [
            ("begin_export_block", EXPORT_NEEDS, [8, 64]),
            ("begin_receive_block", RECEIPT_NEEDS, [8, 64]),
            ("receive_into", INTO_NEEDS, [8, 64]),
            ("export_chunk", WRAP_NEEDS, [24, 64]),
            ("export_last", WRAP_NEEDS, [24, 64]),
            ("receive_chunk", WRAP_NEEDS, [24, 64]),
            ("receive_last", WRAP_NEEDS, [24, 64]),
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

    /// The data of the first chunk, which `flip` changes, varied in every piece.
    fn first_data(flip: u8) -> std::boxed::Box<[u8; CHUNK_LEN]> {
        let mut data: std::boxed::Box<[u8; CHUNK_LEN]> = std::vec![0; CHUNK_LEN]
            .into_boxed_slice()
            .try_into()
            .unwrap();
        for (at, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from(at % 251).unwrap().wrapping_mul(29) ^ flip;
        }
        data
    }

    /// The data of the last chunk.
    fn last_data(flip: u8) -> [u8; 33] {
        core::array::from_fn(|at| u8::try_from(at).unwrap().wrapping_mul(53).wrapping_add(7) ^ flip)
    }

    /// The key for transfers both devices hold, which `flip` changes.
    fn transfer_key(flip: u8) -> [u8; 32] {
        let mut key = pattern::<32>(41, 3);
        key[0] ^= flip;
        key
    }

    /// The pieces of a block: the header, the first chunk and its tag, the last chunk and its tag.
    type Pieces = (
        [u8; BLOCK_HEADER_LEN],
        std::boxed::Box<[u8; CHUNK_LEN]>,
        [u8; CHUNK_TAG_LEN],
        [u8; 33],
        [u8; CHUNK_TAG_LEN],
    );

    fn pieces_of(block: &[u8]) -> Pieces {
        let at = BLOCK_HEADER_LEN;
        let first = at + CHUNK_LEN;
        (
            block[..at].try_into().unwrap(),
            std::boxed::Box::new(block[at..first].try_into().unwrap()),
            block[first..first + CHUNK_TAG_LEN].try_into().unwrap(),
            block[first + CHUNK_TAG_LEN..block.len() - CHUNK_TAG_LEN]
                .try_into()
                .unwrap(),
            block[block.len() - CHUNK_TAG_LEN..].try_into().unwrap(),
        )
    }

    fn joined(pieces: &Pieces) -> Vec<u8> {
        let mut block = pieces.0.to_vec();
        block.extend_from_slice(&pieces.1[..]);
        block.extend_from_slice(&pieces.2);
        block.extend_from_slice(&pieces.3);
        block.extend_from_slice(&pieces.4);
        block
    }

    /// Slots of a device whose epoch key `flip` changes, with a key for data that a record of this
    /// epoch holds and a key for transfers, and a block of two chunks sealed under the key for data.
    fn device<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
        flip: u8,
    ) -> (Slots<'a>, Handle<'a>, Handle<'a>, Vec<u8>) {
        let mut slots = Slots::new(memory, epoch, EPOCH, &mut flipped_epoch_key(flip));
        let set = slots
            .generate(Purpose::Data, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let parent = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, parent, b"note", &mut Counting, &mut record)
            .unwrap();
        let transfer = slots
            .import32(Purpose::Transfer, &mut transfer_key(flip))
            .unwrap();
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut sealing = slots
            .begin_seal(set, b"note", &mut Counting, &mut header)
            .unwrap();
        let (mut first, mut last) = (first_data(flip), last_data(flip));
        let (mut first_tag, mut last_tag) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        slots
            .seal_chunk(&mut sealing, &mut first, &mut first_tag)
            .unwrap();
        slots.seal_last(sealing, &mut last, &mut last_tag).unwrap();
        let block = joined(&(header, first, first_tag, last, last_tag));
        (slots, set, transfer, block)
    }

    /// The beginning of the carriage of `block` out of `slots`.
    fn begin_export_block<'a>(
        slots: &mut Slots<'a>,
        (set, transfer): (Handle<'a>, Handle<'a>),
        block: &[u8],
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Exporting<'a> {
        let source: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = slots.begin_open(set, b"note", &source, length).unwrap();
        slots
            .begin_export_block(opening, transfer, b"move", &mut Counting, header)
            .unwrap()
    }

    /// The beginning of the receipt of `carried` into a new set of `slots`.
    fn begin_receipt<'a>(
        slots: &mut Slots<'a>,
        transfer: Handle<'a>,
        carried: &[u8],
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> (Receiving<'a>, Handle<'a>) {
        let source: [u8; BLOCK_HEADER_LEN] = carried[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(carried.len()).unwrap();
        let receipt = slots
            .begin_receive_block(transfer, b"move", &source, length)
            .unwrap();
        slots
            .receive_into(receipt, None, b"kept", &mut Counting, header)
            .unwrap()
    }

    /// A block of `memory` whose epoch key `flip` changes, carried out of it and received into a
    /// new set of the slots over `other`, and the secrets the calls handle on both: the keys for
    /// data and for transfers, the keys of the chunks of the three blocks, the cipher's keys and
    /// keystream for each pass, the derivations of those keys and the checks, the hedges of the
    /// salts and the new key, and the data; and the three headers, which are public: a call copies
    /// the salt of each.
    #[expect(clippy::too_many_lines, reason = "both devices are gathered at once")]
    fn carried(
        memory: &mut [Slot],
        epoch: &mut Epoch,
        other: (&mut [Slot], &mut Epoch),
        flip: u8,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let (mut slots, set, transfer, block) = device(memory, epoch, flip);
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut exporting = begin_export_block(&mut slots, (set, transfer), &block, &mut header);
        let (_, mut first, first_tag, mut last, last_tag) = pieces_of(&block);
        let (mut carried_first, mut carried_last) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        slots
            .export_chunk(&mut exporting, &mut first, &first_tag, &mut carried_first)
            .unwrap();
        slots
            .export_last(exporting, &mut last, &last_tag, &mut carried_last)
            .unwrap();
        let carried = joined(&(header, first, carried_first, last, carried_last));
        let (mut to, into) = receiver(other, flip);
        let mut local = [0; BLOCK_HEADER_LEN];
        let (mut receiving, new) = begin_receipt(&mut to, into, &carried, &mut local);
        let (_, mut first, _, mut last, _) = pieces_of(&carried);
        let (mut kept_first, mut kept_last) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        to.receive_chunk(&mut receiving, &mut first, &carried_first, &mut kept_first)
            .unwrap();
        to.receive_last(receiving, &mut last, &carried_last, &mut kept_last)
            .unwrap();

        let data_key = slots.memory[set.index].key(Position::First);
        let carry_key = slots.memory[transfer.index].key(Position::First);
        let new_key = to.memory[new.index].key(Position::First);
        let (epoch_key, other_epoch_key) =
            (flipped_epoch_key(flip), flipped_epoch_key(flip ^ 0x33));
        let mut secrets = std::vec![
            data_key.bytes()[..32].to_vec(),
            carry_key.bytes()[..32].to_vec(),
            new_key.bytes()[..32].to_vec(),
            epoch_key.to_vec(),
            other_epoch_key.to_vec(),
            first_data(flip).to_vec(),
            last_data(flip).to_vec(),
        ];
        // The hedges of the carried salt, the fifth draw of its device, and of the salt and the key
        // of the new set, the first two of the other.
        for (key, drawn, count, branch) in [
            (&epoch_key, 16, 4_u64, Branch::HedgeSalt),
            (&other_epoch_key, 16, 0, Branch::HedgeSalt),
            (&other_epoch_key, 32, 1, Branch::HedgeKey),
        ] {
            let mut material: Vec<u8> = (1..=drawn).collect();
            material.extend_from_slice(&count.to_le_bytes());
            secrets.extend(secrets_of(&material, key, branch));
        }
        let carried_salt: [u8; 16] = header[..16].try_into().unwrap();
        let local_salt: [u8; 16] = local[..16].try_into().unwrap();
        secrets.extend(secrets_of(
            carry_key.material().unwrap(),
            &carried_salt,
            Branch::CarryCheck,
        ));
        secrets.extend(secrets_of(
            new_key.material().unwrap(),
            &local_salt,
            Branch::DataCheck,
        ));
        for (key, header, branch, tags) in [
            (
                data_key,
                &block[..BLOCK_HEADER_LEN],
                Branch::DataChunk,
                (first_tag, last_tag),
            ),
            (
                carry_key,
                &header[..],
                Branch::CarryChunk,
                (carried_first, carried_last),
            ),
            (
                new_key,
                &local[..],
                Branch::DataChunk,
                (kept_first, kept_last),
            ),
        ] {
            let salt: [u8; 16] = header[..16].try_into().unwrap();
            let mut chunk_key = [0; 32];
            if branch == Branch::DataChunk {
                derive_data_chunk(key, &salt, &mut chunk_key).unwrap();
            } else {
                derive_carry_chunk(key, &salt, &mut chunk_key).unwrap();
            }
            secrets.extend(keying_secrets(
                &chunk_key,
                &chunk_nonce(0, false),
                &tags.0,
                CHUNK_LEN,
            ));
            secrets.extend(keying_secrets(
                &chunk_key,
                &chunk_nonce(1, true),
                &tags.1,
                33,
            ));
            secrets.extend(secrets_of(key.material().unwrap(), &salt, branch));
        }
        (
            secrets,
            std::vec![
                block[..BLOCK_HEADER_LEN].to_vec(),
                header.to_vec(),
                local.to_vec()
            ],
        )
    }

    /// The slots over `other` with the key for transfers `flip` gives.
    fn receiver<'a>(
        (memory, epoch): (&'a mut [Slot], &'a mut Epoch),
        flip: u8,
    ) -> (Slots<'a>, Handle<'a>) {
        let mut slots = Slots::new(memory, epoch, 4, &mut flipped_epoch_key(flip ^ 0x33));
        let transfer = slots
            .import32(Purpose::Transfer, &mut transfer_key(flip))
            .unwrap();
        (slots, transfer)
    }

    /// Carrying a chunk out and receiving it without the wipe after them leave on the stack some
    /// of what they handle, so that the test below can tell the wipe from its absence: each seals
    /// last, and a seal leaves its keystream.
    #[test]
    fn the_calls_on_a_carried_chunk_without_the_wipe_leave_residue() {
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut far, mut far_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut others, _) = carried(
            &mut other_memory,
            &mut other_epoch,
            (&mut far, &mut far_epoch),
            0x5a,
        );
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut to_memory, mut to_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (secrets, public) =
            carried(&mut memory, &mut epoch, (&mut to_memory, &mut to_epoch), 0);
        others.extend(public);
        let pieces = key_dependent(&secrets, &others);
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, set, transfer, block) = device(&mut memory, &mut epoch, 0);
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut exporting = begin_export_block(&mut slots, (set, transfer), &block, &mut header);
        let (_, mut first, first_tag, _, _) = pieces_of(&block);
        let mut out = [0; CHUNK_TAG_LEN];
        let range = below_pad(false, || {
            slots
                .export_chunk_on_stack(
                    &mut exporting,
                    &mut first[..],
                    false,
                    (&first_tag, &mut out),
                    seal::Aes,
                    seal::Aes,
                )
                .unwrap();
            black_box(&first);
        });
        assert!(residue(range, &pieces) > 0, "a chunk carried out");
        let mut carried = header.to_vec();
        carried.extend_from_slice(&first[..]);
        carried.extend_from_slice(&out);
        (to_memory, to_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut to, into) = receiver((&mut to_memory, &mut to_epoch), 0);
        let source: [u8; BLOCK_HEADER_LEN] = header;
        let length = u64::try_from(block.len()).unwrap();
        let receipt = to
            .begin_receive_block(into, b"move", &source, length)
            .unwrap();
        let mut local = [0; BLOCK_HEADER_LEN];
        let (mut receiving, _) = to
            .receive_into(receipt, None, b"kept", &mut Counting, &mut local)
            .unwrap();
        let mut kept = [0; CHUNK_TAG_LEN];
        let range = below_pad(false, || {
            to.receive_chunk_on_stack(
                &mut receiving,
                &mut first[..],
                false,
                (&out, &mut kept),
                seal::Aes,
                seal::Aes,
            )
            .unwrap();
            black_box(&first);
        });
        assert!(residue(range, &pieces) > 0, "a chunk received");
    }

    /// Carrying a block out and receiving it leave on the stack none of the secrets [`carried`]
    /// names, and none of the data.
    #[test]
    fn the_calls_on_a_carried_block_leave_no_key_on_the_stack() {
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut far, mut far_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut others, _) = carried(
            &mut other_memory,
            &mut other_epoch,
            (&mut far, &mut far_epoch),
            0x5a,
        );
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut to_memory, mut to_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (secrets, public) =
            carried(&mut memory, &mut epoch, (&mut to_memory, &mut to_epoch), 0);
        others.extend(public);
        let pieces = key_dependent(&secrets, &others);
        assert_ne!(pieces.len(), 0);
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, set, transfer, block) = device(&mut memory, &mut epoch, 0);
        let source: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = slots.begin_open(set, b"note", &source, length).unwrap();
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut exporting = None;
        assert_clean(&pieces, || {
            exporting = Some(
                slots
                    .begin_export_block(opening, transfer, b"move", &mut Counting, &mut header)
                    .unwrap(),
            );
        });
        let mut exporting = exporting.unwrap();
        let (_, mut first, first_tag, mut last, last_tag) = pieces_of(&block);
        let (mut carried_first, mut carried_last) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        assert_clean(&pieces, || {
            slots
                .export_chunk(&mut exporting, &mut first, &first_tag, &mut carried_first)
                .unwrap();
            black_box(&first);
        });
        assert_clean(&pieces, || {
            slots
                .export_last(exporting, &mut last, &last_tag, &mut carried_last)
                .unwrap();
            black_box(&last);
        });
        let carried = joined(&(header, first, carried_first, last, carried_last));
        (to_memory, to_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut to, into) = receiver((&mut to_memory, &mut to_epoch), 0);
        let mut receipt = None;
        assert_clean(&pieces, || {
            receipt = Some(
                to.begin_receive_block(into, b"move", &header, length)
                    .unwrap(),
            );
        });
        let mut local = [0; BLOCK_HEADER_LEN];
        let mut receiving = None;
        let receipt = receipt.unwrap();
        assert_clean(&pieces, || {
            receiving = Some(
                to.receive_into(receipt, None, b"kept", &mut Counting, &mut local)
                    .unwrap()
                    .0,
            );
        });
        let mut receiving = receiving.unwrap();
        let (_, mut first, _, mut last, _) = pieces_of(&carried);
        let (mut kept_first, mut kept_last) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        assert_clean(&pieces, || {
            to.receive_chunk(&mut receiving, &mut first, &carried_first, &mut kept_first)
                .unwrap();
            black_box(&first);
        });
        assert_clean(&pieces, || {
            to.receive_last(receiving, &mut last, &carried_last, &mut kept_last)
                .unwrap();
            black_box(&last);
        });
    }

    /// The wipes that follow each call reach as deep as they are meant to, and no call reaches
    /// deeper than its documentation says it needs.
    #[test]
    #[expect(clippy::too_many_lines, reason = "each call is measured in turn")]
    fn the_calls_on_a_carried_block_wipe_and_need_the_stack_documented() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, set, transfer, block) = device(&mut memory, &mut epoch, 0);
        let source: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = slots.begin_open(set, b"note", &source, length).unwrap();
        let mut deep = Vec::new();
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut exporting = None;
        deep.push((
            depth_changed(|| {
                exporting = Some(
                    slots
                        .begin_export_block(opening, transfer, b"move", &mut Counting, &mut header)
                        .unwrap(),
                );
            }),
            STACK_WIPE,
            EXPORT_NEEDS,
        ));
        let mut exporting = exporting.unwrap();
        let (_, mut first, first_tag, mut last, last_tag) = pieces_of(&block);
        let (mut carried_first, mut carried_last) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        deep.push((
            depth_changed(|| {
                let mut copy = first.clone();
                let refused = slots.export_chunk(
                    &mut exporting,
                    &mut copy,
                    &[0; CHUNK_TAG_LEN],
                    &mut carried_first,
                );
                assert_eq!(black_box(refused), Err(crate::Error::RecordRejected));
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                slots
                    .export_chunk(&mut exporting, &mut first, &first_tag, &mut carried_first)
                    .unwrap();
                black_box(&first);
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                slots
                    .export_last(exporting, &mut last, &last_tag, &mut carried_last)
                    .unwrap();
                black_box(&last);
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        let carried = joined(&(header, first, carried_first, last, carried_last));
        let (mut to_memory, mut to_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut to, into) = receiver((&mut to_memory, &mut to_epoch), 0);
        let mut receipt = None;
        deep.push((
            depth_changed(|| {
                let refused = to.begin_receive_block(into, b"move", &[0; BLOCK_HEADER_LEN], length);
                assert_eq!(black_box(refused.err()), Some(crate::Error::RecordRejected));
            }),
            STACK_WIPE,
            RECEIPT_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                receipt = Some(
                    to.begin_receive_block(into, b"move", &header, length)
                        .unwrap(),
                );
            }),
            STACK_WIPE,
            RECEIPT_NEEDS,
        ));
        let mut local = [0; BLOCK_HEADER_LEN];
        let mut receiving = None;
        let receipt = receipt.unwrap();
        deep.push((
            depth_changed(|| {
                receiving = Some(
                    to.receive_into(receipt, None, b"kept", &mut Counting, &mut local)
                        .unwrap()
                        .0,
                );
            }),
            STACK_WIPE,
            INTO_NEEDS,
        ));
        let mut receiving = receiving.unwrap();
        let (_, mut first, _, mut last, _) = pieces_of(&carried);
        let (mut kept_first, mut kept_last) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        deep.push((
            depth_changed(|| {
                to.receive_chunk(&mut receiving, &mut first, &carried_first, &mut kept_first)
                    .unwrap();
                black_box(&first);
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                to.receive_last(receiving, &mut last, &carried_last, &mut kept_last)
                    .unwrap();
                black_box(&last);
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        std::println!(
            "calls on a carried block reach {:?} bytes",
            deep.iter().map(|(depth, ..)| *depth).collect::<Vec<_>>()
        );
        for (depth, wipe, needs) in deep {
            assert!(depth >= wipe, "{depth} bytes wiped");
            assert!(depth <= needs[build] * 1024, "{depth} bytes reached");
        }
    }
}
