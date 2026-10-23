// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Blocks of the caller's data, encrypted in the library under a set for data: a header of a salt
//! and a check that names the key, then chunks, each sealed with AES-256-GCM-SIV under a key
//! derived from that key and the salt.

use super::{Handle, Slots, hedged_draw};
use crate::{
    block::{
        BLOCK_HEADER_LEN, CHECK_LEN, CHUNK_LEN, CHUNK_TAG_LEN, SALT_LEN, chunk_nonce, chunks_in,
        data_len_in, first_match, same_check,
    },
    derive::{Branch, derive_data_check, derive_data_chunk, wipe_cipher_stack, wipe_stack},
    entropy::Entropy,
    epoch::Epoch,
    error::Error,
    key::wipe,
    keyset::Position,
    record::{AssociatedData, Purpose, Status},
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, NONCE_LEN, Rejected, SealFailed, TAG_LEN},
};

/// A block being written under the primary key of a set for data, from [`Slots::begin_seal`]: it
/// names the set, the key and the salt, and holds no key. It cannot be copied or cloned, and it
/// stops working once the set changes.
pub struct Sealing<'a> {
    pub(super) set: Handle<'a>,
    pub(super) at: Position,
    pub(super) revision: u64,
    pub(super) salt: [u8; SALT_LEN],
    pub(super) associated: AssociatedData,
    pub(super) next: u64,
}

/// A block being read under the key of a set for data its header names, from
/// [`Slots::begin_open`]: it names the set, the key and the salt, knows how many chunks the block
/// holds, and holds no key. It cannot be copied or cloned, and it stops working once the set
/// changes.
pub struct Opening<'a> {
    pub(super) set: Handle<'a>,
    pub(super) at: Position,
    pub(super) revision: u64,
    pub(super) salt: [u8; SALT_LEN],
    pub(super) associated: AssociatedData,
    pub(super) next: u64,
    pub(super) chunks: u64,
    pub(super) last: u64,
}

impl Opening<'_> {
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

impl core::fmt::Debug for Sealing<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealing").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Opening<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opening").finish_non_exhaustive()
    }
}

/// What seals a chunk of any length: AES-256-GCM-SIV, which is all a build outside the proofs and
/// the tests has, or a model of it in them.
pub(super) trait SealChunk {
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed>;
}

impl SealChunk for seal::Aes {
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        seal::seal_data(key, nonce, aad, buffer)
    }
}

#[cfg(any(test, kani))]
impl<F> SealChunk for F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed>,
{
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        self(key, nonce, aad, buffer)
    }
}

/// What opens a chunk of any length.
pub(super) trait OpenChunk {
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected>;
}

impl OpenChunk for seal::Aes {
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        seal::open_data(key, nonce, aad, buffer, tag)
    }
}

#[cfg(any(test, kani))]
impl<F> OpenChunk for F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8],
        &[u8; TAG_LEN],
    ) -> Result<(), Rejected>,
{
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        self(key, nonce, aad, buffer, tag)
    }
}

impl<'a> Slots<'a> {
    /// Begins a block of data under the primary key of the set for data that `set` refers to, bound
    /// to `context`, from 1 to 255 bytes, which names the place the block is kept, and writes its
    /// header into `header`: a salt from `entropy`, hedged with the key of this epoch, and a check
    /// derived from the key and the salt, which tells that key from any other and is random to
    /// whoever lacks it. The chunks follow with [`Slots::seal_chunk`] and [`Slots::seal_last`].
    /// A block is written once: a change to its data is a new block.
    ///
    /// The set is to be held by a record of this epoch as it is now, so that the key outlives the
    /// slots. Whether that record is kept, and the records of the keys above it, the library
    /// cannot see.
    ///
    /// Needs 11 KiB of stack, or 69 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the hedge, the derivation and the whole call are each followed
    /// by a wipe of 8 KiB, or 64 KiB, below them, whether it succeeded or not. A build that
    /// optimises this crate but not the hash code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::Data`], [`Error::Unsaved`] if
    /// no record of this epoch holds it as it is now, [`Error::EntropyFailed`] if `entropy` fails,
    /// and [`Error::DerivationFailed`] if the salt cannot be hedged or the check cannot be derived.
    /// `header` is then left as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and `header` is left as it was.
    pub fn begin_seal(
        &mut self,
        set: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Result<Sealing<'a>, Error> {
        let begun = crate::timing::with(|| self.begin_seal_in(set, context, entropy, header));
        wipe_stack();
        begun
    }

    /// The beginning itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    pub(super) fn begin_seal_in(
        &mut self,
        set: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        header: &mut [u8; BLOCK_HEADER_LEN],
    ) -> Result<Sealing<'a>, Error> {
        let associated = AssociatedData::of_data(context).map_err(|_| Error::InvalidContext)?;
        let index = self.serving(set, Purpose::Data)?;
        let Self { memory, epoch } = self;
        let slot = memory.get(index).ok_or(Error::StaleHandle)?;
        if !slot.recorded {
            return Err(Error::Unsaved);
        }
        let at = slot.stages.primary_position().ok_or(Error::StaleHandle)?;
        let Epoch { key, drawn, .. } = &mut **epoch;
        let mut salt = [0; SALT_LEN];
        hedged_draw(entropy, key, drawn, Branch::HedgeSalt, &mut salt)?;
        let mut check = [0; CHECK_LEN];
        let derived = derive_data_check(slot.key(at), &salt, &mut check);
        if derived.is_ok()
            && let Some((salt_out, check_out)) = header.split_first_chunk_mut::<SALT_LEN>()
        {
            *salt_out = salt;
            check_out.copy_from_slice(&check);
        }
        wipe(&mut check);
        derived.map_err(|_| Error::DerivationFailed)?;
        Ok(Sealing {
            set,
            at,
            revision: slot.stages.revision(),
            salt,
            associated,
            next: 0,
        })
    }

    /// Seals `chunk`, the next chunk of the block `sealing` writes and not its last, in place, and
    /// writes its tag into `tag`. The chunk is then opened and sealed again to the same tag and
    /// ciphertext, so that a fault of the cipher in one of these passes fails the seal while the
    /// caller still holds its own copy of the data.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::StaleHandle`] if the set is not held here now or has changed since the block began,
    /// [`Error::Unsaved`] if no record of this epoch holds it as it is now, [`Error::WrongChunk`]
    /// if the block holds as many chunks as a number of 64 bits counts, [`Error::DerivationFailed`]
    /// if the key that encrypts the chunks cannot be derived, and [`Error::CipherFailed`] if the
    /// cipher gives a known input a wrong answer or fails, or the chunk does not open and seal
    /// again to the same tag and ciphertext. `chunk` is then wiped if the cipher ran,
    /// and left as it was if not; `tag` is left as it was, and the block goes on as before the
    /// call.
    pub fn seal_chunk(
        &self,
        sealing: &mut Sealing<'a>,
        chunk: &mut [u8; CHUNK_LEN],
        tag: &mut [u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let sealed =
            crate::timing::with(|| self.seal_chunk_on_stack(sealing, chunk, false, tag, seal::Aes));
        wipe_cipher_stack();
        sealed
    }

    /// Seals `chunk`, the last chunk of the block `sealing` writes, in place, writes its tag into
    /// `tag`, and ends the block. The last chunk holds from 1 to [`CHUNK_LEN`] bytes, or none if it
    /// is the only one and the data are empty.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongChunk`] if `chunk` is longer than [`CHUNK_LEN`], or empty after other chunks,
    /// and the errors of [`Slots::seal_chunk`]. `tag` is then left as it was, and the block is not
    /// written.
    pub fn seal_last(
        &self,
        mut sealing: Sealing<'a>,
        chunk: &mut [u8],
        tag: &mut [u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let sealed = crate::timing::with(|| {
            self.seal_last_in::<CHUNK_LEN>(&mut sealing, chunk, tag, seal::Aes)
        });
        wipe_cipher_stack();
        sealed
    }

    /// The last chunk, of up to `C` bytes.
    pub(super) fn seal_last_in<const C: usize>(
        &self,
        sealing: &mut Sealing<'a>,
        chunk: &mut [u8],
        tag: &mut [u8; CHUNK_TAG_LEN],
        seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        if chunk.len() > C || (chunk.is_empty() && sealing.next != 0) {
            return Err(Error::WrongChunk);
        }
        self.seal_chunk_on_stack(sealing, chunk, true, tag, seal_with)
    }

    /// The seal of a chunk itself, in a frame of its own: the wipe that follows starts where this
    /// frame starts.
    #[inline(never)]
    pub(super) fn seal_chunk_on_stack(
        &self,
        sealing: &mut Sealing<'a>,
        chunk: &mut [u8],
        last: bool,
        tag: &mut [u8; CHUNK_TAG_LEN],
        mut seal_with: impl SealChunk,
    ) -> Result<(), Error> {
        let index = self.loaded(sealing.set)?;
        let slot = self.memory.get(index).ok_or(Error::StaleHandle)?;
        if slot.stages.revision() != sealing.revision {
            return Err(Error::StaleHandle);
        }
        if !slot.recorded {
            return Err(Error::Unsaved);
        }
        let next = sealing.next.checked_add(1).ok_or(Error::WrongChunk)?;
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        if derive_data_chunk(slot.key(sealing.at), &sealing.salt, &mut cipher_key).is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let nonce = chunk_nonce(sealing.next, last);
        let sealed = seal_with.seal(&cipher_key, &nonce, sealing.associated.bytes(), chunk);
        wipe(&mut cipher_key);
        *tag = sealed.map_err(|_| Error::CipherFailed)?;
        sealing.next = next;
        Ok(())
    }

    /// Begins to read the block of `block` bytes whose header is `header`, under the set for data
    /// that `set` refers to and the `context` it was written for: the check of each key of the set
    /// is derived from the salt and compared with the header's, all of them, with no early exit,
    /// and the block is read under the key whose check it holds. The chunks follow with
    /// [`Slots::open_chunk`] and [`Slots::open_last`]; only the last tells that the block is whole.
    ///
    /// Needs 11 KiB of stack, or 69 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: each derivation, and the whole call, are each followed by a
    /// wipe of 8 KiB, or 64 KiB, below them. A build that optimises this crate but not the hash
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `set` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::Data`],
    /// [`Error::RecordRejected`] if no block is `block` bytes long, [`Error::DerivationFailed`] if a
    /// check cannot be derived, [`Error::RecordRejected`] if the header names no key of the set,
    /// and [`Error::KeyDisabled`] if it names a disabled one.
    pub fn begin_open(
        &self,
        set: Handle<'a>,
        context: &[u8],
        header: &[u8; BLOCK_HEADER_LEN],
        block: u64,
    ) -> Result<Opening<'a>, Error> {
        let begun =
            crate::timing::with(|| self.begin_open_in::<CHUNK_LEN>(set, context, header, block));
        wipe_stack();
        begun
    }

    /// The beginning itself, for chunks of `C` bytes, in a frame of its own: the wipe that follows
    /// starts where this frame starts.
    #[inline(never)]
    pub(super) fn begin_open_in<const C: usize>(
        &self,
        set: Handle<'a>,
        context: &[u8],
        header: &[u8; BLOCK_HEADER_LEN],
        block: u64,
    ) -> Result<Opening<'a>, Error> {
        let associated = AssociatedData::of_data(context).map_err(|_| Error::InvalidContext)?;
        let index = self.serving(set, Purpose::Data)?;
        let slot = self.memory.get(index).ok_or(Error::StaleHandle)?;
        let len = data_len_in::<C>(block).ok_or(Error::RecordRejected)?;
        let (chunks, last) = chunks_in::<C>(len);
        let (salt, kept) = split_header(header);
        // Read from a copy: Kani 0.68.0 misreads the stages of a slot chosen at run time in the
        // closure.
        let stages = slot.stages;
        let mut check = [0; CHECK_LEN];
        let mut matches = |position: Position| -> Result<bool, Error> {
            if stages.stage(position.index()).is_none() {
                return Ok(false);
            }
            let derived = derive_data_check(slot.key(position), &salt, &mut check);
            let found = derived.is_ok() && same_check(&check, &kept);
            wipe(&mut check);
            derived.map(|()| found).map_err(|_| Error::DerivationFailed)
        };
        let found = [
            matches(Position::First)?,
            matches(Position::Second)?,
            matches(Position::Third)?,
        ];
        let (at, any) = first_match(found);
        let at = Position::at(at)
            .filter(|_| any)
            .ok_or(Error::RecordRejected)?;
        if stages.stage(at.index()) == Some(Status::Disabled) {
            return Err(Error::KeyDisabled);
        }
        Ok(Opening {
            set,
            at,
            revision: stages.revision(),
            salt,
            associated,
            next: 0,
            chunks,
            last,
        })
    }

    /// Opens `chunk`, the next chunk of the block `opening` reads and not its last, in place, if
    /// `tag` is its tag.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongChunk`] if the last chunk is due, [`Error::StaleHandle`] if the set is not held
    /// here now or has changed since the block began to be read, [`Error::DerivationFailed`] if
    /// the key that encrypts the chunks cannot be derived, and [`Error::RecordRejected`] if the
    /// chunk does not open as the next of this block, for its context. `chunk` is then wiped if
    /// the cipher ran, and left as it was if not, and the block goes on as before the call.
    pub fn open_chunk(
        &self,
        opening: &mut Opening<'a>,
        chunk: &mut [u8; CHUNK_LEN],
        tag: &[u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let opened = crate::timing::with(|| self.open_next_in(opening, chunk, tag, seal::Aes));
        wipe_cipher_stack();
        opened
    }

    /// A chunk that is not the last.
    pub(super) fn open_next_in(
        &self,
        opening: &mut Opening<'a>,
        chunk: &mut [u8],
        tag: &[u8; CHUNK_TAG_LEN],
        open_with: impl OpenChunk,
    ) -> Result<(), Error> {
        if opening
            .next
            .checked_add(1)
            .is_none_or(|after| after >= opening.chunks)
        {
            return Err(Error::WrongChunk);
        }
        self.open_chunk_on_stack(opening, chunk, false, tag, open_with)
    }

    /// Opens `chunk`, the last chunk of the block `opening` reads, in place, if `tag` is its tag,
    /// and ends the block: the whole block has then opened, in order.
    ///
    /// Needs 25 KiB of stack, or 72 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 24 KiB, or 64 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the hash and cipher
    /// code it calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::WrongChunk`] if more chunks are due before the last, or `chunk` is not as long as
    /// [`Opening::last_len`] says, and the errors of [`Slots::open_chunk`].
    pub fn open_last(
        &self,
        mut opening: Opening<'a>,
        chunk: &mut [u8],
        tag: &[u8; CHUNK_TAG_LEN],
    ) -> Result<(), Error> {
        let opened = crate::timing::with(|| self.open_last_in(&mut opening, chunk, tag, seal::Aes));
        wipe_cipher_stack();
        opened
    }

    /// The last chunk.
    pub(super) fn open_last_in(
        &self,
        opening: &mut Opening<'a>,
        chunk: &mut [u8],
        tag: &[u8; CHUNK_TAG_LEN],
        open_with: impl OpenChunk,
    ) -> Result<(), Error> {
        let length = u64::try_from(chunk.len()).map_err(|_| Error::WrongChunk)?;
        if opening.next.checked_add(1) != Some(opening.chunks) || length != opening.last {
            return Err(Error::WrongChunk);
        }
        self.open_chunk_on_stack(opening, chunk, true, tag, open_with)
    }

    /// The opening of a chunk itself, in a frame of its own: the wipe that follows starts where
    /// this frame starts.
    #[inline(never)]
    pub(super) fn open_chunk_on_stack(
        &self,
        opening: &mut Opening<'a>,
        chunk: &mut [u8],
        last: bool,
        tag: &[u8; CHUNK_TAG_LEN],
        mut open_with: impl OpenChunk,
    ) -> Result<(), Error> {
        let index = self.loaded(opening.set)?;
        let slot = self.memory.get(index).ok_or(Error::StaleHandle)?;
        if slot.stages.revision() != opening.revision {
            return Err(Error::StaleHandle);
        }
        let mut cipher_key = [0; CIPHER_KEY_LEN];
        if derive_data_chunk(slot.key(opening.at), &opening.salt, &mut cipher_key).is_err() {
            wipe(&mut cipher_key);
            return Err(Error::DerivationFailed);
        }
        let nonce = chunk_nonce(opening.next, last);
        let opened = open_with.open(&cipher_key, &nonce, opening.associated.bytes(), chunk, tag);
        wipe(&mut cipher_key);
        opened.map_err(|Rejected| Error::RecordRejected)?;
        opening.next = opening.next.saturating_add(1);
        Ok(())
    }
}

/// The salt and the check of a block's header.
fn split_header(header: &[u8; BLOCK_HEADER_LEN]) -> ([u8; SALT_LEN], [u8; CHECK_LEN]) {
    let mut salt = [0; SALT_LEN];
    let mut check = [0; CHECK_LEN];
    if let Some((first, rest)) = header.split_first_chunk::<SALT_LEN>()
        && let Some((second, _)) = rest.split_first_chunk::<CHECK_LEN>()
    {
        salt = *first;
        check = *second;
    }
    (salt, check)
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::large_stack_arrays,
    reason = "a test lays chunks out, picks bits and holds a full chunk"
)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use sha2::{Digest, Sha256};

    use crate::block::{BLOCK_HEADER_LEN, CHUNK_LEN, CHUNK_TAG_LEN, block_len};
    use crate::entropy::{Entropy, EntropyError};
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::KeyLength;
    use crate::key::tests::{Random, from_environment};
    use crate::keyset::Position;
    use crate::record::{Purpose, RECORD_LEN};
    use crate::slots::tests::{EPOCH, epoch_key, pattern};
    use crate::slots::{Erasure, Handle, Slot, Slots};
    use crate::timing::timed;

    /// Writes the bytes it was made with, over and over.
    struct Fixed<'b>(&'b [u8]);

    impl Entropy for Fixed<'_> {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            for (to, from) in dest.iter_mut().zip(self.0.iter().cycle()) {
                *to = *from;
            }
            Ok(())
        }
    }

    const NONCE: [u8; 12] = [
        0x05, 0x16, 0x27, 0x38, 0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xc0,
    ];

    /// Writes `data` as one block under the set `set` refers to, for `context`: the header, then
    /// each chunk followed by its tag.
    fn seal_block<'a>(
        slots: &mut Slots<'a>,
        set: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut sealing = slots.begin_seal(set, context, entropy, &mut header)?;
        let mut block = header.to_vec();
        let mut pieces = data.chunks(CHUNK_LEN).peekable();
        if pieces.peek().is_none() {
            let mut tag = [0; CHUNK_TAG_LEN];
            slots.seal_last(sealing, &mut [], &mut tag)?;
            block.extend_from_slice(&tag);
            return Ok(block);
        }
        while let Some(piece) = pieces.next() {
            let mut tag = [0; CHUNK_TAG_LEN];
            let mut chunk = piece.to_vec();
            if pieces.peek().is_some() {
                let full: &mut [u8; CHUNK_LEN] = (&mut chunk[..]).try_into().unwrap();
                slots.seal_chunk(&mut sealing, full, &mut tag)?;
            } else {
                slots.seal_last(sealing, &mut chunk, &mut tag)?;
                block.extend_from_slice(&chunk);
                block.extend_from_slice(&tag);
                return Ok(block);
            }
            block.extend_from_slice(&chunk);
            block.extend_from_slice(&tag);
        }
        unreachable!("the last chunk returns")
    }

    /// Reads `block` under the set `set` refers to, for `context`.
    fn open_block<'a>(
        slots: &Slots<'a>,
        set: Handle<'a>,
        context: &[u8],
        block: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let header: &[u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let mut opening = slots.begin_open(set, context, header, length)?;
        let mut data = Vec::new();
        let mut at = BLOCK_HEADER_LEN;
        for _ in 1..opening.chunks() {
            let mut chunk: [u8; CHUNK_LEN] = block[at..at + CHUNK_LEN].try_into().unwrap();
            let tag: [u8; CHUNK_TAG_LEN] = block[at + CHUNK_LEN..at + CHUNK_LEN + CHUNK_TAG_LEN]
                .try_into()
                .unwrap();
            slots.open_chunk(&mut opening, &mut chunk, &tag)?;
            data.extend_from_slice(&chunk);
            at += CHUNK_LEN + CHUNK_TAG_LEN;
        }
        let last = usize::try_from(opening.last_len()).unwrap();
        let mut chunk = block[at..at + last].to_vec();
        let tag: [u8; CHUNK_TAG_LEN] = block[at + last..].try_into().unwrap();
        slots.open_last(opening, &mut chunk, &tag)?;
        data.extend_from_slice(&chunk);
        Ok(data)
    }

    /// A key for data from `pattern(59, 201)` as the first draw of `slots`, wrapped under a stored
    /// key as the second, so that a record of this epoch holds it.
    fn recorded_set<'a>(slots: &mut Slots<'a>) -> (Handle<'a>, Handle<'a>) {
        let data = slots
            .generate(
                Purpose::Data,
                KeyLength::Bytes32,
                &mut Fixed(&pattern::<32>(59, 201)),
            )
            .unwrap();
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let parent = slots.store(parent);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(data, parent, b"chat 7", &mut Fixed(&NONCE), &mut record)
            .unwrap();
        (data, parent)
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn pattern_of(length: usize) -> Vec<u8> {
        (0..length)
            .map(|at| {
                u8::try_from(at % 256)
                    .unwrap()
                    .wrapping_mul(97)
                    .wrapping_add(13)
            })
            .collect()
    }

    /// Blocks computed by an implementation independent of this library: the length of the
    /// context, of the data and of the block, and the block, or its SHA-256 when long.
    const KNOWN_BLOCKS: [(usize, usize, usize, &str); 5] = [
        (
            6,
            0,
            64,
            concat!(
                "8fb066c36f73dcb034bb7c13b665e9a73ab77de3963fd03926d94e210652eef4",
                "1a44362663593400baa7c598d70f718434cf98639fef71810870bb445977a4e0",
            ),
        ),
        (
            6,
            1,
            65,
            concat!(
                "5ec0693f3cab9fae3896278c3c5cae9702ab21e5d5d30b2d4bf271798b1ba89c",
                "44d07e876a1cb6f0533708d3c1f615cc61bfc2f12d7719f362eced2173e794d3",
                "30",
            ),
        ),
        (
            255,
            33,
            97,
            concat!(
                "4d12d777e70957ccb2f20ee9e5645b145d288be0a3eaceb0c18fddb378a3ce54",
                "3efeaf96202ef316d044676ae218218ca493e64d3c9c0ccaed5166036292ff5c",
                "d8ac749f84d77434c1f468ee991301ad5f4a265d4c819a06dbce4c0373224b4f",
                "a2",
            ),
        ),
        (
            6,
            65_536,
            65_600,
            "471576eeba284b3f779fc5302c44c0d035c9082f125dbd3153204db1042b0eaa",
        ),
        (
            6,
            65_537,
            65_617,
            "fe12a53c550b675e70a1f6cac9d9f5e05489def6dd303bc79c251429960201a3",
        ),
    ];

    #[test]
    fn blocks_match_ones_computed_independently() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        for (context_len, data_len, block_len_of, known) in KNOWN_BLOCKS {
            let context = if context_len == 255 {
                [b'x'; 255].to_vec()
            } else {
                b"chat 7".to_vec()
            };
            let data = pattern_of(data_len);
            let block = seal_block(
                &mut slots,
                set,
                &context,
                &mut Fixed(&pattern::<16>(17, 5)),
                &data,
            )
            .unwrap();
            assert_eq!(block.len(), block_len_of);
            assert_eq!(
                block_len(u64::try_from(data_len).unwrap()),
                Some(u64::try_from(block_len_of).unwrap())
            );
            if block.len() <= 128 {
                assert_eq!(block, unhex(known), "{data_len}");
            } else {
                assert_eq!(Sha256::digest(&block).to_vec(), unhex(known), "{data_len}");
            }
            assert_eq!(open_block(&slots, set, &context, &block).unwrap(), data);
        }
    }

    #[test]
    fn debug_shows_no_state_of_a_block() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let block = seal_block(&mut slots, set, b"chat 7", &mut Fixed(&NONCE), &[7]).unwrap();
        let mut header = [0; BLOCK_HEADER_LEN];
        let sealing = slots
            .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
            .unwrap();
        let header: [u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = slots.begin_open(set, b"chat 7", &header, length).unwrap();
        assert_eq!(std::format!("{sealing:?}"), "Sealing { .. }");
        assert_eq!(std::format!("{opening:?}"), "Opening { .. }");
    }

    #[test]
    fn a_block_opens_back_to_its_data_at_every_boundary_of_a_chunk() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let mut random = Random(5);
        for length in [
            0, 1, 15, 16, 17, 65_535, 65_536, 65_537, 131_071, 131_072, 131_073,
        ] {
            let data: Vec<u8> = (0..length).map(|_| random.bytes::<1>()[0]).collect();
            let block = seal_block(
                &mut slots,
                set,
                b"note",
                &mut random_source(&mut random),
                &data,
            )
            .unwrap();
            assert_eq!(
                block.len(),
                usize::try_from(block_len(u64::try_from(length).unwrap()).unwrap()).unwrap()
            );
            assert_eq!(
                open_block(&slots, set, b"note", &block).unwrap(),
                data,
                "{length}"
            );
        }
    }

    #[test]
    fn every_bit_of_a_block_is_bound() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let data = pattern_of(33);
        let block = seal_block(&mut slots, set, b"chat 7", &mut Fixed(&NONCE), &data).unwrap();
        for at in 0..block.len() * 8 {
            let mut changed = block.clone();
            changed[at / 8] ^= 1 << (at % 8);
            assert_eq!(
                open_block(&slots, set, b"chat 7", &changed),
                Err(Error::RecordRejected),
                "bit {at}"
            );
        }
        assert_eq!(open_block(&slots, set, b"chat 7", &block).unwrap(), data);
    }

    #[test]
    fn a_chunk_that_does_not_open_is_wiped() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let data = pattern_of(CHUNK_LEN + 40);
        let block = seal_block(&mut slots, set, b"chat 7", &mut Fixed(&NONCE), &data).unwrap();
        let header: &[u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let mut opening = slots.begin_open(set, b"chat 7", header, length).unwrap();
        let mut chunk: [u8; CHUNK_LEN] = block[BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + CHUNK_LEN]
            .try_into()
            .unwrap();
        let mut tag: [u8; CHUNK_TAG_LEN] = block
            [BLOCK_HEADER_LEN + CHUNK_LEN..BLOCK_HEADER_LEN + CHUNK_LEN + CHUNK_TAG_LEN]
            .try_into()
            .unwrap();
        tag[3] ^= 0x10;
        assert_eq!(
            slots.open_chunk(&mut opening, &mut chunk, &tag),
            Err(Error::RecordRejected)
        );
        assert!(chunk.iter().all(|&byte| byte == 0));
        // The block goes on from the same chunk.
        tag[3] ^= 0x10;
        chunk.copy_from_slice(&block[BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + CHUNK_LEN]);
        slots.open_chunk(&mut opening, &mut chunk, &tag).unwrap();
        assert_eq!(&chunk[..], &data[..CHUNK_LEN]);
    }

    #[test]
    fn a_block_cut_reordered_or_mixed_with_another_does_not_open() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let whole = CHUNK_LEN + CHUNK_TAG_LEN;
        let data = pattern_of(2 * CHUNK_LEN + 9);
        let block = seal_block(&mut slots, set, b"file", &mut Fixed(&NONCE), &data).unwrap();
        let other = seal_block(&mut slots, set, b"file", &mut Fixed(&[3; 16]), &data).unwrap();
        let header = BLOCK_HEADER_LEN;
        let first = header..header + whole;
        let second = header + whole..header + 2 * whole;
        // The last chunk dropped: the second is then the last, and was not sealed as one.
        let cut = block[..second.end].to_vec();
        assert_eq!(
            open_block(&slots, set, b"file", &cut),
            Err(Error::RecordRejected)
        );
        // Both full chunks dropped after the first: the same.
        let cut = block[..first.end].to_vec();
        assert_eq!(
            open_block(&slots, set, b"file", &cut),
            Err(Error::RecordRejected)
        );
        // A byte cut or added anywhere: no block is that long, or the last tag moves.
        for length in [
            block.len() - 1,
            block.len() + 1,
            block.len() - 16,
            block.len() + 16,
        ] {
            let mut changed = block.clone();
            changed.resize(length, 0);
            assert_eq!(
                open_block(&slots, set, b"file", &changed),
                Err(Error::RecordRejected)
            );
        }
        // The two full chunks swapped.
        let mut swapped = block.clone();
        swapped[first.clone()].copy_from_slice(&block[second.clone()]);
        swapped[second.clone()].copy_from_slice(&block[first.clone()]);
        assert_eq!(
            open_block(&slots, set, b"file", &swapped),
            Err(Error::RecordRejected)
        );
        // A chunk of the other block, of the same key, context and place.
        let mut mixed = block.clone();
        mixed[second.clone()].copy_from_slice(&other[second.clone()]);
        assert_eq!(
            open_block(&slots, set, b"file", &mixed),
            Err(Error::RecordRejected)
        );
        // The other block's header on this block's chunks.
        let mut mixed = block.clone();
        mixed[..header].copy_from_slice(&other[..header]);
        assert_eq!(
            open_block(&slots, set, b"file", &mixed),
            Err(Error::RecordRejected)
        );
        // Another context, shorter or of the same length.
        for context in [&b"fil"[..], b"filf"] {
            assert_eq!(
                open_block(&slots, set, context, &block),
                Err(Error::RecordRejected)
            );
        }
        assert_eq!(open_block(&slots, set, b"file", &block).unwrap(), data);
        assert_eq!(open_block(&slots, set, b"file", &other).unwrap(), data);
    }

    #[test]
    fn a_block_opens_only_under_a_key_of_its_set() {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, parent) = recorded_set(&mut slots);
        let block = seal_block(&mut slots, set, b"chat 7", &mut Fixed(&NONCE), b"hello").unwrap();
        let other = slots
            .generate(Purpose::Data, KeyLength::Bytes32, &mut Fixed(&[8; 32]))
            .unwrap();
        assert_eq!(
            open_block(&slots, other, b"chat 7", &block),
            Err(Error::RecordRejected)
        );
        let external = slots.import32(Purpose::ExternalData, &mut [6; 32]).unwrap();
        let header: &[u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        assert_eq!(
            slots.begin_open(external, b"chat 7", header, 69).err(),
            Some(Error::WrongPurpose)
        );
        assert_eq!(
            slots
                .begin_seal(
                    external,
                    b"chat 7",
                    &mut Fixed(&NONCE),
                    &mut [0; BLOCK_HEADER_LEN]
                )
                .err(),
            Some(Error::WrongPurpose)
        );
        assert_eq!(
            slots.begin_open(set, b"", header, 69).err(),
            Some(Error::InvalidContext)
        );
        slots.release(other).unwrap();
        assert_eq!(
            slots.begin_open(other, b"chat 7", header, 69).err(),
            Some(Error::StaleHandle)
        );
        let _ = parent;
    }

    #[test]
    fn a_key_for_data_comes_only_from_the_source_and_stays_in() {
        let mut memory = [const { Slot::empty() }; 3];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        assert_eq!(
            slots.import32(Purpose::Data, &mut [1; 32]).err(),
            Some(Error::WrongPurpose)
        );
        assert_eq!(
            slots.import64(Purpose::Data, &mut [1; 64]).err(),
            Some(Error::WrongPurpose)
        );
        assert_eq!(
            slots
                .generate(Purpose::Data, KeyLength::Bytes64, &mut Fixed(&[1; 64]))
                .err(),
            Some(Error::WrongLength)
        );
        let (set, _) = recorded_set(&mut slots);
        assert_eq!(
            slots.reveal32(set, Position::First, Purpose::Data, &mut [0; 32]),
            Err(Error::WrongPurpose)
        );
        slots.settle();
        assert_eq!(slots.add32(set, &mut [2; 32]), Err(Error::WrongPurpose));
        let transfer = slots.import32(Purpose::Transfer, &mut [3; 32]).unwrap();
        assert_eq!(
            slots.export(
                set,
                transfer,
                b"chat 7",
                &mut Fixed(&NONCE),
                &mut [0; RECORD_LEN]
            ),
            Err(Error::WrongLevel)
        );
    }

    #[test]
    fn a_block_is_written_only_under_a_set_a_record_of_this_epoch_holds() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let set = slots
            .generate(Purpose::Data, KeyLength::Bytes32, &mut Fixed(&[4; 32]))
            .unwrap();
        let mut header = [7; BLOCK_HEADER_LEN];
        assert_eq!(
            slots
                .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
                .err(),
            Some(Error::Unsaved)
        );
        assert_eq!(header, [7; BLOCK_HEADER_LEN]);
        let parent = slots.import32(Purpose::Wrap, &mut pattern(97, 13)).unwrap();
        let parent = slots.store(parent);
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, parent, b"chat 7", &mut Fixed(&NONCE), &mut record)
            .unwrap();
        let mut sealing = slots
            .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
            .unwrap();
        // A change between two chunks: the block stops, and no new one begins before a record.
        slots
            .add_generated(set, KeyLength::Bytes32, &mut Fixed(&[5; 32]))
            .unwrap();
        let mut chunk = [1; CHUNK_LEN];
        assert_eq!(
            slots.seal_chunk(&mut sealing, &mut chunk, &mut [0; CHUNK_TAG_LEN]),
            Err(Error::StaleHandle)
        );
        assert_eq!(chunk, [1; CHUNK_LEN]);
        assert_eq!(
            slots
                .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
                .err(),
            Some(Error::Unsaved)
        );
        // Wrapped in the next epoch and committed, the set is held by a record of the new one.
        slots.begin_epoch(&mut [9; 32]).unwrap();
        slots
            .wrap(set, parent, b"chat 7", &mut Fixed(&NONCE), &mut record)
            .unwrap();
        assert_eq!(
            slots.commit_epoch(&mut crate::slots::tests::Platform::default()),
            Ok(Erasure::Guaranteed)
        );
        assert!(
            slots
                .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
                .is_ok()
        );
        // So does a change of stage.
        slots.promote(set, Position::Second).unwrap();
        assert_eq!(
            slots
                .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
                .err(),
            Some(Error::Unsaved)
        );
    }

    #[test]
    fn a_set_not_wrapped_in_the_next_epoch_writes_no_block_after_it() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut sealing = slots
            .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
            .unwrap();
        slots.begin_epoch(&mut [9; 32]).unwrap();
        assert_eq!(
            slots.commit_epoch(&mut crate::slots::tests::Platform::default()),
            Ok(Erasure::Guaranteed)
        );
        let mut chunk = [1; CHUNK_LEN];
        assert_eq!(
            slots.seal_chunk(&mut sealing, &mut chunk, &mut [0; CHUNK_TAG_LEN]),
            Err(Error::Unsaved)
        );
        assert_eq!(chunk, [1; CHUNK_LEN]);
        assert_eq!(
            slots
                .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
                .err(),
            Some(Error::Unsaved)
        );
    }

    // A block under way, or being read, cannot be copied to write or read it twice.
    assert_not_impl!(super::Sealing<'static>: Clone, Copy);
    assert_not_impl!(super::Opening<'static>: Clone, Copy);

    /// Saves a change of `set` as a new epoch would, and wraps it under `parent` in this one.
    fn save<'a>(slots: &mut Slots<'a>, set: Handle<'a>, parent: Handle<'a>) {
        slots.settle();
        let mut record = [0; RECORD_LEN];
        slots
            .wrap(set, parent, b"chat 7", &mut Fixed(&NONCE), &mut record)
            .unwrap();
    }

    #[test]
    fn a_block_follows_the_stages_of_its_key() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, parent) = recorded_set(&mut slots);
        let old = seal_block(&mut slots, set, b"chat 7", &mut Fixed(&NONCE), b"old").unwrap();
        let at = slots
            .add_generated(set, KeyLength::Bytes32, &mut Fixed(&[5; 32]))
            .unwrap();
        save(&mut slots, set, parent);
        slots.promote(set, at).unwrap();
        save(&mut slots, set, parent);
        let new = seal_block(&mut slots, set, b"chat 7", &mut Fixed(&[2; 16]), b"new").unwrap();
        assert_eq!(open_block(&slots, set, b"chat 7", &old).unwrap(), b"old");
        assert_eq!(open_block(&slots, set, b"chat 7", &new).unwrap(), b"new");
        slots.disable(set, Position::First).unwrap();
        save(&mut slots, set, parent);
        assert_eq!(
            open_block(&slots, set, b"chat 7", &old),
            Err(Error::KeyDisabled)
        );
        assert_eq!(open_block(&slots, set, b"chat 7", &new).unwrap(), b"new");
        slots.enable(set, Position::First).unwrap();
        save(&mut slots, set, parent);
        assert_eq!(open_block(&slots, set, b"chat 7", &old).unwrap(), b"old");
        slots.disable(set, Position::First).unwrap();
        save(&mut slots, set, parent);
        slots.destroy(set, Position::First).unwrap();
        assert_eq!(
            open_block(&slots, set, b"chat 7", &old),
            Err(Error::RecordRejected)
        );
        assert_eq!(open_block(&slots, set, b"chat 7", &new).unwrap(), b"new");
    }

    #[test]
    fn chunks_go_in_the_order_and_lengths_of_their_block() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut tag = [9; CHUNK_TAG_LEN];
        let mut sealing = slots
            .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
            .unwrap();
        slots
            .seal_chunk(&mut sealing, &mut [1; CHUNK_LEN], &mut tag)
            .unwrap();
        tag = [9; CHUNK_TAG_LEN];
        assert_eq!(
            slots.seal_last(sealing, &mut [], &mut tag),
            Err(Error::WrongChunk)
        );
        assert_eq!(tag, [9; CHUNK_TAG_LEN]);
        let sealing = slots
            .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
            .unwrap();
        let mut long = std::vec![1; CHUNK_LEN + 1];
        assert_eq!(
            slots.seal_last(sealing, &mut long, &mut tag),
            Err(Error::WrongChunk)
        );
        let block = seal_block(
            &mut slots,
            set,
            b"chat 7",
            &mut Fixed(&NONCE),
            &pattern_of(CHUNK_LEN + 3),
        )
        .unwrap();
        let header: &[u8; BLOCK_HEADER_LEN] = block[..BLOCK_HEADER_LEN].try_into().unwrap();
        let length = u64::try_from(block.len()).unwrap();
        let opening = slots.begin_open(set, b"chat 7", header, length).unwrap();
        assert_eq!((opening.chunks(), opening.last_len()), (2, 3));
        // The last before the others.
        assert_eq!(
            slots.open_last(opening, &mut [0; 3], &[0; CHUNK_TAG_LEN]),
            Err(Error::WrongChunk)
        );
        let mut opening = slots.begin_open(set, b"chat 7", header, length).unwrap();
        let tag: [u8; CHUNK_TAG_LEN] = block
            [BLOCK_HEADER_LEN + CHUNK_LEN..BLOCK_HEADER_LEN + CHUNK_LEN + CHUNK_TAG_LEN]
            .try_into()
            .unwrap();
        let mut chunk: [u8; CHUNK_LEN] = block[BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + CHUNK_LEN]
            .try_into()
            .unwrap();
        slots.open_chunk(&mut opening, &mut chunk, &tag).unwrap();
        // Another full chunk where the last is due, and a last one of another length.
        assert_eq!(
            slots.open_chunk(&mut opening, &mut [0; CHUNK_LEN], &tag),
            Err(Error::WrongChunk)
        );
        assert_eq!(
            slots.open_last(opening, &mut [0; 4], &tag),
            Err(Error::WrongChunk)
        );
    }

    #[test]
    fn every_call_on_a_block_holds_data_independent_timing() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut tag = [0; CHUNK_TAG_LEN];
        let mut sealing = timed(|| {
            slots
                .begin_seal(set, b"chat 7", &mut Fixed(&NONCE), &mut header)
                .unwrap()
        });
        let mut first = [1; CHUNK_LEN];
        timed(|| {
            slots
                .seal_chunk(&mut sealing, &mut first, &mut tag)
                .unwrap();
        });
        let first_tag = tag;
        let mut last = [2; 5];
        timed(|| slots.seal_last(sealing, &mut last, &mut tag).unwrap());
        let length = block_len(u64::try_from(CHUNK_LEN + 5).unwrap()).unwrap();
        let mut opening = timed(|| slots.begin_open(set, b"chat 7", &header, length).unwrap());
        timed(|| {
            slots
                .open_chunk(&mut opening, &mut first, &first_tag)
                .unwrap();
        });
        timed(|| slots.open_last(opening, &mut last, &tag).unwrap());
        assert_eq!((first, last), ([1; CHUNK_LEN], [2; 5]));
    }

    fn random_blocks(rounds: u64, seed: u64) {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let (set, _) = recorded_set(&mut slots);
        let mut random = Random(seed);
        for round in 0..rounds {
            let length = match random.below(4) {
                0 => random.below(64),
                1 => random.below(3 * CHUNK_LEN),
                2 => CHUNK_LEN * (1 + random.below(3)) + random.below(2),
                _ => random.below(CHUNK_LEN),
            };
            let context: Vec<u8> = (0..=random.below(255))
                .map(|_| random.bytes::<1>()[0])
                .collect();
            let data: Vec<u8> = (0..length).map(|_| random.bytes::<1>()[0]).collect();
            let block = seal_block(
                &mut slots,
                set,
                &context,
                &mut random_source(&mut random),
                &data,
            )
            .unwrap();
            assert_eq!(
                open_block(&slots, set, &context, &block).unwrap(),
                data,
                "round {round}"
            );
            let mut changed = block.clone();
            let at = random.below(changed.len());
            changed[at] ^= 1 << random.below(8);
            assert_eq!(
                open_block(&slots, set, &context, &changed),
                Err(Error::RecordRejected),
                "round {round}, byte {at}"
            );
        }
    }

    #[test]
    fn random_blocks_open_to_their_data_and_refuse_a_changed_bit() {
        random_blocks(20, 1);
    }

    /// The same over as many rounds and from the seed `LETHEWIS_RANDOM_ROUNDS` and
    /// `LETHEWIS_RANDOM_SEED` give.
    #[test]
    #[ignore = "long; the rounds and the seed come from the environment"]
    fn many_random_blocks_open_to_their_data_and_refuse_a_changed_bit() {
        random_blocks(
            from_environment("LETHEWIS_RANDOM_ROUNDS", 10_000),
            from_environment("LETHEWIS_RANDOM_SEED", 2),
        );
    }

    /// A source of the next bytes of `random`.
    fn random_source(random: &mut Random) -> Fixed<'static> {
        Fixed(std::boxed::Box::leak(std::boxed::Box::new(
            random.bytes::<64>(),
        )))
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
    use crate::block::{BLOCK_HEADER_LEN, CHUNK_LEN, CHUNK_TAG_LEN, chunk_nonce};
    use crate::derive::stack::secrets_of;
    use crate::derive::{Branch, CIPHER_STACK_WIPE, STACK_WIPE, derive_data_chunk};
    use crate::key::tests::{Counting, Failing};
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::slots::tests::{EPOCH, WRAP_NEEDS, flipped_epoch_key};
    use crate::{Epoch, Error, Handle, KeyLength, Purpose, RECORD_LEN, Slot, Slots, seal};

    /// The stack a beginning needs, in KiB, in an optimised build and in one without optimisation:
    /// a little more than a load, for the block it returns.
    const BEGIN_NEEDS: [usize; 2] = [11, 69];

    /// The documentation of the public call `name` in this file, its lines joined.
    fn documentation(name: &str) -> String {
        let source = include_str!("data.rs");
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

    /// The documentation of each call on a block states the stack it needs and the depth of the
    /// wipe after it: a beginning derives, a chunk derives and runs the cipher.
    #[test]
    fn the_documentation_states_the_stack_calls_need() {
        for (call, needs, wipes) in [
            ("begin_seal", BEGIN_NEEDS, [8, 64]),
            ("begin_open", BEGIN_NEEDS, [8, 64]),
            ("seal_chunk", WRAP_NEEDS, [24, 64]),
            ("seal_last", WRAP_NEEDS, [24, 64]),
            ("open_chunk", WRAP_NEEDS, [24, 64]),
            ("open_last", WRAP_NEEDS, [24, 64]),
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

    /// Slots over `memory` whose epoch key `flip` changes, with a key for data that a record of this
    /// epoch holds, in the state [`blocked`] begins its block in.
    fn before_sealing<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
        flip: u8,
    ) -> (Slots<'a>, Handle<'a>) {
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
        (slots, set)
    }

    /// A block of two chunks under a key for data in slots over `memory` whose epoch key `flip`
    /// changes, the handle of its set, and the secrets the calls on it handle: the key, the key of
    /// the epoch and the hedge of the salt, the key of its chunks, the cipher's keys and keystream
    /// for each chunk, and the derivations of the check and of the key of the chunks.
    fn blocked<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
        flip: u8,
    ) -> (Slots<'a>, Handle<'a>, Vec<u8>, Vec<Vec<u8>>) {
        let (mut slots, set) = before_sealing(memory, epoch, flip);
        let count = slots.epoch.drawn;
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut sealing = slots
            .begin_seal(set, b"note", &mut Counting, &mut header)
            .unwrap();
        let mut first = first_data(flip);
        let (mut first_tag, mut last_tag) = ([0; CHUNK_TAG_LEN], [0; CHUNK_TAG_LEN]);
        slots
            .seal_chunk(&mut sealing, &mut first, &mut first_tag)
            .unwrap();
        let mut last = last_data(flip);
        slots.seal_last(sealing, &mut last, &mut last_tag).unwrap();
        let mut block = header.to_vec();
        block.extend_from_slice(&first[..]);
        block.extend_from_slice(&first_tag);
        block.extend_from_slice(&last);
        block.extend_from_slice(&last_tag);
        let key = slots.memory[set.index].key(crate::Position::First);
        let salt: [u8; 16] = header[..16].try_into().unwrap();
        let mut chunk_key = [0; 32];
        derive_data_chunk(key, &salt, &mut chunk_key).unwrap();
        let epoch_key = flipped_epoch_key(flip);
        let mut material: Vec<u8> = (1..=16).collect();
        material.extend_from_slice(&count.to_le_bytes());
        let mut secrets = std::vec![key.bytes()[..32].to_vec(), epoch_key.to_vec()];
        secrets.extend(secrets_of(&material, &epoch_key, Branch::HedgeSalt));
        secrets.extend(keying_secrets(
            &chunk_key,
            &chunk_nonce(0, false),
            &first_tag,
            CHUNK_LEN,
        ));
        secrets.extend(keying_secrets(
            &chunk_key,
            &chunk_nonce(1, true),
            &last_tag,
            33,
        ));
        for branch in [Branch::DataCheck, Branch::DataChunk] {
            secrets.extend(secrets_of(key.material().unwrap(), &salt, branch));
        }
        (slots, set, block, secrets)
    }

    /// The data of the first chunk [`blocked`] seals, which `flip` changes, varied in every piece.
    fn first_data(flip: u8) -> std::boxed::Box<[u8; CHUNK_LEN]> {
        let mut data: std::boxed::Box<[u8; CHUNK_LEN]> = std::vec![0; CHUNK_LEN]
            .into_boxed_slice()
            .try_into()
            .unwrap();
        for (at, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from(at % 251).unwrap().wrapping_mul(31) ^ flip;
        }
        data
    }

    /// The data of the last chunk [`blocked`] seals.
    fn last_data(flip: u8) -> [u8; 33] {
        core::array::from_fn(|at| u8::try_from(at).unwrap().wrapping_mul(57).wrapping_add(3) ^ flip)
    }

    /// The header, the first chunk and its tag, and the last chunk and its tag of `block`.
    #[expect(clippy::type_complexity, reason = "the parts of a block of two chunks")]
    fn parts(
        block: &[u8],
    ) -> (
        [u8; BLOCK_HEADER_LEN],
        std::boxed::Box<[u8; CHUNK_LEN]>,
        [u8; CHUNK_TAG_LEN],
        Vec<u8>,
        [u8; CHUNK_TAG_LEN],
    ) {
        let at = BLOCK_HEADER_LEN;
        let first = at + CHUNK_LEN;
        (
            block[..at].try_into().unwrap(),
            std::boxed::Box::new(block[at..first].try_into().unwrap()),
            block[first..first + CHUNK_TAG_LEN].try_into().unwrap(),
            block[first + CHUNK_TAG_LEN..block.len() - CHUNK_TAG_LEN].to_vec(),
            block[block.len() - CHUNK_TAG_LEN..].try_into().unwrap(),
        )
    }

    fn length(block: &[u8]) -> u64 {
        u64::try_from(block.len()).unwrap()
    }

    /// Sealing and opening a chunk without the wipe after them leave on the stack some of what they
    /// handle, so that the test below can tell the wipe from its absence; an opening in the portable
    /// code built without optimisation leaves nothing even so. The block is sealed again from the
    /// same state, so it handles the same values. A beginning keeps nothing secret in its own frame:
    /// the hedge and the derivations it runs wipe after themselves.
    #[test]
    fn the_calls_on_a_chunk_without_the_wipe_leave_residue() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 2], [const { Slot::empty() }; 2]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (.., mut others) = blocked(&mut other, &mut other_epoch, 0x5a);
        let (slots, set, block, secrets) = blocked(&mut memory, &mut epoch, 0);
        // The salt is in the header, public: a beginning to read copies it.
        others.push(block[..BLOCK_HEADER_LEN].to_vec());
        let pieces = key_dependent(&secrets, &others);
        // The portable cipher wipes its keys itself, and its hash of the plaintext runs last, over
        // the keystream.
        let opening_leaves = !(cfg!(aes_backend = "soft") && cfg!(lethewis_unoptimised));
        let (header, mut first, first_tag, mut last, last_tag) = parts(&block);
        let mut opening = slots
            .begin_open(set, b"note", &header, length(&block))
            .unwrap();
        let range = below_pad(false, || {
            slots
                .open_chunk_on_stack(&mut opening, &mut first[..], false, &first_tag, seal::Aes)
                .unwrap();
            black_box(&first);
        });
        assert_eq!(
            residue(range, &pieces) > 0,
            opening_leaves,
            "an opening of a chunk"
        );
        let range = below_pad(false, || {
            slots
                .open_chunk_on_stack(&mut opening, &mut last, true, &last_tag, seal::Aes)
                .unwrap();
            black_box(&last);
        });
        assert_eq!(
            residue(range, &pieces) > 0,
            opening_leaves,
            "an opening of the last chunk"
        );
        let (mut again, mut again_epoch) = ([const { Slot::empty() }; 2], Epoch::empty());
        let (mut slots, set) = before_sealing(&mut again, &mut again_epoch, 0);
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut sealing = slots
            .begin_seal(set, b"note", &mut Counting, &mut header)
            .unwrap();
        let mut chunk = first_data(0);
        let mut tag = [0; CHUNK_TAG_LEN];
        let range = below_pad(false, || {
            slots
                .seal_chunk_on_stack(&mut sealing, &mut chunk[..], false, &mut tag, seal::Aes)
                .unwrap();
            black_box(&chunk);
        });
        assert!(residue(range, &pieces) > 0, "a seal of a chunk");
        assert_eq!(
            &chunk[..],
            &block[BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + CHUNK_LEN]
        );
    }

    /// Beginning, sealing and opening a block leave on the stack none of the secrets [`blocked`]
    /// names, and none of the data of its chunks.
    #[test]
    fn the_calls_on_a_block_leave_no_key_on_the_stack() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 2], [const { Slot::empty() }; 2]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (.., mut others) = blocked(&mut other, &mut other_epoch, 0x5a);
        let (slots, set, block, mut secrets) = blocked(&mut memory, &mut epoch, 0);
        secrets.extend([first_data(0).to_vec(), last_data(0).to_vec()]);
        // The salt is in the header, public: a beginning to read copies it.
        others.push(block[..BLOCK_HEADER_LEN].to_vec());
        let pieces = key_dependent(&secrets, &others);
        assert_ne!(pieces.len(), 0);
        let (header, mut first, first_tag, mut last, last_tag) = parts(&block);
        let mut opening = None;
        assert_clean(&pieces, || {
            opening = Some(
                slots
                    .begin_open(set, b"note", &header, length(&block))
                    .unwrap(),
            );
        });
        let mut opening = opening.unwrap();
        assert_clean(&pieces, || {
            slots
                .open_chunk(&mut opening, &mut first, &first_tag)
                .unwrap();
            black_box(&first);
        });
        assert_clean(&pieces, || {
            slots.open_last(opening, &mut last, &last_tag).unwrap();
            black_box(&last);
        });
        let (mut again, mut again_epoch) = ([const { Slot::empty() }; 2], Epoch::empty());
        let (mut slots, set) = before_sealing(&mut again, &mut again_epoch, 0);
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut sealing = None;
        assert_clean(&pieces, || {
            sealing = Some(
                slots
                    .begin_seal(set, b"note", &mut Counting, &mut header)
                    .unwrap(),
            );
        });
        let mut sealing = sealing.unwrap();
        let mut tag = [0; CHUNK_TAG_LEN];
        let mut chunk = first_data(0);
        assert_clean(&pieces, || {
            slots
                .seal_chunk(&mut sealing, &mut chunk, &mut tag)
                .unwrap();
            black_box(&chunk);
        });
        let mut last = last_data(0);
        assert_clean(&pieces, || {
            slots.seal_last(sealing, &mut last, &mut tag).unwrap();
            black_box(&last);
        });
        assert_eq!(
            &last[..],
            &block[block.len() - CHUNK_TAG_LEN - 33..block.len() - CHUNK_TAG_LEN]
        );
    }

    /// The wipe after a chunk covers more than the cipher uses on a chunk, full or short; the
    /// derivations a beginning and a chunk run are measured with the derivation, and wiped after it
    /// besides.
    #[test]
    fn the_wipe_is_deeper_than_the_cipher_on_a_chunk() {
        let (key, nonce) = ([7; 32], chunk_nonce(3, false));
        let mut full: std::boxed::Box<[u8; CHUNK_LEN]> = std::vec![9; CHUNK_LEN]
            .into_boxed_slice()
            .try_into()
            .unwrap();
        let mut short = [9; 33];
        let mut tags = [[0; CHUNK_TAG_LEN]; 2];
        let mut used = Vec::new();
        used.push(depth_changed(|| {
            tags[0] = seal::seal_data(&key, &nonce, b"note", &mut full[..]).unwrap();
            black_box(&full);
        }));
        used.push(depth_changed(|| {
            tags[1] = seal::seal_data(&key, &nonce, b"note", &mut short).unwrap();
            black_box(&short);
        }));
        used.push(depth_changed(|| {
            seal::open_data(&key, &nonce, b"note", &mut full[..], &tags[0]).unwrap();
            black_box(&full);
        }));
        used.push(depth_changed(|| {
            seal::open_data(&key, &nonce, b"note", &mut short, &tags[1]).unwrap();
            black_box(&short);
        }));
        std::println!("the cipher on a chunk uses {used:?} bytes of stack");
        for used in used {
            assert!(
                used.saturating_mul(2) <= CIPHER_STACK_WIPE,
                "{used} bytes used"
            );
            assert!(
                used.saturating_mul(16) >= CIPHER_STACK_WIPE,
                "{used} bytes used"
            );
        }
    }

    /// The wipes that follow each call reach as deep as they are meant to, also when the call
    /// fails, and no call reaches deeper than its documentation says it needs.
    #[test]
    fn the_calls_on_a_block_wipe_and_need_the_stack_documented() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 2], Epoch::empty());
        let (mut slots, set, block, _) = blocked(&mut memory, &mut epoch, 0);
        let (header, mut first, first_tag, mut last, last_tag) = parts(&block);
        let mut deep = Vec::new();
        let mut opening = None;
        deep.push((
            depth_changed(|| {
                opening = Some(
                    slots
                        .begin_open(set, b"note", &header, length(&block))
                        .unwrap(),
                );
            }),
            STACK_WIPE,
            BEGIN_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                let refused =
                    slots.begin_open(set, b"other", &[0; BLOCK_HEADER_LEN], length(&block));
                assert_eq!(black_box(refused.err()), Some(Error::RecordRejected));
            }),
            STACK_WIPE,
            BEGIN_NEEDS,
        ));
        let mut opening = opening.unwrap();
        deep.push((
            depth_changed(|| {
                slots
                    .open_chunk(&mut opening, &mut first, &first_tag)
                    .unwrap();
                black_box(&first);
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                let refused = slots.open_last(opening, &mut last, &[0; CHUNK_TAG_LEN]);
                assert_eq!(black_box(refused), Err(Error::RecordRejected));
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        let mut header = [0; BLOCK_HEADER_LEN];
        let mut sealing = None;
        deep.push((
            depth_changed(|| {
                sealing = Some(
                    slots
                        .begin_seal(set, b"note", &mut Counting, &mut header)
                        .unwrap(),
                );
            }),
            STACK_WIPE,
            BEGIN_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                let failed = slots.begin_seal(set, b"note", &mut Failing, &mut header);
                assert_eq!(black_box(failed.err()), Some(Error::EntropyFailed));
            }),
            STACK_WIPE,
            BEGIN_NEEDS,
        ));
        let mut sealing = sealing.unwrap();
        let mut tag = [0; CHUNK_TAG_LEN];
        deep.push((
            depth_changed(|| {
                slots
                    .seal_chunk(&mut sealing, &mut first, &mut tag)
                    .unwrap();
                black_box(&first);
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        deep.push((
            depth_changed(|| {
                slots.seal_last(sealing, &mut last, &mut tag).unwrap();
                black_box(&last);
            }),
            CIPHER_STACK_WIPE,
            WRAP_NEEDS,
        ));
        let _ = last_tag;
        std::println!(
            "calls on a block reach {:?} bytes",
            deep.iter().map(|(depth, ..)| *depth).collect::<Vec<_>>()
        );
        for (depth, wipe, needs) in deep {
            assert!(depth >= wipe, "{depth} bytes wiped");
            assert!(depth <= needs[build] * 1024, "{depth} bytes reached");
        }
    }
}
