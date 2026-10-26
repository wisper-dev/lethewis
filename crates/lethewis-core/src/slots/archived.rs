// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The records of an archive: a ciphertext of X-Wing to an archive key under the key of a chat for
//! its archive, and the bodies of their batches, sealed under a key derived from its shared secret.

use super::archive::{open_archive_layer, seed_of, split_body, wipe_archive_stack};
use core::marker::PhantomData;

use super::batch::{self, Chunks, OpenBatch, SealBatch, wipe_batch_stack};
use super::{Handle, Open, Seal, Slot, Slots, hedged_draw};
use crate::{
    block::CHUNK_LEN,
    derive::{
        Branch, KeyId, derive_archive_batch, derive_archive_check, derive_archive_randomness,
        derive_archive_seal_key,
    },
    entropy::Entropy,
    epoch::Epoch,
    error::Error,
    key::{Key, wipe, wipe_slice},
    record::{
        ARCHIVE_BODY_LEN, ARCHIVE_KEY_RECORD_LEN, ARCHIVE_LAYER_LEN, ARCHIVE_RECORD_LEN,
        ARCHIVED_LEN, AssociatedData, ID_LEN, Purpose,
    },
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, NONCE_LEN, TAG_LEN},
    xwing::{self, CIPHERTEXT_LEN, KNOWN, Known, PUBLIC_LEN, RANDOMNESS_LEN, SHARED_LEN},
};

/// The identifier and the public key of an archive key, as the record of the key holds them under
/// the profile's stored key for wrapping, for the set of slots and the epoch it was read in. Only
/// [`Slots::archive_public_key`] makes one.
pub struct ArchivePublic<'a> {
    pub(super) id: [u8; ID_LEN],
    pub(super) public: [u8; PUBLIC_LEN],
    pub(super) slots: usize,
    pub(super) epoch: u64,
    pub(super) memory: PhantomData<&'a [Slot]>,
}

impl core::fmt::Debug for ArchivePublic<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArchivePublic").finish_non_exhaustive()
    }
}

impl<'a> Slots<'a> {
    /// Reads the identifier and the public key of the archive key whose record is `record`, for the
    /// `context` it was written for, under the stored key for wrapping that `profile` refers to and
    /// the key of this epoch; the stored key of the archive is not needed. It serves these slots in
    /// this epoch only. Whether the public key is the one the seed gives is known only once
    /// [`Slots::load_archive_key`] loads the key, or [`Slots::open_archive`] opens a batch.
    ///
    /// Needs 100 KiB of stack, or 232 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 96 KiB, or 224 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the code it calls has
    /// to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `profile` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::Wrap`],
    /// [`Error::WrongLevel`] if it is a key from a secret, [`Error::DerivationFailed`] if the key
    /// of the layer cannot be derived, and [`Error::StaleRecord`] if the record does not open with
    /// that stored key, this context and the key of this epoch, or names another epoch.
    pub fn archive_public_key(
        &self,
        profile: Handle<'a>,
        context: &[u8],
        record: &[u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Result<ArchivePublic<'a>, Error> {
        let read = crate::timing::with(|| {
            self.archive_public_key_on_stack(profile, context, record, seal::Aes)
        });
        wipe_archive_stack();
        read
    }

    /// The reading itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    pub(super) fn archive_public_key_on_stack(
        &self,
        profile: Handle<'a>,
        context: &[u8],
        record: &[u8; ARCHIVE_KEY_RECORD_LEN],
        mut open: impl Open<ARCHIVE_LAYER_LEN>,
    ) -> Result<ArchivePublic<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let profile = self.profile_key(profile)?;
        let stored = self.memory.get(profile).ok_or(Error::StaleHandle)?;
        let mut body = [0; ARCHIVE_BODY_LEN];
        open_archive_layer(
            (stored.wrapping_key().0, &self.epoch.key, self.epoch.number),
            associated.bytes(),
            record,
            &mut body,
            &mut open,
        )?;
        let (id, public, mut inner) = split_body(&body);
        wipe(&mut inner);
        wipe(&mut body);
        Ok(ArchivePublic {
            id,
            public,
            slots: self.id(),
            epoch: self.epoch.number,
            memory: PhantomData,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "a batch takes its data, its record and its body"
    )]
    /// Archives `data`, a batch of a chat: encapsulates to the archive key `public` names, writes
    /// into `record` the identifier of the archive key, the ciphertext and a check of the shared
    /// secret, and into `body`, [`batch_len`](crate::batch_len) bytes long, the data in chunks
    /// sealed under a key derived from the shared secret, which never leaves the library. The
    /// record is under the key of the chat for its archive that `seal` refers to, bound to
    /// `context`, from 1 to 255 bytes, in no epoch, and the body is bound to the same context;
    /// only that key and the archive key open them, with [`Slots::open_archive`]. The context names the place of the
    /// batch: a record and body of another batch of the same context open in its place. The
    /// randomness of the encapsulation and the nonce come from `entropy`, hedged with the key of
    /// this epoch, the randomness also with the key of the chat. X-Wing gives a known answer
    /// first, once in a process. The data are sealed in a buffer of the library, and only their
    /// ciphertext goes into `body`.
    ///
    /// Needs 164 KiB of stack, or 232 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 160 KiB, or 224 KiB,
    /// deep, whether it succeeded or not. A build that optimises this crate but not the code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `seal` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::ArchiveSeal`],
    /// [`Error::StaleRecord`] if `public` was read from other slots or in another epoch,
    /// [`Error::WrongLength`] if `body` is not as long as the chunks of `data` take,
    /// [`Error::CipherFailed`] if X-Wing gives a known input a wrong answer,
    /// [`Error::EntropyFailed`] if `entropy` fails, [`Error::DerivationFailed`] if a value cannot
    /// be derived from a key, [`Error::RecordRejected`] if X-Wing refuses the public key, and
    /// [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails. `record`
    /// is then left as it was, and `body` is wiped.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and `record` and `body` are left as they
    /// were.
    pub fn archive(
        &mut self,
        seal: Handle<'a>,
        public: &ArchivePublic<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        data: &[u8],
        record: &mut [u8; ARCHIVE_RECORD_LEN],
        body: &mut [u8],
    ) -> Result<(), Error> {
        let archived = crate::timing::with(|| {
            self.archive_on_stack(
                seal,
                public,
                context,
                entropy,
                (data, record, body),
                &KNOWN,
                (seal::Aes, Chunks),
            )
        });
        wipe_batch_stack();
        archived
    }

    /// The archiving itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts. X-Wing has to give `known` first.
    #[inline(never)]
    #[expect(
        clippy::too_many_arguments,
        reason = "the proofs give the known answer and the cipher"
    )]
    pub(super) fn archive_on_stack(
        &mut self,
        seal: Handle<'a>,
        public: &ArchivePublic<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        (data, record, body): (&[u8], &mut [u8; ARCHIVE_RECORD_LEN], &mut [u8]),
        known: &Known,
        sealers: (impl Seal<ARCHIVED_LEN>, impl SealBatch),
    ) -> Result<(), Error> {
        let written = self.write_archive(
            seal,
            public,
            context,
            entropy,
            (data, record, &mut *body),
            known,
            sealers,
        );
        if written.is_err() {
            wipe_slice(body);
        }
        written
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the proofs give the known answer and the cipher"
    )]
    fn write_archive(
        &mut self,
        seal: Handle<'a>,
        public: &ArchivePublic<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        (data, record, body): (&[u8], &mut [u8; ARCHIVE_RECORD_LEN], &mut [u8]),
        known: &Known,
        (seal_with, mut batch_with): (impl Seal<ARCHIVED_LEN>, impl SealBatch),
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let batched = AssociatedData::of_batch(context).map_err(|_| Error::InvalidContext)?;
        let seal = self.serving(seal, Purpose::ArchiveSeal)?;
        if public.slots != self.id() || public.epoch != self.epoch.number {
            return Err(Error::StaleRecord);
        }
        batch::fits::<CHUNK_LEN>(data.len(), body.len())?;
        if !xwing::answers(known) {
            return Err(Error::CipherFailed);
        }
        let Self { memory, epoch } = self;
        let chat = memory.get(seal).ok_or(Error::StaleHandle)?.wrapping_key().0;
        let Epoch { key, drawn, .. } = &mut **epoch;
        let mut nonce = [0; NONCE_LEN];
        hedged_draw(entropy, key, drawn, Branch::HedgeNonce, &mut nonce)?;
        let mut hedged = [0; RANDOMNESS_LEN];
        hedged_draw(entropy, key, drawn, Branch::HedgeEncaps, &mut hedged)?;
        let mut randomness = [0; RANDOMNESS_LEN];
        let derived = derive_archive_randomness(chat, &hedged, &mut randomness);
        wipe(&mut hedged);
        let mut ciphertext = [0; CIPHERTEXT_LEN];
        let mut shared = [0; SHARED_LEN];
        let encapsulated = derived.map_err(|_| Error::DerivationFailed).and_then(|()| {
            xwing::encapsulate(&public.public, &randomness, &mut ciphertext, &mut shared)
                .map_err(|_| Error::RecordRejected)
        });
        wipe(&mut randomness);
        let (mut batch, mut check) = ([0; 32], KeyId::empty());
        let mut sealed = [0; ARCHIVE_RECORD_LEN];
        let written = encapsulated
            .and_then(|()| batch_keys(&shared, &ciphertext, &mut batch, &mut check))
            .and_then(|()| {
                seal_archived(
                    chat,
                    &nonce,
                    associated.bytes(),
                    (&public.id, &ciphertext, &check.bytes()),
                    (&mut sealed, seal_with),
                )
            })
            .and_then(|()| batch_with.seal(&batch, batched.bytes(), data, body));
        wipe(&mut shared);
        wipe(&mut batch);
        if written.is_ok() {
            *record = sealed;
        }
        written
    }

    /// Opens into `data` the batch whose record of the archive is `record` and whose body is `body`,
    /// for the `context` it was written for: the record opens with the key of the chat for its
    /// archive that `seal` refers to, the key of the body is derived from the shared secret the
    /// archive key that `archive` refers to gives its ciphertext, if the record's check of that
    /// secret holds, and the body opens under it. `data` is
    /// [`batch_data_len`](crate::batch_data_len) bytes long. Each chunk opens in a buffer of the
    /// library and goes into `data` only once it has opened; if one does not, `data` is wiped, so
    /// it is to be memory of this process, not a mapped file. X-Wing gives a known answer first,
    /// once in a process.
    ///
    /// Needs 164 KiB of stack, or 232 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 160 KiB, or 224 KiB,
    /// deep, whether it succeeded or not. A build that optimises this crate but not the code it
    /// calls has to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if either handle does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if the set `archive` refers to does not serve [`Purpose::Archive`]
    /// or the one `seal` refers to [`Purpose::ArchiveSeal`], [`Error::RecordRejected`] if no body
    /// of a batch is as long as `body`, [`Error::WrongLength`] if `data` is not as long as the body
    /// holds or the set `archive` refers to holds no key of 32 bytes, [`Error::CipherFailed`] if
    /// X-Wing gives a known input a wrong answer, [`Error::DerivationFailed`] if a value cannot be
    /// derived from a key, [`Error::RecordRejected`] if the record does not open with that key of
    /// the chat and this context, [`Error::WrongArchiveKey`] if it was written to another archive
    /// key, [`Error::PublicKeyMismatch`] if the check of the shared secret fails: the batch was
    /// archived to another public key, or its ciphertext or check changed, and
    /// [`Error::RecordRejected`] if a chunk of the body does not open as the next of this batch.
    /// `data` is then wiped.
    pub fn open_archive(
        &self,
        archive: Handle<'a>,
        seal: Handle<'a>,
        context: &[u8],
        record: &[u8; ARCHIVE_RECORD_LEN],
        body: &[u8],
        data: &mut [u8],
    ) -> Result<(), Error> {
        let opened = crate::timing::with(|| {
            self.open_archive_on_stack(
                (archive, seal),
                context,
                (record, body, data),
                &KNOWN,
                (seal::Aes, Chunks),
            )
        });
        wipe_batch_stack();
        opened
    }

    /// The opening itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts. X-Wing has to give `known` first.
    #[inline(never)]
    pub(super) fn open_archive_on_stack(
        &self,
        (archive, seal): (Handle<'a>, Handle<'a>),
        context: &[u8],
        (record, body, data): (&[u8; ARCHIVE_RECORD_LEN], &[u8], &mut [u8]),
        known: &Known,
        openers: (impl Open<ARCHIVED_LEN>, impl OpenBatch),
    ) -> Result<(), Error> {
        let opened = self.read_archive(
            (archive, seal),
            context,
            (record, body, &mut *data),
            known,
            openers,
        );
        if opened.is_err() {
            wipe_slice(data);
        }
        opened
    }

    fn read_archive(
        &self,
        (archive, seal): (Handle<'a>, Handle<'a>),
        context: &[u8],
        (record, body, data): (&[u8; ARCHIVE_RECORD_LEN], &[u8], &mut [u8]),
        known: &Known,
        (mut open, mut batch_with): (impl Open<ARCHIVED_LEN>, impl OpenBatch),
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let batched = AssociatedData::of_batch(context).map_err(|_| Error::InvalidContext)?;
        let archive = self.serving(archive, Purpose::Archive)?;
        let seal = self.serving(seal, Purpose::ArchiveSeal)?;
        batch::holds::<CHUNK_LEN>(body.len(), data.len())?;
        if !xwing::answers(known) {
            return Err(Error::CipherFailed);
        }
        let (Some(archived), Some(chat)) = (self.memory.get(archive), self.memory.get(seal)) else {
            return Err(Error::StaleHandle);
        };
        let mut sealed = [0; ARCHIVED_LEN];
        open_archived(
            chat.wrapping_key().0,
            associated.bytes(),
            record,
            &mut sealed,
            &mut open,
        )?;
        let (id, ciphertext, kept) = split_archived(&sealed);
        let (seed, seed_id) = archived.wrapping_key();
        if !seed_id.is(&id) {
            return Err(Error::WrongArchiveKey);
        }
        let seed = seed_of(seed).ok_or(Error::WrongLength)?;
        let mut shared = [0; SHARED_LEN];
        xwing::decapsulate(seed, &ciphertext, &mut shared);
        let (mut batch, mut check) = ([0; 32], KeyId::empty());
        let opened = batch_keys(&shared, &ciphertext, &mut batch, &mut check)
            .and_then(|()| {
                if check.is(&kept) {
                    Ok(())
                } else {
                    Err(Error::PublicKeyMismatch)
                }
            })
            .and_then(|()| batch_with.open(&batch, batched.bytes(), body, data));
        wipe(&mut shared);
        wipe(&mut batch);
        opened
    }

    /// Moves the record of an archive `record` from the key of a chat for its archive that `from`
    /// refers to, to the one `to` refers to, which may be the same, and writes it into `out`, for
    /// the same `context`: the archive key and the body are not needed, and the identifier, the
    /// ciphertext and the check stay the same, so the moved record opens the same body. The nonce
    /// comes from `entropy`, hedged with the key of this epoch.
    ///
    /// Needs 100 KiB of stack, or 232 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 96 KiB, or 224 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the code it calls has
    /// to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if either handle does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if either set does not serve [`Purpose::ArchiveSeal`],
    /// [`Error::EntropyFailed`] if `entropy` fails, [`Error::DerivationFailed`] if the nonce
    /// cannot be hedged or a key that encrypts a record cannot be derived,
    /// [`Error::RecordRejected`] if `record` does not open with the first key and this context,
    /// and [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails.
    /// `out` is then left as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and `out` is left as it was.
    pub fn reseal_archive(
        &mut self,
        from: Handle<'a>,
        to: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &[u8; ARCHIVE_RECORD_LEN],
        out: &mut [u8; ARCHIVE_RECORD_LEN],
    ) -> Result<(), Error> {
        let resealed = crate::timing::with(|| {
            self.reseal_archive_on_stack(
                (from, to),
                context,
                entropy,
                (record, out),
                seal::Aes,
                seal::Aes,
            )
        });
        wipe_archive_stack();
        resealed
    }

    /// The move itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    pub(super) fn reseal_archive_on_stack(
        &mut self,
        (from, to): (Handle<'a>, Handle<'a>),
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        (record, out): (&[u8; ARCHIVE_RECORD_LEN], &mut [u8; ARCHIVE_RECORD_LEN]),
        mut open: impl Open<ARCHIVED_LEN>,
        seal_with: impl Seal<ARCHIVED_LEN>,
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let from = self.serving(from, Purpose::ArchiveSeal)?;
        let to = self.serving(to, Purpose::ArchiveSeal)?;
        let Self { memory, epoch } = self;
        let (Some(old), Some(new)) = (memory.get(from), memory.get(to)) else {
            return Err(Error::StaleHandle);
        };
        let Epoch { key, drawn, .. } = &mut **epoch;
        let mut nonce = [0; NONCE_LEN];
        hedged_draw(entropy, key, drawn, Branch::HedgeNonce, &mut nonce)?;
        let mut sealed = [0; ARCHIVED_LEN];
        open_archived(
            old.wrapping_key().0,
            associated.bytes(),
            record,
            &mut sealed,
            &mut open,
        )?;
        let (id, ciphertext, check) = split_archived(&sealed);
        seal_archived(
            new.wrapping_key().0,
            &nonce,
            associated.bytes(),
            (&id, &ciphertext, &check),
            (out, seal_with),
        )
    }
}

/// Writes into `batch` the key of the body of a batch, and into `check` the check a record keeps,
/// derived from the shared secret `shared` and the ciphertext it came with.
fn batch_keys(
    shared: &[u8; SHARED_LEN],
    ciphertext: &[u8; CIPHERTEXT_LEN],
    batch: &mut [u8; 32],
    check: &mut KeyId,
) -> Result<(), Error> {
    let mut secret = Key::empty();
    secret.copy32(shared);
    let derived = derive_archive_batch(&secret, ciphertext, batch)
        .and_then(|()| derive_archive_check(&secret, ciphertext, check));
    secret.wipe();
    derived.map_err(|_| Error::DerivationFailed)
}

/// Seals the identifier `id` of an archive key, the ciphertext to it and the check of its shared
/// secret with `seal_with` under the key derived from the key of a chat for its archive `chat`,
/// under `nonce` into `out`. `out` is written only when this succeeds.
fn seal_archived(
    chat: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    (id, ciphertext, check): (&[u8; ID_LEN], &[u8; CIPHERTEXT_LEN], &[u8; ID_LEN]),
    (out, mut seal_with): (&mut [u8; ARCHIVE_RECORD_LEN], impl Seal<ARCHIVED_LEN>),
) -> Result<(), Error> {
    let mut cipher_key = [0; CIPHER_KEY_LEN];
    if derive_archive_seal_key(chat, &mut cipher_key).is_err() {
        wipe(&mut cipher_key);
        return Err(Error::DerivationFailed);
    }
    let mut sealed = [0; ARCHIVED_LEN];
    if let Some((id_out, rest)) = sealed.split_first_chunk_mut::<ID_LEN>()
        && let Some((ciphertext_out, check_out)) = rest.split_first_chunk_mut::<CIPHERTEXT_LEN>()
        && let Ok(check_out) = <&mut [u8; ID_LEN]>::try_from(check_out)
    {
        *id_out = *id;
        *ciphertext_out = *ciphertext;
        *check_out = *check;
    }
    let tag = seal_with.seal(&cipher_key, nonce, aad, &mut sealed);
    wipe(&mut cipher_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    if let Some((nonce_out, rest)) = out.split_first_chunk_mut::<NONCE_LEN>()
        && let Some((sealed_out, tag_out)) = rest.split_first_chunk_mut::<ARCHIVED_LEN>()
    {
        *nonce_out = *nonce;
        *sealed_out = sealed;
        tag_out.copy_from_slice(&tag);
    }
    Ok(())
}

/// Opens the record of an archive `record` under the key derived from the key of a chat for its
/// archive `chat` and keeps what it holds in `sealed`; otherwise `RecordRejected`, and `sealed` is
/// left as it was.
fn open_archived(
    chat: &Key,
    aad: &[u8],
    record: &[u8; ARCHIVE_RECORD_LEN],
    sealed: &mut [u8; ARCHIVED_LEN],
    open: &mut impl Open<ARCHIVED_LEN>,
) -> Result<(), Error> {
    let mut cipher_key = [0; CIPHER_KEY_LEN];
    if derive_archive_seal_key(chat, &mut cipher_key).is_err() {
        wipe(&mut cipher_key);
        return Err(Error::DerivationFailed);
    }
    let mut parts = ([0; NONCE_LEN], [0; ARCHIVED_LEN], [0; TAG_LEN]);
    if let Some((nonce, rest)) = record.split_first_chunk::<NONCE_LEN>()
        && let Some((layer, tag)) = rest.split_first_chunk::<ARCHIVED_LEN>()
        && let Ok(tag) = <[u8; TAG_LEN]>::try_from(tag)
    {
        parts = (*nonce, *layer, tag);
    }
    let (nonce, mut layer, tag) = parts;
    let opened = open.open(&cipher_key, &nonce, aad, &mut layer, &tag);
    wipe(&mut cipher_key);
    opened.map_err(|_| Error::RecordRejected)?;
    *sealed = layer;
    Ok(())
}

/// The identifier of the archive key, the ciphertext and the check that a record of an archive
/// holds.
fn split_archived(
    sealed: &[u8; ARCHIVED_LEN],
) -> ([u8; ID_LEN], [u8; CIPHERTEXT_LEN], [u8; ID_LEN]) {
    let mut parts = ([0; ID_LEN], [0; CIPHERTEXT_LEN], [0; ID_LEN]);
    if let Some((id, rest)) = sealed.split_first_chunk::<ID_LEN>()
        && let Some((ciphertext, check)) = rest.split_first_chunk::<CIPHERTEXT_LEN>()
        && let Ok(check) = <[u8; ID_LEN]>::try_from(check)
    {
        parts = (*id, *ciphertext, check);
    }
    parts
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        ARCHIVE_RECORD_LEN, ARCHIVED_LEN, ArchivePublic, CIPHERTEXT_LEN, ID_LEN, KeyId, PUBLIC_LEN,
    };
    use crate::derive::{derive_archive_batch, derive_archive_check, derive_archive_seal_key};
    use crate::epoch::{Erasure, Root, RootFailed};
    use crate::key::Key;
    use crate::key::tests::{Counting, Failing, Random, from_environment};
    use crate::record::AssociatedData;
    use crate::slots::batch::{Chunks, seal_batch_in};
    use crate::slots::data::tests::pattern_of;
    use crate::slots::tests::{EPOCH, epoch_key};
    use crate::timing::timed;
    use crate::xwing::{self, wrong_known};
    use crate::{
        ARCHIVE_KEY_RECORD_LEN, CHUNK_LEN, Epoch, Error, Handle, KeyLength, Purpose, Slot, Slots,
        batch_data_len, batch_len, seal,
    };
    use std::{vec, vec::Vec};

    struct Platform;

    impl Root for Platform {
        fn switch(&mut self, _: u64) -> Result<(), RootFailed> {
            Ok(())
        }

        fn erase(&mut self, _: u64) -> Erasure {
            Erasure::Guaranteed
        }
    }

    /// A stored key for wrapping, a stored key of the archive, two keys of chats for their archives
    /// and the public key of an archive key created under the first two, with its record.
    fn archive<'a>(
        slots: &mut Slots<'a>,
    ) -> (
        [Handle<'a>; 4],
        ArchivePublic<'a>,
        [u8; ARCHIVE_KEY_RECORD_LEN],
    ) {
        let mut generate = |purpose| {
            slots
                .generate(purpose, KeyLength::Bytes32, &mut Counting)
                .unwrap()
        };
        let keys = [
            generate(Purpose::Wrap),
            generate(Purpose::ArchiveWrap),
            generate(Purpose::ArchiveSeal),
            generate(Purpose::ArchiveSeal),
        ];
        let [stored, store, ..] = keys;
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        let public = slots
            .archive_public_key(stored, b"archive", &record)
            .unwrap();
        (keys, public, record)
    }

    /// How long the body of data of `len` bytes is.
    fn body_len(len: usize) -> usize {
        usize::try_from(batch_len(u64::try_from(len).unwrap()).unwrap()).unwrap()
    }

    /// `data` archived under the key of a chat `chat` to the archive key `public` names, for
    /// `context`: the record and the body.
    fn archive_batch<'a>(
        slots: &mut Slots<'a>,
        chat: Handle<'a>,
        public: &ArchivePublic<'a>,
        context: &[u8],
        data: &[u8],
    ) -> ([u8; ARCHIVE_RECORD_LEN], Vec<u8>) {
        let (mut record, mut body) = ([0; ARCHIVE_RECORD_LEN], vec![0; body_len(data.len())]);
        slots
            .archive(
                chat,
                public,
                context,
                &mut Counting,
                data,
                &mut record,
                &mut body,
            )
            .unwrap();
        (record, body)
    }

    /// What opening the batch of `record` and `body` gives, into data as long as the body holds,
    /// or five bytes for a body no batch has, that start as 7s.
    fn open_batch<'a>(
        slots: &Slots<'a>,
        (archive, chat): (Handle<'a>, Handle<'a>),
        context: &[u8],
        record: &[u8; ARCHIVE_RECORD_LEN],
        body: &[u8],
    ) -> (Result<(), Error>, Vec<u8>) {
        let held = batch_data_len(u64::try_from(body.len()).unwrap())
            .map_or(5, |len| usize::try_from(len).unwrap());
        let mut data = vec![7; held];
        let opened = slots.open_archive(archive, chat, context, record, body, &mut data);
        (opened, data)
    }

    fn wiped(bytes: &[u8]) -> bool {
        bytes.iter().all(|&byte| byte == 0)
    }

    /// A batch opens only with the archive key it was archived to, the key of its chat and its
    /// context, and its own body; a refusal wipes the data.
    #[test]
    fn a_batch_opens_with_its_archive_key_and_its_chat_only() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, other_chat], public, key_record) = archive(&mut slots);
        let data = pattern_of(CHUNK_LEN + 5);
        let (record, body) = archive_batch(&mut slots, chat, &public, b"chat", &data);
        let (again, again_body) = archive_batch(&mut slots, chat, &public, b"chat", &data);
        assert_ne!(again, record);
        assert_ne!(again_body, body);
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        for (handles, context, refused) in [
            ((key, other_chat), &b"chat"[..], Error::RecordRejected),
            ((key, chat), &b"chap"[..], Error::RecordRejected),
            ((chat, chat), &b"chat"[..], Error::WrongPurpose),
            ((key, key), &b"chat"[..], Error::WrongPurpose),
            ((key, chat), &b""[..], Error::InvalidContext),
        ] {
            let (opened, held) = open_batch(&slots, handles, context, &record, &body);
            assert_eq!(opened, Err(refused));
            assert!(wiped(&held));
        }
        let mut changed = record;
        changed[ARCHIVE_RECORD_LEN - 1] ^= 1;
        let (opened, held) = open_batch(&slots, (key, chat), b"chat", &changed, &body);
        assert_eq!(opened, Err(Error::RecordRejected));
        assert!(wiped(&held));
        let (opened, held) = open_batch(&slots, (key, chat), b"chat", &record, &again_body);
        assert_eq!(opened, Err(Error::RecordRejected));
        assert!(wiped(&held));
        assert_eq!(
            open_batch(&slots, (key, chat), b"chat", &record, &body),
            (Ok(()), data.clone())
        );
        assert_eq!(
            open_batch(&slots, (key, chat), b"chat", &again, &again_body),
            (Ok(()), data)
        );
    }

    /// The context names the place of a batch: the record and body of another batch of the same
    /// context open in its place, those of another context do not.
    #[test]
    fn the_context_is_the_place_of_a_batch() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, _], public, key_record) = archive(&mut slots);
        let (first, first_body) = archive_batch(&mut slots, chat, &public, b"chat", b"first");
        let (second, second_body) = archive_batch(&mut slots, chat, &public, b"chat", b"second");
        let (other, other_body) = archive_batch(&mut slots, chat, &public, b"chap", b"other");
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let handles = (key, chat);
        assert_eq!(
            open_batch(&slots, handles, b"chat", &first, &first_body),
            (Ok(()), b"first".to_vec())
        );
        assert_eq!(
            open_batch(&slots, handles, b"chat", &second, &second_body),
            (Ok(()), b"second".to_vec())
        );
        let (opened, held) = open_batch(&slots, handles, b"chat", &other, &other_body);
        assert_eq!(opened, Err(Error::RecordRejected));
        assert!(wiped(&held));
        let (opened, held) = open_batch(&slots, handles, b"chap", &first, &first_body);
        assert_eq!(opened, Err(Error::RecordRejected));
        assert!(wiped(&held));
        assert_eq!(
            open_batch(&slots, handles, b"chap", &other, &other_body),
            (Ok(()), b"other".to_vec())
        );
    }

    /// A body changed in any chunk or tag, cut by a chunk, grown by one, with its chunks swapped,
    /// or of a length no body has, does not open, and the data are wiped; data of another length
    /// than the body holds are refused as `WrongLength`.
    #[test]
    fn a_changed_body_is_refused() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, _], public, key_record) = archive(&mut slots);
        let data = pattern_of(2 * CHUNK_LEN + 5);
        let (record, body) = archive_batch(&mut slots, chat, &public, b"chat", &data);
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let handles = (key, chat);
        let whole = CHUNK_LEN + 16;
        let mut bodies = Vec::new();
        for at in [0, CHUNK_LEN, whole, 2 * whole, body.len() - 1] {
            let mut changed = body.clone();
            changed[at] ^= 0x10;
            bodies.push(changed);
        }
        bodies.push(body[..2 * whole].to_vec());
        let mut grown = body[..2 * whole].to_vec();
        grown.extend_from_slice(&body[whole..]);
        bodies.push(grown);
        let mut swapped = body[whole..2 * whole].to_vec();
        swapped.extend_from_slice(&body[..whole]);
        swapped.extend_from_slice(&body[2 * whole..]);
        bodies.push(swapped);
        bodies.push(body[..whole + 16].to_vec());
        for (round, changed) in bodies.iter().enumerate() {
            let (opened, held) = open_batch(&slots, handles, b"chat", &record, changed);
            assert_eq!(opened, Err(Error::RecordRejected), "{round}");
            assert!(wiped(&held), "{round}");
        }
        for len in [data.len() - 1, data.len() + 1] {
            let mut held = vec![7; len];
            assert_eq!(
                slots.open_archive(key, chat, b"chat", &record, &body, &mut held),
                Err(Error::WrongLength)
            );
            assert!(wiped(&held));
        }
        assert_eq!(
            open_batch(&slots, handles, b"chat", &record, &body),
            (Ok(()), data)
        );
    }

    /// Every call on a batch of an archive derives and runs the cipher and X-Wing inside the switch
    /// of data-independent timing, and with the mode on where it is offered.
    #[test]
    fn every_call_on_a_record_of_an_archive_holds_data_independent_timing() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, other_chat], _, key_record) = archive(&mut slots);
        let public = timed(|| {
            slots
                .archive_public_key(stored, b"archive", &key_record)
                .unwrap()
        });
        let data = pattern_of(CHUNK_LEN + 5);
        let (mut record, mut body) = ([0; ARCHIVE_RECORD_LEN], vec![0; body_len(data.len())]);
        timed(|| {
            slots
                .archive(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    &data,
                    &mut record,
                    &mut body,
                )
                .unwrap();
        });
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let mut opened = vec![0; data.len()];
        timed(|| {
            slots
                .open_archive(key, chat, b"chat", &record, &body, &mut opened)
                .unwrap();
        });
        let mut moved = [0; ARCHIVE_RECORD_LEN];
        timed(|| {
            slots
                .reseal_archive(
                    chat,
                    other_chat,
                    b"chat",
                    &mut Counting,
                    &record,
                    &mut moved,
                )
                .unwrap();
        });
    }

    /// A public key serves only the slots and the epoch it was read in, and shows nothing of
    /// itself.
    #[test]
    fn a_public_key_serves_its_slots_and_epoch_only() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, _, chat, _], public, key_record) = archive(&mut slots);
        assert_eq!(std::format!("{public:?}"), "ArchivePublic { .. }");
        let (mut other_memory, mut other_epoch) = ([const { Slot::empty() }; 8], Epoch::empty());
        let mut other = Slots::new(&mut other_memory, &mut other_epoch, EPOCH, &mut epoch_key());
        let ([_, _, other_chat, _], ..) = archive(&mut other);
        let (mut record, mut body) = ([5; ARCHIVE_RECORD_LEN], [5; 19]);
        assert_eq!(
            other.archive(
                other_chat,
                &public,
                b"chat",
                &mut Counting,
                b"abc",
                &mut record,
                &mut body
            ),
            Err(Error::StaleRecord)
        );
        assert_eq!((record, body), ([5; ARCHIVE_RECORD_LEN], [0; 19]));
        slots.begin_epoch(&mut [8; 32]).unwrap();
        let mut carried = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .carry_archive_key(
                stored,
                stored,
                b"archive",
                &mut Counting,
                &key_record,
                &mut carried,
            )
            .unwrap();
        slots.settle();
        assert_eq!(slots.commit_epoch(&mut Platform), Ok(Erasure::Guaranteed));
        body = [5; 19];
        assert_eq!(
            slots.archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                b"abc",
                &mut record,
                &mut body
            ),
            Err(Error::StaleRecord)
        );
        assert_eq!((record, body), ([5; ARCHIVE_RECORD_LEN], [0; 19]));
        let public = slots
            .archive_public_key(stored, b"archive", &carried)
            .unwrap();
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                b"abc",
                &mut record,
                &mut body,
            )
            .unwrap();
        slots.release(chat).unwrap();
        assert_eq!(
            slots.archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                b"abc",
                &mut record,
                &mut body
            ),
            Err(Error::StaleHandle)
        );
    }

    /// A batch archived to a public key other than its archive key's, or whose ciphertext was
    /// changed under the key of its chat, does not open: the check of the shared secret fails.
    #[test]
    fn a_batch_of_another_public_key_is_refused() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, _], public, key_record) = archive(&mut slots);
        let mut second = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut second)
            .unwrap();
        let other = slots
            .archive_public_key(stored, b"archive", &second)
            .unwrap();
        let swapped = ArchivePublic {
            public: other.public,
            ..public
        };
        let (record, body) = archive_batch(&mut slots, chat, &swapped, b"chat", b"abc");
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let (opened, held) = open_batch(&slots, (key, chat), b"chat", &record, &body);
        assert_eq!(opened, Err(Error::PublicKeyMismatch));
        assert!(wiped(&held));
        let (record, body) = archive_batch(&mut slots, chat, &public, b"chat", b"abc");
        let associated = AssociatedData::new(b"chat").unwrap();
        let mut sealed = [0; ARCHIVED_LEN];
        super::open_archived(
            slots.memory[chat.index].wrapping_key().0,
            associated.bytes(),
            &record,
            &mut sealed,
            &mut seal::open,
        )
        .unwrap();
        let (id, mut ciphertext, check) = super::split_archived(&sealed);
        ciphertext[CIPHERTEXT_LEN - 1] ^= 1;
        let mut changed = [0; ARCHIVE_RECORD_LEN];
        super::seal_archived(
            slots.memory[chat.index].wrapping_key().0,
            &[2; 12],
            associated.bytes(),
            (&id, &ciphertext, &check),
            (&mut changed, seal::seal),
        )
        .unwrap();
        let (opened, held) = open_batch(&slots, (key, chat), b"chat", &changed, &body);
        assert_eq!(opened, Err(Error::PublicKeyMismatch));
        assert!(wiped(&held));
        assert_eq!(
            open_batch(&slots, (key, chat), b"chat", &record, &body),
            (Ok(()), b"abc".to_vec())
        );
    }

    /// A record of an archive written to one archive key does not open with another.
    #[test]
    fn a_record_of_another_archive_key_is_refused() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, _], public, _) = archive(&mut slots);
        let (record, body) = archive_batch(&mut slots, chat, &public, b"chat", b"abc");
        let mut other = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut other)
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &other)
            .unwrap();
        let (opened, held) = open_batch(&slots, (key, chat), b"chat", &record, &body);
        assert_eq!(opened, Err(Error::WrongArchiveKey));
        assert!(wiped(&held));
    }

    /// A record moves to another key of the chat for its archive without the archive key; the
    /// moved record opens with that key only, and opens the same body.
    #[test]
    fn a_record_of_an_archive_is_resealed_without_its_archive_key() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, other_chat], public, key_record) = archive(&mut slots);
        let (record, body) = archive_batch(&mut slots, chat, &public, b"chat", b"abc");
        let mut moved = [9; ARCHIVE_RECORD_LEN];
        for (from, to, context, refused) in [
            (other_chat, chat, &b"chat"[..], Error::RecordRejected),
            (chat, other_chat, &b"chap"[..], Error::RecordRejected),
            (chat, stored, &b"chat"[..], Error::WrongPurpose),
            (stored, other_chat, &b"chat"[..], Error::WrongPurpose),
        ] {
            assert_eq!(
                slots.reseal_archive(from, to, context, &mut Counting, &record, &mut moved),
                Err(refused)
            );
            assert_eq!(moved, [9; ARCHIVE_RECORD_LEN]);
        }
        assert_eq!(
            slots.reseal_archive(chat, other_chat, b"chat", &mut Failing, &record, &mut moved),
            Err(Error::EntropyFailed)
        );
        assert_eq!(moved, [9; ARCHIVE_RECORD_LEN]);
        slots
            .reseal_archive(
                chat,
                other_chat,
                b"chat",
                &mut Counting,
                &record,
                &mut moved,
            )
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let (opened, _) = open_batch(&slots, (key, chat), b"chat", &moved, &body);
        assert_eq!(opened, Err(Error::RecordRejected));
        assert_eq!(
            open_batch(&slots, (key, other_chat), b"chat", &moved, &body),
            (Ok(()), b"abc".to_vec())
        );
    }

    /// The public key comes only from a record that opens with the profile's stored key, its
    /// context and the key of this epoch.
    #[test]
    fn the_public_key_is_read_from_its_record_only() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, _], public, key_record) = archive(&mut slots);
        let secret = slots.import32(Purpose::Wrap, &mut [3; 32]).unwrap();
        for (profile, context, refused) in [
            (stored, &b"vault"[..], Error::StaleRecord),
            (secret, &b"archive"[..], Error::WrongLevel),
            (chat, &b"archive"[..], Error::WrongPurpose),
            (stored, &b""[..], Error::InvalidContext),
        ] {
            assert_eq!(
                slots
                    .archive_public_key(profile, context, &key_record)
                    .map(|_| ()),
                Err(refused)
            );
        }
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let mut seed_public = [0; PUBLIC_LEN];
        let (seed, id) = slots.memory[key.index].wrapping_key();
        xwing::public_key(super::seed_of(seed).unwrap(), &mut seed_public);
        assert_eq!(public.public, seed_public);
        assert_eq!(public.id, id.bytes());
    }

    /// A public key X-Wing refuses, a wrong answer of X-Wing, a failed source, a body of another
    /// length and a failed seal of the body archive nothing: the record is left as it was, and
    /// the body is wiped. An opening that fails wipes the data.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one test goes through every failure")]
    fn an_archive_that_fails_writes_no_record_and_wipes_its_body() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, _], public, key_record) = archive(&mut slots);
        let mut unreduced = ArchivePublic {
            id: [0; ID_LEN],
            public: public.public,
            slots: public.slots,
            epoch: public.epoch,
            memory: core::marker::PhantomData,
        };
        unreduced.public[..2].copy_from_slice(&[0xff, 0xff]);
        let mut record = [5; ARCHIVE_RECORD_LEN];
        let wrong = wrong_known();
        let failing = |_: &[u8; 32], _: &[u8], _: &[u8], _: &mut [u8]| Err(Error::CipherFailed);
        for (round, (public, entropy, known, length, refused)) in [
            (&unreduced, true, true, 19, Error::RecordRejected),
            (&public, false, true, 19, Error::EntropyFailed),
            (&public, true, false, 19, Error::CipherFailed),
            (&public, true, true, 18, Error::WrongLength),
            (&public, true, true, 20, Error::WrongLength),
        ]
        .into_iter()
        .enumerate()
        {
            let mut body = vec![5; length];
            let archived = if entropy {
                slots.archive_on_stack(
                    chat,
                    public,
                    b"chat",
                    &mut Counting,
                    (b"abc", &mut record, &mut body),
                    if known { &xwing::KNOWN } else { &wrong },
                    (seal::seal, Chunks),
                )
            } else {
                slots.archive(
                    chat,
                    public,
                    b"chat",
                    &mut Failing,
                    b"abc",
                    &mut record,
                    &mut body,
                )
            };
            assert_eq!(archived, Err(refused), "{round}");
            assert_eq!(record, [5; ARCHIVE_RECORD_LEN], "{round}");
            assert!(wiped(&body), "{round}");
        }
        let mut body = [5; 19];
        assert_eq!(
            slots.archive(
                stored,
                &public,
                b"chat",
                &mut Counting,
                b"abc",
                &mut record,
                &mut body
            ),
            Err(Error::WrongPurpose)
        );
        assert_eq!(record, [5; ARCHIVE_RECORD_LEN]);
        assert!(wiped(&body));
        body = [5; 19];
        assert_eq!(
            slots.archive_on_stack(
                chat,
                &public,
                b"chat",
                &mut Counting,
                (b"abc", &mut record, &mut body),
                &xwing::KNOWN,
                (seal::seal, failing),
            ),
            Err(Error::CipherFailed)
        );
        assert_eq!(record, [5; ARCHIVE_RECORD_LEN]);
        assert!(wiped(&body));
        let (record, body) = archive_batch(&mut slots, chat, &public, b"chat", b"abc");
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let refusing = |_: &[u8; 32], _: &[u8], _: &[u8], _: &mut [u8]| Err(Error::RecordRejected);
        let mut opened = [7; 3];
        assert_eq!(
            slots.open_archive_on_stack(
                (key, chat),
                b"chat",
                (&record, &body, &mut opened),
                &wrong,
                (seal::open, Chunks),
            ),
            Err(Error::CipherFailed)
        );
        assert_eq!(opened, [0; 3]);
        opened = [7; 3];
        assert_eq!(
            slots.open_archive_on_stack(
                (key, chat),
                b"chat",
                (&record, &body, &mut opened),
                &xwing::KNOWN,
                (seal::open, refusing),
            ),
            Err(Error::RecordRejected)
        );
        assert_eq!(opened, [0; 3]);
    }

    /// Every changed bit of a record of an archive is refused by the move, which opens it as the
    /// opening does and writes nothing, without optimisation, where the cipher is slow, one bit of
    /// every byte; and a changed byte in each part of it by the opening.
    #[test]
    #[expect(clippy::integer_division, reason = "a test picks bits of a record")]
    fn every_changed_bit_of_a_record_of_an_archive_is_refused() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, other_chat], public, key_record) = archive(&mut slots);
        let (record, body) = archive_batch(&mut slots, chat, &public, b"chat", b"abc");
        let mut moved = [9; ARCHIVE_RECORD_LEN];
        let bits = (0..ARCHIVE_RECORD_LEN * 8)
            .filter(|bit| !cfg!(lethewis_unoptimised) || bit % 8 == bit / 8 % 8);
        for bit in bits {
            let mut changed = record;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                slots.reseal_archive(
                    chat,
                    other_chat,
                    b"chat",
                    &mut Counting,
                    &changed,
                    &mut moved
                ),
                Err(Error::RecordRejected),
                "bit {bit}"
            );
            assert_eq!(moved, [9; ARCHIVE_RECORD_LEN], "bit {bit}");
        }
        assert_eq!(
            slots.reseal_archive(
                chat,
                other_chat,
                b"chat",
                &mut Counting,
                &record,
                &mut moved
            ),
            Ok(())
        );
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        // The nonce, the identifier, the ciphertext, the check and the tag, at each end.
        for at in [0, 11, 12, 27, 28, 1147, 1148, 1163, 1164, 1179] {
            let mut changed = record;
            changed[at] ^= 0x80;
            let (opened, held) = open_batch(&slots, (key, chat), b"chat", &changed, &body);
            assert_eq!(opened, Err(Error::RecordRejected), "byte {at}");
            assert!(wiped(&held), "byte {at}");
        }
        assert_eq!(
            open_batch(&slots, (key, chat), b"chat", &record, &body),
            (Ok(()), b"abc".to_vec())
        );
    }

    /// `id`, `ciphertext` and `check` sealed under the key of the chat `chat` for its archive,
    /// bound to `context`, with `nonce`, laid out without the library's code for it.
    fn seal_parts(
        chat: &Key,
        context: &[u8],
        nonce: &[u8; 12],
        (id, ciphertext, check): (&[u8; ID_LEN], &[u8; CIPHERTEXT_LEN], &[u8; ID_LEN]),
    ) -> [u8; ARCHIVE_RECORD_LEN] {
        let mut cipher_key = [0; 32];
        derive_archive_seal_key(chat, &mut cipher_key).unwrap();
        let mut sealed = [0; ARCHIVED_LEN];
        sealed[..16].copy_from_slice(id);
        sealed[16..1136].copy_from_slice(ciphertext);
        sealed[1136..].copy_from_slice(check);
        let associated = AssociatedData::new(context).unwrap();
        let tag = seal::seal(&cipher_key, nonce, associated.bytes(), &mut sealed).unwrap();
        let mut record = [0; ARCHIVE_RECORD_LEN];
        record[..12].copy_from_slice(nonce);
        record[12..1164].copy_from_slice(&sealed);
        record[1164..].copy_from_slice(&tag);
        record
    }

    /// What a record of an archive under the key of the chat `chat` for its archive holds, bound to
    /// `context`, read without the library's code for it.
    fn opened_parts(
        chat: &Key,
        context: &[u8],
        record: &[u8; ARCHIVE_RECORD_LEN],
    ) -> Result<[u8; ARCHIVED_LEN], seal::Rejected> {
        let mut cipher_key = [0; 32];
        derive_archive_seal_key(chat, &mut cipher_key).unwrap();
        let associated = AssociatedData::new(context).unwrap();
        let mut sealed = <[u8; ARCHIVED_LEN]>::try_from(&record[12..1164]).unwrap();
        let tag = <[u8; 16]>::try_from(&record[1164..]).unwrap();
        let nonce = <[u8; 12]>::try_from(&record[..12]).unwrap();
        seal::open(&cipher_key, &nonce, associated.bytes(), &mut sealed, &tag).map(|()| sealed)
    }

    /// What a round of random records of an archive gets wrong.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        Nothing,
        /// A context of no bytes or of more than 255.
        Context,
        /// A context other than the record's.
        OtherContext,
        /// A changed bit of the record.
        Record,
        /// The record under the key of another chat.
        OtherChat,
        /// The record under a key no slot holds.
        Outsider,
        /// The identifier of another archive key.
        Id,
        /// A changed bit of the ciphertext.
        Ciphertext,
        /// A ciphertext of random bytes.
        RandomCiphertext,
        /// A changed bit of the check, in each byte in turn.
        Check,
        /// A changed bit of the body.
        Body,
    }

    /// Each fault in turn; one round in four gets a second, at random.
    const FAULTS: [Fault; 14] = [
        Fault::Nothing,
        Fault::Nothing,
        Fault::Nothing,
        Fault::Context,
        Fault::OtherContext,
        Fault::Record,
        Fault::OtherChat,
        Fault::Outsider,
        Fault::Id,
        Fault::Ciphertext,
        Fault::RandomCiphertext,
        Fault::Check,
        Fault::Check,
        Fault::Body,
    ];

    /// Records of an archive sealed through the real derivation and cipher and laid out by hand,
    /// from real encapsulations to the archive key, with bodies of random data sealed under the key
    /// the encapsulation gives, with every fault of [`FAULTS`] in turn and at times a second: a
    /// context, the key of the chat, the identifier, the ciphertext, the check or the body wrong.
    /// The opening and the move never panic, refuse exactly what they should, with the error they
    /// should; the opening gives the data or wipes them, and the move writes the same parts under
    /// the other key or nothing.
    #[expect(clippy::too_many_lines, reason = "one round builds and reads a record")]
    fn open_random_archive_records(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, other_chat], public, key_record) = archive(&mut slots);
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let (mut faults, mut checked) = (FAULTS.iter().cycle(), (0..ID_LEN).cycle());
        for round in 0..rounds {
            let first = *faults.next().unwrap();
            let second = if random.below(4) == 0 {
                FAULTS[random.below(FAULTS.len())]
            } else {
                Fault::Nothing
            };
            let has = |fault| first == fault || second == fault;
            let mut outsider = Key::empty();
            outsider.copy32(&random.bytes());
            let context: Vec<u8> = if has(Fault::Context) {
                (0..[0, 256, 300][random.below(3)]).map(|_| 7).collect()
            } else {
                (0..=random.below(255))
                    .map(|_| random.bytes::<1>()[0])
                    .collect()
            };
            let sealed_for = if has(Fault::Context) {
                &b"chat"[..]
            } else {
                &context[..]
            };
            let (mut ciphertext, mut shared) = ([0; CIPHERTEXT_LEN], [0; 32]);
            xwing::encapsulate(
                &public.public,
                &random.bytes(),
                &mut ciphertext,
                &mut shared,
            )
            .unwrap();
            let mut secret = Key::empty();
            secret.copy32(&shared);
            let (mut batch, mut check) = ([0; 32], KeyId::empty());
            derive_archive_batch(&secret, &ciphertext, &mut batch).unwrap();
            let data: Vec<u8> = (0..random.below(40))
                .map(|_| random.bytes::<1>()[0])
                .collect();
            let mut body = vec![0; body_len(data.len())];
            let batched = AssociatedData::of_batch(sealed_for).unwrap();
            seal_batch_in::<CHUNK_LEN>(&batch, batched.bytes(), &data, &mut body, seal::Aes)
                .unwrap();
            if has(Fault::Body) {
                let at = random.below(body.len());
                body[at] ^= 1 << random.below(8);
            }
            derive_archive_check(&secret, &ciphertext, &mut check).unwrap();
            let mut check = check.bytes();
            let id = if has(Fault::Id) {
                random.bytes()
            } else {
                public.id
            };
            if has(Fault::Ciphertext) {
                ciphertext[random.below(CIPHERTEXT_LEN)] ^= 1 << random.below(8);
            }
            if has(Fault::RandomCiphertext) {
                ciphertext = random.bytes();
            }
            if has(Fault::Check) {
                check[checked.next().unwrap()] ^= 1 << random.below(8);
            }
            let sealed_by = if has(Fault::Outsider) {
                &outsider
            } else if has(Fault::OtherChat) {
                slots.memory[other_chat.index].wrapping_key().0
            } else {
                slots.memory[chat.index].wrapping_key().0
            };
            let parts = (&id, &ciphertext, &check);
            let mut record = seal_parts(sealed_by, sealed_for, &random.bytes(), parts);
            if has(Fault::Record) {
                record[random.below(ARCHIVE_RECORD_LEN)] ^= 1 << random.below(8);
            }
            let mut asked = context.clone();
            if has(Fault::OtherContext) && !has(Fault::Context) {
                let at = random.below(asked.len());
                asked[at] ^= 1 << random.below(8);
            }

            let at = std::format!("round {round} of seed {seed}");
            let opens = if has(Fault::Context) {
                Err(Error::InvalidContext)
            } else if has(Fault::OtherContext)
                || has(Fault::Record)
                || has(Fault::OtherChat)
                || has(Fault::Outsider)
            {
                Err(Error::RecordRejected)
            } else {
                Ok(())
            };
            let expected = opens.and(if has(Fault::Id) {
                Err(Error::WrongArchiveKey)
            } else if has(Fault::Ciphertext) || has(Fault::RandomCiphertext) || has(Fault::Check) {
                Err(Error::PublicKeyMismatch)
            } else if has(Fault::Body) {
                Err(Error::RecordRejected)
            } else {
                Ok(())
            });
            let (result, opened) = open_batch(&slots, (key, chat), &asked, &record, &body);
            assert_eq!(result, expected, "{at}");
            if result.is_ok() {
                assert_eq!(opened, data, "{at}");
            } else {
                assert!(wiped(&opened), "{at}");
            }
            let mut moved = [9; ARCHIVE_RECORD_LEN];
            let result =
                slots.reseal_archive(chat, other_chat, &asked, &mut Counting, &record, &mut moved);
            assert_eq!(result, opens, "{at}");
            if result.is_ok() {
                let mut parts = [0; ARCHIVED_LEN];
                parts[..16].copy_from_slice(&id);
                parts[16..1136].copy_from_slice(&ciphertext);
                parts[1136..].copy_from_slice(&check);
                let other = slots.memory[other_chat.index].wrapping_key().0;
                assert_eq!(opened_parts(other, sealed_for, &moved), Ok(parts), "{at}");
            } else {
                assert_eq!(moved, [9; ARCHIVE_RECORD_LEN], "{at}");
            }
        }
    }

    #[test]
    fn random_records_of_an_archive_open_as_their_parts_say() {
        open_random_archive_records(100, 1);
    }

    /// The same over as many rounds and from the seed `LETHEWIS_RANDOM_ROUNDS` and
    /// `LETHEWIS_RANDOM_SEED` give.
    #[test]
    #[ignore = "long; the rounds and the seed come from the environment"]
    fn many_random_records_of_an_archive_open_as_their_parts_say() {
        open_random_archive_records(
            from_environment("LETHEWIS_RANDOM_ROUNDS", 10_000),
            from_environment("LETHEWIS_RANDOM_SEED", 2),
        );
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    extern crate std;

    use core::hint::black_box;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use shake::{ExtendableOutput, Shake256, Update, XofReader};

    use super::super::archive::stack::layer_secrets;
    use super::super::stack::keying_secrets;
    use super::{ARCHIVE_RECORD_LEN, ARCHIVED_LEN, ArchivePublic, open_archived, split_archived};
    use crate::block::chunk_nonce;
    use crate::derive::stack::{hedge_secrets, secrets_of};
    use crate::derive::{
        Branch, SALT, derive_archive_batch, derive_archive_randomness, derive_archive_seal_key,
        hedge,
    };
    use crate::key::Key;
    use crate::key::tests::{Counting, Failing, counted};
    use crate::record::AssociatedData;
    use crate::residue::{
        assert_clean, below_pad, depth_changed, key_dependent, panic_at, residue,
    };
    use crate::slots::batch::{self, Chunks};
    use crate::slots::tests::{EPOCH, flipped_epoch_key};
    use crate::xwing::stack::{encapsulation_secrets, seed_secrets};
    use crate::{
        ARCHIVE_KEY_RECORD_LEN, Epoch, Error, Handle, KeyLength, Purpose, Slot, Slots, seal, xwing,
    };

    /// The data of a batch: 48 bytes that depend on `flip`, so that they tell one run from the
    /// other on the stack.
    fn data_of(flip: u8) -> [u8; 48] {
        let mut shake = Shake256::default();
        shake.update(&[flip, 0x2b]);
        let mut data = [0; 48];
        shake.finalize_xof().read(&mut data);
        data
    }

    /// The body of those data.
    type Body = [u8; 64];

    /// The stack each call needs, and the depth of the wipe after it, in KiB, in an optimised build
    /// and in one without optimisation; archiving and opening, with a chunk of the body in a buffer
    /// of its own, need more.
    const NEEDS: [usize; 2] = [100, 232];
    const WIPES: [usize; 2] = [96, 224];
    const ARCHIVE_NEEDS: [usize; 2] = [164, 232];
    const ARCHIVE_WIPES: [usize; 2] = [160, 224];

    /// The documentation of the public call `name` in this file, its lines joined.
    fn documentation(name: &str) -> String {
        let source = include_str!("archived.rs");
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

    /// The documentation of each call on a record of an archive states the stack it needs and the
    /// depth of the wipe after it, and those depths are the library's.
    #[test]
    fn the_documentation_states_the_stack_calls_need() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(WIPES[build] * 1024, xwing::STACK_WIPE);
        assert_eq!(ARCHIVE_WIPES[build] * 1024, batch::STACK_WIPE);
        for (call, needs, wipes) in [
            ("archive_public_key", NEEDS, WIPES),
            ("archive", ARCHIVE_NEEDS, ARCHIVE_WIPES),
            ("open_archive", ARCHIVE_NEEDS, ARCHIVE_WIPES),
            ("reseal_archive", NEEDS, WIPES),
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

    /// The handles of a set of slots over `memory` in an epoch whose key `flip` changes: a stored
    /// key for wrapping, two keys of chats for their archives and a loaded archive key.
    type Keys<'a> = [Handle<'a>; 4];

    /// Those slots and keys, the record of the archive key and its public key, the record and body
    /// of a batch, and the secrets.
    type Archived<'a> = (
        Slots<'a>,
        Keys<'a>,
        ([u8; ARCHIVE_KEY_RECORD_LEN], ArchivePublic<'a>),
        ([u8; ARCHIVE_RECORD_LEN], Body),
        Vec<Vec<u8>>,
    );

    /// Those slots, with the record of the archive key, the public key it holds, the record and
    /// body of a batch of [`data_of`] archived to it under the first key of a chat, and what the
    /// calls on it handle: the keys, the seed and what X-Wing makes of it, the randomness of the
    /// encapsulation and what X-Wing makes of that, the shared secret, the key of the body, the
    /// data, what the ciphers of the record and the body and the derivation of the key of the
    /// record handle, and the key of the epoch and the hedges of both draws under it.
    #[expect(
        clippy::too_many_lines,
        reason = "the secrets of every call are gathered at once"
    )]
    fn archived<'a>(memory: &'a mut [Slot], epoch: &'a mut Epoch, flip: u8) -> Archived<'a> {
        let mut slots = Slots::new(memory, epoch, EPOCH, &mut flipped_epoch_key(flip));
        let generate = |slots: &mut Slots<'a>, purpose| {
            slots
                .generate(purpose, KeyLength::Bytes32, &mut Counting)
                .unwrap()
        };
        let stored = generate(&mut slots, Purpose::Wrap);
        let store = generate(&mut slots, Purpose::ArchiveWrap);
        let chat = generate(&mut slots, Purpose::ArchiveSeal);
        let other = generate(&mut slots, Purpose::ArchiveSeal);
        let mut key_record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut key_record)
            .unwrap();
        let public = slots
            .archive_public_key(stored, b"archive", &key_record)
            .unwrap();
        let count = slots.epoch.drawn;
        let data = data_of(flip);
        let (mut record, mut body) = ([0; ARCHIVE_RECORD_LEN], [0; 64]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &data,
                &mut record,
                &mut body,
            )
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let keys = (
            slots.memory[stored.index].wrapping_key().0,
            slots.memory[store.index].wrapping_key().0,
            &slots.epoch.key,
        );
        let layers = layer_secrets(keys, &key_record);
        slots.release(store).unwrap();
        let bytes = |slots: &Slots<'_>, handle: Handle<'_>| {
            slots.memory[handle.index].wrapping_key().0.bytes()[..32].to_vec()
        };
        let mut secrets: Vec<Vec<u8>> = [stored, chat, other, key]
            .iter()
            .map(|&handle| bytes(&slots, handle))
            .collect();
        let mut shake = Shake256::default();
        shake.update(&secrets[3]);
        let mut expanded = [0; 96];
        shake.finalize_xof().read(&mut expanded);
        secrets.push(expanded.to_vec());
        let mut sealed = [0; ARCHIVED_LEN];
        open_archived(
            slots.memory[chat.index].wrapping_key().0,
            AssociatedData::new(b"chat").unwrap().bytes(),
            &record,
            &mut sealed,
            &mut seal::open,
        )
        .unwrap();
        let (_, ciphertext, _) = split_archived(&sealed);
        let mut shared = [0; 32];
        xwing::decapsulate(
            secrets[3].as_slice().try_into().unwrap(),
            &ciphertext,
            &mut shared,
        );
        secrets.push(shared.to_vec());
        let mut secret = Key::empty();
        secret.copy32(&shared);
        let mut batch = [0; 32];
        derive_archive_batch(&secret, &ciphertext, &mut batch).unwrap();
        let tag = body[48..].try_into().unwrap();
        secrets.extend(keying_secrets(&batch, &chunk_nonce(0, true), tag, 48));
        secrets.push(data.to_vec());
        secrets.extend(seed_secrets(secrets[3].as_slice().try_into().unwrap()));
        secrets.extend(layers);
        let chat_key = slots.memory[chat.index].wrapping_key().0;
        let drawn: [u8; 64] = core::array::from_fn(|at| u8::try_from(at).unwrap().wrapping_add(1));
        let mut hedged = [0; 64];
        hedge(
            &slots.epoch.key,
            count.wrapping_add(1),
            Branch::HedgeEncaps,
            &drawn,
            &mut hedged,
        )
        .unwrap();
        let mut randomness = [0; 64];
        derive_archive_randomness(chat_key, &hedged, &mut randomness).unwrap();
        secrets.extend([hedged.to_vec(), randomness.to_vec()]);
        let epoch_key = flipped_epoch_key(flip);
        secrets.extend(hedge_secrets(
            &epoch_key,
            count,
            Branch::HedgeNonce,
            &drawn[..12],
        ));
        secrets.extend(hedge_secrets(
            &epoch_key,
            count.wrapping_add(1),
            Branch::HedgeEncaps,
            &drawn,
        ));
        secrets.push(epoch_key.to_vec());
        secrets.extend(encapsulation_secrets(&public.public, &randomness));
        let mut seal_key = [0; 32];
        derive_archive_seal_key(chat_key, &mut seal_key).unwrap();
        let (nonce, tag) = (
            record[..12].try_into().unwrap(),
            record[1164..].try_into().unwrap(),
        );
        secrets.extend(keying_secrets(&seal_key, nonce, tag, ARCHIVED_LEN));
        secrets.extend(secrets_of(
            chat_key.material().unwrap(),
            SALT,
            Branch::ArchiveSeal,
        ));
        (
            slots,
            [stored, chat, other, key],
            (key_record, public),
            (record, body),
            secrets,
        )
    }

    /// What moving the record of a batch from the slots [`archived`] makes with `flip` to the second
    /// key of a chat handles to seal it: the cipher of the moved record, the derivation of its key
    /// and the hedge of its nonce.
    fn moved_secrets(flip: u8) -> Vec<Vec<u8>> {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [_, chat, other_chat, _], _, (record, _), _) =
            archived(&mut memory, &mut epoch, flip);
        let count = slots.epoch.drawn;
        let mut moved = [0; ARCHIVE_RECORD_LEN];
        slots
            .reseal_archive(
                chat,
                other_chat,
                b"chat",
                &mut Counting,
                &record,
                &mut moved,
            )
            .unwrap();
        let other = slots.memory[other_chat.index].wrapping_key().0;
        let mut seal_key = [0; 32];
        derive_archive_seal_key(other, &mut seal_key).unwrap();
        let (nonce, tag) = (
            moved[..12].try_into().unwrap(),
            moved[1164..].try_into().unwrap(),
        );
        let mut secrets = keying_secrets(&seal_key, nonce, tag, ARCHIVED_LEN);
        secrets.extend(secrets_of(
            other.material().unwrap(),
            SALT,
            Branch::ArchiveSeal,
        ));
        secrets.extend(hedge_secrets(
            &flipped_epoch_key(flip),
            count,
            Branch::HedgeNonce,
            &counted::<12>(),
        ));
        secrets
    }

    /// Fresh slots over `memory` in the state [`archived`] archives its batch in, with both keys of
    /// a chat and the public key of its archive key.
    fn before_archiving<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
    ) -> (Slots<'a>, [Handle<'a>; 2], ArchivePublic<'a>) {
        let mut slots = Slots::new(memory, epoch, EPOCH, &mut flipped_epoch_key(0));
        let mut generate = |purpose| {
            slots
                .generate(purpose, KeyLength::Bytes32, &mut Counting)
                .unwrap()
        };
        let stored = generate(Purpose::Wrap);
        let store = generate(Purpose::ArchiveWrap);
        let chats = [Purpose::ArchiveSeal; 2].map(&mut generate);
        let mut created = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut created)
            .unwrap();
        let public = slots
            .archive_public_key(stored, b"archive", &created)
            .unwrap();
        (slots, chats, public)
    }

    /// Reading a public key, archiving, opening and moving a record without the wipe after them
    /// leave on the stack some of what they handle, so that the test below can tell the wipe from
    /// its absence. Archiving runs from the state [`archived`] archives in, so it handles the same
    /// values.
    #[test]
    fn the_calls_on_records_of_an_archive_without_the_wipe_leave_residue() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 6], [const { Slot::empty() }; 6]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (.., mut others) = archived(&mut other, &mut other_epoch, 0x5a);
        let (
            mut slots,
            [stored, chat, other_chat, key],
            (key_record, _),
            (record, body),
            mut secrets,
        ) = archived(&mut memory, &mut epoch, 0);
        secrets.extend(moved_secrets(0));
        others.extend(moved_secrets(0x5a));
        let pieces = key_dependent(&secrets, &others);
        let known = xwing::unanswered();
        let range = below_pad(false, || {
            black_box(
                slots
                    .archive_public_key_on_stack(stored, b"archive", &key_record, seal::open)
                    .unwrap(),
            );
        });
        assert!(residue(range, &pieces) > 0, "a reading");
        let mut data = [0; 48];
        let range = below_pad(false, || {
            slots
                .open_archive_on_stack(
                    (key, chat),
                    b"chat",
                    (&record, &body, &mut data),
                    &known,
                    (seal::open, Chunks),
                )
                .unwrap();
            black_box(&data);
        });
        assert_eq!(data, data_of(0));
        assert!(residue(range, &pieces) > 0, "an opening");
        let mut moved = [0; ARCHIVE_RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .reseal_archive_on_stack(
                    (chat, other_chat),
                    b"chat",
                    &mut Counting,
                    (&record, &mut moved),
                    seal::open,
                    seal::seal,
                )
                .unwrap();
            black_box(&moved);
        });
        assert!(residue(range, &pieces) > 0, "a move");
        let (mut again, mut again_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [chat, _], public) = before_archiving(&mut again, &mut again_epoch);
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 64]);
        let data = data_of(0);
        let range = below_pad(false, || {
            slots
                .archive_on_stack(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    (&data, &mut written.0, &mut written.1),
                    &known,
                    (seal::seal, Chunks),
                )
                .unwrap();
            black_box(&written);
        });
        assert_eq!(written, (record, body));
        assert!(residue(range, &pieces) > 0, "an archiving");
    }

    /// Reading a public key, archiving, opening and moving a record leave none of the keys, the
    /// expanded seed, the shared secret, the key of the body or the data on the stack: archiving
    /// runs again from the same state, so it makes the same record and body.
    #[test]
    fn the_calls_on_records_of_an_archive_leave_no_key_on_the_stack() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 6], [const { Slot::empty() }; 6]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (
            mut slots,
            [stored, chat, other_chat, key],
            (key_record, _),
            (record, body),
            mut secrets,
        ) = archived(&mut memory, &mut epoch, 0);
        let (.., mut others) = archived(&mut other, &mut other_epoch, 0x5a);
        secrets.extend(moved_secrets(0));
        others.extend(moved_secrets(0x5a));
        let pieces = key_dependent(&secrets, &others);
        assert_ne!(pieces.len(), 0);
        assert_clean(&pieces, || {
            black_box(
                slots
                    .archive_public_key(stored, b"archive", &key_record)
                    .unwrap(),
            );
        });
        let mut data = [0; 48];
        assert_clean(&pieces, || {
            slots
                .open_archive(key, chat, b"chat", &record, &body, &mut data)
                .unwrap();
            black_box(&data);
        });
        let mut moved = [0; ARCHIVE_RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .reseal_archive(
                    chat,
                    other_chat,
                    b"chat",
                    &mut Counting,
                    &record,
                    &mut moved,
                )
                .unwrap();
            black_box(&moved);
        });
        let (mut again, mut again_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [chat, _], public) = before_archiving(&mut again, &mut again_epoch);
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 64]);
        let data = data_of(0);
        assert_clean(&pieces, || {
            slots
                .archive(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    &data,
                    &mut written.0,
                    &mut written.1,
                )
                .unwrap();
            black_box(&written);
        });
        assert_eq!(written, (record, body));
    }

    /// A source that panics on any of its calls leaves none of what archiving or a move handles on
    /// the stack, at the panic or after it, and writes nothing. Each runs from the state
    /// [`archived`] runs it from, so it handles the same values until the panic.
    #[test]
    fn a_panicking_source_leaves_no_secret_of_archiving_or_a_move() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 6], [const { Slot::empty() }; 6]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (_, _, _, (record, body), mut secrets) = archived(&mut memory, &mut epoch, 0);
        let (.., mut others) = archived(&mut other, &mut other_epoch, 0x5a);
        secrets.extend(moved_secrets(0));
        others.extend(moved_secrets(0x5a));
        let pieces = key_dependent(&secrets, &others);
        let data = data_of(0);
        for (moving, calls) in [(false, 2), (true, 1)] {
            for at in 1..=calls + 1 {
                let (mut again, mut again_epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
                let (mut slots, [chat, other_chat], public) =
                    before_archiving(&mut again, &mut again_epoch);
                let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 64]);
                let reached = if moving {
                    let mut archived = ([0; ARCHIVE_RECORD_LEN], [0; 64]);
                    slots
                        .archive(
                            chat,
                            &public,
                            b"chat",
                            &mut Counting,
                            &data,
                            &mut archived.0,
                            &mut archived.1,
                        )
                        .unwrap();
                    assert_eq!(archived, (record, body));
                    panic_at(&pieces, (Counting, at), |source| {
                        slots
                            .reseal_archive(
                                chat,
                                other_chat,
                                b"chat",
                                source,
                                &record,
                                &mut written.0,
                            )
                            .unwrap();
                    })
                } else {
                    panic_at(&pieces, (Counting, at), |source| {
                        slots
                            .archive(
                                chat,
                                &public,
                                b"chat",
                                source,
                                &data,
                                &mut written.0,
                                &mut written.1,
                            )
                            .unwrap();
                    })
                };
                assert_eq!(reached, at <= calls);
                assert_eq!(written.0 == [0; ARCHIVE_RECORD_LEN], reached);
                if reached {
                    assert_eq!(written.1, [0; 64]);
                }
            }
        }
    }

    /// The wipes cover more than the calls use, with the self-test of X-Wing asked for the first
    /// time, and not needlessly more.
    #[test]
    fn the_wipes_are_deeper_than_the_calls_on_records_of_an_archive() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [stored, chat, other_chat, key], (key_record, public), (record, body), _) =
            archived(&mut memory, &mut epoch, 0);
        let read = depth_changed(|| {
            black_box(
                slots
                    .archive_public_key_on_stack(stored, b"archive", &key_record, seal::open)
                    .unwrap(),
            );
        });
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 64]);
        let (first, second) = (xwing::unanswered(), xwing::unanswered());
        let archived = depth_changed(|| {
            slots
                .archive_on_stack(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    (&data_of(0), &mut written.0, &mut written.1),
                    &first,
                    (seal::seal, Chunks),
                )
                .unwrap();
            black_box(&written);
        });
        let mut data = [0; 48];
        let opened = depth_changed(|| {
            slots
                .open_archive_on_stack(
                    (key, chat),
                    b"chat",
                    (&record, &body, &mut data),
                    &second,
                    (seal::open, Chunks),
                )
                .unwrap();
            black_box(&data);
        });
        let moved = depth_changed(|| {
            slots
                .reseal_archive_on_stack(
                    (chat, other_chat),
                    b"chat",
                    &mut Counting,
                    (&record, &mut written.0),
                    seal::open,
                    seal::seal,
                )
                .unwrap();
            black_box(&written);
        });
        std::println!("records of an archive take {read}, {archived}, {opened} and {moved} bytes");
        for (used, wipe) in [
            (read, xwing::STACK_WIPE),
            (archived, batch::STACK_WIPE),
            (opened, batch::STACK_WIPE),
            (moved, xwing::STACK_WIPE),
        ] {
            assert!(used.saturating_mul(2) <= wipe, "{used} bytes used");
            assert!(used.saturating_mul(16) >= wipe, "{used} bytes used");
        }
    }

    /// The wipes that follow each call reach as deep as they are meant to, also when the call
    /// fails, and no call reaches deeper than its documentation says it needs.
    #[test]
    fn the_calls_on_records_of_an_archive_wipe_and_need_the_stack_documented() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [stored, chat, other_chat, key], (key_record, public), (record, body), _) =
            archived(&mut memory, &mut epoch, 0);
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 64]);
        let mut data = [0; 48];
        let mut deep = Vec::new();
        let mut archiving = Vec::new();
        deep.push(depth_changed(|| {
            black_box(
                slots
                    .archive_public_key(stored, b"archive", &key_record)
                    .unwrap(),
            );
        }));
        deep.push(depth_changed(|| {
            let refused = slots.archive_public_key(stored, b"other", &key_record);
            assert_eq!(black_box(refused.map(|_| ())), Err(Error::StaleRecord));
        }));
        archiving.push(depth_changed(|| {
            slots
                .archive(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    &data_of(0),
                    &mut written.0,
                    &mut written.1,
                )
                .unwrap();
            black_box(&written);
        }));
        archiving.push(depth_changed(|| {
            let failed = slots.archive(
                chat,
                &public,
                b"chat",
                &mut Failing,
                &data_of(0),
                &mut written.0,
                &mut written.1,
            );
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        archiving.push(depth_changed(|| {
            slots
                .open_archive(key, chat, b"chat", &record, &body, &mut data)
                .unwrap();
            black_box(&data);
        }));
        archiving.push(depth_changed(|| {
            let refused = slots.open_archive(key, chat, b"other", &record, &body, &mut data);
            assert_eq!(black_box(refused), Err(Error::RecordRejected));
        }));
        deep.push(depth_changed(|| {
            slots
                .reseal_archive(
                    chat,
                    other_chat,
                    b"chat",
                    &mut Counting,
                    &record,
                    &mut written.0,
                )
                .unwrap();
            black_box(&written);
        }));
        deep.push(depth_changed(|| {
            let failed = slots.reseal_archive(
                chat,
                other_chat,
                b"chat",
                &mut Failing,
                &record,
                &mut written.0,
            );
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        for depth in deep {
            assert!(depth >= xwing::STACK_WIPE, "{depth} bytes wiped");
            assert!(depth <= NEEDS[build] * 1024, "{depth} bytes reached");
        }
        for depth in archiving {
            assert!(depth >= batch::STACK_WIPE, "{depth} bytes wiped");
            assert!(
                depth <= ARCHIVE_NEEDS[build] * 1024,
                "{depth} bytes reached"
            );
        }
    }
}
