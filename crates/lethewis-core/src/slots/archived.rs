// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The records of an archive: a ciphertext of X-Wing to an archive key, from whose shared secret
//! the key of a batch is derived, under the key of a chat for its archive.

use super::archive::{open_archive_layer, seed_of, split_body, wipe_archive_stack};
use core::marker::PhantomData;

use super::{Handle, Open, Seal, Slot, Slots, hedged_draw};
use crate::{
    derive::{
        Branch, KeyId, derive_archive_check, derive_archive_data, derive_archive_randomness,
        derive_archive_seal_key,
    },
    entropy::Entropy,
    epoch::Epoch,
    error::Error,
    key::{Key, wipe},
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

    /// Archives a batch of a chat: encapsulates to the archive key `public` names, writes into
    /// `data_key` the key of the batch, derived from the shared secret, and into `record` the
    /// identifier of the archive key, the ciphertext and a check of the shared secret. The record
    /// is under the key of the chat for its archive that `seal` refers to, bound to `context`, from
    /// 1 to 255 bytes, in no epoch; only that key and the archive key give the key of the batch
    /// back, with [`Slots::open_archive`]. The randomness of the encapsulation and the nonce come
    /// from `entropy`, hedged with the key of this epoch, the randomness also with the key of the
    /// chat. X-Wing gives a known answer first, once in a process.
    ///
    /// Needs 100 KiB of stack, or 232 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the stack it used is wiped after it, 96 KiB, or 224 KiB, deep,
    /// whether it succeeded or not. A build that optimises this crate but not the code it calls has
    /// to set that flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidContext`] if `context` is empty or longer than 255 bytes,
    /// [`Error::StaleHandle`] if `seal` does not refer to a set held here now,
    /// [`Error::WrongPurpose`] if that set does not serve [`Purpose::ArchiveSeal`],
    /// [`Error::StaleRecord`] if `public` was read from other slots or in another epoch,
    /// [`Error::CipherFailed`] if X-Wing or the cipher gives a known input a wrong answer or the
    /// cipher fails, [`Error::EntropyFailed`] if `entropy` fails, [`Error::DerivationFailed`] if a
    /// value cannot be derived from a key, and [`Error::RecordRejected`] if X-Wing refuses the
    /// public key. `record` and `data_key` are then left as they were.
    pub fn archive(
        &mut self,
        seal: Handle<'a>,
        public: &ArchivePublic<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; ARCHIVE_RECORD_LEN],
        data_key: &mut [u8; 32],
    ) -> Result<(), Error> {
        let archived = crate::timing::with(|| {
            self.archive_on_stack(
                seal,
                public,
                context,
                entropy,
                (record, data_key),
                &KNOWN,
                seal::Aes,
            )
        });
        wipe_archive_stack();
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
        (record, data_key): (&mut [u8; ARCHIVE_RECORD_LEN], &mut [u8; 32]),
        known: &Known,
        seal_with: impl Seal<ARCHIVED_LEN>,
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let seal = self.serving(seal, Purpose::ArchiveSeal)?;
        if public.slots != self.id() || public.epoch != self.epoch.number {
            return Err(Error::StaleRecord);
        }
        if !xwing::answers(known) {
            return Err(Error::CipherFailed);
        }
        let Self { memory, epoch } = self;
        let chat = memory.get(seal).ok_or(Error::StaleHandle)?.wrapping_key().0;
        let Epoch { key, drawn, .. } = &mut **epoch;
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
        let written = encapsulated
            .and_then(|()| batch_keys(&shared, &ciphertext, &mut batch, &mut check))
            .and_then(|()| {
                seal_archived(
                    chat,
                    (entropy, key, drawn),
                    associated.bytes(),
                    (&public.id, &ciphertext, &check.bytes()),
                    (record, seal_with),
                )
            });
        wipe(&mut shared);
        if written.is_ok() {
            *data_key = batch;
        }
        wipe(&mut batch);
        written
    }

    /// Writes into `data_key` the key of the batch whose record of the archive is `record`, for the
    /// `context` it was written for: the record opens with the key of the chat for its archive that
    /// `seal` refers to, and the key of the batch is derived from the shared secret the archive key
    /// that `archive` refers to gives its ciphertext, if the record's check of that secret holds.
    /// X-Wing gives a known answer first, once in a process.
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
    /// [`Error::WrongPurpose`] if the set `archive` refers to does not serve [`Purpose::Archive`]
    /// or the one `seal` refers to [`Purpose::ArchiveSeal`], [`Error::CipherFailed`] if X-Wing
    /// gives a known input a wrong answer, [`Error::DerivationFailed`] if a value cannot be derived
    /// from a key, [`Error::RecordRejected`] if the record does not open with that key of the chat
    /// and this context, [`Error::WrongArchiveKey`] if it was written to another archive key,
    /// [`Error::WrongLength`] if the set `archive` refers to holds no key of 32 bytes, and
    /// [`Error::PublicKeyMismatch`] if the check of the shared secret fails: the batch was archived
    /// to another public key, or its ciphertext or check changed. `data_key` is then left as it was.
    pub fn open_archive(
        &self,
        archive: Handle<'a>,
        seal: Handle<'a>,
        context: &[u8],
        record: &[u8; ARCHIVE_RECORD_LEN],
        data_key: &mut [u8; 32],
    ) -> Result<(), Error> {
        let opened = crate::timing::with(|| {
            self.open_archive_on_stack(
                (archive, seal),
                context,
                (record, data_key),
                &KNOWN,
                seal::Aes,
            )
        });
        wipe_archive_stack();
        opened
    }

    /// The opening itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts. X-Wing has to give `known` first.
    #[inline(never)]
    pub(super) fn open_archive_on_stack(
        &self,
        (archive, seal): (Handle<'a>, Handle<'a>),
        context: &[u8],
        (record, data_key): (&[u8; ARCHIVE_RECORD_LEN], &mut [u8; 32]),
        known: &Known,
        mut open: impl Open<ARCHIVED_LEN>,
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let archive = self.serving(archive, Purpose::Archive)?;
        let seal = self.serving(seal, Purpose::ArchiveSeal)?;
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
        let opened = batch_keys(&shared, &ciphertext, &mut batch, &mut check).and_then(|()| {
            if check.is(&kept) {
                Ok(())
            } else {
                Err(Error::PublicKeyMismatch)
            }
        });
        wipe(&mut shared);
        if opened.is_ok() {
            *data_key = batch;
        }
        wipe(&mut batch);
        opened
    }

    /// Moves the record of an archive `record` from the key of a chat for its archive that `from`
    /// refers to, to the one `to` refers to, which may be the same, and writes it into `out`, for
    /// the same `context`: the archive key and the key of the batch are not needed, and the
    /// identifier, the ciphertext and the check stay the same. The nonce comes from `entropy`,
    /// hedged with the key of this epoch.
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
    /// [`Error::DerivationFailed`] if a key that encrypts a record cannot be derived or the nonce
    /// cannot be hedged, [`Error::RecordRejected`] if `record` does not open with the first key and
    /// this context, [`Error::EntropyFailed`] if `entropy` fails, and [`Error::CipherFailed`] if
    /// the cipher gives a known input a wrong answer or fails. `out` is then left as it was.
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
            (entropy, key, drawn),
            associated.bytes(),
            (&id, &ciphertext, &check),
            (out, seal_with),
        )
    }
}

/// Writes into `batch` the key of a batch, and into `check` the check a record keeps, derived from
/// the shared secret `shared` and the ciphertext it came with.
fn batch_keys(
    shared: &[u8; SHARED_LEN],
    ciphertext: &[u8; CIPHERTEXT_LEN],
    batch: &mut [u8; 32],
    check: &mut KeyId,
) -> Result<(), Error> {
    let mut secret = Key::empty();
    secret.copy32(shared);
    let derived = derive_archive_data(&secret, ciphertext, batch)
        .and_then(|()| derive_archive_check(&secret, ciphertext, check));
    secret.wipe();
    derived.map_err(|_| Error::DerivationFailed)
}

/// Seals the identifier `id` of an archive key, the ciphertext to it and the check of its shared
/// secret with `seal_with` under the key derived from the key of a chat for its archive `chat`,
/// into `out`; the nonce comes from `entropy`, hedged with the key of the epoch `epoch_key`. `out`
/// is written only when this succeeds.
fn seal_archived(
    chat: &Key,
    (entropy, epoch_key, drawn): (&mut (impl Entropy + ?Sized), &Key, &mut u64),
    aad: &[u8],
    (id, ciphertext, check): (&[u8; ID_LEN], &[u8; CIPHERTEXT_LEN], &[u8; ID_LEN]),
    (out, mut seal_with): (&mut [u8; ARCHIVE_RECORD_LEN], impl Seal<ARCHIVED_LEN>),
) -> Result<(), Error> {
    let mut nonce = [0; NONCE_LEN];
    hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, &mut nonce)?;
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
    let tag = seal_with.seal(&cipher_key, &nonce, aad, &mut sealed);
    wipe(&mut cipher_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    if let Some((nonce_out, rest)) = out.split_first_chunk_mut::<NONCE_LEN>()
        && let Some((sealed_out, tag_out)) = rest.split_first_chunk_mut::<ARCHIVED_LEN>()
    {
        *nonce_out = nonce;
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
    use crate::derive::{derive_archive_check, derive_archive_data, derive_archive_seal_key};
    use crate::epoch::{Erasure, Root, RootFailed};
    use crate::key::Key;
    use crate::key::tests::{Counting, Failing, Random, from_environment};
    use crate::record::AssociatedData;
    use crate::slots::tests::{EPOCH, epoch_key};
    use crate::timing::timed;
    use crate::xwing::{self, wrong_known};
    use crate::{
        ARCHIVE_KEY_RECORD_LEN, Epoch, Error, Handle, KeyLength, Purpose, Slot, Slots, seal,
    };

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

    /// The key of a batch comes back only with the archive key it was archived to, the key of its
    /// chat and its context; a refusal leaves the output as it was.
    #[test]
    fn a_batch_opens_with_its_archive_key_and_its_chat_only() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, other_chat], public, key_record) = archive(&mut slots);
        let (mut record, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
        assert_ne!(data_key, [0; 32]);
        let mut again = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut again.0,
                &mut again.1,
            )
            .unwrap();
        assert_ne!(again.0, record);
        assert_ne!(again.1, data_key);
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let mut opened = [7; 32];
        for (archive, chat, context, refused) in [
            (key, other_chat, &b"chat"[..], Error::RecordRejected),
            (key, chat, &b"chap"[..], Error::RecordRejected),
            (chat, chat, &b"chat"[..], Error::WrongPurpose),
            (key, key, &b"chat"[..], Error::WrongPurpose),
            (key, chat, &b""[..], Error::InvalidContext),
        ] {
            assert_eq!(
                slots.open_archive(archive, chat, context, &record, &mut opened),
                Err(refused)
            );
            assert_eq!(opened, [7; 32]);
        }
        let mut changed = record;
        changed[ARCHIVE_RECORD_LEN - 1] ^= 1;
        assert_eq!(
            slots.open_archive(key, chat, b"chat", &changed, &mut opened),
            Err(Error::RecordRejected)
        );
        slots
            .open_archive(key, chat, b"chat", &record, &mut opened)
            .unwrap();
        assert_eq!(opened, data_key);
        slots
            .open_archive(key, chat, b"chat", &again.0, &mut opened)
            .unwrap();
        assert_eq!(opened, again.1);
    }

    /// Every call on a record of an archive derives and runs the cipher and X-Wing inside the switch
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
        let (mut record, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        timed(|| {
            slots
                .archive(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    &mut record,
                    &mut data_key,
                )
                .unwrap();
        });
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        timed(|| {
            slots
                .open_archive(key, chat, b"chat", &record, &mut data_key)
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
        let (mut record, mut data_key) = ([5; ARCHIVE_RECORD_LEN], [5; 32]);
        assert_eq!(
            other.archive(
                other_chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key
            ),
            Err(Error::StaleRecord)
        );
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
        assert_eq!(
            slots.archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key
            ),
            Err(Error::StaleRecord)
        );
        assert_eq!((record, data_key), ([5; ARCHIVE_RECORD_LEN], [5; 32]));
        let public = slots
            .archive_public_key(stored, b"archive", &carried)
            .unwrap();
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
        slots.release(chat).unwrap();
        assert_eq!(
            slots.archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key
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
        let (mut record, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &swapped,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let mut opened = [7; 32];
        assert_eq!(
            slots.open_archive(key, chat, b"chat", &record, &mut opened),
            Err(Error::PublicKeyMismatch)
        );
        assert_eq!(opened, [7; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
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
        let Epoch {
            key: epoch, drawn, ..
        } = &mut *slots.epoch;
        super::seal_archived(
            slots.memory[chat.index].wrapping_key().0,
            (&mut Counting, &*epoch, drawn),
            associated.bytes(),
            (&id, &ciphertext, &check),
            (&mut changed, seal::seal),
        )
        .unwrap();
        assert_eq!(
            slots.open_archive(key, chat, b"chat", &changed, &mut opened),
            Err(Error::PublicKeyMismatch)
        );
        assert_eq!(opened, [7; 32]);
        slots
            .open_archive(key, chat, b"chat", &record, &mut opened)
            .unwrap();
        assert_eq!(opened, data_key);
    }

    /// A record of an archive written to one archive key does not open with another.
    #[test]
    fn a_record_of_another_archive_key_is_refused() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, _], public, _) = archive(&mut slots);
        let (mut record, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
        let mut other = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut other)
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &other)
            .unwrap();
        let mut opened = [7; 32];
        assert_eq!(
            slots.open_archive(key, chat, b"chat", &record, &mut opened),
            Err(Error::WrongArchiveKey)
        );
        assert_eq!(opened, [7; 32]);
    }

    /// A record moves to another key of the chat for its archive without the archive key; the
    /// moved record opens with that key only, and gives the same key of the batch.
    #[test]
    fn a_record_of_an_archive_is_resealed_without_its_archive_key() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let ([stored, store, chat, other_chat], public, key_record) = archive(&mut slots);
        let (mut record, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
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
        let mut opened = [0; 32];
        assert_eq!(
            slots.open_archive(key, chat, b"chat", &moved, &mut opened),
            Err(Error::RecordRejected)
        );
        slots
            .open_archive(key, other_chat, b"chat", &moved, &mut opened)
            .unwrap();
        assert_eq!(opened, data_key);
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

    /// A public key X-Wing refuses, a wrong answer of X-Wing and a failed source archive nothing.
    #[test]
    fn an_archive_that_fails_writes_nothing() {
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
        let (mut record, mut data_key) = ([5; ARCHIVE_RECORD_LEN], [5; 32]);
        assert_eq!(
            slots.archive(
                chat,
                &unreduced,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key
            ),
            Err(Error::RecordRejected)
        );
        assert_eq!(
            slots.archive(
                chat,
                &public,
                b"chat",
                &mut Failing,
                &mut record,
                &mut data_key
            ),
            Err(Error::EntropyFailed)
        );
        assert_eq!(
            slots.archive(
                stored,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key
            ),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.archive_on_stack(
                chat,
                &public,
                b"chat",
                &mut Counting,
                (&mut record, &mut data_key),
                &wrong_known(),
                seal::seal,
            ),
            Err(Error::CipherFailed)
        );
        assert_eq!((record, data_key), ([5; ARCHIVE_RECORD_LEN], [5; 32]));
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &key_record)
            .unwrap();
        let mut opened = [5; 32];
        assert_eq!(
            slots.open_archive_on_stack(
                (key, chat),
                b"chat",
                (&record, &mut opened),
                &wrong_known(),
                seal::open,
            ),
            Err(Error::CipherFailed)
        );
        assert_eq!(opened, [5; 32]);
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
        let (mut record, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
            )
            .unwrap();
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
        let mut opened = [7; 32];
        // The nonce, the identifier, the ciphertext, the check and the tag, at each end.
        for at in [0, 11, 12, 27, 28, 1147, 1148, 1163, 1164, 1179] {
            let mut changed = record;
            changed[at] ^= 0x80;
            assert_eq!(
                slots.open_archive(key, chat, b"chat", &changed, &mut opened),
                Err(Error::RecordRejected),
                "byte {at}"
            );
            assert_eq!(opened, [7; 32], "byte {at}");
        }
        slots
            .open_archive(key, chat, b"chat", &record, &mut opened)
            .unwrap();
        assert_eq!(opened, data_key);
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
    }

    /// Each fault in turn; one round in four gets a second, at random.
    const FAULTS: [Fault; 13] = [
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
    ];

    /// Records of an archive sealed through the real derivation and cipher and laid out by hand,
    /// from real encapsulations to the archive key, with every fault of [`FAULTS`] in turn and at
    /// times a second: a context, the key of the chat, the identifier, the ciphertext or the check
    /// wrong. The opening and the move never panic, refuse exactly what they should, with the error
    /// they should, and write nothing then; the opening gives the key of the batch the
    /// encapsulation gave, and the move the same parts under the other key.
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
            let context: std::vec::Vec<u8> = if has(Fault::Context) {
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
            derive_archive_data(&secret, &ciphertext, &mut batch).unwrap();
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
            } else {
                Ok(batch)
            });
            let mut opened = [7; 32];
            let result = slots.open_archive(key, chat, &asked, &record, &mut opened);
            assert_eq!(result.map(|()| opened), expected, "{at}");
            if result.is_err() {
                assert_eq!(opened, [7; 32], "{at}");
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
    use crate::derive::stack::secrets_of;
    use crate::derive::{Branch, SALT, derive_archive_randomness, derive_archive_seal_key, hedge};
    use crate::key::tests::{Counting, Failing};
    use crate::record::AssociatedData;
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::slots::tests::{EPOCH, flipped_epoch_key};
    use crate::xwing::stack::{encapsulation_secrets, seed_secrets};
    use crate::{
        ARCHIVE_KEY_RECORD_LEN, Epoch, Error, Handle, KeyLength, Purpose, Slot, Slots, seal, xwing,
    };

    /// The stack each call needs, and the depth of the wipe after it, in KiB, in an optimised build
    /// and in one without optimisation.
    const NEEDS: [usize; 2] = [100, 232];
    const WIPES: [usize; 2] = [96, 224];

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
        for call in [
            "archive_public_key",
            "archive",
            "open_archive",
            "reseal_archive",
        ] {
            let text = documentation(call);
            for stated in [
                format!("Needs {} KiB of stack, or {} KiB when", NEEDS[0], NEEDS[1]),
                format!(" {} KiB, or {} KiB, ", WIPES[0], WIPES[1]),
            ] {
                assert!(text.contains(&stated), "{call}: {stated}");
            }
        }
    }

    /// The handles of a set of slots over `memory` in an epoch whose key `flip` changes: a stored
    /// key for wrapping, two keys of chats for their archives and a loaded archive key.
    type Keys<'a> = [Handle<'a>; 4];

    /// Those slots and keys, the record of the archive key and its public key, a record of a batch,
    /// and the secrets.
    type Archived<'a> = (
        Slots<'a>,
        Keys<'a>,
        ([u8; ARCHIVE_KEY_RECORD_LEN], ArchivePublic<'a>),
        [u8; ARCHIVE_RECORD_LEN],
        Vec<Vec<u8>>,
    );

    /// Those slots, with the record of the archive key, the public key it holds, a record of a
    /// batch archived to it under the first key of a chat, the key of the batch, and what the calls
    /// on it handle: the keys, the seed and what X-Wing makes of it, the randomness of the
    /// encapsulation and what X-Wing makes of that, the shared secret, the key of the batch, and
    /// what the cipher of the record and the derivation of its key handle.
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
        let (mut record, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Counting,
                &mut record,
                &mut data_key,
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
        secrets.push(data_key.to_vec());
        secrets.extend(seed_secrets(secrets[3].as_slice().try_into().unwrap()));
        secrets.extend(layers);
        let chat_key = slots.memory[chat.index].wrapping_key().0;
        let drawn: [u8; 64] = core::array::from_fn(|at| u8::try_from(at).unwrap().wrapping_add(1));
        let mut hedged = [0; 64];
        hedge(
            &slots.epoch.key,
            count,
            Branch::HedgeEncaps,
            &drawn,
            &mut hedged,
        )
        .unwrap();
        let mut randomness = [0; 64];
        derive_archive_randomness(chat_key, &hedged, &mut randomness).unwrap();
        secrets.extend([hedged.to_vec(), randomness.to_vec()]);
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
            record,
            secrets,
        )
    }

    /// What moving the record of a batch from the slots [`archived`] makes with `flip` to the second
    /// key of a chat handles to seal it: the cipher of the moved record and the derivation of its
    /// key.
    fn moved_secrets(flip: u8) -> Vec<Vec<u8>> {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [_, chat, other_chat, _], _, record, _) =
            archived(&mut memory, &mut epoch, flip);
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
        secrets
    }

    /// Fresh slots over `memory` in the state [`archived`] archives its batch in, with its keys and
    /// the public key of its archive key.
    fn before_archiving<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
    ) -> (Slots<'a>, Handle<'a>, ArchivePublic<'a>) {
        let mut slots = Slots::new(memory, epoch, EPOCH, &mut flipped_epoch_key(0));
        let mut generate = |purpose| {
            slots
                .generate(purpose, KeyLength::Bytes32, &mut Counting)
                .unwrap()
        };
        let stored = generate(Purpose::Wrap);
        let store = generate(Purpose::ArchiveWrap);
        let chat = generate(Purpose::ArchiveSeal);
        generate(Purpose::ArchiveSeal);
        let mut created = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut created)
            .unwrap();
        let public = slots
            .archive_public_key(stored, b"archive", &created)
            .unwrap();
        (slots, chat, public)
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
        let (mut slots, [stored, chat, other_chat, key], (key_record, _), record, mut secrets) =
            archived(&mut memory, &mut epoch, 0);
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
        let mut data_key = [0; 32];
        let range = below_pad(false, || {
            slots
                .open_archive_on_stack(
                    (key, chat),
                    b"chat",
                    (&record, &mut data_key),
                    &known,
                    seal::open,
                )
                .unwrap();
            black_box(&data_key);
        });
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
        let (mut slots, chat, public) = before_archiving(&mut again, &mut again_epoch);
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        let range = below_pad(false, || {
            slots
                .archive_on_stack(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    (&mut written.0, &mut written.1),
                    &known,
                    seal::seal,
                )
                .unwrap();
            black_box(&written);
        });
        assert_eq!(written.0, record);
        assert!(residue(range, &pieces) > 0, "an archiving");
    }

    /// Reading a public key, archiving, opening and moving a record leave none of the keys, the
    /// expanded seed, the shared secret or the key of the batch on the stack: archiving runs again
    /// from the same state, so it makes the same record.
    #[test]
    fn the_calls_on_records_of_an_archive_leave_no_key_on_the_stack() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 6], [const { Slot::empty() }; 6]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (mut slots, [stored, chat, other_chat, key], (key_record, _), record, mut secrets) =
            archived(&mut memory, &mut epoch, 0);
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
        let mut data_key = [0; 32];
        assert_clean(&pieces, || {
            slots
                .open_archive(key, chat, b"chat", &record, &mut data_key)
                .unwrap();
            black_box(&data_key);
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
        let mut slots = Slots::new(
            &mut again,
            &mut again_epoch,
            EPOCH,
            &mut flipped_epoch_key(0),
        );
        let mut generate = |purpose| {
            slots
                .generate(purpose, KeyLength::Bytes32, &mut Counting)
                .unwrap()
        };
        let stored = generate(Purpose::Wrap);
        let store = generate(Purpose::ArchiveWrap);
        let chat = generate(Purpose::ArchiveSeal);
        generate(Purpose::ArchiveSeal);
        let mut created = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut created)
            .unwrap();
        let public = slots
            .archive_public_key(stored, b"archive", &created)
            .unwrap();
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        assert_clean(&pieces, || {
            slots
                .archive(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    &mut written.0,
                    &mut written.1,
                )
                .unwrap();
            black_box(&written);
        });
        assert_eq!(written.0, record);
    }

    /// The wipes cover more than the calls use, with the self-test of X-Wing asked for the first
    /// time, and not needlessly more.
    #[test]
    fn the_wipes_are_deeper_than_the_calls_on_records_of_an_archive() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [stored, chat, other_chat, key], (key_record, public), record, _) =
            archived(&mut memory, &mut epoch, 0);
        let read = depth_changed(|| {
            black_box(
                slots
                    .archive_public_key_on_stack(stored, b"archive", &key_record, seal::open)
                    .unwrap(),
            );
        });
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        let (first, second) = (xwing::unanswered(), xwing::unanswered());
        let archived = depth_changed(|| {
            slots
                .archive_on_stack(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    (&mut written.0, &mut written.1),
                    &first,
                    seal::seal,
                )
                .unwrap();
            black_box(&written);
        });
        let opened = depth_changed(|| {
            slots
                .open_archive_on_stack(
                    (key, chat),
                    b"chat",
                    (&record, &mut written.1),
                    &second,
                    seal::open,
                )
                .unwrap();
            black_box(&written);
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
        for used in [read, archived, opened, moved] {
            assert!(
                used.saturating_mul(2) <= xwing::STACK_WIPE,
                "{used} bytes used"
            );
            assert!(
                used.saturating_mul(16) >= xwing::STACK_WIPE,
                "{used} bytes used"
            );
        }
    }

    /// The wipes that follow each call reach as deep as they are meant to, also when the call
    /// fails, and no call reaches deeper than its documentation says it needs.
    #[test]
    fn the_calls_on_records_of_an_archive_wipe_and_need_the_stack_documented() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
        let (mut slots, [stored, chat, other_chat, key], (key_record, public), record, _) =
            archived(&mut memory, &mut epoch, 0);
        let mut written = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        let mut deep = Vec::new();
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
        deep.push(depth_changed(|| {
            slots
                .archive(
                    chat,
                    &public,
                    b"chat",
                    &mut Counting,
                    &mut written.0,
                    &mut written.1,
                )
                .unwrap();
            black_box(&written);
        }));
        deep.push(depth_changed(|| {
            let failed = slots.archive(
                chat,
                &public,
                b"chat",
                &mut Failing,
                &mut written.0,
                &mut written.1,
            );
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        deep.push(depth_changed(|| {
            slots
                .open_archive(key, chat, b"chat", &record, &mut written.1)
                .unwrap();
            black_box(&written);
        }));
        deep.push(depth_changed(|| {
            let refused = slots.open_archive(key, chat, b"other", &record, &mut written.1);
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
    }
}
