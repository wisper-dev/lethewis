// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The record of an archive key: its seed under a stored key of the archive, and its public key,
//! under the profile's stored key for wrapping and the key of an epoch.

use super::{Handle, Index, Kind, Open, Slots, derive_record_key, hedged_draw, write_record};
use crate::{
    derive::{Branch, KeyId, derive_archive_layer_key, derive_archive_seed, derive_key_id},
    entropy::Entropy,
    epoch::Epoch,
    error::Error,
    key::{Key, wipe},
    keyset::{self, Header, Stages},
    record::{
        ARCHIVE_BODY_LEN, ARCHIVE_KEY_RECORD_LEN, ARCHIVE_LAYER_LEN, AssociatedData, ID_LEN,
        PLAINTEXT_LEN, Purpose, RECORD_LEN,
    },
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, NONCE_LEN, TAG_LEN},
    xwing::{self, KNOWN, Known, PUBLIC_LEN, SEED_LEN},
};

impl<'a> Slots<'a> {
    /// Creates an archive key under the stored key of the archive that `store` refers to, and
    /// writes its record into `record`, in this epoch, or in the next while a change to it is under
    /// way; no slot holds the new key. The record has two layers, both bound to `context`, from 1 to
    /// 255 bytes. The inner one holds the seed of the key and opens only with that stored key,
    /// whatever the epoch. The outer one holds the inner one, the key's identifier and its public
    /// key, and opens only with the stored key for wrapping that `profile` refers to and the key of
    /// the epoch; [`Slots::carry_archive_key`] moves it on to the next epoch without the stored key
    /// of the archive. The seed is derived from that stored key and bytes from `entropy`, hedged
    /// with the key of the epoch, as the nonces are. X-Wing gives a known answer first, once in a
    /// process, and the new key pair has to agree with itself: an encapsulation to its public key
    /// and the decapsulation with its seed give one secret.
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
    /// [`Error::WrongPurpose`] if the set `store` refers to does not serve
    /// [`Purpose::ArchiveWrap`] or the one `profile` refers to [`Purpose::Wrap`],
    /// [`Error::WrongLevel`] if `profile` refers to a key from a secret, [`Error::EpochExhausted`]
    /// if a change to the last epoch is under way, [`Error::CipherFailed`] if X-Wing gives a known
    /// input a wrong answer, [`Error::EntropyFailed`] if `entropy` fails,
    /// [`Error::DerivationFailed`] if a value cannot be derived from a key, and
    /// [`Error::CipherFailed`] if the new key pair does not agree with itself or the cipher gives a
    /// known input a wrong answer or fails. `record` is then left as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and `record` is left as it was.
    pub fn create_archive_key(
        &mut self,
        store: Handle<'a>,
        profile: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Result<(), Error> {
        let created = crate::timing::with(|| {
            self.create_archive_key_on_stack(store, profile, context, entropy, record, &KNOWN)
        });
        wipe_archive_stack();
        created
    }

    /// The creation itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts. X-Wing has to give `known` first.
    #[inline(never)]
    pub(super) fn create_archive_key_on_stack(
        &mut self,
        store: Handle<'a>,
        profile: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
        known: &Known,
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let (store, profile) = self.archive_parents(store, profile)?;
        let Self { memory, epoch } = self;
        let (Some(archive), Some(stored)) = (memory.get(store), memory.get(profile)) else {
            return Err(Error::StaleHandle);
        };
        let Epoch {
            number,
            key,
            next,
            changing,
            drawn,
        } = &mut **epoch;
        let (number, epoch_key) = if *changing {
            (number.checked_add(1).ok_or(Error::EpochExhausted)?, &*next)
        } else {
            (*number, &*key)
        };
        if !xwing::answers(known) {
            return Err(Error::CipherFailed);
        }
        let mut nonces = [[0; NONCE_LEN]; 2];
        let [inner, outer] = &mut nonces;
        hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, inner)?;
        hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, outer)?;
        let mut hedged = [0; SEED_LEN];
        hedged_draw(entropy, epoch_key, drawn, Branch::HedgeKey, &mut hedged)?;
        let (archive_key, archive_id) = archive.wrapping_key();
        let mut seed_bytes = [0; SEED_LEN];
        let derived = derive_archive_seed(archive_key, &hedged, &mut seed_bytes);
        wipe(&mut hedged);
        let mut seed = Key::empty();
        seed.copy32(&seed_bytes);
        wipe(&mut seed_bytes);
        let written = derived.map_err(|_| Error::DerivationFailed).and_then(|()| {
            write_archive_key(
                (&seed, known),
                (archive_key, archive_id),
                (stored.wrapping_key().0, epoch_key, number),
                &nonces,
                associated.bytes(),
                record,
            )
        });
        seed.wipe();
        written
    }

    /// Loads the archive key whose record is `record`, for the `context` it was written for, into
    /// a free slot: the record opens with the stored key for wrapping that `profile` refers to and
    /// the key of this epoch, and its seed with the stored key of the archive that `store` refers
    /// to. X-Wing gives a known answer first, once in a process, and the public key in the record is
    /// then the one the seed gives; otherwise the record was changed by someone who held the key of
    /// the epoch and the stored key for wrapping, and the call fails with
    /// [`Error::PublicKeyMismatch`].
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
    /// [`Error::WrongPurpose`] if the set `store` refers to does not serve
    /// [`Purpose::ArchiveWrap`] or the one `profile` refers to [`Purpose::Wrap`],
    /// [`Error::WrongLevel`] if `profile` refers to a key from a secret, [`Error::NoFreeSlot`] if
    /// no slot is free, [`Error::CipherFailed`] if X-Wing gives a known input a wrong answer,
    /// [`Error::DerivationFailed`] if a value cannot be derived from a key,
    /// [`Error::StaleRecord`] if the record does not open with that stored key for wrapping, this
    /// context and the key of this epoch, or names another epoch, [`Error::RecordRejected`] if its
    /// seed does not open with the stored key of the archive or is not the seed of one archive key,
    /// [`Error::PublicKeyMismatch`] if its identifier or public key is not the seed's, and
    /// [`Error::DuplicateKey`] if these slots hold the key already. No slot changes then.
    pub fn load_archive_key(
        &mut self,
        store: Handle<'a>,
        profile: Handle<'a>,
        context: &[u8],
        record: &[u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Result<Handle<'a>, Error> {
        let loaded = crate::timing::with(|| {
            self.load_archive_key_on_stack(
                store,
                profile,
                context,
                record,
                &KNOWN,
                seal::Aes,
                seal::Aes,
            )
        });
        wipe_archive_stack();
        loaded
    }

    /// The load itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts. X-Wing has to give `known` first.
    #[inline(never)]
    #[expect(
        clippy::too_many_arguments,
        reason = "the proofs give the known answer and both ciphers"
    )]
    pub(super) fn load_archive_key_on_stack(
        &mut self,
        store: Handle<'a>,
        profile: Handle<'a>,
        context: &[u8],
        record: &[u8; ARCHIVE_KEY_RECORD_LEN],
        known: &Known,
        mut open_layer_with: impl Open<ARCHIVE_LAYER_LEN>,
        mut open: impl Open<PLAINTEXT_LEN>,
    ) -> Result<Handle<'a>, Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let (store, profile) = self.archive_parents(store, profile)?;
        if !self.has_free() {
            return Err(Error::NoFreeSlot);
        }
        if !xwing::answers(known) {
            return Err(Error::CipherFailed);
        }
        let stored = self.memory.get(profile).ok_or(Error::StaleHandle)?;
        let mut body = [0; ARCHIVE_BODY_LEN];
        let mut plaintext = [0; PLAINTEXT_LEN];
        let loaded = open_archive_layer(
            (stored.wrapping_key().0, &self.epoch.key, self.epoch.number),
            associated.bytes(),
            record,
            &mut body,
            &mut open_layer_with,
        )
        .and_then(|()| {
            let (id, public, inner) = split_body(&body);
            self.open_under(
                store,
                associated.bytes(),
                &inner,
                &mut plaintext,
                &mut open,
                Kind::ArchiveKey,
            )
            .and_then(|()| seed_gives(&plaintext, &id, &public))
        })
        .and_then(|()| self.admit(&plaintext, Kind::ArchiveKey));
        wipe(&mut plaintext);
        wipe(&mut body);
        loaded
    }

    /// Carries the record of an archive key `from` into the next epoch while a change to it is
    /// under way, from the stored key for wrapping that `profile` refers to to the one
    /// `next_profile` refers to, which may be the same, and writes it into `to`, for the same
    /// `context`; the stored key of the archive is not needed. The nonce comes from `entropy`,
    /// hedged with the key of the next epoch. A record not carried opens no more once the change
    /// is committed, and the archive key with it.
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
    /// [`Error::WrongPurpose`] if either set does not serve [`Purpose::Wrap`],
    /// [`Error::WrongLevel`] if either is a key from a secret, [`Error::NoEpochChange`] if no
    /// change to the next epoch is under way, [`Error::EpochExhausted`] if it is the last,
    /// [`Error::EntropyFailed`] if `entropy` fails, [`Error::DerivationFailed`] if the nonce
    /// cannot be hedged or a key that encrypts a layer cannot be derived, [`Error::StaleRecord`]
    /// if `from` does not open with the first stored key, this context and the key of this epoch,
    /// and [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails. `to`
    /// is then left as it was.
    ///
    /// # Panics
    ///
    /// Only if `entropy` panics. The panic passes through, and `to` is left as it was.
    pub fn carry_archive_key(
        &mut self,
        profile: Handle<'a>,
        next_profile: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        from: &[u8; ARCHIVE_KEY_RECORD_LEN],
        to: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Result<(), Error> {
        let carried = crate::timing::with(|| {
            self.carry_archive_key_on_stack(
                profile,
                next_profile,
                context,
                entropy,
                (from, to),
                seal::Aes,
            )
        });
        wipe_archive_stack();
        carried
    }

    /// The carry itself, in a frame of its own: the wipe that follows starts where this frame
    /// starts.
    #[inline(never)]
    pub(super) fn carry_archive_key_on_stack(
        &mut self,
        profile: Handle<'a>,
        next_profile: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        (from, to): (
            &[u8; ARCHIVE_KEY_RECORD_LEN],
            &mut [u8; ARCHIVE_KEY_RECORD_LEN],
        ),
        mut open: impl Open<ARCHIVE_LAYER_LEN>,
    ) -> Result<(), Error> {
        let associated = AssociatedData::new(context).map_err(|_| Error::InvalidContext)?;
        let (profile, next_profile) = (self.profile_key(profile)?, self.profile_key(next_profile)?);
        let Self { memory, epoch } = self;
        let (Some(stored), Some(next_stored)) = (memory.get(profile), memory.get(next_profile))
        else {
            return Err(Error::StaleHandle);
        };
        let Epoch {
            number,
            key,
            next,
            changing,
            drawn,
        } = &mut **epoch;
        if !*changing {
            return Err(Error::NoEpochChange);
        }
        let following = number.checked_add(1).ok_or(Error::EpochExhausted)?;
        let mut nonce = [0; NONCE_LEN];
        hedged_draw(entropy, next, drawn, Branch::HedgeNonce, &mut nonce)?;
        let mut body = [0; ARCHIVE_BODY_LEN];
        let carried = open_archive_layer(
            (stored.wrapping_key().0, &*key, *number),
            associated.bytes(),
            from,
            &mut body,
            &mut open,
        )
        .and_then(|()| {
            seal_archive_layer(
                (next_stored.wrapping_key().0, &*next, following),
                &nonce,
                associated.bytes(),
                &body,
                to,
            )
        });
        wipe(&mut body);
        carried
    }

    /// The slots of the stored key of the archive that `store` refers to and of the stored key for
    /// wrapping that `profile` refers to.
    fn archive_parents(
        &self,
        store: Handle<'a>,
        profile: Handle<'a>,
    ) -> Result<(Index, Index), Error> {
        let (store, profile) = (self.loaded(store)?, self.loaded(profile)?);
        let (Some(archive), Some(stored)) = (self.memory.get(store), self.memory.get(profile))
        else {
            return Err(Error::StaleHandle);
        };
        if archive.purpose != Purpose::ArchiveWrap || stored.purpose != Purpose::Wrap {
            return Err(Error::WrongPurpose);
        }
        if stored.unlocks {
            return Err(Error::WrongLevel);
        }
        Ok((store, profile))
    }

    /// The slot of the stored key for wrapping that `profile` refers to.
    pub(super) fn profile_key(&self, profile: Handle<'a>) -> Result<Index, Error> {
        let index = self.serving(profile, Purpose::Wrap)?;
        if self.memory.get(index).is_none_or(|stored| stored.unlocks) {
            return Err(Error::WrongLevel);
        }
        Ok(index)
    }
}

/// Wipes the stack below the caller's frame, as deep as X-Wing and the layers of a record reach.
pub(super) fn wipe_archive_stack() {
    // The wipe ends in inline assembly, which Kani cannot model.
    #[cfg(not(kani))]
    zeroize::zeroize_stack::<{ xwing::STACK_WIPE }>();
}

/// Writes the record of the archive key `seed`, once its key pair agrees with itself, which makes
/// `known` asked for again if it does not: its inner layer under `archive`, the stored key of the
/// archive and its identifier, its outer layer under `outer`, a stored key for wrapping, the key of
/// an epoch and its number, each under its nonce of `nonces`.
fn write_archive_key(
    (seed, known): (&Key, &Known),
    (archive, archive_id): (&Key, &KeyId),
    outer: (&Key, &Key, u64),
    [nonce, outer_nonce]: &[[u8; NONCE_LEN]; 2],
    aad: &[u8],
    record: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
) -> Result<(), Error> {
    let (_, epoch_key, _) = outer;
    let mut id = KeyId::empty();
    derive_key_id(seed, &mut id).map_err(|_| Error::DerivationFailed)?;
    let mut public = [0; PUBLIC_LEN];
    let agrees = seed_of(seed).is_some_and(|seed| {
        xwing::public_key(seed, &mut public);
        xwing::agrees(known, seed, &public)
    });
    if !agrees {
        return Err(Error::CipherFailed);
    }
    let mut cipher_key = [0; CIPHER_KEY_LEN];
    if derive_record_key(Kind::ArchiveKey, archive, epoch_key, &mut cipher_key).is_err() {
        wipe(&mut cipher_key);
        return Err(Error::DerivationFailed);
    }
    let header = Header {
        purpose: Purpose::Archive,
        parent: archive_id.bytes(),
        epoch: 0,
    };
    let empty = Key::empty();
    let mut sealed = [0; PLAINTEXT_LEN];
    keyset::build(&header, &Stages::one(), [seed, &empty, &empty], &mut sealed);
    let tag = seal::seal(&cipher_key, nonce, aad, &mut sealed);
    wipe(&mut cipher_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    let mut inner = [0; RECORD_LEN];
    write_record(&mut inner, nonce, &sealed, &tag);
    wipe(&mut sealed);
    let mut body = [0; ARCHIVE_BODY_LEN];
    join_body(&mut body, &id.bytes(), &public, &inner);
    wipe(&mut inner);
    let sealed = seal_archive_layer(outer, outer_nonce, aad, &body, record);
    wipe(&mut body);
    sealed
}

/// Whether the seed that `plaintext` holds gives `id` and `public`: the plaintext is a set of one
/// seed of an archive key, of epoch zero, or `RecordRejected`.
fn seed_gives(
    plaintext: &[u8; PLAINTEXT_LEN],
    id: &[u8; ID_LEN],
    public: &[u8; PUBLIC_LEN],
) -> Result<(), Error> {
    let (header, stages, [first, _, _]) =
        keyset::parse(plaintext).map_err(|_| Error::RecordRejected)?;
    let Some(first) = first else {
        return Err(Error::RecordRejected);
    };
    if !Kind::ArchiveKey.holds(header.purpose) || header.epoch != 0 || !stages.is_one() {
        return Err(Error::RecordRejected);
    }
    let mut seed = Key::empty();
    first.load_into(&mut seed);
    let mut derived = KeyId::empty();
    let named = derive_key_id(&seed, &mut derived);
    let mut given = [0; PUBLIC_LEN];
    if let Some(seed) = seed_of(&seed) {
        xwing::public_key(seed, &mut given);
    }
    seed.wipe();
    named.map_err(|_| Error::DerivationFailed)?;
    if derived.is(id) && same_public(&given, public) {
        Ok(())
    } else {
        Err(Error::PublicKeyMismatch)
    }
}

/// The 32 bytes of the seed of an archive key.
pub(super) fn seed_of(seed: &Key) -> Option<&[u8; SEED_LEN]> {
    seed.as32()
}

/// Whether two public keys are the same, compared in pieces no longer than a key.
fn same_public(a: &[u8; PUBLIC_LEN], b: &[u8; PUBLIC_LEN]) -> bool {
    a.chunks(64).zip(b.chunks(64)).all(|(x, y)| x == y)
}

/// The identifier, the public key and the inner record that `body` holds.
pub(super) fn split_body(
    body: &[u8; ARCHIVE_BODY_LEN],
) -> ([u8; ID_LEN], [u8; PUBLIC_LEN], [u8; RECORD_LEN]) {
    let mut parts = ([0; ID_LEN], [0; PUBLIC_LEN], [0; RECORD_LEN]);
    if let Some((id, rest)) = body.split_first_chunk::<ID_LEN>()
        && let Some((public, inner)) = rest.split_first_chunk::<PUBLIC_LEN>()
        && let Ok(inner) = <&[u8; RECORD_LEN]>::try_from(inner)
    {
        parts = (*id, *public, *inner);
    }
    parts
}

/// Writes the identifier, the public key and the inner record into `body`.
fn join_body(
    body: &mut [u8; ARCHIVE_BODY_LEN],
    id: &[u8; ID_LEN],
    public: &[u8; PUBLIC_LEN],
    inner: &[u8; RECORD_LEN],
) {
    if let Some((id_out, rest)) = body.split_first_chunk_mut::<ID_LEN>()
        && let Some((public_out, inner_out)) = rest.split_first_chunk_mut::<PUBLIC_LEN>()
        && let Ok(inner_out) = <&mut [u8; RECORD_LEN]>::try_from(inner_out)
    {
        *id_out = *id;
        *public_out = *public;
        *inner_out = *inner;
    }
}

/// Seals `body` with the epoch's `number` under the key derived from the stored key for wrapping
/// `stored` and the key of the epoch `epoch_key`, under `nonce` into `out`. `out` is written only
/// when this succeeds.
fn seal_archive_layer(
    (stored, epoch_key, number): (&Key, &Key, u64),
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    body: &[u8; ARCHIVE_BODY_LEN],
    out: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
) -> Result<(), Error> {
    let mut layer_key = [0; CIPHER_KEY_LEN];
    if derive_archive_layer_key(stored, epoch_key, &mut layer_key).is_err() {
        wipe(&mut layer_key);
        return Err(Error::DerivationFailed);
    }
    let mut layer = [0; ARCHIVE_LAYER_LEN];
    if let Some((head, rest)) = layer.split_first_chunk_mut::<8>()
        && let Ok(rest) = <&mut [u8; ARCHIVE_BODY_LEN]>::try_from(rest)
    {
        *head = number.to_le_bytes();
        *rest = *body;
    }
    let tag = seal::seal(&layer_key, nonce, aad, &mut layer);
    wipe(&mut layer_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    if let Some((nonce_out, rest)) = out.split_first_chunk_mut::<NONCE_LEN>()
        && let Some((layer_out, tag_out)) = rest.split_first_chunk_mut::<ARCHIVE_LAYER_LEN>()
    {
        *nonce_out = *nonce;
        *layer_out = layer;
        tag_out.copy_from_slice(&tag);
    }
    wipe(&mut layer);
    Ok(())
}

/// Opens the record of an archive key `record` under the key derived from the stored key for
/// wrapping `stored` and the key of the epoch `epoch_key`, and keeps what it holds after the number
/// in `body` if it names `number`; otherwise `StaleRecord`, and `body` is left as it was.
pub(super) fn open_archive_layer(
    (stored, epoch_key, number): (&Key, &Key, u64),
    aad: &[u8],
    record: &[u8; ARCHIVE_KEY_RECORD_LEN],
    body: &mut [u8; ARCHIVE_BODY_LEN],
    open: &mut impl Open<ARCHIVE_LAYER_LEN>,
) -> Result<(), Error> {
    let mut layer_key = [0; CIPHER_KEY_LEN];
    if derive_archive_layer_key(stored, epoch_key, &mut layer_key).is_err() {
        wipe(&mut layer_key);
        return Err(Error::DerivationFailed);
    }
    let mut parts = ([0; NONCE_LEN], [0; ARCHIVE_LAYER_LEN], [0; TAG_LEN]);
    if let Some((nonce, rest)) = record.split_first_chunk::<NONCE_LEN>()
        && let Some((layer, tag)) = rest.split_first_chunk::<ARCHIVE_LAYER_LEN>()
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
        && let Ok(rest) = <&[u8; ARCHIVE_BODY_LEN]>::try_from(rest)
        && u64::from_le_bytes(*head) == number
    {
        *body = *rest;
        current = true;
    }
    wipe(&mut layer);
    if current {
        Ok(())
    } else {
        Err(Error::StaleRecord)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::super::Occupancy;
    use super::{
        ARCHIVE_BODY_LEN, ARCHIVE_KEY_RECORD_LEN, PUBLIC_LEN, join_body, open_archive_layer,
        seal_archive_layer, seed_of, split_body,
    };
    use sha2::{Digest, Sha256};

    use crate::derive::{KeyId, derive_archive_key, derive_archive_layer_key, derive_key_id};
    use crate::key::Key;
    use crate::key::tests::{Counting, Random, from_environment};
    use crate::keyset::{self, Header, Stages};
    use crate::record::AssociatedData;
    use crate::record::PLAINTEXT_LEN;
    use crate::slots::tests::{EPOCH, epoch_key, flipped_epoch_key, pattern};
    use crate::slots::write_record;
    use crate::timing::timed;
    use crate::xwing::{self, wrong_known};
    use crate::{
        ARCHIVE_RECORD_LEN, Entropy, EntropyError, Epoch, Erasure, Error, Handle, KeyLength,
        Position, Purpose, RECORD_LEN, Root, RootFailed, Slot, Slots, batch_len, seal,
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

    /// A key from a secret, two stored keys for wrapping and two stored keys of the archive.
    fn keys<'a>(slots: &mut Slots<'a>) -> [Handle<'a>; 5] {
        let secret = slots.import32(Purpose::Wrap, &mut [3; 32]).unwrap();
        let mut generate = |purpose| {
            slots
                .generate(purpose, KeyLength::Bytes32, &mut Counting)
                .unwrap()
        };
        [
            secret,
            generate(Purpose::Wrap),
            generate(Purpose::Wrap),
            generate(Purpose::ArchiveWrap),
            generate(Purpose::ArchiveWrap),
        ]
    }

    /// What the outer layer of `record` holds, opened under the stored key `profile` and the key of
    /// this epoch.
    fn opened(
        slots: &Slots<'_>,
        profile: Handle<'_>,
        record: &[u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> [u8; ARCHIVE_BODY_LEN] {
        let mut body = [0; ARCHIVE_BODY_LEN];
        open_archive_layer(
            (
                slots.memory[profile.index.number()].wrapping_key().0,
                &slots.epoch.key,
                slots.epoch.number,
            ),
            AssociatedData::new(b"archive").unwrap().bytes(),
            record,
            &mut body,
            &mut seal::open,
        )
        .unwrap();
        body
    }

    /// An archive key opens with its two stored keys, its context and the key of its epoch only;
    /// the public key in its record is the one its seed gives, and it never leaves the library.
    #[test]
    fn an_archive_key_opens_with_its_two_keys_only() {
        let mut memory = [const { Slot::empty() }; 8];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [secret, stored, other, archive, other_archive] = keys(&mut slots);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        assert_eq!(
            slots.create_archive_key(stored, archive, b"archive", &mut Counting, &mut record),
            Err(Error::WrongPurpose)
        );
        assert_eq!(
            slots.create_archive_key(archive, secret, b"archive", &mut Counting, &mut record),
            Err(Error::WrongLevel)
        );
        assert_eq!(record, [0; ARCHIVE_KEY_RECORD_LEN]);
        slots
            .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        assert!(
            slots.memory[5..]
                .iter()
                .all(|slot| slot.occupancy == Occupancy::Free)
        );
        for (store, profile, context, refused) in [
            (archive, stored, &b"archive 2"[..], Error::StaleRecord),
            (archive, other, &b"archive"[..], Error::StaleRecord),
            (
                other_archive,
                stored,
                &b"archive"[..],
                Error::RecordRejected,
            ),
            (stored, stored, &b"archive"[..], Error::WrongPurpose),
            (archive, secret, &b"archive"[..], Error::WrongLevel),
        ] {
            assert_eq!(
                slots.load_archive_key(store, profile, context, &record),
                Err(refused)
            );
        }
        for at in [0, 12, 20, 36, 700, 1252, 1500, 1528] {
            let mut changed = record;
            changed[at] ^= 1;
            assert_eq!(
                slots.load_archive_key(archive, stored, b"archive", &changed),
                Err(Error::StaleRecord),
                "byte {at}"
            );
        }
        let key = slots
            .load_archive_key(archive, stored, b"archive", &record)
            .unwrap();
        let slot = &slots.memory[key.index.number()];
        assert_eq!((slot.purpose, slot.unlocks), (Purpose::Archive, false));
        let (id, public, _) = split_body(&opened(&slots, stored, &record));
        let mut given = [0; PUBLIC_LEN];
        xwing::public_key(seed_of(slot.wrapping_key().0).unwrap(), &mut given);
        assert_eq!((given, slot.ids[0].bytes()), (public, id));
        assert_eq!(
            slots.load_archive_key(archive, stored, b"archive", &record),
            Err(Error::DuplicateKey)
        );
        let mut out = [0; 32];
        assert_eq!(
            slots.reveal32(key, Position::First, Purpose::Archive, &mut out),
            Err(Error::WrongPurpose)
        );
        let mut plain = [0; RECORD_LEN];
        assert_eq!(
            slots.wrap(key, stored, b"seed", &mut Counting, &mut plain),
            Err(Error::WrongLevel)
        );
        slots.release(key).unwrap();
        assert!(
            slots
                .load_archive_key(archive, stored, b"archive", &record)
                .is_ok()
        );
    }

    /// A record whose public key or identifier was changed under its two keys is refused, and the
    /// slots stay as they were.
    #[test]
    fn a_changed_public_key_is_refused_at_load() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [_, stored, _, archive, _] = keys(&mut slots);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        let (id, public, inner) = split_body(&opened(&slots, stored, &record));
        for change in 0..2 {
            let (mut id, mut public) = (id, public);
            if change == 0 {
                public[PUBLIC_LEN - 1] ^= 1;
            } else {
                id[0] ^= 1;
            }
            let mut body = [0; ARCHIVE_BODY_LEN];
            join_body(&mut body, &id, &public, &inner);
            let mut changed = [0; ARCHIVE_KEY_RECORD_LEN];
            let Epoch { key, number, .. } = &*slots.epoch;
            seal_archive_layer(
                (
                    slots.memory[stored.index.number()].wrapping_key().0,
                    key,
                    *number,
                ),
                &[2; 12],
                AssociatedData::new(b"archive").unwrap().bytes(),
                &body,
                &mut changed,
            )
            .unwrap();
            assert_eq!(
                slots.load_archive_key(archive, stored, b"archive", &changed),
                Err(Error::PublicKeyMismatch),
                "change {change}"
            );
            assert_eq!(slots.memory[5].occupancy, Occupancy::Free);
        }
    }

    /// Every call on an archive key derives and runs the cipher and X-Wing inside the switch of
    /// data-independent timing, and with the mode on where it is offered.
    #[test]
    fn every_call_on_an_archive_key_holds_data_independent_timing() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [_, stored, _, archive, _] = keys(&mut slots);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        timed(|| {
            slots
                .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
                .unwrap();
        });
        let key = timed(|| {
            slots
                .load_archive_key(archive, stored, b"archive", &record)
                .unwrap()
        });
        slots.release(key).unwrap();
        slots.begin_epoch(&mut [8; 32]).unwrap();
        let mut carried = [0; ARCHIVE_KEY_RECORD_LEN];
        timed(|| {
            slots
                .carry_archive_key(
                    stored,
                    stored,
                    b"archive",
                    &mut Counting,
                    &record,
                    &mut carried,
                )
                .unwrap();
        });
    }

    /// An inner layer that opens under the stored key of the archive but holds no seed of an archive
    /// key, of epoch zero and alone in its set, is refused as such before its public key is looked
    /// at: a set of another epoch, of two keys or of another purpose.
    #[test]
    fn an_inner_layer_without_one_seed_is_refused() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [_, stored, _, archive, _] = keys(&mut slots);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        let (id, public, _) = split_body(&opened(&slots, stored, &record));
        let (mut seed, mut other) = (Key::empty(), Key::empty());
        seed.copy32(&[5; 32]);
        other.copy32(&[6; 32]);
        let mut two = Stages::one();
        two.add().unwrap();
        let associated = AssociatedData::new(b"archive").unwrap();
        for (purpose, epoch, stages) in [
            (Purpose::Archive, 1, Stages::one()),
            (Purpose::Archive, 0, two),
            (Purpose::ExternalData, 0, Stages::one()),
        ] {
            let (archive_key, archive_id) = slots.memory[archive.index.number()].wrapping_key();
            let header = Header {
                purpose,
                parent: archive_id.bytes(),
                epoch,
            };
            let mut plaintext = [0; PLAINTEXT_LEN];
            keyset::build(
                &header,
                &stages,
                [&seed, &other, &Key::empty()],
                &mut plaintext,
            );
            let mut cipher_key = [0; 32];
            derive_archive_key(archive_key, &mut cipher_key).unwrap();
            let tag =
                seal::seal(&cipher_key, &[1; 12], associated.bytes(), &mut plaintext).unwrap();
            let mut inner = [0; RECORD_LEN];
            write_record(&mut inner, &[1; 12], &plaintext, &tag);
            let mut body = [0; ARCHIVE_BODY_LEN];
            join_body(&mut body, &id, &public, &inner);
            let mut changed = [0; ARCHIVE_KEY_RECORD_LEN];
            let Epoch { key, number, .. } = &*slots.epoch;
            seal_archive_layer(
                (
                    slots.memory[stored.index.number()].wrapping_key().0,
                    key,
                    *number,
                ),
                &[2; 12],
                associated.bytes(),
                &body,
                &mut changed,
            )
            .unwrap();
            assert_eq!(
                slots.load_archive_key(archive, stored, b"archive", &changed),
                Err(Error::RecordRejected),
                "{purpose:?} in epoch {epoch}"
            );
            assert_eq!(slots.memory[5].occupancy, Occupancy::Free);
        }
    }

    /// The record is carried into the next epoch under another stored key without the stored key
    /// of the archive; after the commit only the carried copy opens.
    #[test]
    fn an_archive_key_is_carried_without_its_store() {
        let mut memory = [const { Slot::empty() }; 7];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [secret, stored, other, archive, _] = keys(&mut slots);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        let mut carried = [0; ARCHIVE_KEY_RECORD_LEN];
        assert_eq!(
            slots.carry_archive_key(
                stored,
                other,
                b"archive",
                &mut Counting,
                &record,
                &mut carried
            ),
            Err(Error::NoEpochChange)
        );
        slots.begin_epoch(&mut [8; 32]).unwrap();
        assert_eq!(
            slots.carry_archive_key(
                secret,
                other,
                b"archive",
                &mut Counting,
                &record,
                &mut carried
            ),
            Err(Error::WrongLevel)
        );
        assert_eq!(
            slots.carry_archive_key(
                other,
                other,
                b"archive",
                &mut Counting,
                &record,
                &mut carried
            ),
            Err(Error::StaleRecord)
        );
        assert_eq!(carried, [0; ARCHIVE_KEY_RECORD_LEN]);
        slots
            .carry_archive_key(
                stored,
                other,
                b"archive",
                &mut Counting,
                &record,
                &mut carried,
            )
            .unwrap();
        assert_eq!(slots.commit_epoch(&mut Platform), Ok(Erasure::Guaranteed));
        assert_eq!(
            slots.load_archive_key(archive, stored, b"archive", &record),
            Err(Error::StaleRecord)
        );
        assert_eq!(
            slots.load_archive_key(archive, stored, b"archive", &carried),
            Err(Error::StaleRecord)
        );
        assert!(
            slots
                .load_archive_key(archive, other, b"archive", &carried)
                .is_ok()
        );
    }

    /// A wrong answer from X-Wing refuses the creation and the load, which write and change
    /// nothing.
    #[test]
    fn a_wrong_answer_of_x_wing_refuses_the_archive_key() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [_, stored, _, archive, _] = keys(&mut slots);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        assert_eq!(
            slots.create_archive_key_on_stack(
                archive,
                stored,
                b"archive",
                &mut Counting,
                &mut record,
                &wrong_known()
            ),
            Err(Error::CipherFailed)
        );
        assert_eq!(record, [0; ARCHIVE_KEY_RECORD_LEN]);
        slots
            .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        assert_eq!(
            slots.load_archive_key_on_stack(
                archive,
                stored,
                b"archive",
                &record,
                &wrong_known(),
                seal::open,
                seal::open
            ),
            Err(Error::CipherFailed)
        );
        assert_eq!(slots.memory[5].occupancy, Occupancy::Free);
    }

    /// Every changed bit of the record of an archive key is refused by the reading of its public key,
    /// which opens it as the load and the carry do; without optimisation, where the cipher is slow,
    /// one bit of every byte. A changed byte at each end of each part of it is refused by the carry,
    /// which writes nothing then.
    #[test]
    #[expect(clippy::integer_division, reason = "a test picks bits of a record")]
    fn every_changed_bit_of_the_record_of_an_archive_key_is_refused() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [_, stored, _, archive, _] = keys(&mut slots);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        let bits = (0..ARCHIVE_KEY_RECORD_LEN * 8)
            .filter(|bit| !cfg!(lethewis_unoptimised) || bit % 8 == bit / 8 % 8);
        for bit in bits {
            let mut changed = record;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                slots
                    .archive_public_key(stored, b"archive", &changed)
                    .map(|_| ()),
                Err(Error::StaleRecord),
                "bit {bit}"
            );
        }
        assert!(
            slots
                .archive_public_key(stored, b"archive", &record)
                .is_ok()
        );
        slots.begin_epoch(&mut [8; 32]).unwrap();
        let mut carried = [7; ARCHIVE_KEY_RECORD_LEN];
        // The nonce, the epoch, the identifier, the public key, the inner layer and the tag.
        for at in [0, 11, 12, 19, 20, 35, 36, 1251, 1252, 1512, 1513, 1528] {
            let mut changed = record;
            changed[at] ^= 0x80;
            assert_eq!(
                slots.carry_archive_key(
                    stored,
                    stored,
                    b"archive",
                    &mut Counting,
                    &changed,
                    &mut carried
                ),
                Err(Error::StaleRecord),
                "byte {at}"
            );
            assert_eq!(carried, [7; ARCHIVE_KEY_RECORD_LEN], "byte {at}");
        }
        assert_eq!(
            slots.carry_archive_key(
                stored,
                stored,
                b"archive",
                &mut Counting,
                &record,
                &mut carried
            ),
            Ok(())
        );
    }

    /// What a slot holds: its occupancy, generation, purpose, level, stages, keys and identifiers.
    type Holding = (
        Occupancy,
        u64,
        Purpose,
        bool,
        Stages,
        [[u8; 64]; 3],
        [[u8; 16]; 3],
    );

    fn holdings(slots: &Slots<'_>) -> std::vec::Vec<Holding> {
        slots
            .memory
            .iter()
            .map(|slot| {
                (
                    slot.occupancy,
                    slot.generation,
                    slot.purpose,
                    slot.unlocks,
                    slot.stages,
                    core::array::from_fn(|at| *slot.keys[at].bytes()),
                    core::array::from_fn(|at| slot.ids[at].bytes()),
                )
            })
            .collect()
    }

    /// What a round of random records of archive keys gets wrong.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        Nothing,
        /// A context of no bytes or of more than 255.
        Context,
        /// A context other than the record's.
        OtherContext,
        /// A changed bit of the record.
        Record,
        /// The outer layer under another key than the profile's.
        Profile,
        /// The outer layer naming another epoch.
        Epoch,
        /// A changed bit of the inner layer.
        Inner,
        /// The inner layer under another key than the store's.
        Store,
        /// A set naming another parent.
        Parent,
        /// A byte of a field the set is read by.
        Field,
        /// A set of two keys.
        SecondKey,
        /// A plaintext of random bytes.
        Plaintext,
        /// An identifier not the seed's.
        Id,
        /// A changed bit of the public key.
        Public,
        /// A seed these slots hold already.
        Held,
    }

    /// Each fault in turn; one round in four gets a second, at random.
    const FAULTS: [Fault; 19] = [
        Fault::Nothing,
        Fault::Nothing,
        Fault::Nothing,
        Fault::Context,
        Fault::OtherContext,
        Fault::Record,
        Fault::Profile,
        Fault::Epoch,
        Fault::Inner,
        Fault::Store,
        Fault::Parent,
        Fault::Field,
        Fault::Field,
        Fault::Field,
        Fault::SecondKey,
        Fault::Plaintext,
        Fault::Id,
        Fault::Public,
        Fault::Held,
    ];

    /// The fields a set of one seed is read by, in its layout: the version, the purpose, the
    /// primary position, both ends of the epoch and of the revision, the stage and the length of
    /// the first position, both ends of its padding, the stage and the length of the second, and
    /// the last byte.
    const FIELDS: [usize; 14] = [0, 1, 2, 19, 26, 27, 34, 35, 36, 69, 100, 101, 102, 232];

    /// Whether `plaintext` holds the set of one seed of an archive key, read from the layout: version
    /// 1, purpose 4, the primary at the first position, epoch and revision zero, the first position
    /// enabled with 32 bytes and zeros past them, and the other two zero throughout.
    fn holds_one_seed(plaintext: &[u8; PLAINTEXT_LEN]) -> bool {
        plaintext[..3] == [1, 4, 0]
            && plaintext[19..35].iter().all(|&byte| byte == 0)
            && plaintext[35..37] == [1, 32]
            && plaintext[69..].iter().all(|&byte| byte == 0)
    }

    /// `plaintext` sealed under `key` with `nonce`, laid out without the library's code for it.
    fn sealed_by_hand<const N: usize, const R: usize>(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8; N],
    ) -> [u8; R] {
        let mut sealed = *plaintext;
        let tag = seal::seal(key, nonce, aad, &mut sealed).unwrap();
        let mut record = [0; R];
        let (nonce_out, rest) = record.split_at_mut(12);
        let (sealed_out, tag_out) = rest.split_at_mut(N);
        nonce_out.copy_from_slice(nonce);
        sealed_out.copy_from_slice(&sealed);
        tag_out.copy_from_slice(&tag);
        record
    }

    /// What `record` holds under `key`, read without the library's code for it.
    fn opened_by_hand<const N: usize, const R: usize>(
        key: &[u8; 32],
        aad: &[u8],
        record: &[u8; R],
    ) -> Result<[u8; N], seal::Rejected> {
        let (nonce, rest) = record.split_at(12);
        let (sealed, tag) = rest.split_at(N);
        let mut sealed = <[u8; N]>::try_from(sealed).unwrap();
        let (nonce, tag) = (nonce.try_into().unwrap(), tag.try_into().unwrap());
        seal::open(key, nonce, aad, &mut sealed, tag).map(|()| sealed)
    }

    /// Records of archive keys sealed through the real derivations and cipher and laid out by hand,
    /// with every fault of [`FAULTS`] in turn and at times a second: a context, either layer or its
    /// key, the epoch, the set, the identifier or the public key wrong, or the seed held already.
    /// The load, the reading of the public key and the carry, to the same stored key or another,
    /// never panic, refuse exactly what they should, with the error they should, and change or
    /// write nothing then; the load fills the first free slot with the seed, the reading gives the
    /// identifier and the public key the record holds, and the carry the same under the next epoch.
    #[expect(clippy::too_many_lines, reason = "one round builds and reads a record")]
    fn load_random_archive_keys(rounds: u64, seed: u64) {
        let mut random = Random(seed);
        let (mut faults, mut fields) = (FAULTS.iter().cycle(), FIELDS.iter().cycle());
        for round in 0..rounds {
            let first = *faults.next().unwrap();
            let second = if random.below(4) == 0 {
                FAULTS[random.below(FAULTS.len())]
            } else {
                Fault::Nothing
            };
            let has = |fault| first == fault || second == fault;
            let mut memory = [const { Slot::empty() }; 6];
            let mut epoch_memory = Epoch::empty();
            let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
            let length = [KeyLength::Bytes32, KeyLength::Bytes64][random.below(2)];
            let stored = slots
                .generate(Purpose::Wrap, length, &mut Counting)
                .unwrap();
            let next_stored = slots
                .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
                .unwrap();
            let store = slots
                .generate(Purpose::ArchiveWrap, KeyLength::Bytes32, &mut Counting)
                .unwrap();
            let next_profile = [stored, next_stored][random.below(2)];
            let held = has(Fault::Held).then(|| {
                let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
                slots
                    .create_archive_key(store, stored, b"archive", &mut Counting, &mut record)
                    .unwrap();
                let key = slots
                    .load_archive_key(store, stored, b"archive", &record)
                    .unwrap();
                <[u8; 32]>::try_from(&slots.memory[key.index.number()].keys[0].bytes()[..32])
                    .unwrap()
            });
            let mut outsider = Key::empty();
            outsider.copy32(&random.bytes());

            let (archive_key, archive_id) = slots.memory[store.index.number()].wrapping_key();
            let mut plaintext = [0; PLAINTEXT_LEN];
            plaintext[..3].copy_from_slice(&[1, 4, 0]);
            plaintext[3..19].copy_from_slice(&if has(Fault::Parent) {
                random.bytes()
            } else {
                archive_id.bytes()
            });
            plaintext[35..37].copy_from_slice(&[1, 32]);
            plaintext[37..69].copy_from_slice(&held.unwrap_or(random.bytes()));
            if has(Fault::Field) {
                plaintext[*fields.next().unwrap()] = random.bytes::<1>()[0];
            }
            if has(Fault::SecondKey) {
                plaintext[101..103].copy_from_slice(&[[1, 2][random.below(2)], 32]);
                plaintext[103..135].copy_from_slice(&random.bytes::<32>());
            }
            if has(Fault::Plaintext) {
                plaintext = random.bytes();
            }
            let context: std::vec::Vec<u8> = if has(Fault::Context) {
                (0..[0, 256, 300][random.below(3)]).map(|_| 7).collect()
            } else {
                (0..=random.below(255))
                    .map(|_| random.bytes::<1>()[0])
                    .collect()
            };
            let sealed_for = if has(Fault::Context) {
                &b"archive"[..]
            } else {
                &context[..]
            };
            let associated = AssociatedData::new(sealed_for).unwrap();
            let mut inner_key = [0; 32];
            derive_archive_key(
                if has(Fault::Store) {
                    &outsider
                } else {
                    archive_key
                },
                &mut inner_key,
            )
            .unwrap();
            let mut inner: [u8; RECORD_LEN] =
                sealed_by_hand(&inner_key, &random.bytes(), associated.bytes(), &plaintext);
            if has(Fault::Inner) {
                inner[random.below(RECORD_LEN)] ^= 1 << random.below(8);
            }

            let given = <[u8; 32]>::try_from(&plaintext[37..69]).unwrap();
            let mut given_key = Key::empty();
            given_key.copy32(&given);
            let mut given_id = KeyId::empty();
            derive_key_id(&given_key, &mut given_id).unwrap();
            let mut public = [0; PUBLIC_LEN];
            xwing::public_key(&given, &mut public);
            let id = if has(Fault::Id) {
                random.bytes()
            } else {
                given_id.bytes()
            };
            if has(Fault::Public) {
                public[random.below(PUBLIC_LEN)] ^= 1 << random.below(8);
            }
            let mut layer = [0; super::ARCHIVE_LAYER_LEN];
            let number = if has(Fault::Epoch) {
                EPOCH ^ (1_u64 << random.below(64))
            } else {
                EPOCH
            };
            layer[..8].copy_from_slice(&number.to_le_bytes());
            layer[8..24].copy_from_slice(&id);
            layer[24..1240].copy_from_slice(&public);
            layer[1240..].copy_from_slice(&inner);
            let mut layer_key = [0; 32];
            derive_archive_layer_key(
                if has(Fault::Profile) {
                    &outsider
                } else {
                    slots.memory[stored.index.number()].wrapping_key().0
                },
                &slots.epoch.key,
                &mut layer_key,
            )
            .unwrap();
            let mut record: [u8; ARCHIVE_KEY_RECORD_LEN] =
                sealed_by_hand(&layer_key, &random.bytes(), associated.bytes(), &layer);
            if has(Fault::Record) {
                record[random.below(ARCHIVE_KEY_RECORD_LEN)] ^= 1 << random.below(8);
            }
            let mut asked = context.clone();
            if has(Fault::OtherContext) && !has(Fault::Context) {
                let at = random.below(asked.len());
                asked[at] ^= 1 << random.below(8);
            }

            let read = if has(Fault::Context) {
                Err(Error::InvalidContext)
            } else if has(Fault::OtherContext)
                || has(Fault::Record)
                || has(Fault::Profile)
                || has(Fault::Epoch)
            {
                Err(Error::StaleRecord)
            } else {
                Ok(())
            };
            let loaded = read.and(
                if has(Fault::Inner)
                    || has(Fault::Store)
                    || plaintext[3..19] != archive_id.bytes()
                    || !holds_one_seed(&plaintext)
                {
                    Err(Error::RecordRejected)
                } else if has(Fault::Id) || has(Fault::Public) {
                    Err(Error::PublicKeyMismatch)
                } else if held.is_some() {
                    Err(Error::DuplicateKey)
                } else {
                    Ok(())
                },
            );
            slots.begin_epoch(&mut [8; 32]).unwrap();
            let at = format!("round {round} of seed {seed}");
            let before = holdings(&slots);
            let first_free = before
                .iter()
                .position(|holding| holding.0 == Occupancy::Free)
                .unwrap();
            let result = slots.load_archive_key(store, stored, &asked, &record);
            assert_eq!(result.map(|_| ()), loaded, "{at}");
            let mut after = before.clone();
            if result.is_ok() {
                let mut keys = [[0; 64]; 3];
                keys[0][..32].copy_from_slice(&given);
                let mut ids = [[0; 16]; 3];
                ids[0] = given_id.bytes();
                after[first_free] = (
                    Occupancy::Loaded,
                    before[first_free].1,
                    Purpose::Archive,
                    false,
                    Stages::one(),
                    keys,
                    ids,
                );
            }
            assert_eq!(holdings(&slots), after, "{at}");
            let public_read = slots
                .archive_public_key(stored, &asked, &record)
                .map(|found| (found.id, found.public));
            assert_eq!(public_read, read.map(|()| (id, public)), "{at}");
            let mut carried = [7; ARCHIVE_KEY_RECORD_LEN];
            let carry = slots.carry_archive_key(
                stored,
                next_profile,
                &asked,
                &mut Counting,
                &record,
                &mut carried,
            );
            assert_eq!(carry, read, "{at}");
            if carry.is_ok() {
                let mut next_key = [0; 32];
                derive_archive_layer_key(
                    slots.memory[next_profile.index.number()].wrapping_key().0,
                    &slots.epoch.next,
                    &mut next_key,
                )
                .unwrap();
                let moved: Result<[u8; super::ARCHIVE_LAYER_LEN], _> =
                    opened_by_hand(&next_key, associated.bytes(), &carried);
                let mut expected = layer;
                expected[..8].copy_from_slice(&(EPOCH + 1).to_le_bytes());
                assert_eq!(moved, Ok(expected), "{at}");
            } else {
                assert_eq!(carried, [7; ARCHIVE_KEY_RECORD_LEN], "{at}");
            }
        }
    }

    #[test]
    fn random_records_of_archive_keys_load_as_their_layers_say() {
        load_random_archive_keys(100, 1);
    }

    /// The same over as many rounds and from the seed `LETHEWIS_RANDOM_ROUNDS` and
    /// `LETHEWIS_RANDOM_SEED` give.
    #[test]
    #[ignore = "long; the rounds and the seed come from the environment"]
    fn many_random_records_of_archive_keys_load_as_their_layers_say() {
        load_random_archive_keys(
            from_environment("LETHEWIS_RANDOM_ROUNDS", 10_000),
            from_environment("LETHEWIS_RANDOM_SEED", 2),
        );
    }

    /// The record of an archive key and the same record carried into the next epoch, computed by an
    /// implementation independent of this library: a source that gives `pattern(17, 5)` for a draw
    /// of any length, the stored key of the archive generated as the first draw, a 64-byte stored
    /// key for wrapping, the record in "archive" from the next three draws, and the carry as the
    /// fifth, into an epoch whose key is the key of the test epoch with every bit flipped; then a
    /// second archive key created during that change, from the next three draws. Once that epoch
    /// is committed, a key of a chat for its archive from the ninth draw, a batch of "chat" archived
    /// to the second archive key from the next two, another key of a chat from the twelfth, and the
    /// record moved to it with the thirteenth.
    const KNOWN_RECORD: &str = concat!(
        "27bae2fc323c379d396cc79bbdf51002a439a6a94cbdf763d122b78635d67108",
        "10af90cacf926bd3f24cf02a42d2f09ee008316790fe361e9f7e4b1fd69fbc92",
        "2133cb5851a809548f4a0ad9c4429a29406eb25b5f324da989773ebac29146dc",
        "e35c5182e154387b2e76cc02fa16daff13e7fd639d0d8e126c1af46a36eff152",
        "b61d0ef6e8587f05255b3bdde4f39318d7bb1b3fcd2ff5b52d51251f5990e5d4",
        "c3546e9c8af6472d04c7937743588f9eb1063117e223b1ec37e9e613c575215d",
        "830cfd9a094c324c4b05510eaf82a8a069418b747e7c059d345bbad5b45f52bf",
        "7fa810b357508fcccdc80aedd343e7d9f66ee5d86e5a26fb98e9e454ef3b279f",
        "420a919c8465bbe17e90ad7e783010497071ef1192c5080c38890a39cba6f916",
        "dbb92569b3305a88cea189df597dff3f1b5caf82acbca3270188497cdd0547b6",
        "96fcb3440c308f4bde32a60502c449bb7c27aaad8e3532195abe0c4767c96c64",
        "1e0bf53398e568ec6732f234c5f370d1d8c5132c687513ee448cee25b05be5cf",
        "506e4b6e7866715051303917c14e2c5a0fb62d9da120c187a0aaf71af862da73",
        "9ccaaaf67a35bbf077bceebc1c8679df16c9defd751d2971c65b678a2539f353",
        "abf0634f2a5e15b20f18a3b7bda51d2927172fa0caf86a5db555e86f2d3926e7",
        "ebfb323f8838736309c08aeac4500ed38870931042ce4486f9c9e0d752613e30",
        "a96c98700e1ea525786332c56890837ac0b029a4f1cec8fe04b918e114bd7a47",
        "732b5dd03c636aa8d48d059fb634e236ed1d3a16890de951cd0a48a5cdbc5af9",
        "a3c449a477a3913c507f3754c01a23e2c23c77e7e39c8d76806a1180b26c95e2",
        "03d8ca79d83e80ba61b74ca578e1bc84ed7cc52e288960304dbb607135e9b113",
        "2e2c7da4adcdbd5aa90e7a5317453d4c094472ee8bb3edde4cd58184d79672ca",
        "7f12f61a602cbc413df3fa9c1079149a2f8668e2fd86efa29848470bad64dc5b",
        "febff36caf7c579e07f1ead9e0c663ac0fc528802d67d0c701b4ad590fcbd2df",
        "d09a5100630614cc207dcefc0e94bccce828fa092447e4f7f7a8b465aa9e2bf0",
        "34b9fadfe07d1fbfda7fbad7e5a7f489ae751e4ca40a1875e4b720c42716563a",
        "1aa9014344fb7e48b0dcfc5d57319bb293fc1d8c47b17513aebf245a41020b23",
        "97e665880a65d597f2887408f2a57b27c8a89f513b71b9fffee3d4f5202383bd",
        "d841be21e8b10fb948c0448e618c035a578411141c4031f92b7951939bfeea8c",
        "c4844fb48553fcc2a2efd2bdc75684289bc7871fc110123862069d0c8ea19f44",
        "cde81d19b41e5622d316f2dca7c87adef05e52683792567eba46cd3edcf73ebf",
        "3e8afc2d970ccf16844c1258b3f244508a8bfb0b5149d7d40c998be2fd09fc75",
        "71b39fc811308759bd830e3c92163686547e2f650143c34a71deb9d44be09b5b",
        "a6baf9a7f8c5bc6f7b03c0129c116671a84eaa9a0b2ff5367639ba1ca8dc5ee0",
        "e81fb2d6b7249b1a810be3f2fe1685d2cba2a774d5ee2656b619e1fe051f494a",
        "6d75e1159cacd6728404268fef8f2a3b85daa38e13821e7e1c39a8890b27b9a1",
        "9d659b88e56438c8fc811fc446c9bab399190293a89947b6b410240be19dd855",
        "28241a1d623478c261b5c959670b7260cd68fe5ae031b96d2a9ab79bd56615c5",
        "94bf1542985e6a4a0bca92f09a88e3e384d59d3f43bf254c0275cf371c9dc949",
        "d0019dfcd1fcdca5eacf415104d10be384e0e6a670fb6a0d1122fbb76710f73a",
        "e97475d7dcb52c2ed3e464a04ee9806b30f2cce3895980608fbd47ef5f5e49c1",
        "49efdf0fb60ba59276f5c8d89437f993c9ca77b52d0dd04801e5e521c2d46116",
        "278ade269263e1d183512e2a5a33f3a470d837d0256184260d20c2b7fa73aacb",
        "c2574a1c3fe40bfe4c1770b088f19ad1a2abe352c92c757bced9c44a4ad523e6",
        "07266a7237855a9fd83341abf1309edcc9a039f618e90e5716c7f96629dfca43",
        "7d05e1272dbacefda49b99c561cc3913e9bf865ce6ed562e3876960109d66cfe",
        "e366448d1f69b857f0eb0573721dcb3d7d8342f2d750341bbd20ab25600ffcb4",
        "7d0dc4300c3dcd9561cf56428b39d623ede02cebcb1c1080947f2622e67bc3ae",
        "dc7dc0783574dfc4dee53af04463c396ecb03a58a39636e027",
    );
    const KNOWN_CARRIED: &str = concat!(
        "3b54f7a561fd4fc7cdd63a60e0aec4ef41620cedb92a8f551cfeee78052df50f",
        "31e144a229fa7b698ea2a04255ef2f44e1b27898160893804cd2aab6e0c6ea16",
        "d576bafe8c5f0b2db37c0cc7c294e9a45ebb89ea30c23f0f43f58b509d5b24d1",
        "40ec9ba342c5d32cff049b47ff751d8edaadc6efa5faec4c1f024c80921c585c",
        "7da17d925963187707de1d3784cb7353c2d7b709b98740cfc2ae2fef00773d7a",
        "91ce2d3e428d266d4a14576489c543e0e1e3650b39777c43ed0445b8ecbeca5e",
        "47de3adf634fba5e49e45e8e23baa93ee93e9fa8aa6ccc05c4f2dcaf21f01319",
        "8f7fb30e1f6c5da438f61e84eab060357f700d56ff22412d049d3d1184e93711",
        "cba310bece112e627562454884b3b34ab60df0649c1057dcede5ea0df0bdbe7a",
        "df4ce66c862b1f539c8b862c069f2138d4f0daeff34d8f58c5e7e31f1809de54",
        "fe17873d0c44162a210bddbc3153f45639894aa3d1a3378dd0c5b27bf5a138ea",
        "686dcef120e7eb3bb0b95fa939bf087c1935e55cc798a20a4bb4f0ca06b89251",
        "d20411a718b19ce2bac180037730d8db7ceb15c9286833bcfb3c31626ccf0072",
        "d64cf2cf37ac1130caf1032299fd5eeb7da3ccbaf980625246d34a87368742d9",
        "01221988beed3d610abb174812eceda1e60fe1c72aa7eb2d20791083faabbc48",
        "38078583836f933676028a613cf1bfa4c79ace781d8b3887d029354139e8e501",
        "a061201c1f246751bc7a6bef21a71adf6ca68046ffea23bbfd8c70fcebde75aa",
        "1edc860cddfc819d06b24e02dde55aff447b218269209d8b32b78f5496e7625a",
        "04f8943d4402e3329300cffb08f9b24735d4623ee620f7d7ee373fcc04246de4",
        "c759f8d5bd537aef8e20fe2bb3b97ead7b2a08ac18047f5db79257ad4757f620",
        "037460809b732c42badc5e3fad25384a46299145f8f84a0164c003fdf9b45c35",
        "f342e8d450bf6d5f87467d8d3fa50f5df8c4f99a71adde19afcf2bf31ca0e7a3",
        "44faa54a47bcd08fa3937a5d8f006c8e020357af0c31a14342fcf478e2481d59",
        "6f0db9c5124ef9e2cfd51d6a928fb4874d7f769f844606a30695293630b5b4f8",
        "95d0dab19d37f06c42ef3c02ae9587ac5c8db67e3f36f81a87c5a2c349fa5475",
        "897682c216ccebf272ab6eae92d1a425d9ffbb28bfba5bd74a3b8b31a849aae2",
        "8f766aa2bf4b990f176061912de6731da1990f5fe620e3bacb16946296171ad9",
        "d791834b26b4d10b1533849a8d61c646b7856fbdf3a81392a01d5c694abc43e4",
        "044e984881e465bd29723970eb1e49f419a1613ad4df7a9ad828e33938a3475a",
        "50414fc5e038d14ef924f0fd63b67b8b22985bd0292331e88d18f7477ef09b9c",
        "4f10e22aec225c33b8f6890d41d350ee2c390fc9ed8abddc969a1247f791c3a3",
        "1148083eea00c4eb0ef4a0e2a3254636b334607ead56ab83d0aff54e6dee4283",
        "938bbc8db36d360e24087b09f497b12652059975afe0a6a76be7ce37b35999d2",
        "7bc616f46ecfa88a214555dee8d054248b3708ee90466be2703218d8d38d1e3d",
        "b23f992e2635216fddc8a6493f12e34befb7c88c6ebd726034329bff197131b3",
        "61a59904c691efc2b2806ea5079e29f22a9a82b8d8569e08f7d902c8bb9b9bd2",
        "c6e2ab944562ee37a8a153d4cd050da4fbea5e79ea533e0b71de0adc0721777e",
        "c05ed75b5ae216c2048f3d7e56f6cd6ab4b5206e609aa4d291414779037ba141",
        "bed81bfe1b7413d90c6f3c1fab9ee13dcb7dd354f4dd0f0d813ebe4ab2676505",
        "575b78832a4f635d322b3db3e563f11bbe48de01ef4033467c2ae08fb59dd158",
        "1f42933a3d61a6df33ecc391e26aea811f3260f15923c4a18fa274971274c214",
        "7ac6dd3cb941dab03ac232e864d8ff4840088efd9fb9659af7a08a50bf133f3f",
        "ece873ae3f104e384134d8f6e25346e99eab2c13a585230ea7d7a8c848b63bfc",
        "f25881dd5bf43248e222a8a535fe1e7f49645d5a78088310a96cc2919154e384",
        "f73ad3bc0076d0ebe958da4564ea80cb52eaebf4f53664434d6f835d302b9c5d",
        "1329ef57c769ff7ce13c47f552fbe4701e0c51dd2ed7573482fd3118ebf0ebb0",
        "c5153826571a3156791184a0a0408040d201dc3dbac3955f502625c29c0672a0",
        "5038571962a7cf524b9f71704672603a41e9b3f08ef6bee10e",
    );
    const KNOWN_CREATED: &str = concat!(
        "56684f17a07a8214aa598ea9d95953b600ae1667af214cb49cca3a97b6ac4e2b",
        "c536ecbb694f8c5127aa532e6eef351e61d5c55dbda655f838cb67e04a5b2944",
        "315822d0680c2f185eb1c5469303a8f16cb97af143861f8b7dd4a278de9452f3",
        "66d5d84fbca6f7880f01ceb75f3e13b21be1d88cf6c85610916f804a8fd6b2da",
        "cceddfeafad10502458f3439a30c12371d32db8f4a1cefc3d1ef36f83d148a82",
        "dcc609e16f3baf972f773b21232306c32253577ae5c89b2708653ae4ffe993df",
        "c712f6684a4bad05570b230408c476f26a6d3dcb2406420f86af4e64bb57c10a",
        "1979cbaecf991430cb4f869090093dbb3e7e12077ea6137c01929040ef94a2c0",
        "6fa0118cb360647061f60c4e73721ba4c60c6ca6f16d1694fc6d541a213c581c",
        "0576f10a740efc8134e47051eea589ee400a7fb0d0ffc39edbc659e17b22fe79",
        "79506e30b7192b0f252d09b7b109a88ebe91a6ab8164fc714d0208af8559b090",
        "9ea5a73ac7be510b2e5c103b0c1f04a529e22f91f2c37234700dafea4b86dca7",
        "6daffea21dbc01918c69a0dd2208a5fc3ab589a835c0f21ff5ad49a7801827c7",
        "1f2968dcf57729b322138d901b98e1e2694b25b0d201947b374416c49b139b1f",
        "c082e1ee1ac312f3aff163d1f11a6444cb80a80476fa421a1e34853d31e2fae7",
        "6fe2f1a664d76273e619266319b9b08905e249cf2d7aacbd731753a736abeff8",
        "dcf4eef84fc4352015c42342490fa37550bba0c1fd7c2390938c16517b7e20ca",
        "2be2ab8006539928c2449e47a3eb36d0e24d28c83c6761f6987aacc90e9072f0",
        "1df0a407185a7ccb89391ae109dbea20c28f69d281026ccc73545cc9399388dd",
        "06a8987969e6b174b653153e8a376df6e7df88da773615af5b101a8e62a5b783",
        "da729921ef04b9adbc0b4983650451036fb117250edc4b9b5b6eed4c3e91683b",
        "bce8bebc1fb55f459e413cc0860d5d77de84f23a4d43eb142b34c3b5b8f78329",
        "a4a43f8ff1233adc024a704d23811b812a11ebec4826c0b74f4e3912700c65f4",
        "6f85ff5f52bb13b9970b70a54404c9fdd7e27f9cf94ecfb2fdc9eb13732b4fd5",
        "43c586edae93f9a1283b157d43d8dbd65917d7055378b98a8e874ccbcf3e8a4e",
        "c5bccbd551f4c10d92730c17b4099282ab748f01eaabe80eefdefb07e847d2e0",
        "6e7afa3a0c584c67916739777b27192050470aac7da4c5eb5a262fbc65db65fc",
        "ec0428790dfe9400dac45ed4a70d0e5d05ce3b9e3bddfb71728df0fa4d6cbb7c",
        "c253d6b94c0f531f51e07efa52fb133b34e1cd89b5938b5dec87109f306a780a",
        "160ec9fe3cf9ab5025137349611b0eb6c842d1980499e1c52afd21560b0dc116",
        "dd184ac90391ea3fc4720a021e1e49b3c1bfe62fa2a66608237a6c1eb5e27471",
        "a8a6b315514a2d7b3a3834e45168f9e3b3539a68fd5c5e9971d043fb504cbe82",
        "e835b8f801761ded5e0f29cabf663cdc9089950303d88ef2466e7c94f6375e96",
        "63c6f8abd68a4ba20077bcdf1aecd0ec5eb96bb9fe51b373783fccf6aa6627e0",
        "712c2354172a7df6008f4cc011a2b309bf4e4d3dd07a3621613a306f7217e1a0",
        "4c8d0883886fa6039bee814fb14f1e69c89328e79775f5e05e579fa6c43dc012",
        "5c13059021c87ec7f7baf7e3245d10f733afbf4bc5c22dd1ad8b2832e19d6239",
        "02d3f96b6b2b813069c487ac8c4ce369bfc9e9a71992c8d6de31e4af0d15dce6",
        "53b999b828ebe432e697aef83e37e843775bf6c4beea182ea61b3b3ba4c69aae",
        "e11ee3d4f7280fe21737c8ee9b0a3e490e5797fb7c12f87811140733186371e2",
        "2c8f5d0ca63c001e8e19773499194f2a04b986315ed18bb0ba77bf81e794b556",
        "7e2547ee81cbf1f5ef9b49eae16e8af23464daf5a7b66fc5c4bfb8dea8b8a334",
        "3d9aba34b8c68cabf2d5d1a811b51edf07327d3425726163bcb00845a32a6ec7",
        "0756ad46e0c45dbc8fa2395bfccb08308b371bb0530b5864b82e1fc8d8f17b79",
        "10430f0a58701ad432473de2554167f8a11e18e5a1f14554e4f2b25931d42366",
        "9f7dd2903f08c48ac52a62500c262385e6686fd72b4bc6223e124e5c34d164de",
        "b7ed2a07ee2da23db345475a6d46081c207e72a146c10e775353d3b444ad0e84",
        "7dacb3c29b92b015c695d8a96e16a2ec2f5834cd832fc7ad7a",
    );
    const KNOWN_BODY: &str = "6b2f3d84baa5f88d121d8dd808fac5883dd5299249720bbf9b61f953e56245e5";
    const KNOWN_ARCHIVED: &str = concat!(
        "fc29cbd9e776d2ed97e664a654f59ac6ff3b395f0dca75cd6ee6855b66f6161a",
        "7bbe8b9b2d6c002b5966d51599dad052cb24fbe225d948129875908454832f65",
        "9e9753bdf916a9b119c98dd49d7a2fd65b6a9a74aa0f4c895b2740d4cbe3ffa0",
        "9d2956376713393c1d31e094b9013ac108beed02d74bac7284517e6f694c5dc8",
        "528e5fb6afd40661119ca8b2d6e0c91488ef6afe06953ae1a41db1eeb5af23e2",
        "2f5c412c29d652f3c7730d31449f579baac804c0f573ee75d51e01b6a9e0d9f0",
        "05f2b850fd6eb7ef5b4361c65847e8961e57b5b8e32bf0886e32ef346b846ebd",
        "2daac2f87b8f3e463b60e8480d34d2722fbd7c901f027f547839b05853817935",
        "c4769dd4fb96bbe6c9001c494b3c9ff9ecb5224c2e680967a986e1d5483e2f9e",
        "2df900953fabe29e0bc6575a64396bffdca4d30926b780d8c14638b4c14db39e",
        "e661fc8b20c512a326c893b3189cbf030ecb5f46ded420af9b77bae8b394baab",
        "682fb5bf1268956318c9d1cf6e365ae9b8ae1f1c8d6495f30e579b448cc70ccb",
        "6258939ac02ad3dd4e20bba8b27abcc369eee8411fc2ea08e55cafa932ee3ff4",
        "2d29d574506fe5b38f39d8ad421581813a89d2ca7cdf0208e99cca8b6f06303f",
        "7fa12b102cbd053f6b764f22e7e48659956a29902d4c8200da7b2de646ece380",
        "15e91c171318f556edd592f9c5568848b46495ccafedfd1476af6d1e139787a6",
        "8c3d93f392bc169ed2d16e89d7f1b39c9dcdfb627413859175dab4efc1f42ef9",
        "26278e6bff8499206f1d22034e6d12386a5b216306329eb824756db0e9475c67",
        "3e888bd06e9bf695524dfc5663ec16175c34a59d8ef9aab982066dd7a001eaa8",
        "905af8eb732ffb1a981b5e4f738b30933c9e294f231a9bb9131622f9ecbb9ed6",
        "84bf7c923d709d4c25d7057379eca95142c947d7266f2bd9f33889d56651d1d5",
        "18ddd1b5ac0ded59e2317df73edd4ba7231033f9f765bb007000a1cb61e233b3",
        "05e982dbff5a7938f6e10531bac1b044bc3067a18e5409d264f025108b259680",
        "8a852f5e0fcb477c6e476af1477bad4ea5b6e8a38bcceea83b208f026d018449",
        "7a11c58f9270ae04bcc6d0eac46d4c0e1e93c268c2802c502069b1d014470aac",
        "9658158640210af3fd1b56960b7f04282eeb9e3afcbf32760135b98b583a5b6f",
        "92348ffd71d25e52006285fc22e56d61fbf0bbe912e301d9be760101fa099ca1",
        "240df6dc9a7fb66104c39f59ad64f4f32f0d25f16dd3c21f8c423ea51ffc9582",
        "00332516a583ff3a7c6a8c09a0f33fe4accdeea6a987b1fb8b35b842a2bddaaa",
        "9f5fa352b392d89a3722f7896d6875f80339d10aa10bf66917375c4e34ef8dc9",
        "d0635667a3c8ef0ba7565be893e622739749773f627c8607910ea5291d46d263",
        "53e01eca805402f38185804747dc300e1e3025fe8670e5ccb0712e372ce50715",
        "5816fbd71eb56122e819e437f526ed583dac26e5e1afcbeefe518486405c7c6c",
        "94f24b52f08cacc45a0d33135ac7db321f6b8c74f7a44ce9580f18c38c3f337c",
        "3478c0b2a375aeb56b0e8e2dc49492b1228ab11aa6f160bff74c73c6f2553924",
        "abad9d67822ea5ea18b2f2c219e7f367141e336a2730a0596487b81ea9fdc031",
        "f2cfbf6b0d05f9d6906525faa10c69b2c7aeb0a16f86e7b4282f29cc",
    );
    const KNOWN_MOVED: &str = concat!(
        "4063a1dbd80d6757dd56d8ea501961b911e6216f19a9bdfad32835e7b7751353",
        "450acbc08aab117eb5b872750ab3124b6c3bd9b62a51b6d1f6f92679fed331ca",
        "e91786dd7960842e2c4328a16f4defb7b5dd64201eec5b99835e57b979effbf8",
        "62952359e1d569c3fcde78e45da84bfedd8b44e7e85e8d2ec176ce5226133a30",
        "973b5d849b363e778e3bfdcdb6ff52a9f41a92e36d0ae2765ccad63023f24f07",
        "6ae94ad24a29b2a1091a1b7ef44b034843f5e6e4af8e717d5981c62aeb915122",
        "a37aaf87726d22c9ab8fb73f99482f1c180f245b7e0fa50d58e0578d5db108c7",
        "7770b09d0b532a85e3fad96f40cacc184c6fb4d7a03a625927637eab8415cfce",
        "6cb0010adb42f80c83a485df60d204941ad04e69542d4ff07768a941d8440c62",
        "b790829cd1c53c8a024ca1af9a9f13ab4bc572d7f56d5df0ae051cbecc38b376",
        "fe5458c0445ec775d26841b3de498c36eabdc26d3335b635a592bc6fd47ca79e",
        "5da349c0072419751a15f06f8addc5b11497f4c6458e250f9c6d5243fb3255e6",
        "303fc285afa0a97db37c50e1be32455bee41339c92797c63048818c411fa63a6",
        "c988f0a077ae84a4fc6cdac151fe5c7cbc0719468d49c2a96933c4d5df6976ce",
        "7a25fdad4cd4e3070616002f669f1b6d6a681c25d1e16d3edcec7d8a18809b93",
        "f73ea660bdb306f6155ddf8b1a4fe773f2c0adee0ffe26a8b4d577c8cb9c053a",
        "e7bb99f4aca864b38376c12981e52af1494d433e6f92d302e621d5ca78707864",
        "2229be2c810649f9a54247070df5e060de2dfb6281c2c6f6e4c4a0265c8d6022",
        "58c699215700caca1bc948a6a5c4b72d336b5356169fad89c64262e5a52b1a6b",
        "d92ad617432cf4a8e5855bcd32a3b72490524b4ead4502f735a1834b69243df0",
        "0e279a81cb3ea2a47301854a433907c1d077764c9334f9b9b3948286528397ec",
        "a584c4ffb73290927d4421f9c7ff92164110c9d91df036fa9bf95c6d6f3c6155",
        "09c5b49399c7cfe289d4be94ab48df058fd448080effb51099e90a19d56bc00b",
        "15bcd8eeadead98a1e3ff07699bbe75e412e60f405f4587c11d7bae1226455ad",
        "3741938c2b06064a74b2c0d8c59287798161db2af8b78e8637bc01b83174cb1f",
        "6e7fb38c03d94aa2c66ee53b27ce40dfc9adcbf83ccb151eab31d4b468da7f80",
        "323db475eccc6600af83bc993501cf48c116f7dcf77fa1cc1ff7e7ca6af458ff",
        "fb1f107f57d48d20d8fe23b3a7a2ed0dad0654e5f242f0381e3691d7e73a0224",
        "5f3d9917fba5454673e6e270959908cdfcb75a416efec82deb4f4378a7b6d759",
        "33ca86236f376af3d1dfb51042f0a410d8835da9c6d6aee6ea7e445e268046b9",
        "7b00b4f2e103382130a3a4813ac844ed12c71ddc0d481857c12fc9efdb75335d",
        "9627ec86dc3ab13808dc68fe29abdfec9d7b23d055d2befed74d34ce1906852d",
        "8f452ca6ed3feb96304c6c3707b1a479599a142a7743babddb88743257203a8f",
        "b92dfa1e62a09289900047ac6a9f0a146bbc883afd86a3d38120139dfb348d8a",
        "3d567cbba307d62e73f939957813ada8e78c62113abe69f65d9ac0e59ad9d5cf",
        "41e15b24263c49295a81148abd2ba33d5ad03b61031ae3a866e097dfeebfaee1",
        "96dfb497c54a1f33eb271a13b6131222441688381275708dc50b7981",
    );

    const KNOWN_EMPTY: &str = concat!(
        "e827f2e77ab289c405759d7f4e356c9b3543f764568243a347ad0916604c5e53",
        "f5920f93e9cec81c1a400cb95e8bbe6c7d4abd4d145e84e216647eca8a65d950",
        "e853dbee969254a2e5785ac5b2584ac6ed546aed8177d661ecca066834f21715",
        "890ea9b75059f0032d5a0620002a57cafd64b60e89bf5c736460eeb1e8959158",
        "8b274e55b1005aadc99660b6e639b9bd565a0a829af52dfadb8e4e7aa76bc053",
        "03171a131048321b766ada68b50e9b9e5ac348c76feef506f8fd34b7a18f2a55",
        "47d08848526ffceecb59a05ce7e46c629b30b3b13a7745221b4f4a3de8fdc12f",
        "b178fab0ba06a1ff2e43313e1db35815a96d2141049ffb3be196428fa3b36df3",
        "5ea50c6cf220c1b34b66dbf1fcdfe8296a37ee4c646009c1cec4edb4a383c4a6",
        "41ce04edc5c1a9a20fc138430fc890dc051b854d928cc35458316545a2900d3b",
        "4ce4baebb7664731c68026df26a8c804a14fa4d4e9aa7dfbf7d2223f76cef15a",
        "1f64f433f5f6ba4d9c5d7e550efad8ccf4a18670795da7cc1f7dc33429b3be01",
        "8b6c742753dbb1c36129dc5f0b06ad81fda1f6f715211da05634ea693d7b6554",
        "8661bed67518f6fe136e35607574b392d3ce9c136c4d42886739cba24add876f",
        "c8128da18741c57b27dfe701a4e183dc09aaa69f5fc0b4759009d92d8b01db43",
        "82e68732d0cf0f6efc6ca4ce1e4106649606d2773091fc82d91edc426eceac3d",
        "24dfbd533832d644c4ee72f46acc3ec3c8371ffea6784908e64f9758c6acb399",
        "39e1109b4eb95e5cf3d7302deafa334d71423132a660a2926b8296076cd7957e",
        "29614a97cc3f7abe6144c087855ad3871834c7c507ed457b67133740db3bf384",
        "5cd7d8ca6613c5f8fff0b4e52f3fb5e038c3b092acc01077e5ef565191c3f5e9",
        "5e6e42cedfe4c3fd5c3d1fadb388db6e884186f5980e13ab1f83d6707b636842",
        "0db0647442fc996588c19738b041836ee4b6bb22904ea47c07677f673f301651",
        "4c3b939c175ba1823adfff948c62624da0080825682d5f7d7369a42604ac29ad",
        "c708a918abef698be0e5fb8430b3783f9be33680fd26cf4fedfee8ec568cc1aa",
        "885067a96e45e822c3babc7e1691bbdac4704b8cc14c7035754dd826defb75e7",
        "82280f87844cefaf82b00e0a0766a7263217dbcf41e59e87c03e2e95f3972135",
        "fb83102928dbec2de7e6a66897ac1c16e6c0d5a057419380ae07030a2d7d1075",
        "9d76e09aa3dbc148c5a4bfc71cecb2548099d005457348b30f68731fe7295b02",
        "343630668aae61fafea628d1e9a92b9e29444eb34e3db7e60aee62cd2506a751",
        "0c06aa5d6e080394cbd5c6552a7f9a7831442fd4e26d9373cf0d1f690879cab9",
        "6d9e0d725324f964fd685db35336c3646f58eea098fbdcfbc8ecf000f998a787",
        "91510662904925a44e848f73f0c00144cdb739bed91282902d32e0b4239286ff",
        "9982b455a89d99959aee1e6d48ebce9a9aa14e6c78e22e0cbebd3960beb88663",
        "ddb351d09f2c125384b38996e372857165ee6fdb76c823424c2cfa7f31f6aa55",
        "d62d22bfd70d842500fa10f9e39b3a119311c2f1ca50bb8d3cc920c8d2d84d6b",
        "502ed3c372eb17fede7d6d10f01fa3c64faa8cace4302dfbb4da9ac3387d9483",
        "16df7d55bde1ec3e4c8fe31b6a3e876310f6fce86a4b993ce92efb50",
    );
    const KNOWN_EMPTY_BODY: &str = "d58f0a7576206d10ae99027a95da6105";

    /// Gives `pattern(17, 5)` for a draw of any length.
    struct Pattern;

    impl Entropy for Pattern {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&pattern::<64>(17, 5)[..dest.len()]);
            Ok(())
        }
    }

    #[expect(clippy::arithmetic_side_effects, reason = "a test decodes hex")]
    fn archive_hex<const N: usize>(text: &str) -> [u8; N] {
        core::array::from_fn(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one test follows an archive key from its creation to an empty batch"
    )]
    fn records_of_the_archive_match_ones_computed_independently() {
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let store = slots
            .generate(Purpose::ArchiveWrap, KeyLength::Bytes32, &mut Pattern)
            .unwrap();
        let profile = slots
            .import64(Purpose::Wrap, &mut pattern(59, 201))
            .unwrap();
        let profile = slots.store(profile);
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, profile, b"archive", &mut Pattern, &mut record)
            .unwrap();
        assert_eq!(record, archive_hex(KNOWN_RECORD));
        let key = slots
            .load_archive_key(store, profile, b"archive", &record)
            .unwrap();
        slots.release(key).unwrap();
        slots.begin_epoch(&mut flipped_epoch_key(0xff)).unwrap();
        let mut carried = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .carry_archive_key(
                profile,
                profile,
                b"archive",
                &mut Pattern,
                &record,
                &mut carried,
            )
            .unwrap();
        assert_eq!(carried, archive_hex(KNOWN_CARRIED));
        let mut created = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(store, profile, b"archive", &mut Pattern, &mut created)
            .unwrap();
        assert_eq!(created, archive_hex(KNOWN_CREATED));
        assert_eq!(slots.commit_epoch(&mut Platform), Ok(Erasure::Guaranteed));
        for record in [carried, created] {
            let key = slots
                .load_archive_key(store, profile, b"archive", &record)
                .unwrap();
            slots.release(key).unwrap();
        }
        let chat = slots
            .generate(Purpose::ArchiveSeal, KeyLength::Bytes32, &mut Pattern)
            .unwrap();
        let public = slots
            .archive_public_key(profile, b"archive", &created)
            .unwrap();
        let data: std::vec::Vec<u8> = (0..131_073_u32)
            .map(|at| {
                u8::try_from(at % 256)
                    .unwrap()
                    .wrapping_mul(97)
                    .wrapping_add(13)
            })
            .collect();
        let length = usize::try_from(batch_len(131_073).unwrap()).unwrap();
        let (mut archived, mut body) = ([0; ARCHIVE_RECORD_LEN], std::vec![0; length]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Pattern,
                &data,
                &mut archived,
                &mut body,
            )
            .unwrap();
        assert_eq!(archived, archive_hex(KNOWN_ARCHIVED));
        assert_eq!(Sha256::digest(&body)[..], archive_hex::<32>(KNOWN_BODY));
        let other = slots
            .generate(Purpose::ArchiveSeal, KeyLength::Bytes32, &mut Pattern)
            .unwrap();
        let mut moved = [0; ARCHIVE_RECORD_LEN];
        slots
            .reseal_archive(chat, other, b"chat", &mut Pattern, &archived, &mut moved)
            .unwrap();
        assert_eq!(moved, archive_hex(KNOWN_MOVED));
        let key = slots
            .load_archive_key(store, profile, b"archive", &created)
            .unwrap();
        let mut opened = std::vec![0; data.len()];
        slots
            .open_archive(key, other, b"chat", &moved, &body, &mut opened)
            .unwrap();
        assert_eq!(opened, data);
        let (mut empty, mut empty_body) = ([0; ARCHIVE_RECORD_LEN], [0; 16]);
        slots
            .archive(
                other,
                &public,
                b"chat",
                &mut Pattern,
                &[],
                &mut empty,
                &mut empty_body,
            )
            .unwrap();
        assert_eq!(empty, archive_hex(KNOWN_EMPTY));
        assert_eq!(empty_body, archive_hex(KNOWN_EMPTY_BODY));
        slots
            .open_archive(key, other, b"chat", &empty, &empty_body, &mut [])
            .unwrap();
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) mod stack {
    extern crate std;

    use core::hint::black_box;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use shake::{ExtendableOutput, Shake256, Update, XofReader};

    use super::super::stack::keying_secrets;
    use super::ARCHIVE_KEY_RECORD_LEN;
    use crate::derive::stack::{hedge_secrets, secrets_of};
    use crate::derive::{Branch, SALT, derive_archive_key, derive_archive_layer_key};
    use crate::key::Key;
    use crate::key::tests::{Counting, Failing, counted};
    use crate::record::AssociatedData;
    use crate::residue::{
        assert_clean, below_pad, depth_changed, key_dependent, panic_at, residue,
    };
    use crate::slots::tests::{EPOCH, flipped_epoch_key};
    use crate::xwing::stack::seed_secrets;
    use crate::{
        Epoch, Erasure, Error, Handle, KeyLength, Purpose, Root, RootFailed, Slot, Slots, seal,
        xwing,
    };

    /// The stack each call needs, and the depth of the wipe after it, in KiB, in an optimised build
    /// and in one without optimisation.
    const NEEDS: [usize; 2] = [100, 232];
    const WIPES: [usize; 2] = [96, 224];

    /// The documentation of the public call `name` in this file, its lines joined.
    fn documentation(name: &str) -> String {
        let source = include_str!("archive.rs");
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

    /// The documentation of each call on an archive key states the stack it needs and the depth
    /// of the wipe after it, and those depths are the library's.
    #[test]
    fn the_documentation_states_the_stack_calls_need() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(WIPES[build] * 1024, xwing::STACK_WIPE);
        for call in [
            "create_archive_key",
            "load_archive_key",
            "carry_archive_key",
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

    struct Platform;

    impl Root for Platform {
        fn switch(&mut self, _: u64) -> Result<(), RootFailed> {
            Ok(())
        }

        fn erase(&mut self, _: u64) -> Erasure {
            Erasure::Guaranteed
        }
    }

    /// What opening the record of an archive key under the stored keys `stored` and `store` and the
    /// key of the epoch `epoch` handles: AES-256-GCM-SIV on both layers, the plaintext of the inner
    /// one, which holds the seed, and the derivations of the keys of both layers.
    pub(in crate::slots) fn layer_secrets(
        (stored, store, epoch): (&Key, &Key, &Key),
        record: &[u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Vec<Vec<u8>> {
        let aad = AssociatedData::new(b"archive").unwrap();
        let mut layer_key = [0; 32];
        derive_archive_layer_key(stored, epoch, &mut layer_key).unwrap();
        let (nonce, rest) = record.split_at(12);
        let (layer, tag) = rest.split_at(1501);
        let (nonce, tag) = (nonce.try_into().unwrap(), tag.try_into().unwrap());
        let mut layer = <[u8; 1501]>::try_from(layer).unwrap();
        seal::open(&layer_key, nonce, aad.bytes(), &mut layer, tag).unwrap();
        let mut secrets = keying_secrets(&layer_key, nonce, tag, 1501);
        secrets.extend(secrets_of(
            stored.material().unwrap(),
            epoch.material().unwrap(),
            Branch::ArchiveLayer,
        ));
        let (inner_nonce, rest) = layer[1240..].split_at(12);
        let (sealed, inner_tag) = rest.split_at(233);
        let (inner_nonce, inner_tag) = (
            inner_nonce.try_into().unwrap(),
            inner_tag.try_into().unwrap(),
        );
        let mut inner_key = [0; 32];
        derive_archive_key(store, &mut inner_key).unwrap();
        let mut plaintext = <[u8; 233]>::try_from(sealed).unwrap();
        seal::open(
            &inner_key,
            inner_nonce,
            aad.bytes(),
            &mut plaintext,
            inner_tag,
        )
        .unwrap();
        secrets.extend(keying_secrets(&inner_key, inner_nonce, inner_tag, 233));
        secrets.extend(secrets_of(
            store.material().unwrap(),
            SALT,
            Branch::ArchiveKey,
        ));
        secrets.push(plaintext.to_vec());
        secrets
    }

    /// What sealing the outer layer of `carried` under the stored key `stored` and the key of the
    /// next epoch `next` handles.
    fn carried_secrets(
        stored: &Key,
        next: &Key,
        carried: &[u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Vec<Vec<u8>> {
        let mut layer_key = [0; 32];
        derive_archive_layer_key(stored, next, &mut layer_key).unwrap();
        let nonce = carried[..12].try_into().unwrap();
        let tag = carried[1513..].try_into().unwrap();
        let mut secrets = keying_secrets(&layer_key, nonce, tag, 1501);
        secrets.extend(secrets_of(
            stored.material().unwrap(),
            next.material().unwrap(),
            Branch::ArchiveLayer,
        ));
        secrets
    }

    /// Slots over `memory` in an epoch whose key `flip` changes, with a stored key for wrapping and
    /// one of the archive, the record of an archive key under them, and what a creation, a load and
    /// a carry of it handle: the three keys, the key of the epoch and the hedges of the three draws
    /// under it, the expansion of the seed and what X-Wing makes of it, and what opening the record
    /// handles; then a change to the next epoch under way, and the record carried into it, what
    /// that handles, the key of that epoch and the hedge of the nonce under it.
    fn archive<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
        flip: u8,
    ) -> (
        Slots<'a>,
        [Handle<'a>; 2],
        [u8; ARCHIVE_KEY_RECORD_LEN],
        Vec<Vec<u8>>,
    ) {
        let mut slots = Slots::new(memory, epoch, EPOCH, &mut flipped_epoch_key(flip));
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let store = slots
            .generate(Purpose::ArchiveWrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        let count = slots.epoch.drawn;
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &record)
            .unwrap();
        let mut secrets = [stored, store, key]
            .map(|handle| {
                slots.memory[handle.index.number()].wrapping_key().0.bytes()[..32].to_vec()
            })
            .to_vec();
        let epoch_key = flipped_epoch_key(flip);
        let nonce = counted::<12>();
        secrets.extend(hedge_secrets(&epoch_key, count, Branch::HedgeNonce, &nonce));
        secrets.extend(hedge_secrets(
            &epoch_key,
            count.wrapping_add(1),
            Branch::HedgeNonce,
            &nonce,
        ));
        secrets.extend(hedge_secrets(
            &epoch_key,
            count.wrapping_add(2),
            Branch::HedgeKey,
            &counted::<32>(),
        ));
        secrets.push(epoch_key.to_vec());
        let seed: [u8; 32] = secrets[2].as_slice().try_into().unwrap();
        // What X-Wing expands the seed to: the seed of ML-KEM, d and z, and the key of X25519.
        let mut shake = Shake256::default();
        shake.update(&seed);
        let mut expanded = [0; 96];
        shake.finalize_xof().read(&mut expanded);
        secrets.push(expanded.to_vec());
        secrets.extend(seed_secrets(&seed));
        let keys = (
            slots.memory[stored.index.number()].wrapping_key().0,
            slots.memory[store.index.number()].wrapping_key().0,
            &slots.epoch.key,
        );
        secrets.extend(layer_secrets(keys, &record));
        slots.release(key).unwrap();
        slots.begin_epoch(&mut next_key(flip)).unwrap();
        let mut carried = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .carry_archive_key(
                stored,
                stored,
                b"archive",
                &mut Counting,
                &record,
                &mut carried,
            )
            .unwrap();
        secrets.extend(carried_secrets(
            slots.memory[stored.index.number()].wrapping_key().0,
            &slots.epoch.next,
            &carried,
        ));
        secrets.extend(hedge_secrets(
            &next_key(flip),
            slots.epoch.drawn.wrapping_sub(1),
            Branch::HedgeNonce,
            &nonce,
        ));
        secrets.push(next_key(flip).to_vec());
        assert_eq!(slots.abandon_epoch(&mut Platform), Ok(Erasure::Guaranteed));
        (slots, [store, stored], record, secrets)
    }

    /// The key of the next epoch in the tests of a carry, made from a `flip`ped pattern.
    fn next_key(flip: u8) -> [u8; 32] {
        flipped_epoch_key(flip ^ 0x5a)
    }

    /// Fresh slots over `memory` in the state [`archive`] creates its archive key in, with the
    /// stored keys it makes.
    fn before_creation<'a>(
        memory: &'a mut [Slot],
        epoch: &'a mut Epoch,
    ) -> (Slots<'a>, [Handle<'a>; 2]) {
        let mut slots = Slots::new(memory, epoch, EPOCH, &mut flipped_epoch_key(0));
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let store = slots
            .generate(Purpose::ArchiveWrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        (slots, [store, stored])
    }

    /// A creation, a load and a carry without the wipe after them leave on the stack some of what
    /// they handle, so that the tests below can tell the wipe from its absence. Each runs from the
    /// state [`archive`] runs it from, so it handles the same values.
    #[test]
    fn the_calls_on_an_archive_key_without_the_wipe_leave_residue() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 4], [const { Slot::empty() }; 4]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (_, _, _, others) = archive(&mut other, &mut other_epoch, 0x5a);
        let (_, _, record, secrets) = archive(&mut memory, &mut epoch, 0);
        let pieces = key_dependent(&secrets, &others);
        let known = xwing::unanswered();
        let (mut again, mut again_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, [store, stored]) = before_creation(&mut again, &mut again_epoch);
        let mut written = [0; ARCHIVE_KEY_RECORD_LEN];
        let range = below_pad(false, || {
            slots
                .create_archive_key_on_stack(
                    store,
                    stored,
                    b"archive",
                    &mut Counting,
                    &mut written,
                    &known,
                )
                .unwrap();
            black_box(&written);
        });
        assert_eq!(written, record);
        assert!(residue(range, &pieces) > 0, "a creation");
        let mut key = None;
        let range = below_pad(false, || {
            key = Some(
                slots
                    .load_archive_key_on_stack(
                        store,
                        stored,
                        b"archive",
                        &record,
                        &known,
                        seal::open,
                        seal::open,
                    )
                    .unwrap(),
            );
        });
        assert!(residue(range, &pieces) > 0, "a load");
        slots.release(key.unwrap()).unwrap();
        slots.begin_epoch(&mut next_key(0)).unwrap();
        let range = below_pad(false, || {
            slots
                .carry_archive_key_on_stack(
                    stored,
                    stored,
                    b"archive",
                    &mut Counting,
                    (&record, &mut written),
                    seal::open,
                )
                .unwrap();
            black_box(&written);
        });
        assert!(residue(range, &pieces) > 0, "a carry");
    }

    /// A creation, a load and a carry leave none of what they handle on the stack: the three keys,
    /// the seed and what X-Wing makes of it, the keys, keystreams and plaintext of the cipher and
    /// the derivations of its keys. The creation and the carry run again from the same state, so
    /// they make the same records.
    #[test]
    fn the_calls_on_an_archive_key_leave_no_key_on_the_stack() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 4], [const { Slot::empty() }; 4]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (mut slots, [store, stored], record, secrets) = archive(&mut memory, &mut epoch, 0);
        let (_, _, _, others) = archive(&mut other, &mut other_epoch, 0x5a);
        let pieces = key_dependent(&secrets, &others);
        assert_clean(&pieces, || {
            black_box(
                slots
                    .load_archive_key(store, stored, b"archive", &record)
                    .unwrap(),
            );
        });
        let (mut again, mut again_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, [store, stored]) = before_creation(&mut again, &mut again_epoch);
        let mut created = [0; ARCHIVE_KEY_RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .create_archive_key(store, stored, b"archive", &mut Counting, &mut created)
                .unwrap();
            black_box(&created);
        });
        assert_eq!(created, record);
        let key = slots
            .load_archive_key(store, stored, b"archive", &record)
            .unwrap();
        slots.release(key).unwrap();
        slots.begin_epoch(&mut next_key(0)).unwrap();
        let mut carried = [0; ARCHIVE_KEY_RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .carry_archive_key(
                    stored,
                    stored,
                    b"archive",
                    &mut Counting,
                    &record,
                    &mut carried,
                )
                .unwrap();
            black_box(&carried);
        });
    }

    /// A source that panics on any of its calls leaves none of what a creation or a carry handles
    /// on the stack, at the panic or after it, and writes nothing. Each runs from the state
    /// [`archive`] runs it from, so it handles the same values until the panic.
    #[test]
    fn a_panicking_source_leaves_no_secret_of_a_creation_or_a_carry() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 4], [const { Slot::empty() }; 4]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (_, _, record, secrets) = archive(&mut memory, &mut epoch, 0);
        let (_, _, _, others) = archive(&mut other, &mut other_epoch, 0x5a);
        let pieces = key_dependent(&secrets, &others);
        for (carry, calls) in [(false, 3), (true, 1)] {
            for at in 1..=calls + 1 {
                let (mut again, mut again_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
                let (mut slots, [store, stored]) = before_creation(&mut again, &mut again_epoch);
                let mut written = [0; ARCHIVE_KEY_RECORD_LEN];
                let reached = if carry {
                    let mut created = [0; ARCHIVE_KEY_RECORD_LEN];
                    slots
                        .create_archive_key(store, stored, b"archive", &mut Counting, &mut created)
                        .unwrap();
                    assert_eq!(created, record);
                    slots.begin_epoch(&mut next_key(0)).unwrap();
                    panic_at(&pieces, (Counting, at), |source| {
                        slots
                            .carry_archive_key(
                                stored,
                                stored,
                                b"archive",
                                source,
                                &record,
                                &mut written,
                            )
                            .unwrap();
                    })
                } else {
                    panic_at(&pieces, (Counting, at), |source| {
                        slots
                            .create_archive_key(store, stored, b"archive", source, &mut written)
                            .unwrap();
                    })
                };
                assert_eq!(reached, at <= calls);
                assert_eq!(written == [0; ARCHIVE_KEY_RECORD_LEN], reached);
            }
        }
    }

    /// The wipes cover more than the calls use, with the self-test of X-Wing asked for the first
    /// time, and not needlessly more.
    #[test]
    fn the_wipes_are_deeper_than_the_calls_on_an_archive_key() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, [store, stored], record, _) = archive(&mut memory, &mut epoch, 0);
        let mut written = [0; ARCHIVE_KEY_RECORD_LEN];
        let (first, second) = (xwing::unanswered(), xwing::unanswered());
        let created = depth_changed(|| {
            slots
                .create_archive_key_on_stack(
                    store,
                    stored,
                    b"archive",
                    &mut Counting,
                    &mut written,
                    &first,
                )
                .unwrap();
            black_box(&written);
        });
        let loaded = depth_changed(|| {
            black_box(
                slots
                    .load_archive_key_on_stack(
                        store,
                        stored,
                        b"archive",
                        &record,
                        &second,
                        seal::open,
                        seal::open,
                    )
                    .unwrap(),
            );
        });
        slots.begin_epoch(&mut [8; 32]).unwrap();
        let carried = depth_changed(|| {
            slots
                .carry_archive_key_on_stack(
                    stored,
                    stored,
                    b"archive",
                    &mut Counting,
                    (&record, &mut written),
                    seal::open,
                )
                .unwrap();
            black_box(&written);
        });
        std::println!("an archive key takes {created}, {loaded} and {carried} bytes of stack");
        for used in [created, loaded, carried] {
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
    fn the_calls_on_an_archive_key_wipe_and_need_the_stack_documented() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, [store, stored], record, _) = archive(&mut memory, &mut epoch, 0);
        let mut written = [0; ARCHIVE_KEY_RECORD_LEN];
        let mut deep = Vec::new();
        deep.push(depth_changed(|| {
            let failed =
                slots.create_archive_key(store, stored, b"archive", &mut Failing, &mut written);
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        deep.push(depth_changed(|| {
            slots
                .create_archive_key(store, stored, b"archive", &mut Counting, &mut written)
                .unwrap();
            black_box(&written);
        }));
        deep.push(depth_changed(|| {
            let refused = slots.load_archive_key(store, stored, b"other", &record);
            assert_eq!(black_box(refused), Err(Error::StaleRecord));
        }));
        deep.push(depth_changed(|| {
            black_box(
                slots
                    .load_archive_key(store, stored, b"archive", &record)
                    .unwrap(),
            );
        }));
        slots.begin_epoch(&mut [8; 32]).unwrap();
        deep.push(depth_changed(|| {
            let failed = slots.carry_archive_key(
                stored,
                stored,
                b"archive",
                &mut Failing,
                &record,
                &mut written,
            );
            assert_eq!(black_box(failed), Err(Error::EntropyFailed));
        }));
        deep.push(depth_changed(|| {
            slots
                .carry_archive_key(
                    stored,
                    stored,
                    b"archive",
                    &mut Counting,
                    &record,
                    &mut written,
                )
                .unwrap();
            black_box(&written);
        }));
        for depth in deep {
            assert!(depth >= xwing::STACK_WIPE, "{depth} bytes wiped");
            assert!(depth <= NEEDS[build] * 1024, "{depth} bytes reached");
        }
    }
}
