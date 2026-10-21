// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The record of an archive key: its seed under a stored key of the archive, and its public key,
//! under the profile's stored key for wrapping and the key of an epoch.

use super::{Handle, Kind, Open, Slots, derive_record_key, hedged_draw, write_record};
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
    /// with the key of the epoch, as the nonces are.
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
    /// if a change to the last epoch is under way, [`Error::CipherFailed`] if X-Wing or the cipher
    /// gives a known input a wrong answer or the cipher fails, [`Error::EntropyFailed`] if
    /// `entropy` fails, and [`Error::DerivationFailed`] if a value cannot be derived from a key.
    /// `record` is then left as it was.
    pub fn create_archive_key(
        &mut self,
        store: Handle<'a>,
        profile: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        record: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Result<(), Error> {
        let created = lethewis_dit::with(|| {
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
                &seed,
                (archive_key, archive_id),
                (stored.wrapping_key().0, epoch_key, number),
                (entropy, drawn),
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
    /// to. X-Wing gives a known answer first, and the public key in the record is then the one the
    /// seed gives; otherwise the record was changed by someone who held the key of the epoch and
    /// the stored key for wrapping, and the call fails with [`Error::PublicKeyMismatch`].
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
        let loaded = lethewis_dit::with(|| {
            self.load_archive_key_on_stack(
                store,
                profile,
                context,
                record,
                &KNOWN,
                seal::open,
                seal::open,
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
    /// [`Error::DerivationFailed`] if a key that encrypts a layer cannot be derived or the nonce
    /// cannot be hedged, [`Error::StaleRecord`] if `from` does not open with the first stored key,
    /// this context and the key of this epoch, [`Error::EntropyFailed`] if `entropy` fails, and
    /// [`Error::CipherFailed`] if the cipher gives a known input a wrong answer or fails. `to` is
    /// then left as it was.
    pub fn carry_archive_key(
        &mut self,
        profile: Handle<'a>,
        next_profile: Handle<'a>,
        context: &[u8],
        entropy: &mut (impl Entropy + ?Sized),
        from: &[u8; ARCHIVE_KEY_RECORD_LEN],
        to: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
    ) -> Result<(), Error> {
        let carried = lethewis_dit::with(|| {
            self.carry_archive_key_on_stack(
                profile,
                next_profile,
                context,
                entropy,
                (from, to),
                seal::open,
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
                (entropy, drawn),
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
    ) -> Result<(usize, usize), Error> {
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
    pub(super) fn profile_key(&self, profile: Handle<'a>) -> Result<usize, Error> {
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

/// Writes the record of the archive key `seed`: its inner layer under `archive`, the stored key of
/// the archive and its identifier, its outer layer under `outer`, a stored key for wrapping, the
/// key of an epoch and its number. The nonces come from `entropy`, hedged with that epoch's key.
fn write_archive_key(
    seed: &Key,
    (archive, archive_id): (&Key, &KeyId),
    outer: (&Key, &Key, u64),
    (entropy, drawn): (&mut (impl Entropy + ?Sized), &mut u64),
    aad: &[u8],
    record: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
) -> Result<(), Error> {
    let (_, epoch_key, _) = outer;
    let mut id = KeyId::empty();
    derive_key_id(seed, &mut id).map_err(|_| Error::DerivationFailed)?;
    let mut public = [0; PUBLIC_LEN];
    if let Some(seed) = seed_of(seed) {
        xwing::public_key(seed, &mut public);
    }
    let mut nonce = [0; NONCE_LEN];
    hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, &mut nonce)?;
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
    let tag = seal::seal(&cipher_key, &nonce, aad, &mut sealed);
    wipe(&mut cipher_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    let mut inner = [0; RECORD_LEN];
    write_record(&mut inner, &nonce, &sealed, &tag);
    wipe(&mut sealed);
    let mut body = [0; ARCHIVE_BODY_LEN];
    join_body(&mut body, &id.bytes(), &public, &inner);
    wipe(&mut inner);
    let sealed = seal_archive_layer(outer, (entropy, drawn), aad, &body, record);
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
/// `stored` and the key of the epoch `epoch_key`, into `out`; the nonce comes from `entropy`, hedged
/// with `epoch_key`. `out` is written only when this succeeds.
fn seal_archive_layer(
    (stored, epoch_key, number): (&Key, &Key, u64),
    (entropy, drawn): (&mut (impl Entropy + ?Sized), &mut u64),
    aad: &[u8],
    body: &[u8; ARCHIVE_BODY_LEN],
    out: &mut [u8; ARCHIVE_KEY_RECORD_LEN],
) -> Result<(), Error> {
    let mut nonce = [0; NONCE_LEN];
    hedged_draw(entropy, epoch_key, drawn, Branch::HedgeNonce, &mut nonce)?;
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
    let tag = seal::seal(&layer_key, &nonce, aad, &mut layer);
    wipe(&mut layer_key);
    let tag = tag.map_err(|_| Error::CipherFailed)?;
    if let Some((nonce_out, rest)) = out.split_first_chunk_mut::<NONCE_LEN>()
        && let Some((layer_out, tag_out)) = rest.split_first_chunk_mut::<ARCHIVE_LAYER_LEN>()
    {
        *nonce_out = nonce;
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
    let opened = open(&layer_key, &nonce, aad, &mut layer, &tag).is_ok();
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

    use super::{
        ARCHIVE_BODY_LEN, ARCHIVE_KEY_RECORD_LEN, PUBLIC_LEN, join_body, open_archive_layer,
        seal_archive_layer, seed_of, split_body,
    };
    use crate::derive::derive_archive_key;
    use crate::key::{Key, tests::Counting};
    use crate::keyset::{self, Header, Stages};
    use crate::record::PLAINTEXT_LEN;
    use crate::slots::tests::{EPOCH, epoch_key, flipped_epoch_key, pattern};
    use crate::slots::write_record;
    use crate::xwing::{self, wrong_known};
    use crate::{
        ARCHIVE_RECORD_LEN, Entropy, EntropyError, Epoch, Erasure, Error, Handle, KeyLength,
        Position, Purpose, RECORD_LEN, Root, RootFailed, Slot, Slots, seal,
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
                slots.memory[profile.index].wrapping_key().0,
                &slots.epoch.key,
                slots.epoch.number,
            ),
            crate::record::AssociatedData::new(b"archive")
                .unwrap()
                .bytes(),
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
                .all(|slot| slot.occupancy == super::super::Occupancy::Free)
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
        let slot = &slots.memory[key.index];
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
            let Epoch {
                key, drawn, number, ..
            } = &mut *slots.epoch;
            seal_archive_layer(
                (slots.memory[stored.index].wrapping_key().0, &*key, *number),
                (&mut Counting, drawn),
                crate::record::AssociatedData::new(b"archive")
                    .unwrap()
                    .bytes(),
                &body,
                &mut changed,
            )
            .unwrap();
            assert_eq!(
                slots.load_archive_key(archive, stored, b"archive", &changed),
                Err(Error::PublicKeyMismatch),
                "change {change}"
            );
            assert_eq!(slots.memory[5].occupancy, super::super::Occupancy::Free);
        }
    }

    /// Every call on an archive key derives with data-independent timing on, where it is offered.
    #[test]
    fn every_call_on_an_archive_key_holds_data_independent_timing() {
        use crate::derive::timing::seen;
        let mut memory = [const { Slot::empty() }; 6];
        let mut epoch_memory = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch_memory, EPOCH, &mut epoch_key());
        let [_, stored, _, archive, _] = keys(&mut slots);
        let _ = seen();
        let mut record = [0; ARCHIVE_KEY_RECORD_LEN];
        slots
            .create_archive_key(archive, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        assert_eq!(seen(), Some(true));
        let key = slots
            .load_archive_key(archive, stored, b"archive", &record)
            .unwrap();
        assert_eq!(seen(), Some(true));
        slots.release(key).unwrap();
        slots.begin_epoch(&mut [8; 32]).unwrap();
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
        assert_eq!(seen(), Some(true));
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
        let associated = crate::record::AssociatedData::new(b"archive").unwrap();
        for (purpose, epoch, stages) in [
            (Purpose::Archive, 1, Stages::one()),
            (Purpose::Archive, 0, two),
            (Purpose::ExternalData, 0, Stages::one()),
        ] {
            let (archive_key, archive_id) = slots.memory[archive.index].wrapping_key();
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
            let Epoch {
                key, drawn, number, ..
            } = &mut *slots.epoch;
            seal_archive_layer(
                (slots.memory[stored.index].wrapping_key().0, &*key, *number),
                (&mut Counting, drawn),
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
            assert_eq!(slots.memory[5].occupancy, super::super::Occupancy::Free);
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
        assert_eq!(slots.memory[5].occupancy, super::super::Occupancy::Free);
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
        "5afbf61400553277f85274b83481e92fd244717a764ba72c32cb4e9f94ecee18",
        "8552df95b427d9e53df937982ca0676a9548ce2a72bdae4799e73418fa5a9a8b",
        "79edd57901d47169ed3e60192c97e87b492075329fe6baee92672838498d28b8",
        "417a40c0b13da9006a7340910cc51b0b8a54cc4939883adc736b4ec85718451e",
        "77559db9ec58063bb023c768e52e0a26c4d4bee0c3d1a30f608e67f333437794",
        "31b6ae7c4868d31a7f04518ec02a12e5d0f2e6c8377a46ac3ecf6380fc6f92f5",
        "b7fdc216bee1f0e9efb75e053c3d3725162a881666f7da91463ab8d16126675c",
        "117621b170f2dcabfba8c1b9a880e373895a8aad9a116b4e738f6007b30f4fcd",
        "40539c16bd0433abff57189a0d226cb019797545a0c604de0f216515e68f8a54",
        "94b2f8c814424c127232d7b836c017c600d7fa25ac8ac5b849d887965f339292",
        "53210b0249180c1e2ea0a7ad1a6a599909b428d61cb04a689909521ca4d0693a",
        "992570b0661f4e726cb722e1f977383c1dde0263a37a29efbbeae60e469ff601",
        "fcbc857a874b1845495836365517634c01bd77846df7e6e0dcf337dbb8d31c2f",
        "8251afe3e476c4b33e912f45468cc000d71b2f65941ce8d6af488dae97c41ed1",
        "bc6d3dd93ba23a9c92ec7433127b95f06b133e473d3406a5242ab04fb6bb6b13",
        "55c3764382c23ddb1ff55a3c022eb3fccdf136f827a2b23c98e3a7215da53c76",
        "45d8a3c4a8994ae0073eb41f511144a2f4b49d7259c2cae7cafffc78dfb66cc8",
        "6bf5c27e4aa119d2c1780bc2b5e88e2bb6bd68a77cce3c1f9d6f566e609c42ae",
        "713e60c0d4487f39cfe183c37d0cf83b5ac591c507ca7e32da5fe87e76d00551",
        "2f14b3a21c832b99192a1ecf277492d4292ceffbaafe1ca14958ac4b68b12e33",
        "272889dc1f0933b2ad6cb5c0c4f7b0ea8257d20d5365a13fd8f678568712b1ab",
        "6f05cc275612ae7d9578b29ba3e0addf0ba5b2daa0988e83e1ad92e69aab7619",
        "739a2c5c0fb96ddce7bf3b6a696fe1f2ec241936d63f173168d51f89e52c943a",
        "9d9bc21138d68c9529bdb899f637d3b86e0326eb59e1b86018b3bddabbaed686",
        "575cbfeff743fd23c63d5e9c1c04e1926eba7015f8798ccc91e3ac7300c0176e",
        "8ee3ad20062233fffbd8d9e5ba5ed7654348b154eceb3a9bc30eafa0efc07afd",
        "4dd46d279518fe3f514086b4eaf6a3fe6389eb2b8502491b5660f0daf15d3773",
        "fff5ce422b343253e8815e8e1159d3261f4519163d3d401cd7e8750e6c1870e2",
        "d07a5ff02f81bad1245d5bf459746b1ac71cb031c92c3487ee5b8a70951bb395",
        "d6e6092181484188b9d51e66faa3db2501b8c0056498c01991729a92fd7929da",
        "428fe51227b761c97153da61a1abfdf080fc45eaed462a1ce4002195cd007671",
        "29187e75838170f030015769c4e519a052104b56df4b8ca6a55f3a58e476cdc7",
        "495161f3310c33bacc93cc00eeb0ffebf730877b6101194351e587779ef2cc1f",
        "a818ef13aa406d37634b581c76d2d212ca2ed2d0be9d6ad61bea0d0c3cb7c477",
        "60259401bebaf9a7c7d59dd2d9bd59ef3087a16f501d96d1a8ad4894f862b060",
        "555b2f560e6752d568b31268103f52c8a6bd9abd758fbadac4c8789b69f47dfe",
        "e1c28011b9959df673554f5ace97edffb2a144e5b25ab3e7926e42241a159d59",
        "2e66d75c287bb4720fe2cfa89104bcc78351d5e92c5b3aa592cab6f36c657843",
        "517f980a1ae4d73546a8f3af0e998bfbd41e03f737d606ab2e67e60166351dc4",
        "479ef418eb5b537f2313c2d0f2eda31ee3ecf9f1aa2b9cc8c9daeb4545ce2ee4",
        "3638ecb87002e50f74dcf7035356a78fa49373a1bbbc628f54e6a9774a108368",
        "bcb4ee49a946131acf256589371a5e7b3611a500dcd60f3bbd2a304409e93f59",
        "2c820f98188422fd67349e314d2d9b540af3b6d6d5c16958a3b3c5240bf92276",
        "a9917d1525b772face7197058c8cf29f4d1c22abd56922f55ed97eb4798bf12c",
        "dd11683128a5e0b8bf1c3fd99627e1d3df47f25e84f87023e44a47b40e918c44",
        "759aceeeb8921fda2d084f484352e0532eee5bb9bb9bced97290948f038f83a2",
        "3552f4b103dde659fa798bb97423f363fab945714f7f5743e75320bbab5ddc65",
        "208ece78bdcbebbd9a39dac25d3e788cbea547ba078e9d6c78",
    );
    const KNOWN_CARRIED: &str = concat!(
        "3b54f7a561fd4fc7cdd63a60dc5cff021092377a8ec410ac44277f15d216cde3",
        "d847fe669286070fe16cdbe90af0fcadfbbb4cfea9d0f410c0a294e392df6d35",
        "7d26f4c6a80f7d1db1773dfb3ddd5b12a5d15763b465d144de47eaecf5ec3916",
        "b13474eee5d39d3ba83de62af53e0ccb363a49c19da65e1cd93380a1140cd771",
        "d683db8e1cfc36c91e217f6529bf385c7935043a45734933cda2f145659b012d",
        "ad59b177494015cee4d7201d0a49baf39a0ccf6367cc629aeb39dbdb07a4c909",
        "8d7b4ba334dcb425a098c078a9b72db1b939a084c2b1bd8c0de3555b3099a3bf",
        "1ecdd0a37355c22d880c19f466744ac6f7670d8fd4e637068a3edd4ffbc44f0b",
        "b95f4cc35f8f2e3b9a942e19fd97f1c0f9ad54402358bb186e175f5791357a8f",
        "24be009ec0d8faae9548094cb211e4cddc90b5500f8932450fe6a5e69134a6f5",
        "00267fd65692bbdce78fa3627551e87c14a395e6a036b61f8979ab97a0f2496f",
        "a046a9d971a032199f1cffac2edfbc197af2bc1721c77e1c29263274694b5484",
        "27c4ebf5d34c83c2422c017affe8235d3c31320b84e533fb2759f743915e8a21",
        "9a4497bd31785d0c97c67f53db7c36172d09826b087111964f002d0326d98f8a",
        "8725eb4751349a450b4b19f40f53edb7c3a1040fb8236def52bd5586e465c559",
        "93a82cae98ba0b03be8a764dba85ad4dfb3ff38e88fdedfa5ff000fbe99f2bd5",
        "c79f3fd4d290ad7040fd3979cd964830d0e988d696b404a92027a16c3fd234fd",
        "eda1acda7e574a4b1db5df0d0a0d3085e549bf3fb6ff193554a73e66f2e30173",
        "bad87b46154f7bb2ac688167302838ea42d328dc46b15cb3ce1a83e2eaf6c642",
        "84f824f57980af5ebff85fd249b86bcac3a67b8ec8b652e243e74bddac11240f",
        "ad2f36228fc98bad1e89253af27045d3391e9e05d1b38290e47ebbf1608420f8",
        "810fc63cf1388175b5f7ab928553182bc1eb7506041bd5a5e174020cc442de11",
        "76e5d2e0196d613b95e63c09aea594ceba87fd8f737de3b46426164080545643",
        "bfd17c5a4d2102bb4db22f5fd975100b05844f39c9f74bb9e8872a19495df437",
        "b403c3f282bdc16dcfa64144179aec7f2f4623c0e5444b7058850c3b76d249d1",
        "488dcb8cbc0c22f559cedb7f42fecba6d8fb26a5819dacb3bb224dac5181fe8f",
        "68a24f2fb4bdc5a1168139fa1e2e13e9fdf280ac426f17e9a572d5ac5d0bcb26",
        "810f7cd953f1ab7f489ccee4abac76bef660b9f471d2f7a5ce79fdfe85e944ec",
        "85e8bf1b9edb9eb81d1d8df72bdfd982f686fb5ccd7ad2e7ca68ee6fce92c5a0",
        "22f1f23dcf328d0ebebe469270c9d848d58142992a428e6d68acae5c3d5b3dda",
        "c11eee5bd7bed674ee76d13013d8b2fb83aae1fabde01ede30893970ad72449e",
        "3cc7cd52e5fa7c29c047033ce0cbc2f4904dc10f28f2177e4e74ada8f45273e2",
        "2f3e9a216ed256374c3cc377da827a392833a6cb33f19abb415e7a2aca1487ad",
        "50f8ec9634ad365bcafe9ab90e726b5b2a4ca9f0cbc087bca07da328cc25de26",
        "b4f761f6cedd02ea2d264ab3a5fdc7cbd65839fb99a3b25555e82fea873528e4",
        "f95f0572a42cfbb5a03872eda5a332ec909cd863d3af1108eb26e4d7ac5c4a05",
        "8582540c9c0ae209e9ab12c7b0694c4b81aa4521464c44aed4e3fb94861ae194",
        "7dac33da00b57b5d1e24538f44895f1ad5598390ff042ad6504005e01d124092",
        "9c38dd9aa93a3085ee16dd716193e23bd1798a2caed997b7490d17cfb8795f71",
        "bc52bcec5a1b360d364d070360b58139fe717dc99154775d4e9af5a4d4cdb0d0",
        "c2d2ca652057116b8a47df0de5e028819b17e145c3454a5a83a1fa0d6b1e692b",
        "854a2c738b331ee46232d7ec5f9f12e9374982b4f59ca10f1c1d4ee50f6ab29c",
        "b98aaa30beb8bc3d07b8cacb1f3fdba64cb13490b202ce8c2d738c7dea83218f",
        "9e218fd3db154ab0e385f7816e86350dfd3cb927ba27e6c936d39cba710e4e19",
        "269d5a10c09a93492cba2ae6edaa4808967c8e7e850e9258adbd4ee3aba1ecea",
        "94ec2cfce51b77a6e4ef826ab5914d608f2c060c7f8bf34d38d8378a7731e20a",
        "9de32c0efec659d67ddea1a24622dba488b83a388d31e85e42d518184ad8d1ec",
        "f58bcc95829563b7ea8fd69fda2edad87b49f62d90398f34e1",
    );
    const KNOWN_CREATED: &str = concat!(
        "932d0cbe6b107a6606e3fa558b076328ac72f1bcf5112bcd8219204167a1daa4",
        "8a79076ffe9de7d7937b6a18fc78c3941c58c01301c8e5f5854dff12fce9380c",
        "50a5580178fde97c81b2f85414d0274a79e9697a3eaab71f272233fe4f45a501",
        "ca94bb74ee9bba97e2c34002c54607483ae29fb5ed84eba9a225289962dc87a9",
        "403a120e8883972485ca18df84145d0de16803762aaf4016daaa0db025e381df",
        "9dded4067385135060c693a6be90a18feacdc58e61cb45f346a38501f093b322",
        "a980b76980e75681ec26bfb72ce4710e05dde83dbc0adafdaf5b38d5252269f8",
        "7d7ebd08e2d2338d8818490da86fa88317f9bf167c84464b682c318e20eb202c",
        "b2bc736950c0283b1fd1096f2f3a9eafbb7e91e9eb2305411776807c5a07fa0b",
        "00f247bc7f8ddf1e8767d6591942c3de9d754386dcecfbb1c05b3ce35e12dbf5",
        "56ac3063602055d65016b3b7dbfb2e3b2769f7fd2b9881718ada3e0752b0f278",
        "eed73c795b26374d0e7e5bfc2b439262aa405f3aa925878b943c08fb337c726d",
        "5b3e01151e73f57f6bf7b59e619758b81f74d3b6fed5575cdace23b19cf9d354",
        "8c4a7c443597a008d876b26bb5084be71b09130482b16a99cd5729617433adee",
        "9e66aabeaef818814520204f768e0ec4e4f0a9425a847815c50c031355462bf6",
        "a6e74b62f4adebd5c1842267caac2e514e776544aaf6820774d92406709ae530",
        "a3bc5b2151109a9e89ac5327c4469454ce0aef0148544c6191e194f30ea09449",
        "52dca54f7f0bf03aa09ec4572a9b1da49c085a5cdf2b041016fd0e39ccba77fa",
        "18f3885b080c1b43671c1a13cd8e83aaae58c8bb391988199427ca933ac031aa",
        "c691358663e1ec6462bbb9ed24d656da53ca2c7daad027f1397420b96fbeecc3",
        "27305ca693de4cf0aa478326e7747ee986faff57e1285c0936cf843c2a728594",
        "07152c6368ac1d928e0d39fc97e7d780bd3eb96f88b6c671faf93a19957e2fac",
        "dbf61868c7dc8a99b9c848a4c4523f0319f13d03ae047eae2d0d47d13d4a7711",
        "72f78eca98db4823e5fbb1eba4efcce1c149c3218425e8c532321d104336a158",
        "fef206375d295dfc6c8105d63744d95d78587727d277f2079ec702549c86b70f",
        "2b058da7afb11bcb3e54a110b3e2759ee30384a666af7c833fd56aa957a5bbea",
        "04fe0ed5c51b61c5c61ad6d03da892bc57e090d82e89e2d79c211498291f75bd",
        "39b534bf354350db10b61bd865319b545cd464f3ab114cdf550e9178b9b73f11",
        "7c72491c564d503bd8d6b6c78f3bd9342505abe604fe3c449e959dac2df6cfc6",
        "ac6840e2b13b21f3d6258cb0c4fc44860b3e37c41c8097f1843b6a1d3de7e42e",
        "9e9b8ad1ad032b6a2139b218c0402afb3ce219efb409dda5465160a332c950b9",
        "a43385a3bab92277efd6a6e3518c987e8175c2749602ed0132c7f15078a7b2ac",
        "bfde8ce1e6bca3ef34cadbecbc65ac8aca853a6d8badbb8075011bcc6037bab3",
        "847d939d1e06fa9cbe63224f1fd5b76a23ced5e0e7042bd51d0f00efee495a24",
        "76a9a12862ed4a1f8d7a1264a79d7ed9d62ca78fca2bca7a2c12a8a0774c76f2",
        "c9fd79f7719929e6f72398dd0b47dafc8ab18cb650a15918c52798e7802ac178",
        "a53bb1c0d0f59ee6fd2367aeaa19eb8792dd7290186be0ac9015366b123f7f56",
        "3b2b5258e2034cd9069782998c080421e1246d09a89e3dee537e0f9c2bb7d2a4",
        "11bf363057b58074c6ffd562403d82e8cd46de9930e7fff870226990a5b8bd2d",
        "5eb043525362024d5ce6f69707e1aca9c7aae233b9f15d0fdb47e16644cb633c",
        "f46e3ff7cb901f8f3e4efebb3a4be89db16ac4bbdba0ed264522e6cc8b66ecf0",
        "e841c12c364250d8375331a6c04f6af03ebe8813cb58007d0be03cac9b66b6f8",
        "bb5f9ac060320665f8159600c892372d9fe535797c433da73db4f50187d24017",
        "c2f234558747cb1d6bcda49192782e39366443086c3749d3d0c21629d33a1457",
        "5b19b9fc173c0d8f0e40ac7c14c8279531a4dbefe7cdd6b8e161874b896f850e",
        "3de8565910626d21a189ced7d740e33dd9323522ad4cb3f939f1857b1fd0a66b",
        "7a52a98a8dfdf6551ccf74e33394f795cff7ef166ce217a054cc9fe6994b8dbe",
        "87618af444dc3ff099d8556423f9b072d88e370a6342884d0f",
    );
    const KNOWN_DATA_KEY: &str = "ba34462d533d6e56240e071de9f8bddbcad2f84ed47bb5302beabd72218ba99f";
    const KNOWN_ARCHIVED: &str = concat!(
        "1550e151dd86770fb739bab0756873bacddd76f929e8ab4fcd5a9fd4a6634b75",
        "87329bfe1ffdaffc7052e20c9aca10bd5a7d6d424320e8388798f8f1a3c966ef",
        "02bc87be02f4b4be4607d0a0a3307e65cb0468c4e70b3436c93ae71770d52d40",
        "12bfdae94e87dfd17f1782385835522ce637849cef7ee59f49d421fe1a9e86a1",
        "8848056a9d0d5f97dc9d01f69415c3af44758606cd72c65bbddba4591684da2d",
        "5fe587b676210b4d68a0ed0d956a082144f250c4c19b22b73b780cc11bcb945a",
        "84f5d4025f2ed0d9f78ca966f847fd017c70e7b42cfc4b6e031ca3f96c55ec25",
        "bdd64a2cec4d13d5f5b9b1cc999c828391645fb61a13c326db2ac51f5fc72ff7",
        "1921fe50762534e5e5074cc87164638e6aa1d9cb75beed4f7667fb18a73163f9",
        "e4a143b55bb2e2909203b46a1f2cfff7e1786bb7710533a3596cbfa48129a0ca",
        "2e832ae55f1d9f783d98ba9a1cff9766af59b7530933458560e201249eee9f0e",
        "c182cc4d15d0e850629ad85b776e4cf818241b1b4f6112ab1d3e809dec2924a5",
        "0d055a353dc28f4c27cff19c9afdd9c9fceeda6bb338749eb0b625f2d527100a",
        "24cc35235b4d9e71e7c61a3b289af5564804e528c334ccee4f9288edc7638e54",
        "2bb3a3399869cf6d6a1547e4a8829e6e5b170a5c593e1439afcaa1610cb42f16",
        "4af592f50a5c07a247e5f51db44a5336d97f150244d9d0e8a466561408e43eee",
        "7955beadfd6bc2a73388e9e98cf2754574263289cc340e3d0fb7d4c345f5aef1",
        "efecd9a251d1b2d88751a667eaea6c98e87e6212dc2d55704f68413f740dbdb9",
        "7f29fa5fba44a4410a4679c10a703e4769deb28f61f946dbfeba110ac6b6ddf2",
        "bd846c4cc62196a68a2278328976af822d1507696337e00a662bf53030f87738",
        "e230909ac5ecd0ff2ec9816ebd379d8265c8e2adbc372f7f0d425a0aa84ad435",
        "419275551335804179dff9de8b47d34ecf135958cb4d505705e1646947dbac3f",
        "427f0c78dc61927782d6e9b2658b961f358fc4c119fcbdfc66910f6ee4d5ecf6",
        "990510438640161003a566d0374c465fef7f467ae0530bc9f699e46ffd72f82f",
        "cdbd3f07c1188651b84eea328b6809c599a4781273d099337fbec3b1108584d8",
        "e1480cef3f5d8c6f9f4c74aeda04d2eeb02c7021a60afb67640edaeca60140a2",
        "53f7ed9519665742108e19070b7d67e6c0e9501f3be0c060cc8208c500428253",
        "4e57f5d8084b0f29cff50ec280fdea5c97213a207830699bd59710edf8d566b1",
        "fb60c6260a6e4ae6a193dcaa6565eb68583aa99e6119aa97c44e6f79e1b37550",
        "e3f97603228c76fbb9ddb85e80098d67f7e4c2f0f9edf424c9a01a456b355181",
        "bdf03801d71526085b2541e6a356474400c7f569035de5fa5f4ff5b10506a403",
        "2c3a2b5c36940d9160a1c2f6ad4e61b8c20d20a0af2187d466ded55d1c34fa30",
        "5a162b35919e77229b6ae7df0878eea5e5d789151ca169de97116ced2e32f453",
        "63506a2224ccc88150a292cb3d0f4bb41d3095374931714506b5d92895459c34",
        "ee0cbb1bcda826a86456a733774baf0d34db5dd28cb2feee94fff658e5d66e1d",
        "958a7c4bbfe697e130a1375331624fe9b2dd5e7aa29bff3093f48e9dbcb1472f",
        "043ea0e4fa89fdc875614387fb502a69e13ddbe4e91bff7e63212cf9",
    );
    const KNOWN_MOVED: &str = concat!(
        "4063a1dbd80d6757dd56d8ea8d539389f855f04c030a74fb88abd21fa8b2f447",
        "29714cf76bdaa54325cc3a14ce44f478a514e5fcdfc82412b063f3d6a3a4c7d0",
        "00f618e201fe1d0b0b182729c1768ba77fa0c4b49f25b8e0ec21ed89cd6aa190",
        "5ba794bf88d55154bac7a15df1a3a2f8f154b659588ec43cc46a43b1929dd374",
        "c6fb404983d56b68fb353ef3097691b5d6bd45df8c740896fd3136bd74a48684",
        "1a9f62c02417e7252e1836addb0f8180b0843f302462ffe0ba392ddeca18d016",
        "40de5821a6eda891a3b5124aed85a640062282fafa6bd075c0213d759a4bec8a",
        "5b7c3a6eb9ef75f07f5fb6c7781fd989f6139d898ce4d7be5b3b8da61d622221",
        "d75865c4759d570aede5f8d4301b49c84a0da36f33396a2126fa3ec29137b273",
        "40751a7087d8751ed606f392fc0b96b5c023e7ce33f075c4b35c0c76c656e3af",
        "6e2a674937fee75c927759870d7107aec6a0bdb0952fdde4405ee2e249709470",
        "04df70a996cda52b3193f71d67649a0f3b62ab3755184d0285fe81b8dc7ba6c5",
        "412dec46add0e9edf631d7470e9d38000ab0cc98eab727fae4e2da4710a684e3",
        "6a05cfd3f88009bd5cd5f1be8c846308f6a4b3bea891b7bd7e780d82c8360c0a",
        "2ffc4db41f5ccfafc8e5a2c40793cf36e2c5840c2d8548325ef22ac6bb41cd73",
        "b51af37c7614bff1feb9f37cdf49efa3e04cc371cf763c51404705b57534c957",
        "6e33c70308a667c5b83b3976c3c6fe312f23e419deef3c7c17da78816822ad75",
        "a8ed83421a0e84cb75922e08bbf8c6609f940f22c944abe0f2b2648fd758b879",
        "8d41493098b60525964083770cf0618cb297df0bb37c34f0d41da8bbe13461b5",
        "e2760e2caea37323f4d2c9456180891ffbff5047e9b1f3630af6b5e28984ff8d",
        "89e0dc4fea708ac196e8d2ac0b1a5b59a210585ef5a9dc6f5c618072aeb9045b",
        "e5e1107da155cfb6406fb3c7b7fe01f3699325e9bab75e1e4ead4184696dfc18",
        "bb74d1f6ddcde5726a2aa3b3e055b981a73d5bc48f4d099c57db2b2203e4b8fd",
        "8d7b46cafe23040154c19efc98f8883e920ae2256d6d66cf22283c99c2ffca0f",
        "21939196d73e6e18f84e3a6e82ca91c75fc2ffca13f81895e569192a6ac8db5e",
        "598d68a9d856231ebf644fb35fd6022c9012ff23565a20efdc6f70883339d0ef",
        "522ed9e9f6f1c049d1aaa6cc12c3f4cc5a7c84cfacbe10d0dba0bb3788fded18",
        "469cae567ffddda33cc5a4258a792334cf0223a30898206c1d3e0172456526c4",
        "71df8db25f1631f13ea94653d7e86a122e4a58eef1aff37882f3a08db2cf7b08",
        "34855b0e575faa8b84e648b3d42d509df39619fd7bd04f74daa644f2ca5321b9",
        "ea178f795817549e97a6341201e05759e1a6d0833c5a382d3e72597f9624e93c",
        "0e8e33bb42d0999e838fd7fb78f6bb9491f98bc73826ac11f8a489c1bee6fb5c",
        "9fc7c6bdbd83270da2426c09280af8b917f4ffbbde203d62bedfa63e70f9a17c",
        "016874bd90e7364f149b1a62fd0b01a722ed633c10c941e64e3550cfb2d29779",
        "6d5c48c2d92769bc89fba33f82a5d1d22c604b1ee19e6971ac1a6ba7c15a189d",
        "383a3ecb2ea648036842a0e00a2bb6a649c8e71275701f574d6fd261348665ea",
        "8d1db027ec36b65217c411a6f7cef4a8762609e3afc9545a7fd98494",
    );

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
        let (mut archived, mut data_key) = ([0; ARCHIVE_RECORD_LEN], [0; 32]);
        slots
            .archive(
                chat,
                &public,
                b"chat",
                &mut Pattern,
                &mut archived,
                &mut data_key,
            )
            .unwrap();
        assert_eq!(data_key, archive_hex(KNOWN_DATA_KEY));
        assert_eq!(archived, archive_hex(KNOWN_ARCHIVED));
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
        let mut opened = [0; 32];
        slots
            .open_archive(key, other, b"chat", &moved, &mut opened)
            .unwrap();
        assert_eq!(opened, data_key);
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

    use super::ARCHIVE_KEY_RECORD_LEN;
    use crate::key::tests::{Counting, Failing};
    use crate::residue::{assert_clean, depth_changed, key_dependent};
    use crate::slots::tests::{EPOCH, flipped_epoch_key};
    use crate::{Epoch, Error, Handle, KeyLength, Purpose, Slot, Slots, seal, xwing};

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

    /// Slots over `memory` in an epoch whose key `flip` changes, with a stored key for wrapping and
    /// one of the archive, the record of an archive key under them, and the bytes of the three keys
    /// and of the expanded seed.
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
        slots
            .create_archive_key(store, stored, b"archive", &mut Counting, &mut record)
            .unwrap();
        let key = slots
            .load_archive_key(store, stored, b"archive", &record)
            .unwrap();
        let mut secrets = [stored, store, key]
            .map(|handle| slots.memory[handle.index].wrapping_key().0.bytes()[..32].to_vec())
            .to_vec();
        // What X-Wing expands the seed to: the seed of ML-KEM, d and z, and the key of X25519.
        let mut shake = Shake256::default();
        shake.update(&secrets[2]);
        let mut expanded = [0; 96];
        shake.finalize_xof().read(&mut expanded);
        secrets.push(expanded.to_vec());
        slots.release(key).unwrap();
        (slots, [store, stored], record, secrets)
    }

    /// A creation, a load and a carry leave none of the seed, its expansion or the two stored keys on
    /// the stack: the creation runs again from the same state, so it makes the same seed.
    #[test]
    fn the_calls_on_an_archive_key_leave_no_key_on_the_stack() {
        let (mut memory, mut other) = ([const { Slot::empty() }; 4], [const { Slot::empty() }; 4]);
        let (mut epoch, mut other_epoch) = (Epoch::empty(), Epoch::empty());
        let (mut slots, [store, stored], record, secrets) = archive(&mut memory, &mut epoch, 0);
        let (_, _, _, others) = archive(&mut other, &mut other_epoch, 0x5a);
        let pieces = key_dependent(&secrets, &others);
        assert_ne!(pieces.len(), 0);
        assert_clean(&pieces, || {
            black_box(
                slots
                    .load_archive_key(store, stored, b"archive", &record)
                    .unwrap(),
            );
        });
        let (mut again, mut again_epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let mut slots = Slots::new(
            &mut again,
            &mut again_epoch,
            EPOCH,
            &mut flipped_epoch_key(0),
        );
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let store = slots
            .generate(Purpose::ArchiveWrap, KeyLength::Bytes32, &mut Counting)
            .unwrap();
        let mut created = [0; ARCHIVE_KEY_RECORD_LEN];
        assert_clean(&pieces, || {
            slots
                .create_archive_key(store, stored, b"archive", &mut Counting, &mut created)
                .unwrap();
            black_box(&created);
        });
        assert_eq!(created, record);
        slots.begin_epoch(&mut [8; 32]).unwrap();
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

    /// The wipes cover more than the calls use, and not needlessly more.
    #[test]
    fn the_wipes_are_deeper_than_the_calls_on_an_archive_key() {
        let (mut memory, mut epoch) = ([const { Slot::empty() }; 4], Epoch::empty());
        let (mut slots, [store, stored], record, _) = archive(&mut memory, &mut epoch, 0);
        let mut written = [0; ARCHIVE_KEY_RECORD_LEN];
        let created = depth_changed(|| {
            slots
                .create_archive_key_on_stack(
                    store,
                    stored,
                    b"archive",
                    &mut Counting,
                    &mut written,
                    &xwing::KNOWN,
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
                        &xwing::KNOWN,
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
