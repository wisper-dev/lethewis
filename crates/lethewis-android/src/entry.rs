// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The two ways into a profile, in one file per epoch: lock records of the core, one opened by the
//! owner's password and the other by a password under duress or by none. Beside each record lie a
//! salt and a tag of what its password may do, keyed by the chip's answer, which needs both the
//! password and the chip. The records share one context, so that the key of the epoch, which needs
//! no password, tells nothing either. Every change of the ways draws the places and salts anew; a
//! carry into the next epoch draws the places.

use std::fs;
use std::io;

use lethewis_core::{
    Entropy, Error as CoreError, Handle, KeyLength, LOCK_RECORD_LEN, MemoryBlock, PasswordParams,
    Purpose, Slots,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::epoch::Written;
use crate::keystore::Keystore;
use crate::profile::{Error, Id, Profile, exists, mark_destroyed, read_file, same_mac, write_file};

/// What the file of the ways in of an epoch is named, with its number after it.
pub(crate) const ENTRIES: &str = "entries-";
/// How the names of the keys of this library begin, as `profile::alias` and `epoch::root_alias`
/// write them.
const KEYS: &str = "lethewis/";

const CONTEXT: &[u8] = b"lethewis entry";
const TAG_KEY_LABEL: &[u8; 23] = b"lethewis entry tag key ";
const TAG_LABEL: &[u8; 19] = b"lethewis entry role";
const SALT_LEN: usize = 32;
const WAY_LEN: usize = LOCK_RECORD_LEN + SALT_LEN + 32;

/// What a password opened the profile as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Owner,
    Duress,
    /// Under duress, destroying every other profile.
    Destroy,
}

const ROLES: [Role; 3] = [Role::Owner, Role::Duress, Role::Destroy];

/// A way in: its record, its salt, and the tag of its role.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Way {
    record: [u8; LOCK_RECORD_LEN],
    salt: [u8; SALT_LEN],
    tag: [u8; 32],
}

/// The key of the tags, from the chip's answer to a password.
type TagKey = Zeroizing<[u8; 32]>;

/// The owner's way in, opened: the stored key, the key from the password and the key of its tags.
struct Owner<'a> {
    stored: Handle<'a>,
    key: Handle<'a>,
    tags: TagKey,
}

impl Profile {
    /// Makes the ways into the profile in its current epoch: the stored key `stored` locked under
    /// `password` and the chip, and a way no password opens, in places drawn from `entropy`.
    /// `password` is wiped.
    ///
    /// # Errors
    ///
    /// [`Error::Exists`] once made, [`Error::NoEpoch`] before [`Profile::epoch`],
    /// [`Error::Changing`] or [`Error::Unsettled`] during a change of epoch, or the core's refusal,
    /// the keystore's or the file system's; the ways in then stay as they were. [`Error::Unsynced`]
    /// when they changed, but a crash may undo it.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    pub fn create_entries<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        stored: Handle<'a>,
        password: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let opened = self.settled_epoch().and_then(|number| {
            outside_change(slots, entropy)?;
            if exists(&self.dir.join(entries_name(number)))? {
                return Err(Error::Exists);
            }
            Ok((
                number,
                self.key_from_password(slots, keystore, password, params, memory)?,
            ))
        });
        password.zeroize();
        let (number, (key, tags)) = opened?;
        let way = locked_way(slots, stored, key, &tags, Role::Owner, entropy);
        release(slots, key);
        drop(tags);
        let way = way?;
        let other = unopenable(slots, entropy)?;
        self.write_ways(number, &way, &other, entropy)
    }

    /// Opens the profile with `password` and the chip: returns its stored key. The work does not
    /// tell which password it was: one derivation, one answer of the chip, every tag compared and
    /// both records tried, and nothing is written. A password under duress set to destroy also
    /// deletes every other key of this library in the keystore, then marks the other profiles under
    /// the same root destroyed for [`sweep`](crate::sweep). `password` is wiped.
    ///
    /// # Errors
    ///
    /// [`Error::NoEpoch`] before [`Profile::epoch`], [`Error::WrongPassword`] when no way in
    /// opens, [`Error::Damaged`] for ways not as written, or the core's refusal, the keystore's or
    /// the file system's.
    pub fn enter<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        password: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<Handle<'a>, Error> {
        let entered = self.enter_as(slots, keystore, password, params, memory);
        password.zeroize();
        entered.map(|(stored, _)| stored)
    }

    pub(crate) fn enter_as<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        password: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<(Handle<'a>, Role), Error> {
        let number = self
            .current
            .map(|current| current.number)
            .ok_or(Error::NoEpoch)?;
        let ways = self.read_ways(number)?;
        let (key, tags) = self.key_from_password(slots, keystore, password, params, memory)?;
        // Every tag and both records, whatever matched or opened before.
        let mut matched = None;
        for (place, way) in ways.iter().enumerate() {
            for role in ROLES {
                #[cfg(test)]
                crate::stand::tried();
                if is_tag(&tags, way, role) {
                    matched = matched.or(Some((place, role)));
                }
            }
        }
        drop(tags);
        let mut opened = [None, None];
        let mut failed = None;
        for (way, out) in ways.iter().zip(&mut opened) {
            #[cfg(test)]
            crate::stand::tried();
            match slots.unlock(key, CONTEXT, &way.record) {
                Ok(stored) => *out = Some(stored),
                Err(CoreError::RecordRejected) => {}
                Err(other) => failed = failed.or(Some(Error::Core(other))),
            }
        }
        release(slots, key);
        let entered = match (failed, matched, opened) {
            (Some(error), _, _) => Err(error),
            (None, Some((0, role)), [Some(stored), None])
            | (None, Some((1, role)), [None, Some(stored)]) => Ok((stored, role)),
            (None, None, [None, None]) => Err(Error::WrongPassword),
            _ => Err(Error::Damaged),
        };
        if entered.is_err() {
            for stored in opened.into_iter().flatten() {
                release(slots, stored);
            }
        }
        if let Ok((_, Role::Destroy)) = entered {
            self.destroy_others(keystore);
        }
        entered
    }

    /// Sets the password under duress to `duress`, with the owner's `owner`: it opens the profile
    /// as the owner's does, and with `destroy` it also destroys every other profile, as
    /// [`Profile::enter`] tells. It replaces any set before; both ways are written anew. Both
    /// passwords are wiped. `slots` must not hold the stored key, which the core holds once only.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`] when `owner` is not the owner's, [`Error::SamePassword`] when
    /// `duress` is, [`Error::NoEpoch`], [`Error::Changing`], [`Error::Unsettled`], or the core's
    /// refusal, the keystore's or the file system's; the ways in then stay as they were.
    /// [`Error::Unsynced`] when they changed, but a crash may undo it.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    pub fn set_duress(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        duress: &mut [u8],
        destroy: bool,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let role = if destroy { Role::Destroy } else { Role::Duress };
        let set = self.settled_ways().and_then(|(number, ways)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways)?;
            let made = self.duress_ways(
                slots, keystore, &opened, duress, role, params, memory, entropy,
            );
            release(slots, opened.key);
            release(slots, opened.stored);
            made.map(|(own, other)| (number, own, other))
        });
        owner.zeroize();
        duress.zeroize();
        let (number, own, other) = set?;
        self.write_ways(number, &own, &other, entropy)
    }

    /// Removes the password under duress, with the owner's `owner`: the other way in becomes one
    /// no password opens, and both are written anew. `owner` is wiped. `slots` must not hold the
    /// stored key, which the core holds once only.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`] when `owner` is not the owner's, [`Error::NoEpoch`],
    /// [`Error::Changing`], [`Error::Unsettled`], or the core's refusal, the keystore's or the file
    /// system's; the ways in then stay as they were. [`Error::Unsynced`] when they changed, but a
    /// crash may undo it.
    pub fn clear_duress(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let cleared = self.settled_ways().and_then(|(number, ways)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways)?;
            let own = locked_way(
                slots,
                opened.stored,
                opened.key,
                &opened.tags,
                Role::Owner,
                entropy,
            );
            release(slots, opened.key);
            release(slots, opened.stored);
            Ok((number, own?, unopenable(slots, entropy)?))
        });
        owner.zeroize();
        let (number, own, other) = cleared?;
        self.write_ways(number, &own, &other, entropy)
    }

    /// Changes the owner's password from `owner` to `new`; both ways are written anew. With
    /// `duress`, the password under duress keeps its way and what it does; without it, the other
    /// way becomes one no password opens. Every password is wiped. `slots` must not hold the stored
    /// key, which the core holds once only.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`] when `owner` is not the owner's or `duress` not the one under
    /// duress, [`Error::SamePassword`] when `new` is `owner` or `duress`, [`Error::NoEpoch`],
    /// [`Error::Changing`], [`Error::Unsettled`], or the core's refusal, the keystore's or the file
    /// system's; the ways in then stay as they were. [`Error::Unsynced`] when they changed, but a
    /// crash may undo it.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    pub fn change_password(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        new: &mut [u8],
        mut duress: Option<&mut [u8]>,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let changed = self.settled_ways().and_then(|(number, ways)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways)?;
            let made = self.changed_ways(
                slots,
                keystore,
                opened.stored,
                opened.key,
                &ways,
                new,
                duress.as_deref_mut(),
                params,
                memory,
                entropy,
            );
            release(slots, opened.stored);
            made.map(|(own, other)| (number, own, other))
        });
        owner.zeroize();
        new.zeroize();
        if let Some(duress) = duress {
            duress.zeroize();
        }
        let (number, own, other) = changed?;
        self.write_ways(number, &own, &other, entropy)
    }

    /// The owner's way for `new`, and the other way: for `duress` in the role it has, or one no
    /// password opens. Releases `old`, the key from the owner's password.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    fn changed_ways<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        stored: Handle<'a>,
        old: Handle<'a>,
        ways: &[Way; 2],
        new: &mut [u8],
        duress: Option<&mut [u8]>,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(Way, Way), Error> {
        let derived = self
            .key_from_password(slots, keystore, new, params, memory)
            .map_err(one_password);
        // Held until now only to refuse the owner's password as the new one.
        release(slots, old);
        let (key, tags) = derived?;
        let made = match duress {
            None => unopenable(slots, entropy),
            Some(duress) => self.kept_way(
                slots, keystore, stored, ways, duress, params, memory, entropy,
            ),
        }
        .and_then(|other| {
            let own = locked_way(slots, stored, key, &tags, Role::Owner, entropy)?;
            Ok((own, other))
        });
        release(slots, key);
        made
    }

    /// The way of the password under duress `duress`, written anew in the role it has.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    fn kept_way<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        stored: Handle<'a>,
        ways: &[Way; 2],
        duress: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<Way, Error> {
        let (key, tags) = self
            .key_from_password(slots, keystore, duress, params, memory)
            .map_err(one_password)?;
        let role = ways.iter().find_map(|way| {
            [Role::Duress, Role::Destroy]
                .into_iter()
                .find(|&role| is_tag(&tags, way, role))
        });
        let way = role
            .ok_or(Error::WrongPassword)
            .and_then(|role| locked_way(slots, stored, key, &tags, role, entropy));
        release(slots, key);
        way
    }

    /// Carries the ways in into the next epoch during a change, after the core's
    /// `Slots::begin_epoch`; they open in the next epoch once it is current, in places drawn anew.
    /// Their file in the current epoch goes with its root.
    ///
    /// # Errors
    ///
    /// [`Error::NoEpoch`] before [`Profile::epoch`], the core's refusal outside a change, or the
    /// file system's.
    pub fn carry_entries(
        &self,
        slots: &mut Slots<'_>,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let current = self.current.ok_or(Error::NoEpoch)?.number;
        let next = self
            .next
            .ok_or(Error::Core(CoreError::NoEpochChange))?
            .number;
        let ways = self.read_ways(current)?;
        let mut carried = ways;
        for (from, to) in ways.iter().zip(&mut carried) {
            slots
                .carry(CONTEXT, entropy, &from.record, &mut to.record)
                .map_err(Error::Core)?;
        }
        let [first, second] = carried;
        self.write_ways(next, &first, &second, entropy)
    }

    /// The owner's way, written anew, and the way for the password under duress `duress` in
    /// `role`.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    fn duress_ways<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        owner: &Owner<'a>,
        duress: &mut [u8],
        role: Role,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(Way, Way), Error> {
        let (key, tags) = self
            .key_from_password(slots, keystore, duress, params, memory)
            .map_err(one_password)?;
        let made = locked_way(slots, owner.stored, key, &tags, role, entropy).and_then(|other| {
            let own = locked_way(
                slots,
                owner.stored,
                owner.key,
                &owner.tags,
                Role::Owner,
                entropy,
            )?;
            Ok((own, other))
        });
        release(slots, key);
        made
    }

    /// The owner's way in as `owner` opens it.
    fn owner<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        ways: &[Way; 2],
    ) -> Result<Owner<'a>, Error> {
        let (key, tags) = self.key_from_password(slots, keystore, owner, params, memory)?;
        let opened = ways
            .iter()
            .find(|way| is_tag(&tags, way, Role::Owner))
            .ok_or(Error::WrongPassword)
            .and_then(|way| {
                slots
                    .unlock(key, CONTEXT, &way.record)
                    .map_err(|error| match error {
                        // Its tag is the owner's, so the record was changed.
                        CoreError::RecordRejected => Error::Damaged,
                        other => Error::Core(other),
                    })
            });
        match opened {
            Ok(stored) => Ok(Owner { stored, key, tags }),
            Err(error) => {
                release(slots, key);
                Err(error)
            }
        }
    }

    /// Checks `password` against the owner's way in, and releases what it opened. `slots` must not
    /// hold the stored key, which the core holds once only.
    pub(crate) fn owner_only(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        password: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<(), Error> {
        let number = self
            .current
            .map(|current| current.number)
            .ok_or(Error::NoEpoch)?;
        let ways = self.read_ways(number)?;
        let opened = self.owner(slots, keystore, password, params, memory, &ways)?;
        release(slots, opened.key);
        release(slots, opened.stored);
        Ok(())
    }

    /// The key from `password` and the chip's answer to it, combined as the core does, and the key
    /// of the tags, from the answer.
    fn key_from_password<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        password: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<(Handle<'a>, TagKey), Error> {
        let key = slots
            .derive_from_password(password, params, memory)
            .map_err(Error::Core)?;
        let mut challenge = [0; 32];
        let mut answer = [0; 32];
        let answered = slots
            .challenge(key, &mut challenge)
            .map_err(Error::Core)
            .and_then(|()| self.answer(keystore, &challenge, &mut answer));
        challenge.zeroize();
        let mut tags: TagKey = Zeroizing::new([0; 32]);
        Sha256::new()
            .chain_update(TAG_KEY_LABEL)
            .chain_update(answer.as_slice())
            .finalize_into((&mut *tags).into());
        let imported = answered.and_then(|()| {
            slots
                .import32(Purpose::Wrap, &mut answer)
                .map_err(Error::Core)
        });
        answer.zeroize();
        let combined = imported.and_then(|answer| {
            slots.combine(key, answer).map_err(|error| {
                release(slots, answer);
                Error::Core(error)
            })
        });
        match combined {
            Ok(combined) => Ok((combined, tags)),
            Err(error) => {
                release(slots, key);
                Err(error)
            }
        }
    }

    /// The epoch the ways in may change in, the current one outside a change, and its ways.
    fn settled_ways(&self) -> Result<(u64, [Way; 2]), Error> {
        let number = self.settled_epoch()?;
        Ok((number, self.read_ways(number)?))
    }

    fn settled_epoch(&self) -> Result<u64, Error> {
        if self.next.is_some() {
            Err(Error::Changing)
        } else if self.unsettled {
            Err(Error::Unsettled)
        } else {
            self.current
                .map(|current| current.number)
                .ok_or(Error::NoEpoch)
        }
    }

    fn read_ways(&self, number: u64) -> Result<[Way; 2], Error> {
        // One byte more tells a longer file.
        let mut bytes = [0; 2 * WAY_LEN + 1];
        let length =
            read_file(&self.dir.join(entries_name(number)), &mut bytes).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    Error::Damaged
                } else {
                    Error::from(error)
                }
            })?;
        let ways = bytes.get(..length).and_then(parse_ways);
        bytes.zeroize();
        ways.ok_or(Error::Damaged)
    }

    /// Writes the ways of epoch `number` in one step, in an order drawn from `entropy`.
    fn write_ways(
        &self,
        number: u64,
        first: &Way,
        second: &Way,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let mut drawn = [0];
        entropy
            .fill(&mut drawn)
            .map_err(|_| Error::Core(CoreError::EntropyFailed))?;
        let [drawn] = drawn;
        let mut ways = [first, second];
        ways.rotate_left(usize::from(drawn & 1));
        let [one, other] = ways;
        let bytes = ways_bytes(one, other);
        write_file(&self.dir, &entries_name(number), &bytes).map_err(|written| match written {
            Written::Before(kind) => Error::Io(kind),
            Written::After(kind) => Error::Unsynced(kind),
        })
    }

    /// Deletes every key of this library in the keystore but this profile's, under any root and
    /// whether or not its directory is there, then marks every other profile's directory under this
    /// root destroyed, for [`sweep`](crate::sweep) to remove. A profile open elsewhere loses its
    /// keys all the same.
    fn destroy_others(&self, keystore: &mut impl Keystore) {
        let own = format!("{KEYS}{}/", self.id);
        if let Ok(aliases) = keystore.aliases(KEYS) {
            for alias in aliases.iter().filter(|alias| !alias.starts_with(&own)) {
                let _ = keystore.delete(alias);
            }
        }
        let Some(Ok(entries)) = self.dir.parent().map(fs::read_dir) else {
            return;
        };
        for entry in entries.flatten() {
            // The type as listed: a link is never followed.
            let directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
            let other = entry
                .file_name()
                .to_str()
                .and_then(Id::parse)
                .is_some_and(|id| id != self.id);
            if directory && other {
                let _ = mark_destroyed(&entry.path());
            }
        }
    }
}

/// Refuses while `slots` are in a change of epoch: what they lock would open only in the next one.
fn outside_change(slots: &mut Slots<'_>, entropy: &mut impl Entropy) -> Result<(), Error> {
    let mut carried = [0; LOCK_RECORD_LEN];
    // Outside a change the core refuses a carry before it reads the record.
    match slots.carry(CONTEXT, entropy, &[0; LOCK_RECORD_LEN], &mut carried) {
        Err(CoreError::NoEpochChange) => Ok(()),
        _ => Err(Error::Changing),
    }
}

/// A key the slots hold already, given for a new password: a password given before, which gives
/// that key again.
const fn one_password(error: Error) -> Error {
    match error {
        Error::Core(CoreError::DuplicateKey) => Error::SamePassword,
        other => other,
    }
}

/// The name of the file of the ways in of epoch `number`.
pub(crate) fn entries_name(number: u64) -> String {
    format!("{ENTRIES}{number}")
}

/// A way in of `stored` locked under `key`, with a fresh salt and the tag of `role`.
fn locked_way<'a>(
    slots: &mut Slots<'a>,
    stored: Handle<'a>,
    key: Handle<'a>,
    tags: &TagKey,
    role: Role,
    entropy: &mut impl Entropy,
) -> Result<Way, Error> {
    let mut way = Way {
        record: [0; LOCK_RECORD_LEN],
        salt: [0; SALT_LEN],
        tag: [0; 32],
    };
    entropy
        .fill(&mut way.salt)
        .map_err(|_| Error::Core(CoreError::EntropyFailed))?;
    slots
        .lock(stored, key, CONTEXT, entropy, &mut way.record)
        .map_err(Error::Core)?;
    way.tag = tag(tags, &way.salt, role);
    Ok(way)
}

/// Whether `way` holds the tag of `role` under `tags`.
fn is_tag(tags: &TagKey, way: &Way, role: Role) -> bool {
    let mut expected = tag(tags, &way.salt, role);
    let same = same_mac(&expected, &way.tag);
    expected.zeroize();
    same
}

impl Way {
    /// The way as written: its record, its salt and its tag.
    fn bytes(&self) -> [u8; WAY_LEN] {
        let mut bytes = [0; WAY_LEN];
        if let Some((record, rest)) = bytes.split_first_chunk_mut::<LOCK_RECORD_LEN>()
            && let Some((salt, tag)) = rest.split_first_chunk_mut::<SALT_LEN>()
            && let Ok(tag) = <&mut [u8; 32]>::try_from(tag)
        {
            *record = self.record;
            *salt = self.salt;
            *tag = self.tag;
        }
        bytes
    }
}

/// The file of the ways `first` and `second`, in that order.
fn ways_bytes(first: &Way, second: &Way) -> [u8; 2 * WAY_LEN] {
    let mut bytes = [0; 2 * WAY_LEN];
    if let Some((one, other)) = bytes.split_first_chunk_mut::<WAY_LEN>()
        && let Ok(other) = <&mut [u8; WAY_LEN]>::try_from(other)
    {
        *one = first.bytes();
        *other = second.bytes();
    }
    bytes
}

/// The two ways of the file `bytes`; none for a file of another length.
fn parse_ways(bytes: &[u8]) -> Option<[Way; 2]> {
    let (first, second) = bytes.split_first_chunk::<WAY_LEN>()?;
    Some([way_of(first)?, way_of(second)?])
}

/// A way as written: its record, its salt and its tag.
fn way_of(bytes: &[u8]) -> Option<Way> {
    let (record, rest) = bytes.split_first_chunk::<LOCK_RECORD_LEN>()?;
    let (salt, tag) = rest.split_first_chunk::<SALT_LEN>()?;
    Some(Way {
        record: *record,
        salt: *salt,
        tag: tag.try_into().ok()?,
    })
}

/// The tag of `role` with `salt`, under the key of the tags. A hash of the key and a message of one
/// length serves as a MAC, and unlike HMAC its state is wiped.
fn tag(tags: &TagKey, salt: &[u8; SALT_LEN], role: Role) -> [u8; 32] {
    let role: u8 = match role {
        Role::Owner => 0,
        Role::Duress => 1,
        Role::Destroy => 2,
    };
    Sha256::new()
        .chain_update(tags.as_slice())
        .chain_update(TAG_LABEL)
        .chain_update(salt)
        .chain_update([role])
        .finalize()
        .into()
}

/// A way in no password opens: a record of a random key under another random key, a random salt
/// and a random tag. Without the keys it reads as one a password opens.
fn unopenable(slots: &mut Slots<'_>, entropy: &mut impl Entropy) -> Result<Way, Error> {
    let mut secret = [0; 32];
    let mut way = Way {
        record: [0; LOCK_RECORD_LEN],
        salt: [0; SALT_LEN],
        tag: [0; 32],
    };
    let parent = entropy
        .fill(&mut secret)
        .and_then(|()| entropy.fill(&mut way.salt))
        .and_then(|()| entropy.fill(&mut way.tag))
        .map_err(|_| CoreError::EntropyFailed)
        .and_then(|()| slots.import32(Purpose::Wrap, &mut secret));
    secret.zeroize();
    let parent = parent.map_err(Error::Core)?;
    let locked = slots
        .generate(Purpose::Wrap, KeyLength::Bytes64, entropy)
        .and_then(|child| {
            let locked = slots.lock(child, parent, CONTEXT, entropy, &mut way.record);
            release(slots, child);
            locked
        });
    release(slots, parent);
    locked.map(|()| way).map_err(Error::Core)
}

/// Releases `handle`; one released already, or stale, is left so.
fn release<'a>(slots: &mut Slots<'a>, handle: Handle<'a>) {
    let _ = slots.release(handle);
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

#[cfg(test)]
mod tests {
    use std::fs;

    use lethewis_core::{
        Error as CoreError, Handle, KeyLength, LOCK_RECORD_LEN, Position, Purpose, RECORD_LEN,
        Slots,
    };
    use sha2::{Digest, Sha256};

    use zeroize::Zeroizing;

    use super::{ROLES, Role, SALT_LEN, TAG_KEY_LABEL, TagKey, WAY_LEN, entries_name, is_tag};
    use crate::profile::{DESTROYED, Error, Profile};
    use crate::stand::{
        DURESS, Made, OTHER, OWNER, Source, Stand, Start, Work, all_free, copied, dir, fail_syncs,
        hmac, made, tries,
    };
    use crate::sweep;

    /// The key of external data `stored` wraps, by which the same stored key is told.
    fn data_of<'a>(
        slots: &mut Slots<'a>,
        stored: Handle<'a>,
        wrapped: &[u8; RECORD_LEN],
    ) -> [u8; 32] {
        let data = slots.unwrap(stored, b"data", wrapped).unwrap();
        let mut key = [0; 32];
        slots
            .reveal32(data, Position::First, Purpose::ExternalData, &mut key)
            .unwrap();
        slots.release(data).unwrap();
        slots.release(stored).unwrap();
        key
    }

    /// Enters `made` with `password`: what it opened as and the key of external data, or the error.
    /// Every slot is free again either way.
    fn enter(made: &Made, stand: &mut Stand, password: &[u8]) -> Result<(Role, [u8; 32]), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let entered = made
            .profile
            .enter_as(
                &mut slots,
                stand,
                &mut password.to_vec(),
                &made.params,
                &mut work.memory,
            )
            .map(|(stored, role)| (role, data_of(&mut slots, stored, &made.wrapped)));
        assert!(all_free(&mut slots));
        entered
    }

    fn set_duress(
        made: &Made,
        stand: &mut Stand,
        owner: &[u8],
        duress: &[u8],
        destroy: bool,
    ) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let set = made.profile.set_duress(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            &mut duress.to_vec(),
            destroy,
            &made.params,
            &mut work.memory,
            &mut Source(99),
        );
        assert!(all_free(&mut slots));
        set
    }

    fn clear_duress(made: &Made, stand: &mut Stand, owner: &[u8]) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let cleared = made.profile.clear_duress(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(98),
        );
        assert!(all_free(&mut slots));
        cleared
    }

    fn change(
        made: &Made,
        stand: &mut Stand,
        owner: &[u8],
        new: &[u8],
        duress: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let mut duress = duress.map(<[u8]>::to_vec);
        let changed = made.profile.change_password(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            &mut new.to_vec(),
            duress.as_deref_mut(),
            &made.params,
            &mut work.memory,
            &mut Source(97),
        );
        assert!(all_free(&mut slots));
        changed
    }

    /// The record, the salt and the tag of a way as written.
    fn parts(way: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let (record, rest) = way.split_at(LOCK_RECORD_LEN);
        let (salt, tag) = rest.split_at(SALT_LEN);
        (record, salt, tag)
    }

    fn file(made: &Made, number: u64) -> Vec<u8> {
        fs::read(made.profile.dir.join(entries_name(number))).unwrap()
    }

    #[test]
    fn the_owners_password_opens_the_profile_and_another_does_not() {
        let root = dir("owner");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
        assert_eq!(enter(&made, &mut stand, OTHER), Err(Error::WrongPassword));
    }

    /// The challenge of `password` to the chip of `made`, and the chip's answer.
    fn answer_of(made: &Made, stand: &Stand, password: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let key = slots
            .derive_from_password(&mut password.to_vec(), &made.params, &mut work.memory)
            .unwrap();
        let mut challenge = [0; 32];
        slots.challenge(key, &mut challenge).unwrap();
        let chip = stand.keys[&crate::profile::alias(made.profile.id())];
        let answer = hmac(
            &chip,
            &[b"lethewis answer ".as_slice(), &challenge].concat(),
        );
        (challenge, answer)
    }

    fn keyed(secret: &[u8; 32]) -> TagKey {
        Zeroizing::new(
            Sha256::new()
                .chain_update(TAG_KEY_LABEL)
                .chain_update(secret)
                .finalize()
                .into(),
        )
    }

    #[test]
    fn the_owners_way_lands_in_either_place() {
        let root = dir("places");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let tags = keyed(&answer_of(&made, &stand, OWNER).1);
        let (_, [first, second]) = made.profile.settled_ways().unwrap();
        let (own, other) = if is_tag(&tags, &first, Role::Owner) {
            (first, second)
        } else {
            (second, first)
        };
        let places: Vec<bool> = (1..=4)
            .map(|seed| {
                made.profile
                    .write_ways(0, &own, &other, &mut Source(seed))
                    .unwrap();
                file(&made, 0).starts_with(&own.record)
            })
            .collect();
        assert!(
            places.contains(&true) && places.contains(&false),
            "{places:?}"
        );
    }

    #[test]
    fn every_password_does_the_same_work_and_writes_nothing() {
        let root = dir("work");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let before = file(&made, 0);
        let mut work = Vec::new();
        for password in [OWNER, DURESS, OTHER] {
            let macs = stand.macs;
            tries();
            let _ = enter(&made, &mut stand, password);
            work.push((stand.macs - macs, tries()));
            assert_eq!(file(&made, 0), before);
        }
        assert_eq!(work, [work[0]; 3]);
        assert_eq!(work[0].1, 8);
    }

    #[test]
    fn a_tag_needs_the_chips_answer() {
        let root = dir("chip");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let (challenge, answer) = answer_of(&made, &stand, OWNER);
        let (_, ways) = made.profile.settled_ways().unwrap();
        let tags_under = |secret: &[u8; 32]| {
            let tags = keyed(secret);
            ways.iter()
                .flat_map(|way| ROLES.map(|role| is_tag(&tags, way, role)))
                .filter(|&same| same)
                .count()
        };
        // The answer, which needs the chip, gives the owner's tag; the challenge alone gives none.
        assert_eq!(tags_under(&answer), 1);
        assert_eq!(tags_under(&challenge), 0);
    }

    #[test]
    fn a_password_under_duress_opens_the_same_profile_and_leaves_the_others() {
        let root = dir("duress");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let other = Profile::create(&root, &mut stand, false).unwrap().id();
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Duress, made.data))
        );
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
        assert!(Profile::open(&root, other).is_ok());
        assert_eq!(stand.deleted, Vec::<String>::new());
    }

    #[test]
    fn a_password_under_duress_set_to_destroy_destroys_every_other_profile() {
        let root = dir("destroy");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Destroy);
        // With ways in of its own, which the sweep removes with it.
        let idle = self::made(&root, &mut stand, 55).profile.id();
        // Held open elsewhere, and keys whose directory is gone.
        let busy = Profile::create(&root, &mut stand, false).unwrap();
        let orphan = "lethewis/00112233445566778899aabbccddeeff/chip".to_owned();
        stand.keys.insert(orphan.clone(), [1; 32]);
        // A link named as a profile, to a directory that is none of them.
        let outside = dir("outside");
        let linked = "ffeeddccbbaa99887766554433221100";
        std::os::unix::fs::symlink(&*outside, root.join(linked)).unwrap();
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
        assert_eq!(stand.deleted, Vec::<String>::new());
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Destroy, made.data))
        );
        let own = format!("lethewis/{}/", made.profile.id());
        assert!(
            stand.keys.keys().all(|alias| alias.starts_with(&own)),
            "{:?}",
            stand.keys.keys()
        );
        assert!(stand.keys.keys().any(|alias| alias.starts_with(&own)));
        assert!(!made.profile.dir.join(DESTROYED).exists());
        assert!(!outside.join(DESTROYED).exists());
        for other in [idle, busy.id()] {
            assert!(root.join(other.to_string()).join(DESTROYED).exists());
        }
        drop(busy);
        assert_eq!(Profile::open(&root, idle).err(), Some(Error::NotFound));
        sweep(&root, &mut stand).unwrap();
        // Nothing of it is left, under its name or another.
        let idle = idle.to_string();
        assert!(fs::read_dir(&*root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&idle)
        }));
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
    }

    #[test]
    fn the_owners_password_is_no_password_under_duress() {
        let root = dir("same");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let before = file(&made, 0);
        assert_eq!(
            set_duress(&made, &mut stand, OWNER, OWNER, true),
            Err(Error::SamePassword)
        );
        assert_eq!(
            set_duress(&made, &mut stand, OTHER, DURESS, true),
            Err(Error::WrongPassword)
        );
        assert_eq!(
            clear_duress(&made, &mut stand, OTHER),
            Err(Error::WrongPassword)
        );
        assert_eq!(file(&made, 0), before);
    }

    #[test]
    fn every_change_writes_both_ways_anew() {
        let root = dir("anew");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let mut before = file(&made, 0);
        for change in 0..2 {
            if change == 0 {
                set_duress(&made, &mut stand, OWNER, DURESS, true).unwrap();
            } else {
                clear_duress(&made, &mut stand, OWNER).unwrap();
            }
            let after = file(&made, 0);
            assert_eq!(after.len(), 2 * WAY_LEN);
            // Nothing of a way stays, in whichever place it lands.
            for old in before.chunks(WAY_LEN).map(parts) {
                for new in after.chunks(WAY_LEN).map(parts) {
                    let same = old.0.iter().zip(new.0).filter(|(a, b)| a == b).count();
                    assert!(same * 8 < LOCK_RECORD_LEN);
                    assert!(old.1 != new.1 && old.2 != new.2);
                }
            }
            before = after;
        }
        assert_eq!(enter(&made, &mut stand, DURESS), Err(Error::WrongPassword));
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
    }

    #[test]
    fn the_key_of_the_epoch_tells_no_way_in_from_another() {
        // Ways no password opens, the owner's, and one under duress set to destroy.
        for start in [Start::Plain, Start::Destroy] {
            let root = dir("epoch");
            let mut stand = Stand::new();
            let made = copied(&root, &mut stand, start);
            let (_, ways) = made.profile.settled_ways().unwrap();
            let mut work = Work::new(&made.params);
            let mut slots = Slots::new(
                &mut work.slots,
                &mut work.epoch,
                0,
                &mut made.epoch_key.clone(),
            );
            let key = slots.import32(Purpose::Wrap, &mut [5; 32]).unwrap();
            // The outer layer opens under the key of the epoch alone; only the inner one refuses.
            for way in &ways {
                assert_eq!(
                    slots.unlock(key, super::CONTEXT, &way.record).err(),
                    Some(CoreError::RecordRejected)
                );
            }
        }
    }

    #[test]
    fn the_ways_in_carried_open_in_the_next_epoch() {
        let root = dir("carried");
        let mut stand = Stand::new();
        let mut made = copied(&root, &mut stand, Start::Duress);
        let mut next_key = [0; 32];
        made.profile
            .next_epoch(&mut stand, false, &mut next_key)
            .unwrap();
        assert_eq!(
            set_duress(&made, &mut stand, OWNER, DURESS, false),
            Err(Error::Changing)
        );
        let mut work = Work::new(&made.params);
        {
            let mut slots = Slots::new(
                &mut work.slots,
                &mut work.epoch,
                0,
                &mut made.epoch_key.clone(),
            );
            slots.begin_epoch(&mut next_key.clone()).unwrap();
            made.profile
                .carry_entries(&mut slots, &mut Source(5))
                .unwrap();
            assert_eq!(
                slots.commit_epoch(&mut made.profile.roots(&mut stand)),
                Ok(lethewis_core::Erasure::BestEffort)
            );
        }
        assert!(!made.profile.dir.join(entries_name(0)).exists());
        let id = made.profile.id();
        drop(made.profile);
        let mut profile = Profile::open(&root, id).unwrap();
        let mut epoch_key = [0; 32];
        assert_eq!(profile.epoch(&mut stand, &mut epoch_key).unwrap().number, 1);
        let mut slots = Slots::new(&mut work.slots, &mut work.epoch, 1, &mut epoch_key.clone());
        // Records wrapped before are the caller's to carry; the ways in opened are the test.
        for (password, role) in [
            (OWNER, Ok(Role::Owner)),
            (DURESS, Ok(Role::Duress)),
            (OTHER, Err(Error::WrongPassword)),
        ] {
            let entered = profile
                .enter_as(
                    &mut slots,
                    &mut stand,
                    &mut password.to_vec(),
                    &made.params,
                    &mut work.memory,
                )
                .map(|(stored, role)| {
                    slots.release(stored).unwrap();
                    role
                });
            assert_eq!(entered, role);
        }
    }

    #[test]
    fn ways_in_of_another_epoch_read_as_stale() {
        let root = dir("stale");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            1,
            &mut made.epoch_key.clone(),
        );
        assert_eq!(
            made.profile
                .enter_as(
                    &mut slots,
                    &mut stand,
                    &mut OWNER.to_vec(),
                    &made.params,
                    &mut work.memory
                )
                .err(),
            Some(Error::Core(CoreError::StaleRecord))
        );
        assert!(all_free(&mut slots));
    }

    #[test]
    fn a_password_is_wiped_once_tried() {
        let root = dir("wiped");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        // Damaged, the profile refuses before the core sees the password.
        for damaged in [false, true] {
            if damaged {
                fs::write(made.profile.dir.join(entries_name(0)), b"short").unwrap();
            }
            for password in [OWNER, OTHER] {
                let mut typed = password.to_vec();
                let _ = made.profile.enter(
                    &mut slots,
                    &mut stand,
                    &mut typed,
                    &made.params,
                    &mut work.memory,
                );
                assert!(typed.iter().all(|&byte| byte == 0));
            }
        }
    }

    #[test]
    fn missing_or_longer_ways_in_read_as_damaged() {
        let root = dir("damaged");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let path = made.profile.dir.join(entries_name(0));
        let mut longer = fs::read(&path).unwrap();
        longer.push(0);
        fs::write(&path, &longer).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Damaged));
        fs::remove_file(&path).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Damaged));
    }

    #[test]
    fn a_password_under_duress_changes_no_way_in() {
        let root = dir("unchanged");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let before = file(&made, 0);
        assert_eq!(
            set_duress(&made, &mut stand, DURESS, OTHER, true),
            Err(Error::WrongPassword)
        );
        assert_eq!(
            clear_duress(&made, &mut stand, DURESS),
            Err(Error::WrongPassword)
        );
        assert_eq!(
            change(&made, &mut stand, DURESS, OTHER, None),
            Err(Error::WrongPassword)
        );
        assert_eq!(file(&made, 0), before);
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Duress, made.data))
        );
    }

    #[test]
    fn a_new_owners_password_keeps_the_one_under_duress_given() {
        let root = dir("change");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Destroy);
        change(&made, &mut stand, OWNER, OTHER, Some(DURESS)).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::WrongPassword));
        assert_eq!(
            enter(&made, &mut stand, OTHER),
            Ok((Role::Owner, made.data))
        );
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Destroy, made.data))
        );
    }

    #[test]
    fn a_new_owners_password_alone_leaves_no_password_under_duress() {
        let root = dir("alone");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        change(&made, &mut stand, OWNER, OTHER, Some(DURESS)).unwrap();
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Duress, made.data))
        );
        change(&made, &mut stand, OTHER, OWNER, None).unwrap();
        assert_eq!(enter(&made, &mut stand, DURESS), Err(Error::WrongPassword));
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
    }

    #[test]
    fn a_new_owners_password_is_refused_as_another_given() {
        let root = dir("refused");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let before = file(&made, 0);
        for (new, duress, refused) in [
            (OWNER, None, Error::SamePassword),
            (DURESS, Some(DURESS), Error::SamePassword),
            (OTHER, Some(OWNER), Error::WrongPassword),
        ] {
            assert_eq!(change(&made, &mut stand, OWNER, new, duress), Err(refused));
        }
        assert_eq!(file(&made, 0), before);
    }

    #[test]
    fn the_ways_in_are_made_once() {
        let root = dir("once");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let before = file(&made, 0);
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Source(3))
            .unwrap();
        let mut password = OTHER.to_vec();
        assert_eq!(
            made.profile.create_entries(
                &mut slots,
                &mut stand,
                stored,
                &mut password,
                &made.params,
                &mut work.memory,
                &mut Source(4),
            ),
            Err(Error::Exists)
        );
        assert!(password.iter().all(|&byte| byte == 0));
        assert_eq!(file(&made, 0), before);
    }

    #[test]
    fn no_way_in_is_written_while_the_slots_change_epoch() {
        let root = dir("midway");
        let mut stand = Stand::new();
        let mut made = copied(&root, &mut stand, Start::Plain);
        let mut fresh = Profile::create(&root, &mut stand, false).unwrap();
        let mut next_key = [0; 32];
        made.profile
            .next_epoch(&mut stand, false, &mut next_key)
            .unwrap();
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        slots.begin_epoch(&mut next_key).unwrap();
        made.profile
            .carry_entries(&mut slots, &mut Source(6))
            .unwrap();
        // Opened again, the profiles know of no change; the slots are still in it.
        let id = made.profile.id();
        drop(made.profile);
        made.profile = Profile::open(&root, id).unwrap();
        made.profile.epoch(&mut stand, &mut [0; 32]).unwrap();
        fresh.epoch(&mut stand, &mut [0; 32]).unwrap();
        let before = file(&made, 0);
        let set = made.profile.set_duress(
            &mut slots,
            &mut stand,
            &mut OWNER.to_vec(),
            &mut DURESS.to_vec(),
            false,
            &made.params,
            &mut work.memory,
            &mut Source(7),
        );
        let cleared = made.profile.clear_duress(
            &mut slots,
            &mut stand,
            &mut OWNER.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(8),
        );
        let changed = made.profile.change_password(
            &mut slots,
            &mut stand,
            &mut OWNER.to_vec(),
            &mut OTHER.to_vec(),
            None,
            &made.params,
            &mut work.memory,
            &mut Source(9),
        );
        let stored = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut Source(10))
            .unwrap();
        let created = fresh.create_entries(
            &mut slots,
            &mut stand,
            stored,
            &mut OWNER.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(11),
        );
        slots.release(stored).unwrap();
        assert_eq!([set, cleared, changed, created], [Err(Error::Changing); 4]);
        assert_eq!(file(&made, 0), before);
        assert!(!fresh.dir.join(entries_name(0)).exists());
        assert!(all_free(&mut slots));
        assert!(
            slots
                .abandon_epoch(&mut made.profile.roots(&mut stand))
                .is_ok()
        );
        drop(slots);
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
    }

    #[test]
    fn a_change_of_epoch_without_its_ways_in_is_not_committed() {
        let root = dir("uncarried");
        let mut stand = Stand::new();
        let mut made = copied(&root, &mut stand, Start::Plain);
        // Left by a change abandoned before, they are not this change's.
        fs::write(made.profile.dir.join(entries_name(1)), file(&made, 0)).unwrap();
        let mut next_key = [0; 32];
        made.profile
            .next_epoch(&mut stand, false, &mut next_key)
            .unwrap();
        let mut work = Work::new(&made.params);
        {
            let mut slots = Slots::new(
                &mut work.slots,
                &mut work.epoch,
                0,
                &mut made.epoch_key.clone(),
            );
            slots.begin_epoch(&mut next_key).unwrap();
            assert!(
                slots
                    .commit_epoch(&mut made.profile.roots(&mut stand))
                    .is_err()
            );
            assert!(
                slots
                    .abandon_epoch(&mut made.profile.roots(&mut stand))
                    .is_ok()
            );
        }
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
    }

    #[test]
    fn records_swapped_under_their_tags_read_as_damaged() {
        let root = dir("swapped");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let bytes = file(&made, 0);
        let (first, second) = bytes.split_at(WAY_LEN);
        let (first, second) = (parts(first), parts(second));
        let swapped = [second.0, first.1, first.2, first.0, second.1, second.2].concat();
        fs::write(made.profile.dir.join(entries_name(0)), swapped).unwrap();
        assert_eq!(
            set_duress(&made, &mut stand, OWNER, DURESS, false),
            Err(Error::Damaged)
        );
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Damaged));
    }

    #[test]
    fn ways_in_written_but_not_synced_are_told_apart() {
        let root = dir("unsynced");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        fail_syncs(0, 1);
        let set = set_duress(&made, &mut stand, OWNER, DURESS, false);
        fail_syncs(0, 0);
        assert!(matches!(set, Err(Error::Unsynced(_))), "{set:?}");
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Duress, made.data))
        );
    }

    #[test]
    fn no_change_of_epoch_begins_over_ways_in_it_cannot_clear() {
        let root = dir("unclear");
        let mut stand = Stand::new();
        let mut made = copied(&root, &mut stand, Start::Plain);
        fs::create_dir(made.profile.dir.join(entries_name(1))).unwrap();
        let begun = made.profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert!(matches!(begun, Err(Error::Io(_))), "{begun:?}");
    }
}
