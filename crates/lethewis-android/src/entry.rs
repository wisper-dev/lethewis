// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The ways into a profile, three in one file per epoch, each in a place of its own: lock records
//! of the core, opened by the owner's password, by a password under duress, and by the owner's
//! password with two shares. A way not set is one nothing opens. After them lies a mark, keyed by
//! the chip with no password, of whether the way with shares is set: a lock needs it. Beside each
//! record lie a salt and a tag of what its password may do, keyed by the chip's answer, which needs
//! both the password and the chip. The records share one context, so that the key of the epoch,
//! which needs no password, tells nothing either. A change writes anew the ways it sets and keeps
//! the bytes of the others; a carry into the next epoch writes them all anew.

use std::fs;
use std::io;

use lethewis_core::{
    Entropy, Error as CoreError, Handle, KeyLength, LOCK_RECORD_LEN, MemoryBlock, PasswordParams,
    Purpose, SHARE_COUNT, SHARE_LEN, Share, Shares, Slots,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::epoch::Written;
use crate::guard::Readings;
use crate::keystore::Keystore;
use crate::profile::{Error, Id, Profile, exists, mark_destroyed, read_file, same_mac, write_file};

/// What the file of the ways in of an epoch is named, with its number after it.
pub(crate) const ENTRIES: &str = "entries-";
/// How the names of the keys of this library begin, as `profile::alias` and `epoch::root_alias`
/// write them.
pub(crate) const KEYS: &str = "lethewis/";

const CONTEXT: &[u8] = b"lethewis entry";
const TAG_KEY_LABEL: &[u8; 23] = b"lethewis entry tag key ";
const TAG_LABEL: &[u8; 19] = b"lethewis entry role";
const SALT_LEN: usize = 32;
const WAY_LEN: usize = LOCK_RECORD_LEN + SALT_LEN + 32;
/// How many ways the file of an epoch holds: the owner's, the other password's and the shares', in
/// that order.
const WAYS: usize = 3;
const MARK_LEN: usize = 32;
const FILE_LEN: usize = WAYS * WAY_LEN + MARK_LEN;

/// The mark of the file of the ways, as [`Profile::shares_mark`] makes it.
type Mark = [u8; MARK_LEN];

/// What a password opened the profile as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Owner,
    Duress,
    /// Under duress, destroying every other profile.
    Destroy,
    /// The owner, with two shares as well.
    Shares,
}

const ROLES: [Role; 4] = [Role::Owner, Role::Duress, Role::Destroy, Role::Shares];

impl Role {
    /// The place of the way of this role.
    const fn place(self) -> usize {
        match self {
            Self::Owner => 0,
            Self::Duress | Self::Destroy => 1,
            Self::Shares => 2,
        }
    }
}

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
    /// `password` and the chip, and ways nothing opens in the other places. `password` is wiped.
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
        let _writing = self.writing();
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
        let ways = [
            way,
            unopenable(slots, entropy)?,
            unopenable(slots, entropy)?,
        ];
        let [_, _, shared] = &ways;
        let mark = self.mark(keystore, false, shared)?;
        self.write_ways(number, &ways, &mark)
    }

    /// Opens the profile with `password` and the chip: returns its stored key. The work does not
    /// tell which password it was: one derivation, one answer of the chip, every tag compared and
    /// every record tried, and nothing is written. A password under duress set to destroy also
    /// deletes every other key of this library in the keystore, then marks the other profiles under
    /// the same root destroyed for [`sweep`](crate::sweep), whether the profile opens or is locked.
    /// `password` is wiped.
    ///
    /// # Errors
    ///
    /// [`Error::NoEpoch`] before [`Profile::epoch`], [`Error::WrongPassword`] when no way in
    /// opens, [`Error::Locked`] for either password of a profile locked, [`Error::Damaged`] for
    /// ways not as written, or the core's refusal, the keystore's or the file system's.
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
        let (ways, mark) = self.read_ways(number)?;
        let (key, tags) = self.key_from_password(slots, keystore, password, params, memory)?;
        // Every tag in every place and every record, whatever matched or opened before.
        let mut matched = None;
        let mut misplaced = false;
        for (place, way) in ways.iter().enumerate() {
            for role in ROLES {
                #[cfg(test)]
                crate::stand::tried();
                if is_tag(&tags, way, role) {
                    if place == role.place() {
                        matched = matched.or(Some((place, role)));
                    } else {
                        misplaced = true;
                    }
                }
            }
        }
        drop(tags);
        let mut opened = [None; WAYS];
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
        let mut places = opened
            .iter()
            .enumerate()
            .filter_map(|(place, stored)| stored.map(|_| place));
        let opened_at = (places.next(), places.next());
        let entered = match (failed, matched, opened_at) {
            (Some(error), _, _) => Err(error),
            _ if misplaced => Err(Error::Damaged),
            (None, None, (None, _)) => Err(Error::WrongPassword),
            // A tag in its place whose record nothing opens: the profile is locked.
            (None, Some(_), (None, _)) => Err(Error::Locked),
            (None, Some((place, role)), (Some(at), None))
                if at == place && role != Role::Shares =>
            {
                opened
                    .get_mut(place)
                    .and_then(Option::take)
                    .map(|stored| (stored, role))
                    .ok_or(Error::Damaged)
            }
            _ => Err(Error::Damaged),
        };
        if entered.is_err() {
            for stored in opened.into_iter().flatten() {
                release(slots, stored);
            }
        }
        let [_, _, shared] = &ways;
        let entered = match entered {
            Err(Error::Locked) if self.unset(keystore, shared, &mark)? => Err(Error::Damaged),
            entered => entered,
        };
        // A profile locked destroys under duress as one opened does.
        if matches!(matched, Some((_, Role::Destroy)))
            && matches!(entered, Ok(_) | Err(Error::Locked))
        {
            self.destroy_others(keystore);
        }
        entered
    }

    /// Sets the password under duress to `duress`, with the owner's `owner`: it opens the profile
    /// as the owner's does, and with `destroy` it also destroys every other profile, as
    /// [`Profile::enter`] tells. It replaces any set before; the ways of both passwords are written
    /// anew. Both passwords are wiped. `slots` must not hold the stored key, which the core holds
    /// once only.
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
        let _writing = self.writing();
        let role = if destroy { Role::Destroy } else { Role::Duress };
        let set = self.settled_ways().and_then(|(number, ways, mark)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways, &mark)?;
            let made = self.duress_ways(
                slots, keystore, &opened, duress, role, params, memory, entropy,
            );
            release(slots, opened.key);
            release(slots, opened.stored);
            made.map(|(own, other)| (number, with_passwords(&ways, &own, &other), mark))
        });
        owner.zeroize();
        duress.zeroize();
        let (number, ways, mark) = set?;
        self.write_ways(number, &ways, &mark)
    }

    /// Removes the password under duress, with the owner's `owner`: the other way in becomes one
    /// no password opens, and the ways of both passwords are written anew. `owner` is wiped.
    /// `slots` must not hold the stored key, which the core holds once only.
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
        let _writing = self.writing();
        let cleared = self.settled_ways().and_then(|(number, ways, mark)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways, &mark)?;
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
            Ok((
                number,
                with_passwords(&ways, &own?, &unopenable(slots, entropy)?),
                mark,
            ))
        });
        owner.zeroize();
        let (number, ways, mark) = cleared?;
        self.write_ways(number, &ways, &mark)
    }

    /// Changes the owner's password from `owner` to `new`; the ways of both passwords are written
    /// anew. With `duress`, the password under duress keeps its way and what it does; without it,
    /// the other way becomes one no password opens. With `shares`, the way with shares is made
    /// anew under `new`, and its three new shares written there: the ones given before open no
    /// more. Every password is wiped. `slots` must not hold the stored key, which the core holds
    /// once only.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`] when `owner` is not the owner's or `duress` not the one under
    /// duress, [`Error::SamePassword`] when `new` is `owner` or `duress`, [`Error::SharesSet`]
    /// without `shares` while a way with shares is set, [`Error::NoEpoch`], [`Error::Changing`],
    /// [`Error::Unsettled`], or the core's refusal, the keystore's or the file system's; the ways
    /// in then stay as they were. [`Error::Unsynced`] when they changed, but a crash may undo it;
    /// `shares` holds the new ones then too.
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
        shares: Option<&mut Shares>,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let _writing = self.writing();
        let mut made_shares = no_shares();
        let asked = shares.is_some();
        let changed = self.settled_ways().and_then(|(number, ways, mark)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways, &mark)?;
            let [_, _, kept] = ways;
            if !asked && is_tag(&opened.tags, &kept, Role::Shares) {
                release(slots, opened.key);
                release(slots, opened.stored);
                return Err(Error::SharesSet);
            }
            let made = self.changed_ways(
                slots,
                keystore,
                opened.stored,
                opened.key,
                &ways,
                new,
                duress.as_deref_mut(),
                asked.then_some(&mut *made_shares),
                params,
                memory,
                entropy,
            );
            release(slots, opened.stored);
            let (own, other, split) = made?;
            let mark = match &split {
                Some(way) => self.mark(keystore, true, way)?,
                None => mark,
            };
            Ok((number, [own, other, split.unwrap_or(kept)], mark))
        });
        owner.zeroize();
        new.zeroize();
        if let Some(duress) = duress {
            duress.zeroize();
        }
        let (number, ways, mark) = changed?;
        let written = self.write_ways(number, &ways, &mark);
        if let (Some(shares), Ok(()) | Err(Error::Unsynced(_))) = (shares, &written) {
            *shares = *made_shares;
        }
        written
    }

    /// The owner's way for `new`; the other way, for `duress` in the role it has or one no password
    /// opens; and with `shares`, the way with the shares it writes there. Releases `old`, the key
    /// from the owner's password.
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
        ways: &[Way; WAYS],
        new: &mut [u8],
        duress: Option<&mut [u8]>,
        shares: Option<&mut Shares>,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(Way, Way, Option<Way>), Error> {
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
        match (made, shares) {
            (Ok((own, other)), Some(shares)) => {
                let split = shared_way(slots, stored, key, &tags, entropy, shares)?;
                Ok((own, other, Some(split)))
            }
            (made, _) => {
                release(slots, key);
                made.map(|(own, other)| (own, other, None))
            }
        }
    }

    /// Makes the way in with the owner's password `owner` and two shares, and writes three shares
    /// into `shares`, to give to three people the owner trusts. Any two of them with the password
    /// open the profile once it is locked; the password alone opens it until then. It replaces any
    /// made before, whose shares open no more. `owner` is wiped. `slots` must not hold the stored
    /// key, which the core holds once only.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`] when `owner` is not the owner's, [`Error::NoEpoch`],
    /// [`Error::Changing`], [`Error::Unsettled`], or the core's refusal, the keystore's or the file
    /// system's; the ways in then stay as they were. [`Error::Unsynced`] when they changed, but a
    /// crash may undo it. `shares` holds the new ones only when the ways changed.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    pub fn set_shares(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
        shares: &mut Shares,
    ) -> Result<(), Error> {
        let _writing = self.writing();
        let mut made_shares = no_shares();
        let set = self.settled_ways().and_then(|(number, ways, mark)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways, &mark)?;
            let split = shared_way(
                slots,
                opened.stored,
                opened.key,
                &opened.tags,
                entropy,
                &mut made_shares,
            );
            release(slots, opened.stored);
            let split = split?;
            let mark = self.mark(keystore, true, &split)?;
            let [own, other, _] = ways;
            Ok((number, [own, other, split], mark))
        });
        owner.zeroize();
        let (number, ways, mark) = set?;
        let written = self.write_ways(number, &ways, &mark);
        if matches!(written, Ok(()) | Err(Error::Unsynced(_))) {
            *shares = *made_shares;
        }
        written
    }

    /// Removes the way in with shares, with the owner's password `owner`: the shares given open the
    /// profile no more. `owner` is wiped. `slots` must not hold the stored key, which the core
    /// holds once only.
    ///
    /// # Errors
    ///
    /// [`Error::NoWayOut`] while a sign is set to [`Action::Lock`](crate::Action::Lock), as
    /// [`Profile::judge`] for the file of the signs, or as [`Profile::set_shares`].
    pub fn clear_shares(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let _writing = self.writing();
        let cleared = self.settled_ways().and_then(|(number, ways, mark)| {
            outside_change(slots, entropy)?;
            let opened = self.owner(slots, keystore, owner, params, memory, &ways, &mark)?;
            release(slots, opened.key);
            release(slots, opened.stored);
            if self.locks(keystore)? {
                return Err(Error::NoWayOut);
            }
            let nobody = unopenable(slots, entropy)?;
            let mark = self.mark(keystore, false, &nobody)?;
            let [own, other, _] = ways;
            Ok((number, [own, other, nobody], mark))
        });
        owner.zeroize();
        let (number, ways, mark) = cleared?;
        self.write_ways(number, &ways, &mark)
    }

    /// Opens the profile with the owner's password `owner` and two shares [`Profile::set_shares`]
    /// wrote, `first` and `second` in either order, whether it is locked or not, and makes the
    /// owner's way anew: the password alone opens the profile again. It takes `readings` as
    /// accepted, as [`Profile::accept_signs`] does, so the sign that locked the profile fires no
    /// more. In a file of the signs that was changed, as [`Verdict::damaged`](crate::Verdict)
    /// tells, what no longer reads becomes [`Action::Ignore`](crate::Action::Ignore). A password
    /// under duress the lock emptied is gone, and [`Profile::set_duress`] sets one again. Returns
    /// the stored key. The password is derived twice, as the key from it opens the way with the
    /// shares and then locks the owner's. `owner` and both shares are wiped.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`] when the password and the shares open no way, whichever is wrong; a
    /// password under duress set to destroy destroys as in [`Profile::enter`]. [`Error::Unread`] as
    /// [`Profile::accept_signs`], [`Error::Damaged`] for
    /// ways not as written, [`Error::NoEpoch`],
    /// [`Error::Changing`], [`Error::Unsettled`], or the core's refusal, the keystore's or the file
    /// system's; the ways in then stay as they were. [`Error::Unsynced`] when they changed, but a
    /// crash may undo it, and the stored key is released then.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    pub fn unlock_with_shares<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        first: &mut Share,
        second: &mut Share,
        readings: &Readings<'_>,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<Handle<'a>, Error> {
        let _writing = self.writing();
        // The core wipes a password once it derives from it.
        let mut again = owner.to_vec();
        let unlocked = self.settled_ways().and_then(|(number, ways, mark)| {
            outside_change(slots, entropy)?;
            let stored = self
                .opened_with_shares(slots, keystore, owner, first, second, params, memory, &ways)?;
            let made = self
                .key_from_password(slots, keystore, &mut again, params, memory)
                .and_then(|(key, tags)| {
                    let [before, other, _] = &ways;
                    // The owner's record opens to the stored key, held already, where the profile
                    // is not locked: the password under duress then keeps its way.
                    let open = match slots.unlock(key, CONTEXT, &before.record) {
                        Ok(again) => {
                            release(slots, again);
                            true
                        }
                        Err(CoreError::DuplicateKey) => true,
                        Err(_) => false,
                    };
                    let own = locked_way(slots, stored, key, &tags, Role::Owner, entropy);
                    release(slots, key);
                    let other = if open {
                        Ok(*other)
                    } else {
                        unopenable(slots, entropy)
                    };
                    Ok((own?, other?))
                })
                .and_then(|made| match self.accept_anew(keystore, readings, entropy) {
                    Ok(()) => Ok((made, None)),
                    Err(Error::Unsynced(kind)) => Ok((made, Some(kind))),
                    Err(error) => Err(error),
                });
            match made {
                Ok(((own, other), unsynced)) => {
                    let [_, _, shared] = ways;
                    Ok((number, [own, other, shared], mark, stored, unsynced))
                }
                Err(error) => {
                    release(slots, stored);
                    Err(error)
                }
            }
        });
        owner.zeroize();
        again.as_mut_slice().zeroize();
        first.zeroize();
        second.zeroize();
        let (number, ways, mark, stored, unsynced) = unlocked?;
        match (self.write_ways(number, &ways, &mark), unsynced) {
            (Ok(()), None) => Ok(stored),
            (Ok(()), Some(kind)) => {
                release(slots, stored);
                Err(Error::Unsynced(kind))
            }
            (Err(error), _) => {
                release(slots, stored);
                Err(error)
            }
        }
    }

    /// The stored key, as the owner's password `owner` with the shares `first` and `second` opens
    /// it.
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    fn opened_with_shares<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        first: &mut Share,
        second: &mut Share,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        ways: &[Way; WAYS],
    ) -> Result<Handle<'a>, Error> {
        let (key, tags) = self.key_from_password(slots, keystore, owner, params, memory)?;
        let [_, other, shared] = ways;
        // Every password goes the same way, so the answer tells none from another.
        let destroying = is_tag(&tags, other, Role::Destroy);
        drop(tags);
        let from_shares = match slots.derive_from_shares(first, second) {
            Ok(from_shares) => from_shares,
            Err(error) => {
                release(slots, key);
                return Err(Error::Core(error));
            }
        };
        let both = slots.combine(key, from_shares).map_err(|error| {
            release(slots, key);
            release(slots, from_shares);
            Error::Core(error)
        })?;
        let opened = slots
            .unlock(both, CONTEXT, &shared.record)
            .map_err(|error| match error {
                CoreError::RecordRejected => Error::WrongPassword,
                other => Error::Core(other),
            });
        release(slots, both);
        if destroying {
            self.destroy_others(keystore);
        }
        opened
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
        ways: &[Way; WAYS],
        duress: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<Way, Error> {
        let (key, tags) = self
            .key_from_password(slots, keystore, duress, params, memory)
            .map_err(one_password)?;
        let [_, other, ..] = ways;
        let role = [Role::Duress, Role::Destroy]
            .into_iter()
            .find(|&role| is_tag(&tags, other, role));
        let way = role
            .ok_or(Error::WrongPassword)
            .and_then(|role| locked_way(slots, stored, key, &tags, role, entropy));
        release(slots, key);
        way
    }

    /// Carries the ways in into the next epoch during a change, after the core's
    /// `Slots::begin_epoch`; they open in the next epoch once it is current, each in its place.
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
        let _writing = self.writing();
        let current = self.current.ok_or(Error::NoEpoch)?.number;
        let next = self
            .next
            .ok_or(Error::Core(CoreError::NoEpochChange))?
            .number;
        let (ways, mark) = self.read_ways(current)?;
        let mut carried = ways;
        for (from, to) in ways.iter().zip(&mut carried) {
            slots
                .carry(CONTEXT, entropy, &from.record, &mut to.record)
                .map_err(Error::Core)?;
        }
        self.write_ways(next, &carried, &mark)
    }

    /// Locks the profile: the ways of the passwords keep their tags, under records nothing opens,
    /// and the way in with shares is kept. Each password then reads as the profile locked; the
    /// owner's opens it only with two shares, as [`Profile::unlock_with_shares`] takes them, and
    /// one under duress set to destroy still destroys. It needs no password: `slots` of the current
    /// epoch, from its key alone, are enough. The records replaced are overwritten in the file, not
    /// erased from the storage. A lock that fails leaves the ways as they were: enter the profile
    /// only once one succeeds.
    ///
    /// # Errors
    ///
    /// [`Error::NoWayOut`] while the file's mark reads as no way in with shares set,
    /// [`Error::NoEpoch`], [`Error::Changing`] or [`Error::Unsettled`] during a change of epoch,
    /// as [`Profile::verify`] for the chip, or the core's refusal or the file system's; the ways in
    /// then stay as they were. [`Error::Unsynced`] when they changed, but a crash may undo it.
    pub fn lock(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        let _writing = self.writing();
        let (number, [own, other, shared], mark) = self.settled_ways()?;
        outside_change(slots, entropy)?;
        // A mark changed locks too.
        if self.unset(keystore, &shared, &mark)? {
            return Err(Error::NoWayOut);
        }
        let ways = [
            emptied(slots, &own, entropy)?,
            emptied(slots, &other, entropy)?,
            shared,
        ];
        self.write_ways(number, &ways, &mark)
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

    /// The owner's way in as `owner` opens it. A record a lock replaced, of the owner's way or of
    /// one under duress, reads as [`Error::Locked`].
    #[expect(
        clippy::too_many_arguments,
        reason = "a derivation's inputs, as the core takes them"
    )]
    fn owner<'a>(
        &self,
        slots: &mut Slots<'a>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        ways: &[Way; WAYS],
        mark: &Mark,
    ) -> Result<Owner<'a>, Error> {
        let (key, tags) = self.key_from_password(slots, keystore, owner, params, memory)?;
        let [own, other, shared] = ways;
        let opens = |slots: &mut Slots<'a>, way: &Way| slots.unlock(key, CONTEXT, &way.record).ok();
        let opened = if is_tag(&tags, own, Role::Owner) {
            match slots.unlock(key, CONTEXT, &own.record) {
                Ok(stored) => Ok(stored),
                Err(CoreError::RecordRejected) => {
                    // Its record lies in another place, or a lock replaced it.
                    match opens(slots, other).or_else(|| opens(slots, shared)) {
                        Some(stored) => {
                            release(slots, stored);
                            Err(Error::Damaged)
                        }
                        None => Err(Error::Locked),
                    }
                }
                Err(error) => Err(Error::Core(error)),
            }
        } else if [Role::Duress, Role::Destroy]
            .into_iter()
            .any(|role| is_tag(&tags, other, role))
        {
            // A password under duress opens nothing here, whether or not the profile is locked.
            match opens(slots, other) {
                Some(stored) => {
                    release(slots, stored);
                    Err(Error::WrongPassword)
                }
                None => Err(Error::Locked),
            }
        } else {
            Err(Error::WrongPassword)
        };
        // Without a way in with shares set, nothing locked it: the record was changed.
        let opened = match opened {
            Err(Error::Locked) => match self.unset(keystore, shared, mark) {
                Ok(true) => Err(Error::Damaged),
                Ok(false) => Err(Error::Locked),
                Err(error) => Err(error),
            },
            opened => opened,
        };
        match opened {
            Ok(stored) => Ok(Owner { stored, key, tags }),
            Err(error) => {
                release(slots, key);
                Err(error)
            }
        }
    }

    /// Checks `password` against the owner's way in, and releases what it opened. Tells whether it
    /// has a way in with shares. `slots` must not hold the stored key, which the core holds once
    /// only.
    pub(crate) fn owner_only(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        password: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<bool, Error> {
        let number = self
            .current
            .map(|current| current.number)
            .ok_or(Error::NoEpoch)?;
        let (ways, mark) = self.read_ways(number)?;
        let opened = self.owner(slots, keystore, password, params, memory, &ways, &mark)?;
        release(slots, opened.key);
        release(slots, opened.stored);
        let [_, _, shared] = &ways;
        Ok(is_tag(&opened.tags, shared, Role::Shares))
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
    fn settled_ways(&self) -> Result<(u64, [Way; WAYS], Mark), Error> {
        let number = self.settled_epoch()?;
        let (ways, mark) = self.read_ways(number)?;
        Ok((number, ways, mark))
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

    fn read_ways(&self, number: u64) -> Result<([Way; WAYS], Mark), Error> {
        // One byte more tells a longer file.
        let mut bytes = [0; FILE_LEN + 1];
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

    /// Writes the ways of epoch `number` and the mark in one step.
    fn write_ways(&self, number: u64, ways: &[Way; WAYS], mark: &Mark) -> Result<(), Error> {
        let bytes = ways_bytes(ways, mark);
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

/// The file of `ways`, in their places, and `mark`.
fn ways_bytes(ways: &[Way; WAYS], mark: &Mark) -> [u8; FILE_LEN] {
    let [own, other, shares] = ways;
    let mut bytes = [0; FILE_LEN];
    if let Some((first, rest)) = bytes.split_first_chunk_mut::<WAY_LEN>()
        && let Some((second, rest)) = rest.split_first_chunk_mut::<WAY_LEN>()
        && let Some((third, last)) = rest.split_first_chunk_mut::<WAY_LEN>()
        && let Ok(last) = <&mut Mark>::try_from(last)
    {
        *first = own.bytes();
        *second = other.bytes();
        *third = shares.bytes();
        *last = *mark;
    }
    bytes
}

/// The ways of the file `bytes`, in their places, and its mark; none for a file of another length.
fn parse_ways(bytes: &[u8]) -> Option<([Way; WAYS], Mark)> {
    let (first, rest) = bytes.split_first_chunk::<WAY_LEN>()?;
    let (second, rest) = rest.split_first_chunk::<WAY_LEN>()?;
    let (third, mark) = rest.split_first_chunk::<WAY_LEN>()?;
    Some((
        [way_of(first)?, way_of(second)?, way_of(third)?],
        mark.try_into().ok()?,
    ))
}

impl Profile {
    /// The mark of whether a way in with shares is set, for `shared` in its place.
    fn mark(&self, keystore: &mut impl Keystore, set: bool, shared: &Way) -> Result<Mark, Error> {
        self.shares_mark(keystore, set, &shared.salt, &shared.tag)
    }

    /// Whether `mark` reads as no way in with shares set, for `shared` in its place.
    fn unset(
        &self,
        keystore: &mut impl Keystore,
        shared: &Way,
        mark: &Mark,
    ) -> Result<bool, Error> {
        Ok(same_mac(mark, &self.mark(keystore, false, shared)?))
    }
}

/// `way` under a record nothing opens: its tag still tells its password, which opens nothing.
fn emptied(slots: &mut Slots<'_>, way: &Way, entropy: &mut impl Entropy) -> Result<Way, Error> {
    let fresh = unopenable(slots, entropy)?;
    Ok(Way {
        record: fresh.record,
        ..*way
    })
}

/// The way in of `stored` under the key `key` with two shares of a key made for it, whose three
/// shares it writes into `shares`. Releases `key`.
fn shared_way<'a>(
    slots: &mut Slots<'a>,
    stored: Handle<'a>,
    key: Handle<'a>,
    tags: &TagKey,
    entropy: &mut impl Entropy,
    shares: &mut Shares,
) -> Result<Way, Error> {
    let from_shares = match slots.generate_shares(entropy, shares) {
        Ok(from_shares) => from_shares,
        Err(error) => {
            release(slots, key);
            return Err(Error::Core(error));
        }
    };
    let both = slots.combine(key, from_shares).map_err(|error| {
        release(slots, key);
        release(slots, from_shares);
        Error::Core(error)
    })?;
    let way = locked_way(slots, stored, both, tags, Role::Shares, entropy);
    release(slots, both);
    way
}

/// Room for shares, wiped when dropped.
fn no_shares() -> Zeroizing<Shares> {
    Zeroizing::new([[0; SHARE_LEN]; SHARE_COUNT])
}

/// `ways` with the owner's way `own` and the other password's `other` in their places.
const fn with_passwords(ways: &[Way; WAYS], own: &Way, other: &Way) -> [Way; WAYS] {
    let [_, _, split] = ways;
    [*own, *other, *split]
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
        Role::Shares => 3,
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
    use std::thread;
    use std::time::Duration;

    use lethewis_core::{
        Error as CoreError, Handle, KeyLength, LOCK_RECORD_LEN, Position, Purpose, RECORD_LEN,
        Share, Shares, Slots,
    };
    use sha2::{Digest, Sha256};

    use zeroize::Zeroizing;

    use super::{
        FILE_LEN, MARK_LEN, ROLES, Role, SALT_LEN, TAG_KEY_LABEL, TagKey, WAY_LEN, entries_name,
        is_tag, no_shares, tag,
    };
    use crate::guard::{Action, Readings, SIGN_COUNT, Sign};
    use crate::profile::{DESTROYED, Error, Profile, WRITING};
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
        shares: Option<&mut Shares>,
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
            shares,
            &made.params,
            &mut work.memory,
            &mut Source(97),
        );
        assert!(all_free(&mut slots));
        changed
    }

    /// Makes the way of `made` with shares under `owner`, drawn from `seed`: the three shares, or
    /// the error.
    fn set_shares(
        made: &Made,
        stand: &mut Stand,
        owner: &[u8],
        seed: u64,
    ) -> Result<Shares, Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let mut shares = *no_shares();
        let set = made.profile.set_shares(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(seed),
            &mut shares,
        );
        assert!(all_free(&mut slots));
        set.map(|()| shares)
    }

    fn clear_shares(made: &Made, stand: &mut Stand, owner: &[u8]) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let cleared = made.profile.clear_shares(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(95),
        );
        assert!(all_free(&mut slots));
        cleared
    }

    /// Unlocks `made` with `owner` and the shares `first` and `second`, accepting no reading: the
    /// key of external data, or the error. Every slot is free again either way.
    fn unlock(
        made: &Made,
        stand: &mut Stand,
        owner: &[u8],
        first: &Share,
        second: &Share,
    ) -> Result<[u8; 32], Error> {
        unlock_in(made, stand, 0, owner, (first, second), &[None; SIGN_COUNT])
    }

    /// As [`unlock`], in epoch `number` and taking `readings` as accepted.
    fn unlock_in(
        made: &Made,
        stand: &mut Stand,
        number: u64,
        owner: &[u8],
        (first, second): (&Share, &Share),
        readings: &Readings<'_>,
    ) -> Result<[u8; 32], Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            number,
            &mut made.epoch_key.clone(),
        );
        let unlocked = made
            .profile
            .unlock_with_shares(
                &mut slots,
                stand,
                &mut owner.to_vec(),
                &mut first.clone(),
                &mut second.clone(),
                readings,
                &made.params,
                &mut work.memory,
                &mut Source(94),
            )
            .map(|stored| data_of(&mut slots, stored, &made.wrapped));
        assert!(all_free(&mut slots));
        unlocked
    }

    /// The readings of the signs, each another.
    const READ: Readings<'static> = [Some(b"one"), Some(b"two"), Some(b"three"), Some(b"four")];
    /// [`READ`] after a restart.
    const BOOTED: Readings<'static> = [Some(b"one"), Some(b"2"), Some(b"three"), Some(b"four")];

    /// Sets the sign of the starts of `made` to lock it, with `owner`, and accepts [`READ`].
    fn lock_on_boots(made: &Made, stand: &mut Stand, owner: &[u8]) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let mut actions = [Action::Ignore; SIGN_COUNT];
        actions[Sign::Boots.at()] = Action::Lock;
        let set = made.profile.set_guards(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            actions,
            false,
            &READ,
            &made.params,
            &mut work.memory,
            &mut Source(93),
        );
        assert!(all_free(&mut slots));
        set
    }

    fn lock(made: &Made, stand: &mut Stand) -> Result<(), Error> {
        lock_in(made, stand, 0)
    }

    fn lock_in(made: &Made, stand: &mut Stand, number: u64) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            number,
            &mut made.epoch_key.clone(),
        );
        let locked = made.profile.lock(&mut slots, stand, &mut Source(92));
        assert!(all_free(&mut slots));
        locked
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
    fn a_change_of_the_password_under_duress_keeps_the_way_of_the_shares() {
        let root = dir("kept");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let shares = |made: &Made| file(made, 0).split_off(2 * WAY_LEN);
        let before = shares(&made);
        set_duress(&made, &mut stand, OWNER, DURESS, true).unwrap();
        assert_eq!(shares(&made), before);
        clear_duress(&made, &mut stand, OWNER).unwrap();
        assert_eq!(shares(&made), before);
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
        // Four roles in each of three places, then three records.
        assert_eq!(work[0].1, 15);
    }

    #[test]
    fn a_tag_needs_the_chips_answer() {
        let root = dir("chip");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let (challenge, answer) = answer_of(&made, &stand, OWNER);
        let (_, ways, _) = made.profile.settled_ways().unwrap();
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
    fn every_change_writes_both_ways_of_the_passwords_anew() {
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
            assert_eq!(after.len(), FILE_LEN);
            // Nothing of a way of a password stays, in either place.
            for old in before.chunks(WAY_LEN).take(2).map(parts) {
                for new in after.chunks(WAY_LEN).take(2).map(parts) {
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
            let (_, ways, _) = made.profile.settled_ways().unwrap();
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
    fn any_two_shares_with_the_owners_password_open_the_profile() {
        let root = dir("shares");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let [one, two, three] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        for (first, second) in [(one, two), (two, three), (three, one), (two, one)] {
            assert_eq!(
                unlock(&made, &mut stand, OWNER, &first, &second),
                Ok(made.data)
            );
        }
        // Until the profile is locked, each password opens it alone as before.
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
    fn shares_open_nothing_without_the_owners_password() {
        let root = dir("sharesalone");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        for password in [DURESS, OTHER] {
            assert_eq!(
                unlock(&made, &mut stand, password, &one, &two),
                Err(Error::WrongPassword)
            );
        }
    }

    #[test]
    fn shares_of_a_split_made_before_open_no_more() {
        let root = dir("split");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [old, older, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        let [new, newer, _] = set_shares(&made, &mut stand, OWNER, 2).unwrap();
        assert_eq!(
            unlock(&made, &mut stand, OWNER, &old, &older),
            Err(Error::WrongPassword)
        );
        assert_eq!(
            unlock(&made, &mut stand, OWNER, &new, &older),
            Err(Error::Core(CoreError::MixedShares))
        );
        assert_eq!(
            unlock(&made, &mut stand, OWNER, &new, &new),
            Err(Error::Core(CoreError::SameShare))
        );
        assert_eq!(
            unlock(&made, &mut stand, OWNER, &new, &newer),
            Ok(made.data)
        );
    }

    #[test]
    fn cleared_shares_open_no_more() {
        let root = dir("cleared");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        assert_eq!(
            clear_shares(&made, &mut stand, OTHER),
            Err(Error::WrongPassword)
        );
        clear_shares(&made, &mut stand, OWNER).unwrap();
        assert_eq!(
            unlock(&made, &mut stand, OWNER, &one, &two),
            Err(Error::WrongPassword)
        );
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
        assert_eq!(lock(&made, &mut stand), Err(Error::NoWayOut));
    }

    #[test]
    fn a_new_password_asks_for_new_shares() {
        let root = dir("newshares");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [old, older, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        let before = file(&made, 0);
        assert_eq!(
            change(&made, &mut stand, OWNER, OTHER, None, None),
            Err(Error::SharesSet)
        );
        assert_eq!(file(&made, 0), before);
        let mut shares = *no_shares();
        change(&made, &mut stand, OWNER, OTHER, None, Some(&mut shares)).unwrap();
        let [one, _, three] = shares;
        assert_eq!(
            unlock(&made, &mut stand, OTHER, &one, &three),
            Ok(made.data)
        );
        assert_eq!(
            unlock(&made, &mut stand, OTHER, &old, &older),
            Err(Error::WrongPassword)
        );
        assert_eq!(
            unlock(&made, &mut stand, OWNER, &one, &three),
            Err(Error::WrongPassword)
        );
    }

    #[test]
    fn shares_are_written_only_where_the_ways_change() {
        let root = dir("written");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let mut shares = *no_shares();
        let refused = made.profile.set_shares(
            &mut slots,
            &mut stand,
            &mut OTHER.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(1),
            &mut shares,
        );
        assert_eq!(refused, Err(Error::WrongPassword));
        assert_eq!(shares, *no_shares());
        // A directory where the file is first written: the ways stay as they were.
        let blocked = made.profile.dir.join(entries_name(0) + WRITING);
        fs::create_dir(&blocked).unwrap();
        let unwritten = made.profile.set_shares(
            &mut slots,
            &mut stand,
            &mut OWNER.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(4),
            &mut shares,
        );
        assert!(matches!(unwritten, Err(Error::Io(_))), "{unwritten:?}");
        assert_eq!(shares, *no_shares());
        fs::remove_dir(&blocked).unwrap();
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 5).unwrap();
        fs::create_dir(&blocked).unwrap();
        let mut renewed = *no_shares();
        let changed = change(&made, &mut stand, OWNER, OTHER, None, Some(&mut renewed));
        fs::remove_dir(&blocked).unwrap();
        assert!(matches!(changed, Err(Error::Io(_))), "{changed:?}");
        assert_eq!(renewed, *no_shares());
        assert_eq!(unlock(&made, &mut stand, OWNER, &one, &two), Ok(made.data));
        fail_syncs(0, 1);
        let mut renewed = *no_shares();
        let changed = change(&made, &mut stand, OWNER, OTHER, None, Some(&mut renewed));
        fail_syncs(0, 0);
        assert!(matches!(changed, Err(Error::Unsynced(_))), "{changed:?}");
        let [first, _, third] = renewed;
        assert_eq!(
            unlock(&made, &mut stand, OTHER, &first, &third),
            Ok(made.data)
        );
        change(&made, &mut stand, OTHER, OWNER, None, Some(&mut renewed)).unwrap();
        fail_syncs(0, 1);
        let unsynced = made.profile.set_shares(
            &mut slots,
            &mut stand,
            &mut OWNER.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(2),
            &mut shares,
        );
        fail_syncs(0, 0);
        assert!(matches!(unsynced, Err(Error::Unsynced(_))), "{unsynced:?}");
        assert!(all_free(&mut slots));
        let [one, two, _] = shares;
        assert_eq!(unlock(&made, &mut stand, OWNER, &one, &two), Ok(made.data));
    }

    #[test]
    fn the_password_and_the_shares_are_wiped_once_tried() {
        let root = dir("shareswiped");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        for (password, second) in [(OTHER, two), (OWNER, one), (OWNER, two)] {
            let (mut typed, mut first, mut second) = (password.to_vec(), one, second);
            if let Ok(stored) = made.profile.unlock_with_shares(
                &mut slots,
                &mut stand,
                &mut typed,
                &mut first,
                &mut second,
                &[None; SIGN_COUNT],
                &made.params,
                &mut work.memory,
                &mut Source(3),
            ) {
                slots.release(stored).unwrap();
            }
            assert!(typed.iter().all(|&byte| byte == 0));
            assert!(first.iter().chain(&second).all(|&byte| byte == 0));
        }
    }

    #[test]
    fn a_locked_profile_opens_only_with_the_owners_password_and_two_shares() {
        let root = dir("locked");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let [one, two, three] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock_on_boots(&made, &mut stand, OWNER).unwrap();
        assert!(made.profile.judge(&mut stand, &BOOTED).unwrap().lock);
        let shared = file(&made, 0).split_off(2 * WAY_LEN);
        lock(&made, &mut stand).unwrap();
        assert_eq!(file(&made, 0).split_off(2 * WAY_LEN), shared);
        // Each password reads the same; only the owner's opens it with shares.
        for password in [OWNER, DURESS] {
            assert_eq!(enter(&made, &mut stand, password), Err(Error::Locked));
        }
        assert_eq!(enter(&made, &mut stand, OTHER), Err(Error::WrongPassword));
        for password in [DURESS, OTHER] {
            assert_eq!(
                unlock(&made, &mut stand, password, &one, &two),
                Err(Error::WrongPassword)
            );
        }
        // Unlocked, the password alone opens it again and the sign that locked it fires no more;
        // the password under duress the lock emptied is gone.
        assert_eq!(
            unlock_in(&made, &mut stand, 0, OWNER, (&three, &one), &BOOTED),
            Ok(made.data)
        );
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
        assert_eq!(enter(&made, &mut stand, DURESS), Err(Error::WrongPassword));
        assert!(!made.profile.judge(&mut stand, &BOOTED).unwrap().lock);
    }

    #[test]
    fn no_lock_is_set_or_made_without_a_way_out() {
        let root = dir("wayout");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let before = file(&made, 0);
        assert_eq!(
            lock_on_boots(&made, &mut stand, OWNER),
            Err(Error::NoWayOut)
        );
        assert_eq!(lock(&made, &mut stand), Err(Error::NoWayOut));
        // Whatever the file of the signs says.
        fs::remove_file(made.profile.dir.join(crate::guard::GUARDS)).unwrap();
        assert!(made.profile.judge(&mut stand, &READ).unwrap().lock);
        assert_eq!(lock(&made, &mut stand), Err(Error::NoWayOut));
        assert_eq!(file(&made, 0), before);
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
    }

    #[test]
    fn the_last_way_out_stays_while_a_sign_locks() {
        let root = dir("lastway");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock_on_boots(&made, &mut stand, OWNER).unwrap();
        let shared = file(&made, 0);
        assert_eq!(clear_shares(&made, &mut stand, OWNER), Err(Error::NoWayOut));
        assert_eq!(file(&made, 0), shared);
    }

    #[test]
    fn a_way_out_set_is_enough_to_lock() {
        let root = dir("lockany");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock(&made, &mut stand).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
        assert_eq!(unlock(&made, &mut stand, OWNER, &one, &two), Ok(made.data));
    }

    #[test]
    fn a_changed_file_of_signs_or_mark_locks() {
        let root = dir("changedlocks");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock_on_boots(&made, &mut stand, OWNER).unwrap();
        // The salt changed: no tag of the file reads.
        let guards = made.profile.dir.join(crate::guard::GUARDS);
        let mut bytes = fs::read(&guards).unwrap();
        bytes[0] ^= 1;
        fs::write(&guards, &bytes).unwrap();
        let verdict = made.profile.judge(&mut stand, &READ).unwrap();
        assert!(verdict.lock && verdict.damaged);
        lock(&made, &mut stand).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
        unlock(&made, &mut stand, OWNER, &one, &two).unwrap();
        // A mark that no longer reads as unset locks too.
        clear_shares(&made, &mut stand, OWNER).unwrap();
        let ways = made.profile.dir.join(entries_name(0));
        let mut bytes = fs::read(&ways).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&ways, &bytes).unwrap();
        lock(&made, &mut stand).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
    }

    #[test]
    fn a_password_under_duress_set_to_destroy_destroys_once_locked() {
        let root = dir("lockdestroy");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Destroy);
        let other = self::made(&root, &mut stand, 56).profile.id();
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock(&made, &mut stand).unwrap();
        assert_eq!(stand.deleted, Vec::<String>::new());
        assert_eq!(enter(&made, &mut stand, DURESS), Err(Error::Locked));
        let others = format!("lethewis/{other}/");
        assert!(stand.deleted.iter().any(|alias| alias.starts_with(&others)));
        assert!(root.join(other.to_string()).join(DESTROYED).exists());
    }

    #[test]
    fn the_owners_calls_read_a_locked_profile_as_locked() {
        let root = dir("lockedcalls");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        // Before the lock a password under duress opens nothing here, and after it reads as the
        // owner's.
        for (password, told) in [(DURESS, Error::WrongPassword), (OWNER, Error::Locked)] {
            if password == OWNER {
                lock(&made, &mut stand).unwrap();
            }
            for password in [password, DURESS] {
                let before = file(&made, 0);
                let expected = if password == DURESS && told == Error::Locked {
                    Error::Locked
                } else {
                    told
                };
                assert_eq!(
                    set_shares(&made, &mut stand, password, 2).err(),
                    Some(expected)
                );
                assert_eq!(clear_shares(&made, &mut stand, password), Err(expected));
                assert_eq!(
                    set_duress(&made, &mut stand, password, OTHER, false),
                    Err(expected)
                );
                let mut shares = *no_shares();
                assert_eq!(
                    change(&made, &mut stand, password, OTHER, None, Some(&mut shares)),
                    Err(expected)
                );
                assert_eq!(lock_on_boots(&made, &mut stand, password), Err(expected));
                assert_eq!(file(&made, 0), before);
            }
        }
    }

    #[test]
    fn an_unlock_tells_no_password_from_another() {
        let root = dir("unlocktells");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Destroy);
        let other = self::made(&root, &mut stand, 57).profile.id();
        let [old, older, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        set_shares(&made, &mut stand, OWNER, 2).unwrap();
        lock(&made, &mut stand).unwrap();
        // Shares of another split read alike under every password; under duress set to destroy,
        // the others are destroyed as at entry.
        for password in [OWNER, OTHER, DURESS] {
            assert_eq!(
                unlock(&made, &mut stand, password, &old, &older),
                Err(Error::WrongPassword)
            );
        }
        assert!(root.join(other.to_string()).join(DESTROYED).exists());
    }

    #[test]
    fn a_record_of_the_owner_replaced_reads_as_locked_only_with_shares() {
        let root = dir("changedrecord");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let ways = made.profile.dir.join(entries_name(0));
        // The record of the way no password opens, under the owner's tag.
        let replaced = |bytes: &[u8]| {
            let mut bytes = bytes.to_vec();
            let nobody = bytes[WAY_LEN..WAY_LEN + LOCK_RECORD_LEN].to_vec();
            bytes[..LOCK_RECORD_LEN].copy_from_slice(&nobody);
            bytes
        };
        let whole = file(&made, 0);
        fs::write(&ways, replaced(&whole)).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Damaged));
        assert_eq!(clear_shares(&made, &mut stand, OWNER), Err(Error::Damaged));
        fs::write(&ways, &whole).unwrap();
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        fs::write(&ways, replaced(&file(&made, 0))).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
    }

    #[test]
    fn a_mark_of_another_way_with_shares_locks() {
        let root = dir("oldmark");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let unset = file(&made, 0).split_off(FILE_LEN - MARK_LEN);
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        let mut current = file(&made, 0);
        current.truncate(FILE_LEN - MARK_LEN);
        current.extend_from_slice(&unset);
        fs::write(made.profile.dir.join(entries_name(0)), &current).unwrap();
        lock(&made, &mut stand).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
    }

    #[test]
    fn a_change_waits_for_another_to_write() {
        let root = dir("oneatatime");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        // Each call waits while another holds the profile's files, then writes.
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        let before = file(&made, 0);
        thread::scope(|scope| {
            let held = made.profile.writing();
            let clearing = scope.spawn(|| clear_shares(&made, &mut stand, OWNER));
            thread::sleep(Duration::from_millis(300));
            assert_eq!(file(&made, 0), before);
            drop(held);
            clearing.join().unwrap().unwrap();
        });
        set_shares(&made, &mut stand, OWNER, 2).unwrap();
        let before = file(&made, 0);
        thread::scope(|scope| {
            let held = made.profile.writing();
            let locking = scope.spawn(|| lock(&made, &mut stand));
            thread::sleep(Duration::from_millis(300));
            assert_eq!(file(&made, 0), before);
            drop(held);
            locking.join().unwrap().unwrap();
        });
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
    }

    #[test]
    fn a_way_in_out_of_its_place_reads_as_damaged() {
        let root = dir("misplaced");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        let mut bytes = file(&made, 0);
        let shared = bytes[2 * WAY_LEN..3 * WAY_LEN].to_vec();
        bytes[WAY_LEN..2 * WAY_LEN].copy_from_slice(&shared);
        fs::write(made.profile.dir.join(entries_name(0)), &bytes).unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Damaged));
    }

    #[test]
    fn the_way_with_shares_is_carried_into_the_next_epoch() {
        let root = dir("sharescarried");
        let mut stand = Stand::new();
        let mut made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
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
            slots.begin_epoch(&mut next_key.clone()).unwrap();
            made.profile
                .carry_entries(&mut slots, &mut Source(5))
                .unwrap();
            assert_eq!(
                slots.commit_epoch(&mut made.profile.roots(&mut stand)),
                Ok(lethewis_core::Erasure::BestEffort)
            );
        }
        made.epoch_key = next_key;
        lock_in(&made, &mut stand, 1).unwrap();
        // Records wrapped in the epoch before are the caller's to carry; the way in is the test.
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            1,
            &mut made.epoch_key.clone(),
        );
        let stored = made
            .profile
            .unlock_with_shares(
                &mut slots,
                &mut stand,
                &mut OWNER.to_vec(),
                &mut one.clone(),
                &mut two.clone(),
                &[None; SIGN_COUNT],
                &made.params,
                &mut work.memory,
                &mut Source(8),
            )
            .unwrap();
        slots.release(stored).unwrap();
        assert!(all_free(&mut slots));
    }

    #[test]
    fn the_calls_with_shares_wait_for_a_change_of_epoch_to_end() {
        let root = dir("sharesmidway");
        let mut stand = Stand::new();
        let mut made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        let before = file(&made, 0);
        let mut next_key = [0; 32];
        made.profile
            .next_epoch(&mut stand, false, &mut next_key)
            .unwrap();
        assert_eq!(
            set_shares(&made, &mut stand, OWNER, 2).err(),
            Some(Error::Changing)
        );
        assert_eq!(clear_shares(&made, &mut stand, OWNER), Err(Error::Changing));
        assert_eq!(
            unlock(&made, &mut stand, OWNER, &one, &two),
            Err(Error::Changing)
        );
        // The slots in a change refuse too, once the profile knows of none.
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        slots.begin_epoch(&mut next_key).unwrap();
        let id = made.profile.id();
        drop(made.profile);
        made.profile = Profile::open(&root, id).unwrap();
        made.profile.epoch(&mut stand, &mut [0; 32]).unwrap();
        let mut shares = *no_shares();
        let set = made.profile.set_shares(
            &mut slots,
            &mut stand,
            &mut OWNER.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(3),
            &mut shares,
        );
        let cleared = made.profile.clear_shares(
            &mut slots,
            &mut stand,
            &mut OWNER.to_vec(),
            &made.params,
            &mut work.memory,
            &mut Source(4),
        );
        let unlocked = made
            .profile
            .unlock_with_shares(
                &mut slots,
                &mut stand,
                &mut OWNER.to_vec(),
                &mut one.clone(),
                &mut two.clone(),
                &[None; SIGN_COUNT],
                &made.params,
                &mut work.memory,
                &mut Source(5),
            )
            .map(|stored| slots.release(stored).unwrap());
        let locked = made.profile.lock(&mut slots, &mut stand, &mut Source(6));
        assert_eq!([set, cleared, unlocked, locked], [Err(Error::Changing); 4]);
        assert_eq!(file(&made, 0), before);
        assert!(all_free(&mut slots));
    }

    #[test]
    fn each_call_keeps_the_bytes_of_the_ways_it_does_not_set() {
        let root = dir("bytes");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let place = |made: &Made, at: usize| {
            file(made, 0)
                .get(at * WAY_LEN..(at + 1) * WAY_LEN)
                .unwrap()
                .to_vec()
        };
        let passwords = [place(&made, 0), place(&made, 1)];
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        assert_eq!([place(&made, 0), place(&made, 1)], passwords);
        clear_shares(&made, &mut stand, OWNER).unwrap();
        assert_eq!([place(&made, 0), place(&made, 1)], passwords);
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Duress, made.data))
        );
        // Unlocking a profile not locked keeps the password under duress and the shares.
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 2).unwrap();
        let shared = place(&made, 2);
        unlock(&made, &mut stand, OWNER, &one, &two).unwrap();
        assert_eq!(
            [place(&made, 1), place(&made, 2)],
            [passwords[1].clone(), shared]
        );
    }

    #[test]
    fn an_unlock_that_fails_leaves_the_profile_locked() {
        let root = dir("unlockfails");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock_on_boots(&made, &mut stand, OWNER).unwrap();
        lock(&made, &mut stand).unwrap();
        // The sign watched has no reading to accept.
        assert_eq!(
            unlock_in(
                &made,
                &mut stand,
                0,
                OWNER,
                (&one, &two),
                &[None; SIGN_COUNT]
            ),
            Err(Error::Unread)
        );
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
        let blocked = made.profile.dir.join(entries_name(0) + WRITING);
        fs::create_dir(&blocked).unwrap();
        let unwritten = unlock_in(&made, &mut stand, 0, OWNER, (&one, &two), &READ);
        fs::remove_dir(&blocked).unwrap();
        assert!(matches!(unwritten, Err(Error::Io(_))), "{unwritten:?}");
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Locked));
    }

    #[test]
    fn an_unlock_whose_file_of_signs_is_not_synced_still_unlocks() {
        let root = dir("unlockunsynced");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock_on_boots(&made, &mut stand, OWNER).unwrap();
        lock(&made, &mut stand).unwrap();
        fail_syncs(0, 1);
        let unlocked = unlock_in(&made, &mut stand, 0, OWNER, (&one, &two), &BOOTED);
        fail_syncs(0, 0);
        assert!(matches!(unlocked, Err(Error::Unsynced(_))), "{unlocked:?}");
        assert_eq!(
            enter(&made, &mut stand, OWNER),
            Ok((Role::Owner, made.data))
        );
        assert!(!made.profile.judge(&mut stand, &BOOTED).unwrap().lock);
    }

    #[test]
    fn a_way_with_shares_the_password_alone_opens_reads_as_damaged() {
        let root = dir("sharesalone");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let tags = keyed(&answer_of(&made, &stand, OWNER).1);
        let (_, [own, nobody, _], mark) = made.profile.settled_ways().unwrap();
        // The owner's record, tagged as the way with shares in its place, and none in the owner's.
        let mut shared = own;
        shared.tag = tag(&tags, &shared.salt, Role::Shares);
        made.profile
            .write_ways(0, &[nobody, nobody, shared], &mark)
            .unwrap();
        assert_eq!(enter(&made, &mut stand, OWNER), Err(Error::Damaged));
    }

    #[test]
    fn a_lock_waits_for_a_change_of_epoch_to_end() {
        let root = dir("lockchanging");
        let mut stand = Stand::new();
        let mut made = copied(&root, &mut stand, Start::Plain);
        set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock_on_boots(&made, &mut stand, OWNER).unwrap();
        let before = file(&made, 0);
        made.profile
            .next_epoch(&mut stand, false, &mut [0; 32])
            .unwrap();
        assert_eq!(lock(&made, &mut stand), Err(Error::Changing));
        assert_eq!(file(&made, 0), before);
    }

    #[test]
    fn unlocking_keeps_what_reads_of_a_changed_file_of_signs() {
        let root = dir("unlockdamaged");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let [one, two, _] = set_shares(&made, &mut stand, OWNER, 1).unwrap();
        lock_on_boots(&made, &mut stand, OWNER).unwrap();
        lock(&made, &mut stand).unwrap();
        // The tag of one sign alone changed: the sign that locks still reads.
        let guards = made.profile.dir.join(crate::guard::GUARDS);
        let mut bytes = fs::read(&guards).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&guards, &bytes).unwrap();
        assert_eq!(
            unlock_in(&made, &mut stand, 0, OWNER, (&one, &two), &BOOTED),
            Ok(made.data)
        );
        let verdict = made.profile.judge(&mut stand, &BOOTED).unwrap();
        assert!(!verdict.lock && !verdict.damaged);
        assert!(made.profile.judge(&mut stand, &READ).unwrap().lock);
        // Nothing reads of a file of other bytes: nothing is watched any more.
        lock(&made, &mut stand).unwrap();
        fs::write(&guards, vec![7; bytes.len()]).unwrap();
        assert_eq!(
            unlock_in(&made, &mut stand, 0, OWNER, (&one, &two), &READ),
            Ok(made.data)
        );
        let verdict = made.profile.judge(&mut stand, &BOOTED).unwrap();
        assert!(!verdict.lock && !verdict.damaged);
        // Nor of one gone.
        lock(&made, &mut stand).unwrap();
        fs::remove_file(&guards).unwrap();
        assert_eq!(
            unlock_in(&made, &mut stand, 0, OWNER, (&one, &two), &READ),
            Ok(made.data)
        );
        assert!(!made.profile.judge(&mut stand, &BOOTED).unwrap().lock);
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
            change(&made, &mut stand, DURESS, OTHER, None, None),
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
        change(&made, &mut stand, OWNER, OTHER, Some(DURESS), None).unwrap();
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
        change(&made, &mut stand, OWNER, OTHER, Some(DURESS), None).unwrap();
        assert_eq!(
            enter(&made, &mut stand, DURESS),
            Ok((Role::Duress, made.data))
        );
        change(&made, &mut stand, OTHER, OWNER, None, None).unwrap();
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
            assert_eq!(
                change(&made, &mut stand, OWNER, new, duress, None),
                Err(refused)
            );
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
        let (first, rest) = bytes.split_at(WAY_LEN);
        let (second, rest) = rest.split_at(WAY_LEN);
        let (first, second) = (parts(first), parts(second));
        let swapped = [
            second.0, first.1, first.2, first.0, second.1, second.2, rest,
        ]
        .concat();
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
