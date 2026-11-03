// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File};
use std::io;
use std::path::Path;

use lethewis_core::{Erasure, Root, RootFailed};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::keystore::{Failure, Keystore, Level};
use crate::profile::{
    Error, Id, Profile, UNLOCKED, WRITING, fill_random, flags_of, generate, join, level_code,
    level_of, read_file, same_mac, sync_dir, unlocked_only, write_file,
};

/// The file that names the current epoch.
pub(crate) const CURRENT: &str = "current";
/// What the file of the root of an epoch is named, with its number after it.
pub(crate) const ROOT: &str = "root-";
const CURRENT_MAGIC: [u8; 4] = *b"LWc1";
pub(crate) const CURRENT_LEN: usize = 44;
const ROOT_MAGIC: [u8; 4] = *b"LWr1";
pub(crate) const ROOT_LEN: usize = 70;
const CURRENT_LABEL: &[u8; 17] = b"lethewis current ";
const ROOT_LABEL: &[u8; 14] = b"lethewis root ";
const SALT_LABEL: &[u8; 14] = b"lethewis salt ";

/// The current epoch of a profile, as [`Profile::epoch`] read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// The number of the epoch.
    pub number: u64,
    /// Where the keystore holds the key of its root.
    pub level: Level,
    /// How surely the roots of other epochs, left by an unfinished change, were erased; none if
    /// there were none and the keystore listed its keys.
    pub swept: Option<Erasure>,
}

/// The root of the next epoch, as [`Profile::next_epoch`] made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Next {
    /// The number of the epoch.
    pub number: u64,
    /// Where the keystore holds the key of its root.
    pub level: Level,
    /// Where it holds the key of the current root, which may be higher.
    pub previous: Level,
    /// How surely the roots of other epochs, left by an earlier change, were erased; none if there
    /// were none and the keystore listed its keys.
    pub swept: Option<Erasure>,
}

/// The keeper of a profile's roots for the core's `Slots::commit_epoch` and
/// `Slots::abandon_epoch`, from [`Profile::roots`].
pub struct Roots<'p, K: Keystore> {
    profile: &'p mut Profile,
    keystore: &'p mut K,
}

/// A root this process read or made: its epoch, where its key is held, and its tag.
#[derive(Clone, Copy)]
pub(crate) struct Known {
    pub(crate) number: u64,
    pub(crate) level: Level,
    pub(crate) tag: [u8; 32],
}

/// A file not written, before its name was taken or after: then the old or the new may outlast a
/// crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written {
    Before(io::ErrorKind),
    After(io::ErrorKind),
}

impl Written {
    pub(crate) const fn error(self) -> Error {
        match self {
            Self::Before(kind) | Self::After(kind) => Error::Io(kind),
        }
    }
}

/// What the file of a root holds.
#[derive(PartialEq, Eq)]
pub(crate) struct RootRecord {
    pub(crate) level: Level,
    pub(crate) unlocked: bool,
    /// The random bytes the key of the epoch is derived from, with the chip's answer as the salt.
    pub(crate) stored: [u8; 32],
    /// The chip's answer to the identifier, the number, the level, the flags and a digest of the
    /// random bytes.
    pub(crate) tag: [u8; 32],
}

impl Drop for RootRecord {
    fn drop(&mut self) {
        #[cfg(not(kani))]
        self.stored.zeroize();
        // zeroize ends in inline assembly, which Kani cannot model.
        #[cfg(kani)]
        {
            self.stored = [0; 32];
        }
    }
}

impl Profile {
    /// Reads the current epoch and writes its key into `key`, for the core's `Slots::new`. Once the
    /// pointer to it is synced, erases the roots of other epochs, which an unfinished change left.
    ///
    /// # Errors
    ///
    /// [`Error::Changing`] while a root [`Profile::next_epoch`] made is neither switched to nor
    /// erased, unless the switch left the profile unsettled. As [`Profile::verify`],
    /// [`Error::Damaged`] for a pointer or a root not as written, the keystore's failure,
    /// [`Failure::Absent`] for a root's key that is gone, or the file system's. Nothing is erased
    /// then.
    pub fn epoch(
        &mut self,
        keystore: &mut impl Keystore,
        key: &mut [u8; 32],
    ) -> Result<Opened, Error> {
        if self.next.is_some() && !self.unsettled {
            return Err(Error::Changing);
        }
        self.verify(keystore)?;
        let (number, pointer) = read_pointer(&self.dir)?;
        let mut record = read_root(&self.dir, number)?;
        let mut answer = [0; 32];
        keystore
            .mac(
                &self.alias,
                &current_input(self.id, number, &record.tag),
                &mut answer,
            )
            .map_err(Error::Keystore)?;
        if !same_mac(&answer, &pointer) {
            return Err(Error::Damaged);
        }
        // A pointer read from memory may not have reached the disk, and roots are erased by it.
        File::open(self.dir.join(CURRENT))
            .and_then(|file| file.sync_all())
            .and_then(|()| sync_dir(&self.dir))?;
        open_root(self.id, number, &mut record, keystore, key)?;
        let current = Known {
            number,
            level: record.level,
            tag: record.tag,
        };
        // An unsettled switch is settled now: the root it did not reach is left to erase, and one
        // it reached is switched to when asked again. Both stay while the same epoch is read.
        if self.unsettled {
            self.settled = self
                .next
                .map(|next| next.number)
                .filter(|&next| next == number);
            self.previous = [self.current, self.next]
                .into_iter()
                .flatten()
                .find(|root| root.number != number);
        } else if self.current.map(|root| root.number) != Some(number) {
            self.settled = None;
            self.previous = None;
        }
        self.current = Some(current);
        self.next = None;
        self.unsettled = false;
        Ok(Opened {
            number,
            level: current.level,
            swept: sweep_roots(&self.dir, self.id, number, keystore),
        })
    }

    /// Makes the root of the next epoch and writes its key into `key`, for the core's
    /// `Slots::begin_epoch`. Roots of other epochs, left by an earlier change, are erased first.
    /// Its key goes where [`Profile::create`] puts keys, and may be lower than the current one.
    ///
    /// # Errors
    ///
    /// [`Error::NoEpoch`] before [`Profile::epoch`], [`Error::Changing`] while a root made before
    /// is neither switched to nor erased, [`Error::Unsettled`], [`Error::Exhausted`],
    /// [`Error::SoftwareOnly`], the keystore's failure, also to delete a key left under the next
    /// root's name, or the file system's.
    pub fn next_epoch(
        &mut self,
        keystore: &mut impl Keystore,
        software: bool,
        key: &mut [u8; 32],
    ) -> Result<Next, Error> {
        if self.unsettled {
            return Err(Error::Unsettled);
        }
        if self.next.is_some() {
            return Err(Error::Changing);
        }
        let current = self.current.ok_or(Error::NoEpoch)?;
        let number = current.number.checked_add(1).ok_or(Error::Exhausted)?;
        let swept = sweep_roots(&self.dir, self.id, current.number, keystore);
        // The keystore replaces a key under a name taken, and a listing that failed may hide one.
        keystore
            .delete(&root_alias(self.id, number))
            .map_err(Error::Keystore)?;
        self.settled = None;
        self.previous = None;
        let made = make_root(&self.dir, self.id, number, keystore, software)?;
        let opened = read_root(&self.dir, number)
            .and_then(|mut record| open_root(self.id, number, &mut record, keystore, key));
        if let Err(error) = opened {
            let _ = erase_root(&self.dir, self.id, number, Some(made.level), keystore);
            return Err(error);
        }
        self.next = Some(made);
        Ok(Next {
            number,
            level: made.level,
            previous: current.level,
            swept,
        })
    }

    /// The keeper of the roots, for the core's `Slots::commit_epoch` and `Slots::abandon_epoch`.
    pub fn roots<'p, K: Keystore>(&'p mut self, keystore: &'p mut K) -> Roots<'p, K> {
        Roots {
            profile: self,
            keystore,
        }
    }

    /// Whether a switch of epoch failed after the new pointer was written and the old one could
    /// not be written back. Either may be current then: keep the records of both epochs until
    /// [`Profile::epoch`] tells which is. Then commit the change again if it is the next, or
    /// abandon it.
    #[must_use]
    pub const fn unsettled(&self) -> bool {
        self.unsettled
    }
}

impl<K: Keystore> Root for Roots<'_, K> {
    fn switch(&mut self, next: u64) -> Result<(), RootFailed> {
        let profile = &mut *self.profile;
        if profile
            .settled
            .take_if(|settled| *settled == next)
            .is_some()
        {
            return Ok(());
        }
        let (Some(current), Some(prepared)) = (profile.current, profile.next) else {
            return Err(RootFailed);
        };
        if profile.unsettled || prepared.number != next {
            return Err(RootFailed);
        }
        // The old pointer is made before the new one is written, so that writing it back needs no
        // chip.
        let (Ok(new), Ok(old)) = (
            current_tag(profile.id, &profile.alias, &prepared, self.keystore),
            current_tag(profile.id, &profile.alias, &current, self.keystore),
        ) else {
            return Err(RootFailed);
        };
        match write_file(&profile.dir, CURRENT, &current_bytes(next, &new)) {
            Ok(()) => {
                profile.previous = Some(current);
                profile.current = Some(prepared);
                profile.next = None;
                Ok(())
            }
            Err(Written::Before(_)) => Err(RootFailed),
            Err(Written::After(_)) => {
                let back = write_file(&profile.dir, CURRENT, &current_bytes(current.number, &old));
                profile.unsettled = back.is_err();
                Err(RootFailed)
            }
        }
    }

    fn erase(&mut self, epoch: u64) -> Erasure {
        let profile = &mut *self.profile;
        let Some(current) = profile.current else {
            return Erasure::NotErased;
        };
        if profile.unsettled || current.number == epoch {
            return Erasure::NotErased;
        }
        let mut known = None;
        for slot in [&mut profile.next, &mut profile.previous] {
            if let Some(root) = slot.take_if(|root| root.number == epoch) {
                known = Some(root.level);
            }
        }
        erase_root(&profile.dir, profile.id, epoch, known, self.keystore).0
    }
}

/// The name of the key of the root of epoch `number` of the profile `id`.
pub(crate) fn root_alias(id: Id, number: u64) -> String {
    format!("{}{number}", root_prefix(id))
}

fn root_prefix(id: Id) -> String {
    format!("lethewis/{id}/root/")
}

fn root_name(number: u64) -> String {
    format!("{ROOT}{number}")
}

/// The number a name of a root's file or key ends in, written as this library writes it.
pub(crate) fn number_of(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || digits.len() > 20 || (digits.len() > 1 && digits.first() == Some(&b'0'))
    {
        return None;
    }
    digits.iter().try_fold(0_u64, |number, &digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        number
            .checked_mul(10)?
            .checked_add(u64::from(digit.wrapping_sub(b'0')))
    })
}

/// Makes the root of epoch `number`: its key, then its file. A key made before a failure is
/// deleted.
pub(crate) fn make_root(
    dir: &Path,
    id: Id,
    number: u64,
    keystore: &mut impl Keystore,
    software: bool,
) -> Result<Known, Error> {
    let alias = root_alias(id, number);
    let unlocked = unlocked_only(keystore);
    let made = generate(keystore, &alias, unlocked, software).and_then(|level| {
        let mut record = RootRecord {
            level,
            unlocked,
            stored: [0; 32],
            tag: [0; 32],
        };
        fill_random(&mut record.stored)?;
        let mut input = tag_input(id, number, &record);
        let tagged = keystore
            .mac(&alias, &input, &mut record.tag)
            .map_err(Error::Keystore);
        input.zeroize();
        tagged?;
        let mut bytes = record.bytes();
        let written = write_file(dir, &root_name(number), &bytes).map_err(Written::error);
        bytes.zeroize();
        written.map(|()| Known {
            number,
            level,
            tag: record.tag,
        })
    });
    if made.is_err() {
        let _ = keystore.delete(&alias);
    }
    made
}

/// Checks the root of epoch `number` against its key, and writes the key of the epoch into `key`.
fn open_root(
    id: Id,
    number: u64,
    record: &mut RootRecord,
    keystore: &mut impl Keystore,
    key: &mut [u8; 32],
) -> Result<(), Error> {
    let alias = root_alias(id, number);
    let mut input = tag_input(id, number, record);
    let mut tag = [0; 32];
    let tagged = keystore.mac(&alias, &input, &mut tag);
    input.zeroize();
    tagged.map_err(Error::Keystore)?;
    if !same_mac(&tag, &record.tag) {
        return Err(Error::Damaged);
    }
    let mut answer = [0; 32];
    keystore
        .mac(&alias, &salt_input(id, number), &mut answer)
        .map_err(Error::Keystore)?;
    // Wipes both inputs; the only failure is an output too long, which 32 bytes never are.
    lethewis_core::epoch_key(&mut record.stored, &mut answer, key).map_err(|_| Error::Damaged)
}

fn read_root(dir: &Path, number: u64) -> Result<RootRecord, Error> {
    let mut bytes = [0; ROOT_LEN + 1];
    let read = read_file(&dir.join(root_name(number)), &mut bytes)
        .map_err(|error| missing_is_damaged(&error));
    let record = read.and_then(|read| {
        bytes
            .get(..read)
            .and_then(RootRecord::parse)
            .ok_or(Error::Damaged)
    });
    bytes.zeroize();
    record
}

fn missing_is_damaged(error: &io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::NotFound => Error::Damaged,
        kind => Error::Io(kind),
    }
}

/// The number of the current epoch and the tag of the pointer to it, as read.
fn read_pointer(dir: &Path) -> Result<(u64, [u8; 32]), Error> {
    let mut bytes = [0; CURRENT_LEN + 1];
    let read =
        read_file(&dir.join(CURRENT), &mut bytes).map_err(|error| missing_is_damaged(&error))?;
    bytes
        .get(..read)
        .and_then(parse_current)
        .ok_or(Error::Damaged)
}

/// The chip's answer that binds the pointer to the root `root` to the chip's key `alias`.
pub(crate) fn current_tag(
    id: Id,
    alias: &str,
    root: &Known,
    keystore: &mut impl Keystore,
) -> Result<[u8; 32], Error> {
    let mut tag = [0; 32];
    keystore
        .mac(alias, &current_input(id, root.number, &root.tag), &mut tag)
        .map_err(Error::Keystore)?;
    Ok(tag)
}

/// The pointer to `root` as the file holds it.
pub(crate) fn pointer_to(
    id: Id,
    alias: &str,
    root: &Known,
    keystore: &mut impl Keystore,
) -> Result<[u8; CURRENT_LEN], Error> {
    let tag = current_tag(id, alias, root, keystore)?;
    Ok(current_bytes(root.number, &tag))
}

pub(crate) fn current_bytes(number: u64, tag: &[u8; 32]) -> [u8; CURRENT_LEN] {
    let mut bytes = [0; CURRENT_LEN];
    if let Some((magic, rest)) = bytes.split_first_chunk_mut::<4>()
        && let Some((written, rest)) = rest.split_first_chunk_mut::<8>()
        && let Ok(to) = <&mut [u8; 32]>::try_from(rest)
    {
        *magic = CURRENT_MAGIC;
        *written = number.to_le_bytes();
        *to = *tag;
    }
    bytes
}

pub(crate) fn parse_current(bytes: &[u8]) -> Option<(u64, [u8; 32])> {
    let (magic, rest) = bytes.split_first_chunk::<4>()?;
    let (number, tag) = rest.split_first_chunk::<8>()?;
    let tag = <[u8; 32]>::try_from(tag).ok()?;
    (*magic == CURRENT_MAGIC).then_some((u64::from_le_bytes(*number), tag))
}

fn current_input(id: Id, number: u64, root: &[u8; 32]) -> [u8; 73] {
    let mut input = [0; 73];
    join(
        &[CURRENT_LABEL.as_slice(), &id.0, &number.to_le_bytes(), root],
        &mut input,
    );
    input
}

/// The input the tag of a root answers: a digest stands for the random bytes, which stay out of
/// the keystore.
fn tag_input(id: Id, number: u64, record: &RootRecord) -> [u8; 72] {
    let mut digest: [u8; 32] = Sha256::digest(record.stored.as_slice()).into();
    let mut input = [0; 72];
    join(
        &[
            ROOT_LABEL.as_slice(),
            &id.0,
            &number.to_le_bytes(),
            &[level_code(record.level), flags_of(record.unlocked)],
            &digest,
        ],
        &mut input,
    );
    digest.zeroize();
    input
}

fn salt_input(id: Id, number: u64) -> [u8; 38] {
    let mut input = [0; 38];
    join(
        &[SALT_LABEL.as_slice(), &id.0, &number.to_le_bytes()],
        &mut input,
    );
    input
}

impl RootRecord {
    pub(crate) fn bytes(&self) -> [u8; ROOT_LEN] {
        let [m0, m1, m2, m3] = ROOT_MAGIC;
        let mut bytes = [0; ROOT_LEN];
        if let Some((head, rest)) = bytes.split_first_chunk_mut::<6>()
            && let Some((stored, tag)) = rest.split_first_chunk_mut::<32>()
            && let Ok(tag) = <&mut [u8; 32]>::try_from(tag)
        {
            *head = [
                m0,
                m1,
                m2,
                m3,
                level_code(self.level),
                flags_of(self.unlocked),
            ];
            *stored = self.stored;
            *tag = self.tag;
        }
        bytes
    }

    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let (magic, rest) = bytes.split_first_chunk::<4>()?;
        let (&[level, flags], rest) = rest.split_first_chunk::<2>()?;
        let (stored, tag) = rest.split_first_chunk::<32>()?;
        let tag = <[u8; 32]>::try_from(tag).ok()?;
        if *magic != ROOT_MAGIC || flags & !UNLOCKED != 0 {
            return None;
        }
        Some(Self {
            level: level_of(level)?,
            unlocked: flags == UNLOCKED,
            stored: *stored,
            tag,
        })
    }
}

/// The worse of two erasures.
pub(crate) const fn worse(a: Erasure, b: Erasure) -> Erasure {
    match (a, b) {
        (Erasure::NotErased, _) | (_, Erasure::NotErased) => Erasure::NotErased,
        (Erasure::BestEffort, _) | (_, Erasure::BestEffort) => Erasure::BestEffort,
        (Erasure::Guaranteed, Erasure::Guaranteed) => Erasure::Guaranteed,
    }
}

/// Erases the root of epoch `number`: its key, then its file, which stays while the key does.
/// `known` is where its key is held, if known; otherwise the file tells, checked against the key.
/// Returns how surely it is gone, and the keystore's failure to delete the key.
pub(crate) fn erase_root(
    dir: &Path,
    id: Id,
    number: u64,
    known: Option<Level>,
    keystore: &mut impl Keystore,
) -> (Erasure, Option<Failure>) {
    let level = known.or_else(|| checked_level(dir, id, number, keystore));
    if let Err(failure) = keystore.delete(&root_alias(id, number)) {
        return (Erasure::NotErased, Some(failure));
    }
    if fs::remove_file(dir.join(root_name(number))).is_ok() {
        let _ = sync_dir(dir);
    }
    let erasure = match level {
        Some(level) if level.secure() => Erasure::BestEffort,
        _ => Erasure::NotErased,
    };
    (erasure, None)
}

/// Where the key of a root is held, as its file says and its key confirms.
fn checked_level(dir: &Path, id: Id, number: u64, keystore: &mut impl Keystore) -> Option<Level> {
    let record = read_root(dir, number).ok()?;
    let mut input = tag_input(id, number, &record);
    let mut tag = [0; 32];
    let tagged = keystore.mac(&root_alias(id, number), &input, &mut tag);
    input.zeroize();
    tagged.ok()?;
    same_mac(&tag, &record.tag).then_some(record.level)
}

/// The numbers of the roots of the profile `id` that a file or a key is left for, and the
/// keystore's failure to list its keys: a listing it cut short only leaves some out.
pub(crate) fn root_numbers(
    dir: &Path,
    id: Id,
    keystore: &mut impl Keystore,
) -> (Vec<u64>, Option<Failure>) {
    let mut numbers: Vec<u64> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            number_of(name.strip_prefix(ROOT)?.as_bytes())
        })
        .collect();
    let prefix = root_prefix(id);
    let listed = keystore.aliases(&prefix);
    for alias in listed.as_deref().unwrap_or_default() {
        if let Some(number) = alias
            .strip_prefix(&prefix)
            .and_then(|digits| number_of(digits.as_bytes()))
        {
            numbers.push(number);
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    (numbers, listed.err())
}

/// Erases every root but that of epoch `current`, and files left half written. Returns how surely
/// the roots are gone, if there were any or the keystore could not list them.
fn sweep_roots(dir: &Path, id: Id, current: u64, keystore: &mut impl Keystore) -> Option<Erasure> {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(WRITING))
        {
            let _ = fs::remove_file(entry.path());
        }
    }
    let (numbers, listing) = root_numbers(dir, id, keystore);
    let mut erasure = listing.map(|_| Erasure::NotErased);
    for number in numbers.into_iter().filter(|&number| number != current) {
        let gone = erase_root(dir, id, number, None, keystore).0;
        erasure = Some(erasure.map_or(gone, |so_far| worse(so_far, gone)));
    }
    erasure
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use lethewis_core::{Erasure, Root, RootFailed, epoch_key};

    use super::{CURRENT, ROOT, number_of, root_alias, root_name};
    use crate::keystore::{Failure, Level};
    use crate::profile::{Error, Id, Profile};
    use crate::stand::{Stand, dir, entries, fail_syncs, hmac};

    fn created(root: &Path, stand: &mut Stand) -> Id {
        Profile::create(root, stand, true).unwrap().id()
    }

    fn opened(root: &Path, id: Id, stand: &mut Stand) -> (Profile, [u8; 32]) {
        let mut profile = Profile::open(root, id).unwrap();
        let mut key = [0; 32];
        profile.epoch(stand, &mut key).unwrap();
        (profile, key)
    }

    fn home(root: &Path, id: Id) -> PathBuf {
        root.join(id.to_string())
    }

    /// The key of epoch `number` as the core derives it from the root's file and key.
    fn expected(root: &Path, id: Id, number: u64, stand: &Stand) -> [u8; 32] {
        let bytes = fs::read(home(root, id).join(format!("root-{number}"))).unwrap();
        let mut stored: [u8; 32] = bytes[6..38].try_into().unwrap();
        let salt = [b"lethewis salt ".as_slice(), &id.0, &number.to_le_bytes()].concat();
        let mut answer = hmac(&stand.keys[&root_alias(id, number)], &salt);
        let mut key = [0; 32];
        epoch_key(&mut stored, &mut answer, &mut key).unwrap();
        key
    }

    #[test]
    fn the_first_epoch_opens_with_the_key_of_its_root() {
        let root = dir("first");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let mut profile = Profile::open(&root, id).unwrap();
        let mut key = [0; 32];
        let current = profile.epoch(&mut stand, &mut key).unwrap();
        assert_eq!(current.number, 0);
        assert_eq!(current.level, Level::StrongBox);
        assert_eq!(current.swept, None);
        assert_eq!(key, expected(&root, id, 0, &stand));
        let file = fs::read(home(&root, id).join("root-0")).unwrap();
        let tag = hmac(
            &stand.keys[&format!("lethewis/{id}/chip")],
            &[b"lethewis current ".as_slice(), &id.0, &[0; 8], &file[38..]].concat(),
        );
        let pointer = fs::read(home(&root, id).join(CURRENT)).unwrap();
        assert_eq!(pointer, [b"LWc1".as_slice(), &[0; 8], &tag].concat());
    }

    #[test]
    fn a_change_moves_the_pointer_and_erases_the_old_root() {
        let root = dir("change");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, first) = opened(&root, id, &mut stand);
        let mut second = [0; 32];
        let next = profile.next_epoch(&mut stand, false, &mut second).unwrap();
        assert_eq!((next.number, next.swept), (1, None));
        assert_eq!(
            (next.level, next.previous),
            (Level::StrongBox, Level::StrongBox)
        );
        assert_ne!(second, first);
        assert_eq!(second, expected(&root, id, 1, &stand));
        let mut roots = profile.roots(&mut stand);
        assert_eq!(roots.switch(1), Ok(()));
        assert_eq!(roots.erase(0), Erasure::BestEffort);
        assert!(!stand.keys.contains_key(&root_alias(id, 0)));
        assert!(!home(&root, id).join("root-0").exists());
        drop(profile);
        let (mut profile, key) = opened(&root, id, &mut stand);
        assert_eq!(key, second);
        let mut current = [0; 32];
        assert_eq!(profile.epoch(&mut stand, &mut current).unwrap().number, 1);
    }

    #[test]
    fn the_old_root_is_erased_as_held_on_a_locked_device_too() {
        let root = dir("locked");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        profile.roots(&mut stand).switch(1).unwrap();
        stand.refuse_mac = Some((0, Failure::Locked));
        assert_eq!(profile.roots(&mut stand).erase(0), Erasure::BestEffort);
        assert!(!stand.keys.contains_key(&root_alias(id, 0)));
    }

    #[test]
    fn an_abandoned_change_erases_the_root_it_made() {
        let root = dir("abandon");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, first) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        assert_eq!(profile.roots(&mut stand).erase(1), Erasure::BestEffort);
        assert!(!stand.keys.contains_key(&root_alias(id, 1)));
        assert_eq!(profile.roots(&mut stand).switch(1), Err(RootFailed));
        drop(profile);
        assert_eq!(opened(&root, id, &mut stand).1, first);
    }

    #[test]
    fn the_current_root_is_never_erased() {
        let root = dir("current");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let mut unread = Profile::open(&root, id).unwrap();
        assert_eq!(unread.roots(&mut stand).erase(0), Erasure::NotErased);
        drop(unread);
        let (mut profile, first) = opened(&root, id, &mut stand);
        assert_eq!(profile.roots(&mut stand).erase(0), Erasure::NotErased);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        profile.roots(&mut stand).switch(1).unwrap();
        assert_eq!(profile.roots(&mut stand).erase(1), Erasure::NotErased);
        assert!(stand.keys.contains_key(&root_alias(id, 1)));
        drop(profile);
        assert_ne!(opened(&root, id, &mut stand).1, first);
    }

    #[test]
    fn the_epoch_is_not_read_again_during_a_change() {
        let root = dir("during");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, first) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        let read = profile.epoch(&mut stand, &mut [0; 32]);
        assert_eq!(read.unwrap_err(), Error::Changing);
        assert!(stand.keys.contains_key(&root_alias(id, 1)));
        assert_eq!(profile.roots(&mut stand).erase(1), Erasure::BestEffort);
        let mut key = [0; 32];
        assert_eq!(profile.epoch(&mut stand, &mut key).unwrap().number, 0);
        assert_eq!(key, first);
    }

    #[test]
    fn roots_an_earlier_change_left_are_erased_before_the_next() {
        let root = dir("earlier");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        profile.roots(&mut stand).switch(1).unwrap();
        stand.refuse_delete = Some(Failure::Transient);
        assert_eq!(profile.roots(&mut stand).erase(0), Erasure::NotErased);
        stand.refuse_delete = None;
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        assert_eq!((next.number, next.swept), (2, Some(Erasure::BestEffort)));
        assert!(!stand.keys.contains_key(&root_alias(id, 0)));
        assert!(!home(&root, id).join("root-0").exists());
    }

    #[test]
    fn only_the_root_made_next_is_switched_to() {
        let root = dir("switch");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        assert_eq!(profile.roots(&mut stand).switch(1), Err(RootFailed));
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        for wrong in [0, 2, u64::MAX] {
            assert_eq!(profile.roots(&mut stand).switch(wrong), Err(RootFailed));
        }
        assert_eq!(profile.roots(&mut stand).switch(1), Ok(()));
    }

    #[test]
    fn a_change_is_made_once_and_only_after_the_epoch_is_read() {
        let root = dir("once");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let mut profile = Profile::open(&root, id).unwrap();
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(next.unwrap_err(), Error::NoEpoch);
        assert_eq!(profile.roots(&mut stand).switch(1), Err(RootFailed));
        profile.epoch(&mut stand, &mut [0; 32]).unwrap();
        let mut first = [0; 32];
        profile.next_epoch(&mut stand, false, &mut first).unwrap();
        let again = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(again.unwrap_err(), Error::Changing);
        assert_eq!(first, expected(&root, id, 1, &stand));
        profile.current.as_mut().unwrap().number = u64::MAX;
        profile.next = None;
        let last = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(last.unwrap_err(), Error::Exhausted);
    }

    #[test]
    fn a_switch_that_cannot_write_keeps_the_old_pointer() {
        let root = dir("unwritten");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, first) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        let home = home(&root, id);
        fs::set_permissions(&home, fs::Permissions::from_mode(0o500)).unwrap();
        let switched = profile.roots(&mut stand).switch(1);
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(switched, Err(RootFailed));
        assert!(!profile.unsettled());
        drop(profile);
        assert_eq!(opened(&root, id, &mut stand).1, first);
    }

    #[test]
    fn a_switch_written_back_after_a_failed_sync_keeps_the_old_epoch() {
        let root = dir("written-back");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, first) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        fail_syncs(0, 1);
        assert_eq!(profile.roots(&mut stand).switch(1), Err(RootFailed));
        assert!(!profile.unsettled());
        assert_eq!(profile.roots(&mut stand).erase(1), Erasure::BestEffort);
        drop(profile);
        assert_eq!(opened(&root, id, &mut stand).1, first);
    }

    #[test]
    fn a_switch_that_cannot_sync_and_cannot_write_back_is_unsettled() {
        let root = dir("unsettled");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, first) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        fail_syncs(0, 2);
        assert_eq!(profile.roots(&mut stand).switch(1), Err(RootFailed));
        assert!(profile.unsettled());
        assert_eq!(profile.roots(&mut stand).switch(1), Err(RootFailed));
        assert_eq!(profile.roots(&mut stand).erase(1), Erasure::NotErased);
        assert_eq!(profile.roots(&mut stand).erase(0), Erasure::NotErased);
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(next.unwrap_err(), Error::Unsettled);
        assert!(stand.keys.contains_key(&root_alias(id, 0)));
        assert!(stand.keys.contains_key(&root_alias(id, 1)));
        fail_syncs(0, 1);
        let read = profile.epoch(&mut stand, &mut [0; 32]);
        assert_eq!(read.unwrap_err(), Error::Io(io::ErrorKind::Other));
        assert!(profile.unsettled());
        // The old pointer was written back last, though not synced.
        let mut key = [0; 32];
        let current = profile.epoch(&mut stand, &mut key).unwrap();
        assert_eq!((current.number, key), (0, first));
        assert!(!profile.unsettled());
        // Read again, the root it did not reach is still known.
        assert_eq!(profile.epoch(&mut stand, &mut key).unwrap().number, 0);
        let mut roots = profile.roots(&mut stand);
        assert_eq!(roots.switch(1), Err(RootFailed));
        assert_eq!(roots.erase(1), Erasure::BestEffort);
    }

    #[test]
    fn a_switch_found_done_on_reading_the_epoch_completes_when_asked_again() {
        let root = dir("settled");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        let mut second = [0; 32];
        profile.next_epoch(&mut stand, false, &mut second).unwrap();
        let (old, prepared) = (profile.current, profile.next);
        profile.roots(&mut stand).switch(1).unwrap();
        // As if the old pointer had failed to be written back over the new one.
        (profile.current, profile.next, profile.previous) = (old, prepared, None);
        profile.unsettled = true;
        let mut key = [0; 32];
        assert_eq!(profile.epoch(&mut stand, &mut key).unwrap().number, 1);
        assert_eq!(key, second);
        // Read again, it is still found done.
        assert_eq!(profile.epoch(&mut stand, &mut key).unwrap().number, 1);
        let mut roots = profile.roots(&mut stand);
        assert_eq!(roots.switch(1), Ok(()));
        assert_eq!(roots.switch(1), Err(RootFailed));
        assert_eq!(roots.erase(0), Erasure::BestEffort);
    }

    #[test]
    fn a_change_begun_after_a_settled_switch_forgets_it() {
        let root = dir("forgets");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        let (old, prepared) = (profile.current, profile.next);
        profile.roots(&mut stand).switch(1).unwrap();
        (profile.current, profile.next, profile.previous) = (old, prepared, None);
        profile.unsettled = true;
        profile.epoch(&mut stand, &mut [0; 32]).unwrap();
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        assert_eq!(next.number, 2);
        let mut roots = profile.roots(&mut stand);
        assert_eq!(roots.switch(1), Err(RootFailed));
        assert_eq!(roots.switch(2), Ok(()));
    }

    #[test]
    fn a_root_an_unsettled_switch_did_not_reach_is_not_taken_for_a_new_one() {
        let root = dir("stale");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        fail_syncs(0, 2);
        assert_eq!(profile.roots(&mut stand).switch(1), Err(RootFailed));
        assert_eq!(profile.epoch(&mut stand, &mut [0; 32]).unwrap().number, 0);
        (stand.strong_box, stand.level) = (false, Level::Software);
        let next = profile.next_epoch(&mut stand, true, &mut [0; 32]).unwrap();
        assert_eq!((next.number, next.level), (1, Level::Software));
        assert_eq!(profile.roots(&mut stand).erase(1), Erasure::NotErased);
    }

    #[test]
    fn a_key_under_the_next_name_goes_though_the_listing_fails() {
        let root = dir("hidden");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        stand.keys.insert(root_alias(id, 1), [9; 32]);
        stand.refuse_aliases = Some(Failure::Transient);
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        assert_eq!(next.swept, Some(Erasure::NotErased));
        assert_eq!(stand.deleted, [root_alias(id, 1)]);
    }

    #[test]
    fn nothing_is_erased_by_a_pointer_that_cannot_be_synced() {
        let root = dir("unsynced");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        drop(profile);
        let home = home(&root, id);
        let mut profile = Profile::open(&root, id).unwrap();
        let mut key = [0; 32];
        fail_syncs(0, 1);
        let read = profile.epoch(&mut stand, &mut key);
        assert_eq!(read.unwrap_err(), Error::Io(io::ErrorKind::Other));
        assert_eq!(key, [0; 32]);
        assert!(stand.keys.contains_key(&root_alias(id, 1)));
        assert!(home.join("root-1").exists());
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(next.unwrap_err(), Error::NoEpoch);
    }

    #[test]
    fn what_an_unfinished_change_left_is_erased_at_the_next_reading() {
        let root = dir("left");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, first) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        drop(profile);
        let home = home(&root, id);
        stand.keys.insert(root_alias(id, 7), [7; 32]);
        fs::write(home.join("root-9"), b"not a root").unwrap();
        fs::write(home.join("current.new"), b"half").unwrap();
        let mut profile = Profile::open(&root, id).unwrap();
        let mut key = [0; 32];
        let current = profile.epoch(&mut stand, &mut key).unwrap();
        assert_eq!((current.number, key), (0, first));
        // The roots of 7 and 9 have a key or a file alone, so their level is not known.
        assert_eq!(current.swept, Some(Erasure::NotErased));
        assert_eq!(entries(&home), ["current", "lock", "profile", "root-0"]);
        assert_eq!(
            stand.names(),
            [format!("lethewis/{id}/chip"), root_alias(id, 0)]
        );
    }

    #[test]
    fn a_listing_that_fails_still_lets_the_files_be_erased() {
        let root = dir("listing");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        drop(profile);
        stand.refuse_aliases = Some(Failure::Transient);
        let mut profile = Profile::open(&root, id).unwrap();
        let current = profile.epoch(&mut stand, &mut [0; 32]).unwrap();
        // A key with no file may be left unlisted.
        assert_eq!(current.swept, Some(Erasure::NotErased));
        assert!(!stand.keys.contains_key(&root_alias(id, 1)));
    }

    #[test]
    fn a_pointer_or_a_root_not_as_written_is_damaged_and_erases_nothing() {
        let root = dir("damaged");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        drop(profile);
        let home = home(&root, id);
        let read = |stand: &mut Stand| {
            let mut profile = Profile::open(&root, id).unwrap();
            profile.epoch(stand, &mut [0; 32]).map(|_| ())
        };
        let pointer = fs::read(home.join(CURRENT)).unwrap();
        let first = fs::read(home.join("root-0")).unwrap();
        // The number, the tag of the pointer; the level, a random byte and the tag of the root.
        for (file, at) in [
            (CURRENT, 4),
            (CURRENT, 43),
            ("root-0", 4),
            ("root-0", 6),
            ("root-0", 69),
        ] {
            let mut bytes = fs::read(home.join(file)).unwrap();
            bytes[at] ^= 1;
            fs::write(home.join(file), &bytes).unwrap();
            assert_eq!(read(&mut stand), Err(Error::Damaged), "{file} {at}");
            fs::write(home.join(CURRENT), &pointer).unwrap();
            fs::write(home.join("root-0"), &first).unwrap();
        }
        fs::remove_file(home.join("root-0")).unwrap();
        assert_eq!(read(&mut stand), Err(Error::Damaged));
        fs::write(home.join("root-0"), &first).unwrap();
        let key = stand.keys.remove(&root_alias(id, 0)).unwrap();
        assert_eq!(read(&mut stand), Err(Error::Keystore(Failure::Absent)));
        stand.keys.insert(root_alias(id, 0), key);
        assert!(stand.keys.contains_key(&root_alias(id, 1)));
        assert!(home.join("root-1").exists());
        assert_eq!(read(&mut stand), Ok(()));
    }

    #[test]
    fn a_pointer_names_its_root_and_no_other_of_its_number() {
        let root = dir("replay");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        profile.roots(&mut stand).switch(1).unwrap();
        let home = home(&root, id);
        let to_first = fs::read(home.join(CURRENT)).unwrap();
        drop(profile);
        // The pointer to epoch 1 is put back over a later root of that number.
        let (mut profile, _) = opened(&root, id, &mut stand);
        fs::remove_file(home.join("root-1")).unwrap();
        stand.keys.remove(&root_alias(id, 1));
        profile.current.as_mut().unwrap().number = 0;
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        drop(profile);
        fs::write(home.join(CURRENT), &to_first).unwrap();
        let mut profile = Profile::open(&root, id).unwrap();
        let read = profile.epoch(&mut stand, &mut [0; 32]);
        assert_eq!(read.unwrap_err(), Error::Damaged);
    }

    #[test]
    fn a_new_root_that_does_not_open_is_erased_at_once() {
        let root = dir("unopened");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        // The root's tag is the first answer, and the check of it on reading the second.
        stand.refuse_mac = Some((stand.macs + 1, Failure::Locked));
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(next.unwrap_err(), Error::Keystore(Failure::Locked));
        assert!(!stand.keys.contains_key(&root_alias(id, 1)));
        assert!(!home(&root, id).join("root-1").exists());
    }

    #[test]
    fn a_left_root_that_cannot_be_deleted_stops_the_next() {
        let root = dir("stale");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        stand.keys.insert(root_alias(id, 1), [9; 32]);
        stand.refuse_delete = Some(Failure::Transient);
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(next.unwrap_err(), Error::Keystore(Failure::Transient));
        assert_eq!(stand.keys[&root_alias(id, 1)], [9; 32]);
    }

    #[test]
    fn a_lower_root_is_made_and_named_so() {
        let root = dir("lower");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        stand.strong_box = false;
        let next = profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        assert_eq!(
            (next.level, next.previous),
            (Level::TrustedEnvironment, Level::StrongBox)
        );
    }

    #[test]
    fn a_root_only_software_holds_needs_consent_and_is_not_surely_erased() {
        let root = dir("software");
        let mut stand = Stand {
            strong_box: false,
            level: Level::Software,
            ..Stand::new()
        };
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        let refused = profile.next_epoch(&mut stand, false, &mut [0; 32]);
        assert_eq!(refused.unwrap_err(), Error::SoftwareOnly);
        assert!(!stand.keys.contains_key(&root_alias(id, 1)));
        assert!(!home(&root, id).join("root-1").exists());
        profile.next_epoch(&mut stand, true, &mut [0; 32]).unwrap();
        profile.roots(&mut stand).switch(1).unwrap();
        assert_eq!(profile.roots(&mut stand).erase(0), Erasure::NotErased);
    }

    #[test]
    fn a_key_that_cannot_be_deleted_keeps_its_file_until_it_is() {
        let root = dir("undeleted");
        let mut stand = Stand::new();
        let id = created(&root, &mut stand);
        let (mut profile, _) = opened(&root, id, &mut stand);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        stand.refuse_delete = Some(Failure::Transient);
        assert_eq!(profile.roots(&mut stand).erase(1), Erasure::NotErased);
        assert!(stand.keys.contains_key(&root_alias(id, 1)));
        assert!(home(&root, id).join("root-1").exists());
        stand.refuse_delete = None;
        stand.refuse_aliases = Some(Failure::Transient);
        drop(profile);
        let mut profile = Profile::open(&root, id).unwrap();
        let current = profile.epoch(&mut stand, &mut [0; 32]).unwrap();
        assert_eq!(current.swept, Some(Erasure::NotErased));
        assert!(!stand.keys.contains_key(&root_alias(id, 1)));
        assert!(!home(&root, id).join("root-1").exists());
    }

    #[test]
    fn a_number_reads_only_as_written() {
        for (text, number) in [
            ("0", Some(0)),
            ("7", Some(7)),
            ("10", Some(10)),
            ("18446744073709551615", Some(u64::MAX)),
            ("18446744073709551616", None),
            ("00", None),
            ("01", None),
            ("", None),
            ("1a", None),
            ("-1", None),
            ("+1", None),
            (" 1", None),
        ] {
            assert_eq!(number_of(text.as_bytes()), number, "{text}");
        }
    }

    #[test]
    fn a_number_written_in_a_name_reads_back() {
        for number in [0, 1, 9, 10, 99, 100, 12_345, u64::MAX - 1, u64::MAX] {
            let name = root_alias(Id([0; 16]), number);
            let digits = name.rsplit('/').next().unwrap();
            assert_eq!(number_of(digits.as_bytes()), Some(number), "{name}");
            assert_eq!(
                number_of(root_name(number).strip_prefix(ROOT).unwrap().as_bytes()),
                Some(number)
            );
        }
    }
}
