// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;

use zeroize::Zeroize;

use crate::keystore::{Failure, Keystore, Level};

/// The file that describes a profile.
const RECORD: &str = "profile";
/// The record while it is written, before it takes its name.
const RECORD_NEW: &str = "profile.new";
/// The file an open profile holds a lock on.
const LOCK: &str = "lock";
const MAGIC: [u8; 4] = *b"LWp1";
const RECORD_LEN: usize = 70;
/// One byte past a record, so a longer file reads as too long.
const RECORD_READ: u64 = 71;
const UNLOCKED: u8 = 1;
/// Below this API level a key usable only while the device is unlocked was deleted with the lock
/// screen.
const UNLOCKED_SAFE_FROM: u32 = 35;
const CHECK_LABEL: &[u8; 15] = b"lethewis check ";
const TAG_LABEL: &[u8; 16] = b"lethewis record ";
const ANSWER_LABEL: &[u8; 16] = b"lethewis answer ";

/// The identifier of a profile: 128 random bits, written as 32 lowercase hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Id([u8; 16]);

impl Id {
    fn random() -> io::Result<Self> {
        let mut bytes = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Reads an identifier as it is displayed, and nothing else.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::from_hex(text.as_bytes().try_into().ok()?)
    }

    fn from_hex(digits: &[u8; 32]) -> Option<Self> {
        let mut bytes = [0; 16];
        for (byte, &[high, low]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
            *byte = digit(high)?.wrapping_shl(4) | digit(low)?;
        }
        Some(Self(bytes))
    }

    fn hex(self) -> [u8; 32] {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0; 32];
        for (&byte, pair) in self.0.iter().zip(out.as_chunks_mut::<2>().0) {
            for (digit, nibble) in pair.iter_mut().zip([byte >> 4, byte & 0xf]) {
                *digit = DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
            }
        }
        out
    }
}

const fn digit(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(character.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hex()
            .iter()
            .try_for_each(|&digit| f.write_char(char::from(digit)))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

/// Why a profile could not be created, opened or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The profile is open elsewhere, in this process or another.
    Busy,
    /// No profile has this identifier.
    NotFound,
    /// The files of the profile are not as this library writes them, or the level, unlocking or tag
    /// of its record was changed since. At creation, the key name drawn is taken.
    Damaged,
    /// The chip's key answers otherwise than when the profile was created: it was replaced, or the
    /// record is another key's.
    ChipChanged,
    /// Only software of the operating system would hold the chip's key. Below API 31 the system
    /// may make it in software after a failure of the secure hardware, so a later try may succeed.
    SoftwareOnly,
    /// The keystore refused.
    Keystore(Failure),
    /// The file system refused.
    Io(io::ErrorKind),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("the profile is open elsewhere"),
            Self::NotFound => f.write_str("there is no such profile"),
            Self::Damaged => f.write_str("the files of the profile are damaged"),
            Self::ChipChanged => f.write_str("the chip's key was replaced"),
            Self::SoftwareOnly => f.write_str("only software would hold the chip's key"),
            Self::Keystore(failure) => write!(f, "the keystore refused: {failure}"),
            Self::Io(kind) => write!(f, "the file system refused: {kind}"),
        }
    }
}

impl std::error::Error for Error {}

/// A profile on this device, held open: no other opening of it succeeds until this one is dropped.
pub struct Profile {
    id: Id,
    alias: String,
    record: Record,
    _lock: File,
}

/// What the file of a profile holds.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Record {
    level: Level,
    unlocked: bool,
    /// The chip's answer to the check of the identifier, which tells a replaced key.
    check: [u8; 32],
    /// The chip's answer to the identifier, the level and the flags, which binds them to the key.
    tag: [u8; 32],
}

/// A failed creation, and whether a key of the profile may be left in the keystore.
struct Failed {
    error: Error,
    key_left: bool,
}

impl From<Error> for Failed {
    fn from(error: Error) -> Self {
        Self {
            error,
            key_left: false,
        }
    }
}

impl Profile {
    /// Creates a profile in a new directory under `root`, which the system must not back up, such
    /// as `Context.getNoBackupFilesDir()`. The chip's key goes into the secure element where the
    /// system offers one for it, and into the isolated part of the processor otherwise; a key only
    /// software would hold is taken only if `software` allows it.
    ///
    /// # Errors
    ///
    /// [`Error::SoftwareOnly`], [`Error::Damaged`] for a key name already taken, the keystore's
    /// failure or the file system's. Nothing of the profile is then left, as far as the keystore
    /// and the file system allow: where the chip's key could not be deleted, or after a crash, its
    /// directory stays.
    pub fn create(
        root: &Path,
        keystore: &mut impl Keystore,
        software: bool,
    ) -> Result<Self, Error> {
        let id = Id::random()?;
        let dir = root.join(id.to_string());
        fs::create_dir(&dir)?;
        Self::create_in(root, &dir, id, keystore, software).map_err(|failed| {
            if !failed.key_left {
                let _ = fs::remove_dir_all(&dir);
            }
            failed.error
        })
    }

    fn create_in(
        root: &Path,
        dir: &Path,
        id: Id,
        keystore: &mut impl Keystore,
        software: bool,
    ) -> Result<Self, Failed> {
        // The directory is to outlast a crash before the key is made, so a key is never left
        // without it.
        sync_dir(root).map_err(Error::from)?;
        let lock = lock(dir)?;
        let alias = alias(id);
        // A key under a name just drawn at random belongs to nothing of ours.
        if keystore.contains(&alias).map_err(Error::Keystore)? {
            return Err(Error::Damaged.into());
        }
        match make_key(dir, id, &alias, keystore, software) {
            Ok(record) => Ok(Self {
                id,
                alias,
                record,
                _lock: lock,
            }),
            Err(error) => Err(Failed {
                error,
                key_left: keystore.delete(&alias).is_err(),
            }),
        }
    }

    /// Opens the profile `id` under `root`; it never creates a profile.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], [`Error::Busy`], [`Error::Damaged`] or the file system's failure.
    pub fn open(root: &Path, id: Id) -> Result<Self, Error> {
        let dir = root.join(id.to_string());
        match fs::metadata(&dir) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(Error::Damaged),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(Error::NotFound),
            Err(error) => return Err(error.into()),
        }
        let lock = lock(&dir)?;
        let mut bytes = Vec::new();
        File::open(dir.join(RECORD))
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => Error::Damaged,
                kind => Error::Io(kind),
            })?
            .take(RECORD_READ)
            .read_to_end(&mut bytes)?;
        let record = Record::parse(&bytes).ok_or(Error::Damaged)?;
        Ok(Self {
            id,
            alias: alias(id),
            record,
            _lock: lock,
        })
    }

    /// The identifier of the profile.
    #[must_use]
    pub const fn id(&self) -> Id {
        self.id
    }

    /// Where the keystore holds the chip's key, as recorded at creation; it holds once
    /// [`Profile::verify`] succeeds.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.record.level
    }

    /// Whether the chip's key works only while the device is unlocked, as recorded at creation; it
    /// holds once [`Profile::verify`] succeeds.
    #[must_use]
    pub const fn unlocked_only(&self) -> bool {
        self.record.unlocked
    }

    /// Checks that the chip's key is still the one the profile was created with, and the level and
    /// unlocking of the record as written then.
    ///
    /// # Errors
    ///
    /// [`Error::ChipChanged`] for another key under the name, [`Error::Damaged`] for a changed
    /// level or unlocking, or the keystore's failure: [`Failure::Absent`] for none.
    pub fn verify(&self, keystore: &mut impl Keystore) -> Result<(), Error> {
        let mut tag = [0; 32];
        keystore
            .mac(&self.alias, &tag_input(self.id, &self.record), &mut tag)
            .map_err(Error::Keystore)?;
        if same_mac(&tag, &self.record.tag) {
            return Ok(());
        }
        let mut check = [0; 32];
        keystore
            .mac(&self.alias, &check_input(self.id), &mut check)
            .map_err(Error::Keystore)?;
        Err(if same_mac(&check, &self.record.check) {
            Error::Damaged
        } else {
            Error::ChipChanged
        })
    }

    /// Writes into `out` the chip's answer to `challenge`, the core's `Slots::challenge`, after
    /// [`Profile::verify`]. A wrong password then cannot be mistaken for a replaced key.
    ///
    /// # Errors
    ///
    /// As [`Profile::verify`], or the keystore's failure; `out` is then left as it was.
    pub fn answer(
        &self,
        keystore: &mut impl Keystore,
        challenge: &[u8; 32],
        out: &mut [u8; 32],
    ) -> Result<(), Error> {
        self.verify(keystore)?;
        let mut input = [0; 48];
        join(&[ANSWER_LABEL.as_slice(), challenge], &mut input);
        let answered = keystore
            .mac(&self.alias, &input, out)
            .map_err(Error::Keystore);
        input.zeroize();
        answered
    }
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("id", &self.id)
            .field("level", &self.record.level)
            .finish_non_exhaustive()
    }
}

/// Makes the chip's key under `alias` and writes the record; returns the record.
fn make_key(
    dir: &Path,
    id: Id,
    alias: &str,
    keystore: &mut impl Keystore,
    software: bool,
) -> Result<Record, Error> {
    let unlocked = keystore.api_level() >= UNLOCKED_SAFE_FROM;
    let level = match keystore.generate(alias, true, unlocked) {
        Err(Failure::StrongBoxUnavailable) => keystore.generate(alias, false, unlocked),
        generated => generated,
    }
    .map_err(Error::Keystore)?;
    if !level.secure() && !software {
        return Err(Error::SoftwareOnly);
    }
    let mut record = Record {
        level,
        unlocked,
        check: [0; 32],
        tag: [0; 32],
    };
    keystore
        .mac(alias, &check_input(id), &mut record.check)
        .map_err(Error::Keystore)?;
    keystore
        .mac(alias, &tag_input(id, &record), &mut record.tag)
        .map_err(Error::Keystore)?;
    write_record(dir, &record.bytes())?;
    Ok(record)
}

/// Constant time, and out of line so that the check of its machine code finds it.
#[inline(never)]
fn same_mac(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use ctutils::CtEq;
    a.ct_eq(b).to_bool()
}

fn alias(id: Id) -> String {
    format!("lethewis/{id}/chip")
}

fn check_input(id: Id) -> [u8; 31] {
    let mut input = [0; 31];
    join(&[CHECK_LABEL.as_slice(), &id.0], &mut input);
    input
}

fn tag_input(id: Id, record: &Record) -> [u8; 34] {
    let mut input = [0; 34];
    join(
        &[
            TAG_LABEL.as_slice(),
            &id.0,
            &[level_code(record.level), record.flags()],
        ],
        &mut input,
    );
    input
}

/// Writes the parts one after another into `out`; their lengths add up to its length.
fn join<const N: usize>(parts: &[&[u8]], out: &mut [u8; N]) {
    for (to, from) in out
        .iter_mut()
        .zip(parts.iter().flat_map(|part| part.iter()))
    {
        *to = *from;
    }
}

const fn level_code(level: Level) -> u8 {
    match level {
        Level::StrongBox => 1,
        Level::TrustedEnvironment => 2,
        Level::UnknownSecure => 3,
        Level::Software => 4,
        Level::Unknown => 5,
    }
}

const fn level_of(code: u8) -> Option<Level> {
    match code {
        1 => Some(Level::StrongBox),
        2 => Some(Level::TrustedEnvironment),
        3 => Some(Level::UnknownSecure),
        4 => Some(Level::Software),
        5 => Some(Level::Unknown),
        _ => None,
    }
}

impl Record {
    const fn flags(&self) -> u8 {
        if self.unlocked { UNLOCKED } else { 0 }
    }

    fn bytes(&self) -> [u8; RECORD_LEN] {
        let [m0, m1, m2, m3] = MAGIC;
        let mut bytes = [0; RECORD_LEN];
        if let Some((head, rest)) = bytes.split_first_chunk_mut::<6>()
            && let Some((check, tag)) = rest.split_first_chunk_mut::<32>()
            && let Ok(tag) = <&mut [u8; 32]>::try_from(tag)
        {
            *head = [m0, m1, m2, m3, level_code(self.level), self.flags()];
            *check = self.check;
            *tag = self.tag;
        }
        bytes
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let (magic, rest) = bytes.split_first_chunk::<4>()?;
        let (&[level, flags], rest) = rest.split_first_chunk::<2>()?;
        let (check, tag) = rest.split_first_chunk::<32>()?;
        let tag = <[u8; 32]>::try_from(tag).ok()?;
        if *magic != MAGIC || flags & !UNLOCKED != 0 {
            return None;
        }
        Some(Self {
            level: level_of(level)?,
            unlocked: flags == UNLOCKED,
            check: *check,
            tag,
        })
    }
}

fn lock(dir: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(LOCK))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(Error::Busy),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

fn write_record(dir: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = dir.join(RECORD_NEW);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, dir.join(RECORD))?;
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::ops::Deref;
    use std::path::{Path, PathBuf};

    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    use super::{
        Error, Failure, Id, Keystore, LOCK, Level, MAGIC, Profile, RECORD, RECORD_LEN, Record,
    };

    /// A keystore in memory: a key is 32 bytes, each new one different.
    struct Stand {
        api: u32,
        strong_box: bool,
        level: Level,
        keys: HashMap<String, [u8; 32]>,
        made: u8,
        taken: bool,
        refuse_generate: Option<Failure>,
        refuse_after_making: Option<Failure>,
        /// The number of answers given before the keystore refuses, and how.
        refuse_mac: Option<(usize, Failure)>,
        macs: usize,
        refuse_delete: Option<Failure>,
        generated: Vec<(bool, bool)>,
        deleted: Vec<String>,
    }

    impl Stand {
        fn new() -> Self {
            Self {
                api: 34,
                strong_box: true,
                level: Level::TrustedEnvironment,
                keys: HashMap::new(),
                made: 0,
                taken: false,
                refuse_generate: None,
                refuse_after_making: None,
                refuse_mac: None,
                macs: 0,
                refuse_delete: None,
                generated: Vec::new(),
                deleted: Vec::new(),
            }
        }
    }

    impl Keystore for Stand {
        fn api_level(&self) -> u32 {
            self.api
        }

        fn contains(&mut self, alias: &str) -> Result<bool, Failure> {
            Ok(self.taken || self.keys.contains_key(alias))
        }

        fn generate(
            &mut self,
            alias: &str,
            strong_box: bool,
            unlocked: bool,
        ) -> Result<Level, Failure> {
            self.generated.push((strong_box, unlocked));
            if let Some(failure) = self.refuse_generate {
                return Err(failure);
            }
            if strong_box && !self.strong_box {
                return Err(Failure::StrongBoxUnavailable);
            }
            self.made = self.made.wrapping_add(1);
            let level = if strong_box {
                Level::StrongBox
            } else {
                self.level
            };
            self.keys.insert(alias.to_owned(), [self.made; 32]);
            match self.refuse_after_making {
                Some(failure) => Err(failure),
                None => Ok(level),
            }
        }

        fn mac(&mut self, alias: &str, data: &[u8], out: &mut [u8; 32]) -> Result<(), Failure> {
            if let Some((after, failure)) = self.refuse_mac
                && self.macs >= after
            {
                return Err(failure);
            }
            self.macs = self.macs.wrapping_add(1);
            *out = hmac(self.keys.get(alias).ok_or(Failure::Absent)?, data);
            Ok(())
        }

        fn delete(&mut self, alias: &str) -> Result<(), Failure> {
            if let Some(failure) = self.refuse_delete {
                return Err(failure);
            }
            self.deleted.push(alias.to_owned());
            self.keys.remove(alias);
            Ok(())
        }
    }

    fn hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// An empty directory of its own for each test, removed with it.
    struct Root(PathBuf);

    impl Deref for Root {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn root(name: &str) -> Root {
        let root =
            std::env::temp_dir().join(format!("lethewis-android-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Root(root)
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn alias(profile: &Profile) -> String {
        format!("lethewis/{}/chip", profile.id())
    }

    fn answer_of(key: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
        hmac(key, &[b"lethewis answer ".as_slice(), challenge].concat())
    }

    #[test]
    fn a_created_profile_opens_and_answers_as_the_chip() {
        let root = root("answers");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let profile = Profile::open(&root, id).unwrap();
        assert_eq!(profile.level(), Level::StrongBox);
        assert_eq!(stand.generated, [(true, false)]);
        let key = stand.keys[&alias(&profile)];
        for challenge in [[0; 32], [7; 32], [0xff; 32]] {
            let mut out = [0; 32];
            profile.answer(&mut stand, &challenge, &mut out).unwrap();
            assert_eq!(out, answer_of(&key, &challenge));
        }
    }

    #[test]
    fn the_record_holds_the_chips_answers_to_its_check_and_to_itself() {
        for api in [34, 35] {
            let root = root(&format!("answers-{api}"));
            let mut stand = Stand {
                api,
                ..Stand::new()
            };
            let profile = Profile::create(&root, &mut stand, false).unwrap();
            let key = stand.keys[&alias(&profile)];
            let bytes = std::fs::read(root.join(profile.id().to_string()).join(RECORD)).unwrap();
            let id = profile.id().0;
            let check = hmac(&key, &[b"lethewis check ".as_slice(), &id].concat());
            let flags = u8::from(api >= 35);
            let tag = hmac(
                &key,
                &[b"lethewis record ".as_slice(), &id, &[1, flags]].concat(),
            );
            assert_eq!(bytes[4..6], [1, flags]);
            assert_eq!(bytes[6..38], check);
            assert_eq!(bytes[38..], tag);
        }
    }

    #[test]
    fn two_profiles_have_their_own_directory_name_and_key() {
        let root = root("two");
        let mut stand = Stand::new();
        let first = Profile::create(&root, &mut stand, false).unwrap();
        let second = Profile::create(&root, &mut stand, false).unwrap();
        assert_ne!(first.id(), second.id());
        assert_ne!(stand.keys[&alias(&first)], stand.keys[&alias(&second)]);
        assert!(root.join(first.id().to_string()).is_dir());
        assert!(root.join(second.id().to_string()).is_dir());
        let (mut one, mut other) = ([0; 32], [0; 32]);
        first.answer(&mut stand, &[1; 32], &mut one).unwrap();
        second.answer(&mut stand, &[1; 32], &mut other).unwrap();
        assert_ne!(one, other);
    }

    #[test]
    fn a_profile_open_elsewhere_is_busy_until_dropped() {
        let root = root("busy");
        let mut stand = Stand::new();
        let created = Profile::create(&root, &mut stand, false).unwrap();
        let id = created.id();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::Busy);
        drop(created);
        let opened = Profile::open(&root, id).unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::Busy);
        drop(opened);
        assert!(Profile::open(&root, id).is_ok());
    }

    #[test]
    fn without_a_secure_element_the_key_goes_to_the_isolated_processor() {
        let root = root("fallback");
        let mut stand = Stand {
            strong_box: false,
            ..Stand::new()
        };
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        assert_eq!(profile.level(), Level::TrustedEnvironment);
        assert_eq!(stand.generated, [(true, false), (false, false)]);
    }

    #[test]
    fn another_failure_of_the_secure_element_is_no_fallback() {
        let root = root("transient");
        let mut stand = Stand {
            refuse_generate: Some(Failure::Transient),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Transient));
        assert_eq!(stand.generated, [(true, false)]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_key_made_before_a_failure_is_deleted() {
        let root = root("made");
        let mut stand = Stand {
            refuse_after_making: Some(Failure::Transient),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Transient));
        assert_eq!(stand.deleted.len(), 1);
        assert!(stand.keys.is_empty());
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_key_that_cannot_be_deleted_keeps_its_directory_without_a_record() {
        let root = root("left");
        let mut stand = Stand {
            refuse_mac: Some((0, Failure::Locked)),
            refuse_delete: Some(Failure::Transient),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Locked));
        assert_eq!(stand.keys.len(), 1);
        let dirs = entries(&root);
        assert_eq!(dirs.len(), 1);
        assert_eq!(entries(&root.join(&dirs[0])), [LOCK]);
        let id = Id::parse(&dirs[0]).unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::Damaged);
    }

    #[test]
    fn from_api_35_the_key_works_only_while_unlocked() {
        for (api, unlocked) in [(28, false), (34, false), (35, true), (37, true)] {
            let root = root(&format!("unlocked-{api}"));
            let mut stand = Stand {
                api,
                ..Stand::new()
            };
            let id = Profile::create(&root, &mut stand, false).unwrap().id();
            assert_eq!(stand.generated, [(true, unlocked)]);
            assert_eq!(Profile::open(&root, id).unwrap().unlocked_only(), unlocked);
        }
    }

    #[test]
    fn a_key_only_software_holds_needs_consent() {
        for level in [Level::Software, Level::Unknown] {
            let root = root(&format!("software-{level:?}"));
            let mut stand = Stand {
                strong_box: false,
                level,
                ..Stand::new()
            };
            let refused = Profile::create(&root, &mut stand, false);
            assert_eq!(refused.unwrap_err(), Error::SoftwareOnly);
            assert!(stand.keys.is_empty());
            assert_eq!(entries(&root), [] as [String; 0]);
            let id = Profile::create(&root, &mut stand, true).unwrap().id();
            assert_eq!(Profile::open(&root, id).unwrap().level(), level);
        }
    }

    #[test]
    fn a_failed_check_at_creation_leaves_nothing() {
        let root = root("check");
        let mut stand = Stand {
            refuse_mac: Some((0, Failure::Locked)),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Locked));
        assert!(stand.keys.is_empty());
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_failed_tag_at_creation_leaves_nothing() {
        let root = root("tag");
        let mut stand = Stand {
            refuse_mac: Some((1, Failure::Transient)),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Transient));
        assert_eq!(stand.macs, 1);
        assert!(stand.keys.is_empty());
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_refusal_while_verifying_is_the_keystores_failure() {
        let root = root("refused");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let file = root.join(id.to_string()).join(RECORD);
        let mut bytes = std::fs::read(&file).unwrap();
        bytes[5] = 1;
        std::fs::write(&file, bytes).unwrap();
        let profile = Profile::open(&root, id).unwrap();
        // Refused at the first answer, and at the second, which tells a changed record.
        for after in [0, 1] {
            stand.macs = 0;
            stand.refuse_mac = Some((after, Failure::Locked));
            assert_eq!(
                profile.verify(&mut stand).unwrap_err(),
                Error::Keystore(Failure::Locked)
            );
        }
        stand.refuse_mac = None;
        assert_eq!(profile.verify(&mut stand).unwrap_err(), Error::Damaged);
    }

    #[test]
    fn a_key_name_already_taken_is_refused_and_kept() {
        let root = root("taken");
        let mut stand = Stand {
            taken: true,
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Damaged);
        assert_eq!(stand.generated, [] as [(bool, bool); 0]);
        assert_eq!(stand.deleted, [] as [String; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_replaced_key_is_told_from_a_wrong_password() {
        let root = root("replaced");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        stand.keys.insert(alias(&profile), [0xaa; 32]);
        let mut out = [0x5a; 32];
        let answered = profile.answer(&mut stand, &[3; 32], &mut out);
        assert_eq!(answered.unwrap_err(), Error::ChipChanged);
        assert_eq!(profile.verify(&mut stand).unwrap_err(), Error::ChipChanged);
        assert_eq!(out, [0x5a; 32]);
        stand.keys.clear();
        assert_eq!(
            profile.answer(&mut stand, &[3; 32], &mut out).unwrap_err(),
            Error::Keystore(Failure::Absent)
        );
        assert_eq!(out, [0x5a; 32]);
    }

    #[test]
    fn a_changed_record_is_damaged() {
        let root = root("changed");
        let mut stand = Stand {
            strong_box: false,
            level: Level::Software,
            ..Stand::new()
        };
        let id = Profile::create(&root, &mut stand, true).unwrap().id();
        let file = root.join(id.to_string()).join(RECORD);
        let written = std::fs::read(&file).unwrap();
        assert!(Profile::open(&root, id).unwrap().verify(&mut stand).is_ok());
        // A higher level, the unlocking turned on, a bit of the tag.
        for (at, value) in [(4, 1), (5, 1), (69, written[69] ^ 1)] {
            let mut bytes = written.clone();
            bytes[at] = value;
            std::fs::write(&file, bytes).unwrap();
            let profile = Profile::open(&root, id).unwrap();
            assert_eq!(profile.verify(&mut stand).unwrap_err(), Error::Damaged);
            let mut out = [0x5a; 32];
            assert_eq!(
                profile.answer(&mut stand, &[3; 32], &mut out).unwrap_err(),
                Error::Damaged
            );
            assert_eq!(out, [0x5a; 32]);
        }
    }

    #[test]
    fn opening_never_creates() {
        let root = root("never");
        let id = Id::parse("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::NotFound);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_failure_to_look_is_no_missing_profile() {
        let root = root("look");
        let id = Id::parse("00112233445566778899aabbccddeeff").unwrap();
        std::fs::write(root.join(id.to_string()), b"").unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::Damaged);
        let file = root.join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            Profile::open(&file, id).unwrap_err(),
            Error::Io(io::ErrorKind::NotADirectory)
        );
    }

    #[test]
    fn a_record_not_as_written_is_damaged() {
        let root = root("damaged");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let file = root.join(id.to_string()).join(RECORD);
        let good = Record {
            level: Level::StrongBox,
            unlocked: false,
            check: [4; 32],
            tag: [5; 32],
        }
        .bytes();
        std::fs::write(&file, good).unwrap();
        assert!(Profile::open(&root, id).is_ok());
        let mut wrong = Vec::new();
        wrong.push(good.split_last().unwrap().1.to_vec());
        wrong.push([good.as_slice(), &[0]].concat());
        wrong.push([b"LWp2".as_slice(), &good[4..]].concat());
        for level in [0, 6, 0xff] {
            let mut bytes = good;
            bytes[4] = level;
            wrong.push(bytes.to_vec());
        }
        for flags in [2, 3, 0x80] {
            let mut bytes = good;
            bytes[5] = flags;
            wrong.push(bytes.to_vec());
        }
        for bytes in wrong {
            std::fs::write(&file, &bytes).unwrap();
            assert_eq!(
                Profile::open(&root, id).unwrap_err(),
                Error::Damaged,
                "{bytes:?}"
            );
        }
        std::fs::remove_file(&file).unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::Damaged);
        assert_eq!(good.len(), RECORD_LEN);
        assert_eq!(&good[..4], &MAGIC);
    }

    #[test]
    fn a_record_holds_level_unlocking_check_and_tag() {
        for level in [
            Level::StrongBox,
            Level::TrustedEnvironment,
            Level::UnknownSecure,
            Level::Software,
            Level::Unknown,
        ] {
            for unlocked in [false, true] {
                let record = Record {
                    level,
                    unlocked,
                    check: [0x3c; 32],
                    tag: [0xc3; 32],
                };
                assert!(Record::parse(&record.bytes()) == Some(record));
            }
        }
    }

    #[test]
    fn the_lock_file_stays_and_no_temporary_record_is_left() {
        let root = root("files");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        assert_eq!(entries(&root.join(id.to_string())), [LOCK, RECORD]);
    }

    #[test]
    fn an_identifier_reads_only_as_it_is_displayed() {
        let id = Id::parse("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
        assert_eq!(format!("{id:?}"), "Id(00112233445566778899aabbccddeeff)");
        assert_eq!(
            id.0,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        for wrong in [
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff0",
            "00112233445566778899aabbccddeefg",
            "0011223344556677 899aabbccddeeff",
            "",
        ] {
            assert_eq!(Id::parse(wrong), None, "{wrong}");
        }
        for _ in 0..8 {
            let random = Id::random().unwrap();
            assert_eq!(Id::parse(&random.to_string()), Some(random));
        }
    }

    #[test]
    fn a_profile_shows_its_identifier_and_level_only() {
        let root = root("debug");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let shown = format!("{profile:?}");
        assert!(shown.contains(&profile.id().to_string()), "{shown}");
        assert!(shown.contains("StrongBox"), "{shown}");
        assert!(!shown.contains("check"), "{shown}");
    }

    #[test]
    fn every_error_reads_differently() {
        let errors = [
            Error::Busy,
            Error::NotFound,
            Error::Damaged,
            Error::ChipChanged,
            Error::SoftwareOnly,
            Error::Keystore(Failure::Transient),
            Error::Keystore(Failure::Locked),
            Error::Keystore(Failure::Absent),
            Error::Keystore(Failure::Corrupted),
            Error::Keystore(Failure::StrongBoxUnavailable),
            Error::Io(io::ErrorKind::NotFound),
            Error::Io(io::ErrorKind::PermissionDenied),
        ];
        let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
        for (index, text) in texts.iter().enumerate() {
            assert_ne!(*text, "");
            assert!(!texts[..index].contains(text), "{text}");
        }
    }
}
