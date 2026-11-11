// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use zeroize::Zeroize;

use crate::epoch::{self, Known, root_alias};
use crate::keystore::{Failure, Keystore, Level, Watchable};

/// The file that describes a profile, written last at creation.
pub(crate) const RECORD: &str = "profile";
/// The file an open profile holds a lock on.
pub(crate) const LOCK: &str = "lock";
/// The file that marks a profile whose destruction has begun.
pub(crate) const DESTROYED: &str = "destroyed";
/// What a file is named while it is written, before it takes its name.
pub(crate) const WRITING: &str = ".new";
/// The name of `Context.getNoBackupFilesDir()`, which no backup of the system takes.
const NO_BACKUP: &str = "no_backup";
const MAGIC: [u8; 4] = *b"LWp1";
pub(crate) const RECORD_LEN: usize = 70;
pub(crate) const UNLOCKED: u8 = 1;
/// Below this API level a key usable only while the device is unlocked was deleted with the lock
/// screen.
const UNLOCKED_SAFE_FROM: u32 = 35;
const CHECK_LABEL: &[u8; 15] = b"lethewis check ";
const TAG_LABEL: &[u8; 16] = b"lethewis record ";
const ANSWER_LABEL: &[u8; 16] = b"lethewis answer ";

/// The identifier of a profile: 128 random bits, written as 32 lowercase hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Id(pub(crate) [u8; 16]);

impl Id {
    fn random() -> io::Result<Self> {
        let mut bytes = [0; 16];
        fill_random(&mut bytes)?;
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
    /// No profile has this identifier, or its destruction has begun.
    NotFound,
    /// The directory of profiles is under none named `no_backup`, so the system may back it up.
    BackedUp,
    /// The files of the profile are not as this library writes them, or the level, unlocking or tag
    /// of its record was changed since. At creation, the key name drawn is taken.
    Damaged,
    /// The chip's key answers otherwise than when the profile was created: it was replaced, or the
    /// record is another key's.
    ChipChanged,
    /// Only software of the operating system would hold the chip's key. Below API 31 the system
    /// may make it in software after a failure of the secure hardware, so a later try may succeed.
    SoftwareOnly,
    /// The system refused the key of [`Sign::Fingerprints`](crate::Sign::Fingerprints), for the
    /// reason the device gives.
    Unwatchable(Watchable),
    /// The system refused the key of [`Sign::Fingerprints`](crate::Sign::Fingerprints), and asking
    /// the device why failed, as where the app gave no context through `Wiper.start` or lacks the
    /// permission to ask.
    Unexplained(Failure),
    /// The current epoch is not known yet: [`Profile::epoch`] reads it.
    NoEpoch,
    /// The root of the next epoch is made, and neither switched to nor erased yet, or the slots
    /// given are in a change of epoch.
    Changing,
    /// No epoch follows the current one.
    Exhausted,
    /// A switch of epoch may or may not have been written: the profile changes no epoch until
    /// [`Profile::epoch`] reads the current one again.
    Unsettled,
    /// No way into the profile opens with the password.
    WrongPassword,
    /// Two of the passwords given are one, or a new password is the owner's.
    SamePassword,
    /// The ways into the profile are made already; [`Profile::change_password`] changes them.
    Exists,
    /// The sign of the fingerprints has no key of its own, so watching it would watch nothing.
    NoKey,
    /// A sign to be watched was given no reading to accept, so it would fire at once.
    Unread,
    /// The profile is locked: the owner's password opens it only with two shares or the signature
    /// of a round.
    Locked,
    /// The owner's password has a way in with shares, which a new password would leave unopenable:
    /// the change asks for new shares.
    SharesSet,
    /// A sign set to lock the profile, or a lock, needs a way in with shares or a time lock.
    NoWayOut,
    /// The owner's password has a way in with a time lock, which a new password would leave
    /// unopenable: it is cleared before the change and made again after.
    TimeLockSet,
    /// A file of the profile is written, but the sync of its directory failed, so a crash may undo
    /// the change.
    Unsynced(io::ErrorKind),
    /// The keystore refused.
    Keystore(Failure),
    /// The core refused.
    Core(lethewis_core::Error),
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
            Self::BackedUp => f.write_str("the profiles are where the system may back them up"),
            Self::Damaged => f.write_str("the files of the profile are damaged"),
            Self::ChipChanged => f.write_str("the chip's key was replaced"),
            Self::SoftwareOnly => f.write_str("only software would hold the chip's key"),
            Self::Unwatchable(why) => write!(f, "the device holds no key of the sign: {why}"),
            Self::Unexplained(failure) => {
                write!(
                    f,
                    "the device holds no key of the sign and does not say why: {failure}"
                )
            }
            Self::NoEpoch => f.write_str("the current epoch was not read"),
            Self::Changing => f.write_str("a change of epoch is under way"),
            Self::Exhausted => f.write_str("no epoch follows the current one"),
            Self::Unsettled => f.write_str("a switch of epoch was not settled"),
            Self::WrongPassword => f.write_str("no way into the profile opens with the password"),
            Self::SamePassword => f.write_str("two of the passwords are one"),
            Self::Exists => f.write_str("the ways into the profile are made already"),
            Self::NoKey => f.write_str("the sign of the fingerprints has no key"),
            Self::Unread => f.write_str("a sign to be watched was given no reading"),
            Self::Locked => f.write_str("the profile is locked"),
            Self::SharesSet => f.write_str("a new password needs new shares"),
            Self::NoWayOut => f.write_str("a lock needs a way in with shares or a time lock"),
            Self::TimeLockSet => f.write_str("a new password needs the time lock made again"),
            Self::Unsynced(kind) => write!(f, "a file is written but not synced: {kind}"),
            Self::Keystore(failure) => write!(f, "the keystore refused: {failure}"),
            Self::Core(error) => write!(f, "the core refused: {error}"),
            Self::Io(kind) => write!(f, "the file system refused: {kind}"),
        }
    }
}

impl std::error::Error for Error {}

/// A profile on this device, held open: no other opening of it succeeds until this one is dropped.
pub struct Profile {
    pub(crate) id: Id,
    pub(crate) dir: PathBuf,
    pub(crate) alias: String,
    pub(crate) record: Record,
    /// The root of the current epoch, once read.
    pub(crate) current: Option<Known>,
    /// The root made for the next epoch, not yet current.
    pub(crate) next: Option<Known>,
    /// A root other than the current whose level is known, until it is erased: the one current
    /// before the last switch, or the one an unsettled switch was found not to reach.
    pub(crate) previous: Option<Known>,
    pub(crate) unsettled: bool,
    /// The epoch an unsettled switch was found to reach, until the switch to it is asked again.
    pub(crate) settled: Option<u64>,
    /// Held from the reading of a file of the ways in or of the signs to its writing.
    writing: Mutex<()>,
    _lock: File,
}

/// What the file of a profile holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) level: Level,
    unlocked: bool,
    /// The chip's answer to the check of the identifier, which tells a replaced key.
    check: [u8; 32],
    /// The chip's answer to the identifier, the level and the flags, which binds them to the key.
    tag: [u8; 32],
}

impl Profile {
    /// Creates a profile in a new directory under `root`, a directory of profiles alone in
    /// `Context.getNoBackupFilesDir()`, with the root of epoch 0. The chip's keys go into the
    /// secure element where the system offers one for them, and into the isolated part of the
    /// processor otherwise; keys only software would hold are taken only if `software` allows it.
    ///
    /// # Errors
    ///
    /// [`Error::BackedUp`], before anything is made, [`Error::SoftwareOnly`], [`Error::Damaged`]
    /// for a key name already taken, the keystore's failure or the file system's. Nothing of the
    /// profile is then left, as far as the keystore and the file system allow: where a key could
    /// not be deleted, or after a crash, a directory without the record, or marked destroyed,
    /// stays for [`sweep`](crate::sweep). A sweep under way delays a creation.
    pub fn create(
        root: &Path,
        keystore: &mut impl Keystore,
        software: bool,
    ) -> Result<Self, Error> {
        out_of_backups(root)?;
        let id = Id::random()?;
        let dir = root.join(id.to_string());
        let alias = alias(id);
        // A key under a name just drawn at random belongs to nothing of ours.
        if keystore.contains(&alias).map_err(Error::Keystore)? {
            return Err(Error::Damaged);
        }
        // Shared with other creations, so that a sweep never finds a directory not yet locked.
        let creating = File::open(root)?;
        creating.lock_shared()?;
        fs::create_dir(&dir)?;
        // The directory is to outlast a crash before a key is made, so a key is never left
        // without it.
        let locked = sync_dir(root)
            .map_err(Error::from)
            .and_then(|()| lock(&dir));
        if locked.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        drop(creating);
        let lock = locked?;
        match make_profile(&dir, id, &alias, keystore, software) {
            Ok((record, root)) => Ok(Self {
                id,
                dir,
                alias,
                record,
                current: Some(root),
                next: None,
                previous: None,
                unsettled: false,
                settled: None,
                writing: Mutex::new(()),
                _lock: lock,
            }),
            Err(error) => {
                // Without its record, or with the mark, the directory is left for a sweep.
                let unrecorded = match remove_record(&dir) {
                    Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
                    _ => sync_dir(&dir),
                };
                if unrecorded.is_err() {
                    let _ = mark_destroyed(&dir);
                }
                let chip = keystore.delete(&alias);
                let root = keystore.delete(&root_alias(id, 0));
                if chip.is_ok() && root.is_ok() {
                    let _ = fs::remove_dir_all(&dir);
                }
                Err(error)
            }
        }
    }

    /// Opens the profile `id` under `root`; it never creates a profile.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], also for a profile whose destruction has begun, [`Error::Busy`],
    /// [`Error::BackedUp`], [`Error::Damaged`] or the file system's failure.
    pub fn open(root: &Path, id: Id) -> Result<Self, Error> {
        let dir = root.join(id.to_string());
        let lock = match lock(&dir) {
            Err(Error::Io(io::ErrorKind::NotFound)) => return Err(Error::NotFound),
            // A file under the profile's name, rather than `root` itself.
            Err(Error::Io(io::ErrorKind::NotADirectory)) if root.is_dir() => {
                return Err(Error::Damaged);
            }
            locked => locked?,
        };
        out_of_backups(&dir)?;
        if exists(&dir.join(DESTROYED))? {
            return Err(Error::NotFound);
        }
        let mut bytes = [0; RECORD_LEN + 1];
        let read =
            read_file(&dir.join(RECORD), &mut bytes).map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => Error::Damaged,
                kind => Error::Io(kind),
            })?;
        let record = bytes
            .get(..read)
            .and_then(Record::parse)
            .ok_or(Error::Damaged)?;
        Ok(Self {
            id,
            dir,
            alias: alias(id),
            record,
            current: None,
            next: None,
            previous: None,
            unsettled: false,
            settled: None,
            writing: Mutex::new(()),
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
        answer_of(&self.alias, keystore, challenge, out)
    }
}

/// Writes into `out` the answer of the chip's key `alias` to `challenge`, which
/// [`Profile::answer`] gives after [`Profile::verify`].
pub(crate) fn answer_of(
    alias: &str,
    keystore: &mut impl Keystore,
    challenge: &[u8; 32],
    out: &mut [u8; 32],
) -> Result<(), Error> {
    let mut input = [0; 48];
    join(&[ANSWER_LABEL.as_slice(), challenge], &mut input);
    let answered = keystore.mac(alias, &input, out).map_err(Error::Keystore);
    input.zeroize();
    answered
}

impl Profile {
    /// Held through a change of the ways in or of the signs, so that two changes at once never
    /// write over what the other wrote.
    pub(crate) fn writing(&self) -> MutexGuard<'_, ()> {
        self.writing.lock().unwrap_or_else(PoisonError::into_inner)
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

/// Makes the chip's key under `alias`, the root of epoch 0 and the pointer to it, and last the
/// record; returns the record and the root.
fn make_profile(
    dir: &Path,
    id: Id,
    alias: &str,
    keystore: &mut impl Keystore,
    software: bool,
) -> Result<(Record, Known), Error> {
    let unlocked = unlocked_only(keystore);
    let level = generate(keystore, alias, unlocked, software)?;
    let root = epoch::make_root(dir, id, 0, keystore, software)?;
    let pointer = epoch::pointer_to(id, alias, &root, keystore)?;
    write_file(dir, epoch::CURRENT, &pointer).map_err(epoch::Written::error)?;
    let guards = crate::guard::fresh_guards(alias, keystore)?;
    write_file(dir, crate::guard::GUARDS, &guards).map_err(epoch::Written::error)?;
    // A device that holds no key of that sign makes the profile all the same. Any other failure
    // is the keystore's and is told.
    let watch = crate::guard::watch_alias(id);
    if let Err(error) = crate::guard::make_watch(keystore, &watch, software) {
        let _ = keystore.delete(&watch);
        if !matches!(error, Error::Unwatchable(_) | Error::Unexplained(_)) {
            return Err(error);
        }
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
    write_file(dir, RECORD, &record.bytes()).map_err(epoch::Written::error)?;
    Ok((record, root))
}

/// Whether the keys made now work only while the device is unlocked.
pub(crate) fn unlocked_only(keystore: &impl Keystore) -> bool {
    keystore.api_level() >= UNLOCKED_SAFE_FROM
}

/// Makes a key under `alias`, in the secure element where the system offers one; returns where it
/// is held. A key left by a failure is the caller's to delete.
pub(crate) fn generate(
    keystore: &mut impl Keystore,
    alias: &str,
    unlocked: bool,
    software: bool,
) -> Result<Level, Error> {
    let level = match keystore.generate(alias, true, unlocked) {
        Err(Failure::StrongBoxUnavailable) => keystore.generate(alias, false, unlocked),
        generated => generated,
    }
    .map_err(Error::Keystore)?;
    if !level.secure() && !software {
        return Err(Error::SoftwareOnly);
    }
    Ok(level)
}

/// Constant time, and out of line so that the check of its machine code finds it.
#[inline(never)]
pub(crate) fn same_mac(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use ctutils::CtEq;
    a.ct_eq(b).to_bool()
}

/// The name of the chip's key of the profile `id`.
pub(crate) fn alias(id: Id) -> String {
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
pub(crate) fn join<const N: usize>(parts: &[&[u8]], out: &mut [u8; N]) {
    for (to, from) in out
        .iter_mut()
        .zip(parts.iter().flat_map(|part| part.iter()))
    {
        *to = *from;
    }
}

pub(crate) const fn level_code(level: Level) -> u8 {
    match level {
        Level::StrongBox => 1,
        Level::TrustedEnvironment => 2,
        Level::UnknownSecure => 3,
        Level::Software => 4,
        Level::Unknown => 5,
    }
}

pub(crate) const fn level_of(code: u8) -> Option<Level> {
    match code {
        1 => Some(Level::StrongBox),
        2 => Some(Level::TrustedEnvironment),
        3 => Some(Level::UnknownSecure),
        4 => Some(Level::Software),
        5 => Some(Level::Unknown),
        _ => None,
    }
}

pub(crate) const fn flags_of(unlocked: bool) -> u8 {
    if unlocked { UNLOCKED } else { 0 }
}

impl Record {
    const fn flags(&self) -> u8 {
        flags_of(self.unlocked)
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

/// Fills `out` with random bytes from the system.
pub(crate) fn fill_random(out: &mut [u8]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(out)
}

/// [`Error::BackedUp`] unless `path`, where it really is, is in a directory named `no_backup`.
fn out_of_backups(path: &Path) -> Result<(), Error> {
    let path = path.canonicalize()?;
    if path.ancestors().any(|dir| dir.ends_with(NO_BACKUP)) {
        Ok(())
    } else {
        Err(Error::BackedUp)
    }
}

pub(crate) fn lock(dir: &Path) -> Result<File, Error> {
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

/// Marks the profile in `dir` destroyed: it then reads as not found.
pub(crate) fn mark_destroyed(dir: &Path) -> io::Result<()> {
    File::create(dir.join(DESTROYED))
        .and_then(|file| file.sync_all())
        .and_then(|()| sync_dir(dir))
}

/// Whether `path` is there; a failure to look is the file system's.
pub(crate) fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Reads the file `path` into `out`, up to its length; returns how many bytes it read. A file as
/// long as `out` or longer reads as `out.len()` bytes.
pub(crate) fn read_file(path: &Path, out: &mut [u8]) -> io::Result<usize> {
    let mut file = File::open(path)?;
    let mut read = 0;
    while let Some(rest) = out.get_mut(read..) {
        match file.read(rest)? {
            0 => break,
            count => read = read.saturating_add(count),
        }
    }
    Ok(read)
}

/// Writes `bytes` to the file `name` in `dir` in one step: to a file of its own first, synced, then
/// renamed over the name, and the directory synced.
pub(crate) fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), epoch::Written> {
    let temporary = dir.join(format!("{name}{WRITING}"));
    let written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temporary, dir.join(name)));
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(epoch::Written::Before(error.kind()));
    }
    sync_dir(dir).map_err(|error| epoch::Written::After(error.kind()))
}

/// Removes the record of a profile whose creation failed.
fn remove_record(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    crate::stand::removal_failure()?;
    fs::remove_file(dir.join(RECORD))
}

pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    crate::stand::sync_failure()?;
    File::open(dir)?.sync_all()
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use lethewis_core::Erasure;

    use super::{
        DESTROYED, Error, Failure, Id, LOCK, Level, MAGIC, Profile, RECORD, RECORD_LEN, Record,
        Watchable,
    };
    use crate::epoch::{CURRENT, root_alias};
    use crate::stand::{Stand, dir, entries, fail_removal, fail_syncs, hmac};

    fn alias(profile: &Profile) -> String {
        format!("lethewis/{}/chip", profile.id())
    }

    fn answer_of(key: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
        hmac(key, &[b"lethewis answer ".as_slice(), challenge].concat())
    }

    #[test]
    fn a_created_profile_opens_and_answers_as_the_chip() {
        let root = dir("answers");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let profile = Profile::open(&root, id).unwrap();
        assert_eq!(profile.level(), Level::StrongBox);
        // The chip, the root of epoch 0, and the key of the sign of the fingerprints.
        assert_eq!(stand.generated, [(true, false); 3]);
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
            let root = dir(&format!("answers-{api}"));
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
    fn profiles_are_made_and_opened_only_out_of_backups() {
        let root = dir("backups");
        let parent = root.parent().unwrap();
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let backed = parent.join("files");
        std::fs::rename(&*root, &backed).unwrap();
        assert_eq!(
            Profile::create(&backed, &mut stand, false).err(),
            Some(Error::BackedUp)
        );
        assert_eq!(Profile::open(&backed, id).err(), Some(Error::BackedUp));
        assert_eq!(entries(&backed), [id.to_string()]);
        assert_eq!(stand.keys.len(), 3);
        // Only where the directory really is counts.
        std::os::unix::fs::symlink(&backed, &*root).unwrap();
        assert_eq!(Profile::open(&root, id).err(), Some(Error::BackedUp));
        let inner = backed.join("no_backup");
        std::fs::create_dir(&inner).unwrap();
        let kept = Profile::create(&inner, &mut stand, false).unwrap().id();
        assert!(Profile::open(&inner, kept).is_ok());
        let name = id.to_string();
        std::os::unix::fs::symlink(backed.join(&name), inner.join(&name)).unwrap();
        assert_eq!(Profile::open(&inner, id).err(), Some(Error::BackedUp));
    }

    #[test]
    fn two_profiles_have_their_own_directory_name_and_key() {
        let root = dir("two");
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
        let root = dir("busy");
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
        let root = dir("fallback");
        let mut stand = Stand {
            strong_box: false,
            ..Stand::new()
        };
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        assert_eq!(profile.level(), Level::TrustedEnvironment);
        // The chip, the root of epoch 0 and the key of the sign of the fingerprints, each asked
        // of the secure element first.
        assert_eq!(stand.generated, [(true, false), (false, false)].repeat(3));
    }

    #[test]
    fn another_failure_of_the_secure_element_is_no_fallback() {
        let root = dir("transient");
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
        let root = dir("made");
        let mut stand = Stand {
            refuse_after_making: Some(Failure::Transient),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Transient));
        assert_eq!(stand.deleted.len(), 2);
        assert!(stand.keys.is_empty());
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_key_that_cannot_be_deleted_keeps_its_directory_without_a_record() {
        let root = dir("left");
        let mut stand = Stand {
            refuse_mac: Some((0, Failure::Locked)),
            refuse_delete: Some((0, Failure::Transient)),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Locked));
        assert_eq!(stand.keys.len(), 2);
        let dirs = entries(&root);
        assert_eq!(dirs.len(), 1);
        assert_eq!(entries(&root.join(&dirs[0])), [LOCK]);
        let id = Id::parse(&dirs[0]).unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::Damaged);
    }

    #[test]
    fn from_api_35_the_key_works_only_while_unlocked() {
        for (api, unlocked) in [(28, false), (34, false), (35, true), (37, true)] {
            let root = dir(&format!("unlocked-{api}"));
            let mut stand = Stand {
                api,
                ..Stand::new()
            };
            let id = Profile::create(&root, &mut stand, false).unwrap().id();
            // The key of the sign of the fingerprints needs the owner at every use, which is more
            // than an unlocked device, so it is made without that flag.
            assert_eq!(
                stand.generated,
                [(true, unlocked), (true, unlocked), (true, false)]
            );
            assert_eq!(Profile::open(&root, id).unwrap().unlocked_only(), unlocked);
        }
    }

    #[test]
    fn a_key_only_software_holds_needs_consent() {
        for level in [Level::Software, Level::Unknown] {
            let root = dir(&format!("software-{level:?}"));
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
        let root = dir("check");
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
        let root = dir("tag");
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
        let root = dir("refused");
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
        let root = dir("taken");
        let mut stand = Stand {
            taken: true,
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Damaged);
        assert_eq!(stand.generated, [] as [(bool, bool); 0]);
        assert_eq!(stand.deleted, [] as [String; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
        stand.taken = false;
        stand.refuse_contains = Some(Failure::Transient);
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Transient));
        assert_eq!(stand.generated, [] as [(bool, bool); 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_replaced_key_is_told_from_a_wrong_password() {
        let root = dir("replaced");
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
        let root = dir("changed");
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
        let root = dir("never");
        let id = Id::parse("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::NotFound);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_failure_to_look_is_no_missing_profile() {
        let root = dir("look");
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
        let root = dir("damaged");
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
        let root = dir("files");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        assert_eq!(
            entries(&root.join(id.to_string())),
            [CURRENT, crate::guard::GUARDS, LOCK, RECORD, "root-0"]
        );
        assert_eq!(
            stand.names(),
            [
                format!("lethewis/{id}/chip"),
                root_alias(id, 0),
                format!("lethewis/{id}/watch")
            ]
        );
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
        let root = dir("debug");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let shown = format!("{profile:?}");
        assert!(shown.contains(&profile.id().to_string()), "{shown}");
        assert!(shown.contains("StrongBox"), "{shown}");
        assert!(!shown.contains("check"), "{shown}");
    }

    #[test]
    fn a_creation_waits_for_a_sweep_under_way() {
        let root = dir("waits");
        let sweeping = File::open(&*root).unwrap();
        sweeping.lock().unwrap();
        let (done, finished) = mpsc::channel();
        let path = root.to_path_buf();
        let creating = thread::spawn(move || {
            let created = Profile::create(&path, &mut Stand::new(), false).map(|made| made.id());
            done.send(()).unwrap();
            created
        });
        assert!(finished.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(entries(&root), [] as [String; 0]);
        drop(sweeping);
        assert!(creating.join().unwrap().is_ok());
    }

    #[test]
    fn a_creation_that_fails_after_its_record_leaves_it_to_the_sweep() {
        let root = dir("after-record");
        let mut stand = Stand {
            refuse_delete: Some((0, Failure::Transient)),
            ..Stand::new()
        };
        // Syncs up to that of the signs watched pass; the record's fails.
        fail_syncs(4, 1);
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Io(io::ErrorKind::Other));
        // The record's check and tag were answered, so it was written.
        assert_eq!(stand.macs, 5);
        let left = entries(&root);
        assert_eq!(left.len(), 1);
        assert!(!root.join(&left[0]).join(RECORD).exists());
        assert!(!root.join(&left[0]).join(DESTROYED).exists());
        stand.refuse_delete = None;
        assert_eq!(
            crate::sweep(&root, &mut stand),
            Ok(Some(Erasure::NotErased))
        );
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_creation_that_fails_with_one_key_left_leaves_its_directory() {
        let root = dir("key-left");
        // The chip's key is deleted, the root's is not.
        let mut stand = Stand {
            refuse_delete: Some((1, Failure::Transient)),
            ..Stand::new()
        };
        fail_syncs(4, 1);
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Io(io::ErrorKind::Other));
        assert_eq!(stand.names().len(), 2);
        assert_eq!(entries(&root).len(), 1);
    }

    #[test]
    fn a_creation_whose_record_cannot_be_removed_is_marked_destroyed() {
        let root = dir("unremoved");
        let mut stand = Stand {
            refuse_delete: Some((0, Failure::Transient)),
            ..Stand::new()
        };
        fail_syncs(4, 1);
        fail_removal();
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Io(io::ErrorKind::Other));
        let left = entries(&root);
        assert!(root.join(&left[0]).join(RECORD).exists());
        assert!(root.join(&left[0]).join(DESTROYED).exists());
    }

    #[test]
    fn a_creation_whose_record_is_not_surely_removed_is_marked_destroyed() {
        let root = dir("marked");
        let mut stand = Stand {
            refuse_delete: Some((0, Failure::Transient)),
            ..Stand::new()
        };
        // The record's sync fails, and so does the sync of its removal.
        fail_syncs(4, 2);
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Io(io::ErrorKind::Other));
        assert_eq!(stand.macs, 5);
        let left = entries(&root);
        assert!(root.join(&left[0]).join(DESTROYED).exists());
        stand.refuse_delete = None;
        assert_eq!(
            crate::sweep(&root, &mut stand),
            Ok(Some(Erasure::NotErased))
        );
        assert_eq!(stand.names(), [] as [&str; 0]);
    }

    #[test]
    fn a_failure_to_look_for_a_file_is_no_answer() {
        let root = dir("look");
        let file = root.join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(super::exists(&file).ok(), Some(true));
        assert_eq!(super::exists(&root.join("missing")).ok(), Some(false));
        assert!(super::exists(&file.join("under")).is_err());
    }

    #[test]
    fn every_error_reads_differently() {
        let errors = [
            Error::Busy,
            Error::NotFound,
            Error::BackedUp,
            Error::Damaged,
            Error::ChipChanged,
            Error::SoftwareOnly,
            Error::Unwatchable(Watchable::Ready),
            Error::Unwatchable(Watchable::NoLockScreen),
            Error::Unwatchable(Watchable::NothingEnrolled),
            Error::Unwatchable(Watchable::NotNow),
            Error::Unwatchable(Watchable::Never),
            Error::Unexplained(Failure::Unknown),
            Error::Unexplained(Failure::Transient),
            Error::NoEpoch,
            Error::Changing,
            Error::Exhausted,
            Error::Unsettled,
            Error::WrongPassword,
            Error::SamePassword,
            Error::Exists,
            Error::NoKey,
            Error::Unread,
            Error::Locked,
            Error::SharesSet,
            Error::NoWayOut,
            Error::TimeLockSet,
            Error::Unsynced(io::ErrorKind::NotFound),
            Error::Core(lethewis_core::Error::StaleRecord),
            Error::Keystore(Failure::Transient),
            Error::Keystore(Failure::Locked),
            Error::Keystore(Failure::Absent),
            Error::Keystore(Failure::Corrupted),
            Error::Keystore(Failure::StrongBoxUnavailable),
            Error::Keystore(Failure::Refused),
            Error::Keystore(Failure::Unknown),
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
