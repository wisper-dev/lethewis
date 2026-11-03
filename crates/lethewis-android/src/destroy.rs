// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, DirEntry, File};
use std::io;
use std::path::Path;

use lethewis_core::Erasure;

use crate::epoch::{CURRENT, ROOT, erase_root, number_of, root_numbers, worse};
use crate::keystore::{Keystore, Level};
use crate::profile::{
    DESTROYED, Error, Id, LOCK, Profile, RECORD, WRITING, alias, exists, lock, mark_destroyed,
    sync_dir,
};

/// What the directory of a destroyed profile is renamed with once its keys are gone, so that it is
/// no profile to open.
const GONE: &str = "gone";

impl Profile {
    /// Destroys the profile: marks it destroyed, then deletes the keys of the chip and of every
    /// root, then its directory. Returns how surely the keys are gone.
    ///
    /// # Errors
    ///
    /// The file system's failure to mark the profile, or the keystore's. Once the mark is written,
    /// the profile reads as not found, and [`sweep`] finishes what this call could not.
    pub fn destroy(self, keystore: &mut impl Keystore) -> Result<Erasure, Error> {
        mark_destroyed(&self.dir)?;
        // The level the record states counts only once the chip's key confirms it.
        let level = self.verify(keystore).is_ok().then_some(self.record.level);
        finish(&self.dir, self.id, level, keystore)
    }
}

/// Finishes what interrupted creations and destructions of profiles under `root` left: deletes
/// their keys and the files a profile keeps. A profile open elsewhere is left for later, and a
/// creation waits for the sweep. Returns how surely the keys are gone, if there were any or a
/// profile could not be checked.
///
/// # Errors
///
/// The file system's failure to lock or list `root`. A profile it cannot finish stays for the next
/// sweep.
pub fn sweep(root: &Path, keystore: &mut impl Keystore) -> Result<Option<Erasure>, Error> {
    // Held alone, so that a directory without its record is never one being created.
    let sweeping = File::open(root)?;
    sweeping.lock()?;
    let mut erasure = None;
    for entry in fs::read_dir(root)? {
        let gone = entry.map_or(Some(Erasure::NotErased), |entry| {
            sweep_one(root, &entry, keystore)
        });
        if let Some(gone) = gone {
            erasure = Some(erasure.map_or(gone, |so_far| worse(so_far, gone)));
        }
    }
    Ok(erasure)
}

/// Finishes the profile `entry` of `root` if it was left unfinished; returns how surely its keys
/// are gone, or none if there was nothing to finish.
fn sweep_one(root: &Path, entry: &DirEntry, keystore: &mut impl Keystore) -> Option<Erasure> {
    let name = entry.file_name();
    let name = name.to_str()?;
    let renamed = name
        .strip_suffix(GONE)
        .and_then(|stem| stem.strip_suffix('.'));
    let id = Id::parse(renamed.unwrap_or(name))?;
    // The type as listed: a link is never followed.
    match entry.file_type() {
        Ok(kind) if !kind.is_dir() => return None,
        Ok(_) => {}
        Err(_) => return Some(Erasure::NotErased),
    }
    let path = entry.path();
    let path = path.as_path();
    if renamed.is_some() {
        // Its keys went before the renaming, so only files are left.
        let _ = remove_files(path).and_then(|()| sync_dir(root));
        return None;
    }
    // Only a directory left unfinished is locked, so that an opening meanwhile is not refused.
    if unfinished(path) == Some(false) {
        return None;
    }
    match lock(path) {
        Err(Error::Busy | Error::Io(io::ErrorKind::NotFound)) => None,
        Err(_) => Some(Erasure::NotErased),
        Ok(_lock) => match unfinished(path) {
            Some(false) => None,
            // A profile left for the next sweep still holds what it held.
            Some(true) => Some(finish(path, id, None, keystore).unwrap_or(Erasure::NotErased)),
            None => Some(Erasure::NotErased),
        },
    }
}

/// Whether the profile in `dir` is marked destroyed or has no record, if the file system tells.
fn unfinished(dir: &Path) -> Option<bool> {
    let destroyed = exists(&dir.join(DESTROYED)).ok()?;
    let recorded = exists(&dir.join(RECORD)).ok()?;
    Some(destroyed || !recorded)
}

/// Deletes the keys of the profile `id`, then its directory `dir`; `level` is where the chip's key
/// is held, if known. Returns how surely the keys are gone.
fn finish(
    dir: &Path,
    id: Id,
    level: Option<Level>,
    keystore: &mut impl Keystore,
) -> Result<Erasure, Error> {
    let mut erasure = Erasure::BestEffort;
    let (numbers, mut failed) = root_numbers(dir, id, keystore);
    for number in numbers {
        let (gone, failure) = erase_root(dir, id, number, None, keystore);
        erasure = worse(erasure, gone);
        failed = failed.or(failure);
    }
    match keystore.delete(&alias(id)) {
        Ok(()) if level.is_some_and(Level::secure) => {}
        Ok(()) => erasure = Erasure::NotErased,
        Err(failure) => failed = failed.or(Some(failure)),
    }
    if let Some(failure) = failed {
        return Err(Error::Keystore(failure));
    }
    // With the keys gone, what a failure leaves of the directory is files a sweep removes.
    let _ = remove_dir(dir);
    Ok(erasure)
}

/// Renames the directory of a profile whose keys are gone, so that it is no profile to open, then
/// removes it.
fn remove_dir(dir: &Path) -> io::Result<()> {
    let gone = dir.with_extension(GONE);
    fs::rename(dir, &gone)?;
    let root = dir.parent().unwrap_or(Path::new(""));
    sync_dir(root)?;
    remove_files(&gone)?;
    sync_dir(root)
}

/// Removes the files a profile keeps in `dir`, then `dir` if nothing else is left in it.
fn remove_files(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_profile_file)
        {
            match fs::remove_file(&path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
    }
    fs::remove_dir(dir)
}

/// Whether a profile names a file of its own `name`.
fn is_profile_file(name: &str) -> bool {
    let name = name.strip_suffix(WRITING).unwrap_or(name);
    [RECORD, CURRENT, LOCK, DESTROYED].contains(&name)
        || name
            .strip_prefix(ROOT)
            .and_then(|digits| number_of(digits.as_bytes()))
            .is_some()
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use lethewis_core::Erasure;

    use super::sweep;
    use crate::epoch::root_alias;
    use crate::keystore::{Failure, Level};
    use crate::profile::{DESTROYED, Error, LOCK, Profile, RECORD, lock};
    use crate::stand::{Stand, dir, entries};

    #[test]
    fn a_destroyed_profile_leaves_no_key_and_no_directory() {
        let root = dir("destroyed");
        let mut stand = Stand::new();
        let mut profile = Profile::create(&root, &mut stand, false).unwrap();
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        let id = profile.id();
        assert_eq!(profile.destroy(&mut stand), Ok(Erasure::BestEffort));
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn a_destruction_cut_short_is_finished_by_a_sweep() {
        let root = dir("finished");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let id = profile.id();
        stand.refuse_delete = Some(Failure::Transient);
        let destroyed = profile.destroy(&mut stand);
        assert_eq!(destroyed, Err(Error::Keystore(Failure::Transient)));
        assert!(root.join(id.to_string()).join(DESTROYED).exists());
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::NotFound);
        assert_eq!(sweep(&root, &mut stand), Ok(Some(Erasure::NotErased)));
        assert!(root.join(id.to_string()).join(DESTROYED).exists());
        stand.refuse_delete = None;
        // The chip's level is not confirmed without the profile, so it is not counted as erased.
        assert_eq!(sweep(&root, &mut stand), Ok(Some(Erasure::NotErased)));
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_sweep_finishes_a_creation_cut_short() {
        let root = dir("cut");
        let mut stand = Stand {
            refuse_mac: Some((2, Failure::Locked)),
            refuse_delete: Some(Failure::Transient),
            ..Stand::new()
        };
        let created = Profile::create(&root, &mut stand, false);
        assert_eq!(created.unwrap_err(), Error::Keystore(Failure::Locked));
        assert_eq!(entries(&root).len(), 1);
        stand.refuse_delete = None;
        assert_eq!(sweep(&root, &mut stand), Ok(Some(Erasure::NotErased)));
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_sweep_leaves_whole_profiles_and_profiles_open_elsewhere() {
        let root = dir("leaves");
        let mut stand = Stand::new();
        let whole = Profile::create(&root, &mut stand, false).unwrap().id();
        let open = Profile::create(&root, &mut stand, false).unwrap();
        File::create(root.join(open.id().to_string()).join(DESTROYED)).unwrap();
        fs::create_dir(root.join("not a profile")).unwrap();
        let names = stand.keys.len();
        assert_eq!(sweep(&root, &mut stand), Ok(None));
        assert_eq!(stand.keys.len(), names);
        drop(open);
        assert!(sweep(&root, &mut stand).unwrap().is_some());
        assert_eq!(
            entries(&root),
            [whole.to_string(), "not a profile".to_owned()]
        );
        let _held = lock(&root.join(whole.to_string())).unwrap();
        assert!(Profile::open(&root, whole).is_err());
    }

    #[test]
    fn a_listing_that_fails_keeps_the_directory_for_the_next_sweep() {
        let root = dir("listing");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let id = profile.id();
        // A key with no file, which only the listing finds.
        stand.keys.insert(root_alias(id, 5), [5; 32]);
        stand.refuse_aliases = Some(Failure::Transient);
        let destroyed = profile.destroy(&mut stand);
        assert_eq!(destroyed, Err(Error::Keystore(Failure::Transient)));
        assert!(root.join(id.to_string()).join(DESTROYED).exists());
        assert_eq!(stand.names(), [root_alias(id, 5)]);
        stand.refuse_aliases = None;
        assert_eq!(sweep(&root, &mut stand), Ok(Some(Erasure::NotErased)));
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn what_a_destruction_renamed_is_removed_by_a_sweep() {
        let root = dir("renamed");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let gone = root.join(format!("{id}.gone"));
        fs::rename(root.join(id.to_string()), &gone).unwrap();
        fs::create_dir(root.join("not a profile.gone")).unwrap();
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::NotFound);
        assert_eq!(sweep(&root, &mut stand), Ok(None));
        assert!(!gone.exists());
        assert_eq!(entries(&root), ["not a profile.gone"]);
    }

    #[test]
    fn a_profile_to_finish_that_cannot_be_locked_is_not_counted_as_erased() {
        let root = dir("unlockable");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let home = root.join(id.to_string());
        File::create(home.join(DESTROYED)).unwrap();
        fs::set_permissions(home.join(LOCK), fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(sweep(&root, &mut stand), Ok(Some(Erasure::NotErased)));
        assert_eq!(stand.keys.len(), 2);
    }

    #[test]
    fn a_sweep_removes_only_the_files_of_a_profile() {
        let root = dir("only");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let home = root.join(id.to_string());
        fs::remove_file(home.join(RECORD)).unwrap();
        fs::create_dir(home.join("kept")).unwrap();
        assert_eq!(sweep(&root, &mut stand), Ok(Some(Erasure::NotErased)));
        assert_eq!(stand.names(), [] as [&str; 0]);
        let gone = format!("{id}.gone");
        assert_eq!(entries(&root), [gone.as_str()]);
        assert_eq!(entries(&root.join(gone)), ["kept"]);
    }

    #[test]
    fn a_destruction_that_cannot_remove_its_directory_still_reports_its_keys() {
        let root = dir("unremoved");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let id = profile.id();
        fs::set_permissions(&*root, fs::Permissions::from_mode(0o500)).unwrap();
        let destroyed = profile.destroy(&mut stand);
        fs::set_permissions(&*root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(destroyed, Ok(Erasure::BestEffort));
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(Profile::open(&root, id).unwrap_err(), Error::NotFound);
        assert!(sweep(&root, &mut stand).unwrap().is_some());
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_sweep_follows_no_link() {
        let root = dir("links");
        let other = dir("other");
        File::create(other.join(RECORD)).unwrap();
        File::create(other.join(DESTROYED)).unwrap();
        for name in [
            "00112233445566778899aabbccddeeff.gone",
            "00112233445566778899aabbccddeef0",
        ] {
            symlink(&*other, root.join(name)).unwrap();
        }
        let mut stand = Stand::new();
        assert_eq!(sweep(&root, &mut stand), Ok(None));
        assert_eq!(entries(&other), [DESTROYED, RECORD]);
        assert_eq!(entries(&root).len(), 2);
    }

    #[test]
    fn a_sweep_waits_for_a_creation_under_way() {
        let root = dir("waits");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        let home = root.join(id.to_string());
        // A directory without its record, as a creation has it before its lock is taken.
        fs::remove_file(home.join(RECORD)).unwrap();
        let creating = File::open(&*root).unwrap();
        creating.lock_shared().unwrap();
        let (done, finished) = mpsc::channel();
        let path = root.to_path_buf();
        let sweeping = thread::spawn(move || {
            let swept = sweep(&path, &mut stand);
            done.send(()).unwrap();
            swept
        });
        assert!(finished.recv_timeout(Duration::from_millis(200)).is_err());
        assert!(home.exists());
        drop(creating);
        assert_eq!(sweeping.join().unwrap(), Ok(Some(Erasure::NotErased)));
        assert!(!home.exists());
    }

    #[test]
    fn a_chip_key_only_software_holds_is_not_surely_erased() {
        let root = dir("soft");
        let mut stand = Stand {
            strong_box: false,
            level: Level::Software,
            ..Stand::new()
        };
        let profile = Profile::create(&root, &mut stand, true).unwrap();
        assert_eq!(profile.destroy(&mut stand), Ok(Erasure::NotErased));
        assert_eq!(stand.names(), [] as [&str; 0]);
    }
}
