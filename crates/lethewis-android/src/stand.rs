// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! What the tests of every module stand on: a keystore in memory and directories of their own.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use hmac::{Hmac, KeyInit, Mac};
use lethewis_core::{
    Entropy, EntropyError, Epoch, KeyLength, MemoryBlock, PasswordParams, Position, Purpose,
    RECORD_LEN, Slot, Slots,
};
use sha2::Sha256;

use crate::keystore::{Failure, Keystore, Level, Unwatchable, Watched};
use crate::profile::{Id, Profile};

/// A keystore in memory: a key is 32 bytes, each new one different.
pub(crate) struct Stand {
    pub(crate) api: u32,
    pub(crate) strong_box: bool,
    pub(crate) level: Level,
    pub(crate) keys: BTreeMap<String, [u8; 32]>,
    pub(crate) made: u8,
    pub(crate) taken: bool,
    pub(crate) refuse_contains: Option<Failure>,
    pub(crate) refuse_generate: Option<Failure>,
    pub(crate) refuse_after_making: Option<Failure>,
    /// The number of answers given before the keystore refuses, and how.
    pub(crate) refuse_mac: Option<(usize, Failure)>,
    pub(crate) macs: usize,
    /// The number of keys deleted before the keystore refuses, and how.
    pub(crate) refuse_delete: Option<(usize, Failure)>,
    pub(crate) refuse_aliases: Option<Failure>,
    /// What the keystore says of each key of a watched sign, by its name.
    pub(crate) watched: BTreeMap<String, Watched>,
    pub(crate) refuse_watched: Option<Failure>,
    /// What the device lacks for a watched key, which the system refuses unless it lacks nothing.
    pub(crate) unwatchable: Option<Unwatchable>,
    /// Where the system refuses a watched key even though the device lacks nothing.
    pub(crate) refuses_watched_key: Option<Refusal>,
    /// How the keystore fails to make a watched key.
    pub(crate) refuse_watched_key: Option<Failure>,
    /// How the device fails to tell what it lacks.
    pub(crate) refuse_unwatchable: Option<Failure>,
    pub(crate) generated: Vec<(bool, bool)>,
    pub(crate) deleted: Vec<String>,
}

impl Stand {
    pub(crate) fn new() -> Self {
        Self {
            api: 34,
            strong_box: true,
            level: Level::TrustedEnvironment,
            keys: BTreeMap::new(),
            made: 0,
            taken: false,
            refuse_contains: None,
            refuse_generate: None,
            refuse_after_making: None,
            refuse_mac: None,
            macs: 0,
            refuse_delete: None,
            refuse_aliases: None,
            watched: BTreeMap::new(),
            refuse_watched: None,
            unwatchable: None,
            refuses_watched_key: None,
            refuse_watched_key: None,
            refuse_unwatchable: None,
            generated: Vec::new(),
            deleted: Vec::new(),
        }
    }

    /// Makes the keystore say that the key `alias` of a watched sign is gone.
    pub(crate) fn gone(&mut self, alias: &str) {
        self.watched.insert(alias.to_owned(), Watched::Gone);
    }

    /// The names of the keys held, in order.
    pub(crate) fn names(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }
}

impl Keystore for Stand {
    fn api_level(&self) -> u32 {
        self.api
    }

    fn contains(&mut self, alias: &str) -> Result<bool, Failure> {
        if let Some(failure) = self.refuse_contains {
            return Err(failure);
        }
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

    fn generate_watched(
        &mut self,
        alias: &str,
        strong_box: bool,
    ) -> Result<Option<Level>, Failure> {
        if let Some(failure) = self.refuse_watched_key {
            return Err(failure);
        }
        let refused = match self.refuses_watched_key {
            Some(Refusal::Anywhere) => true,
            Some(Refusal::InStrongBox) => strong_box,
            None => false,
        };
        if refused || self.unwatchable.is_some() {
            return Ok(None);
        }
        let level = self.generate(alias, strong_box, false)?;
        self.watched.insert(alias.to_owned(), Watched::Kept);
        Ok(Some(level))
    }

    fn unwatchable(&mut self) -> Result<Option<Unwatchable>, Failure> {
        self.refuse_unwatchable.map_or(Ok(self.unwatchable), Err)
    }

    fn watched(&mut self, alias: &str) -> Result<Watched, Failure> {
        if let Some(failure) = self.refuse_watched {
            return Err(failure);
        }
        if !self.keys.contains_key(alias) {
            return Ok(Watched::Gone);
        }
        Ok(self.watched.get(alias).copied().unwrap_or(Watched::Kept))
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

    fn aliases(&mut self, prefix: &str) -> Result<Vec<String>, Failure> {
        if let Some(failure) = self.refuse_aliases {
            return Err(failure);
        }
        Ok(self
            .keys
            .keys()
            .filter(|alias| alias.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn delete(&mut self, alias: &str) -> Result<(), Failure> {
        if let Some((after, failure)) = self.refuse_delete
            && self.deleted.len() >= after
        {
            return Err(failure);
        }
        self.deleted.push(alias.to_owned());
        self.keys.remove(alias);
        Ok(())
    }
}

pub(crate) fn hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// An empty directory of its own for each test, removed with it.
pub(crate) struct Dir(PathBuf);

impl Deref for Dir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

/// A directory named `no_backup`, as profiles need, in one named after the test that asks for it,
/// which the test harness names its thread after, so that tests running at once never share one.
pub(crate) fn dir(name: &str) -> Dir {
    let test = std::thread::current()
        .name()
        .unwrap_or_default()
        .replace("::", "-");
    let parent = std::env::temp_dir().join(format!(
        "lethewis-android-{}-{test}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&parent);
    let dir = parent.join("no_backup");
    std::fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

thread_local! {
    /// How many syncs of a directory pass on this thread, then how many fail.
    static SYNCS: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
    /// How many tags and records of the ways in an entry has tried on this thread.
    static TRIES: Cell<u32> = const { Cell::new(0) };
}

/// Counts a tag or a record of a way in an entry tried.
pub(crate) fn tried() {
    TRIES.set(TRIES.get().saturating_add(1));
}

/// How many tags and records entries have tried on this thread, counting from zero again.
pub(crate) fn tries() -> u32 {
    TRIES.replace(0)
}

/// Makes the syncs of a directory on this thread fail, `failing` of them after `passing` others.
pub(crate) fn fail_syncs(passing: u32, failing: u32) {
    SYNCS.set((passing, failing));
}

/// The failure [`fail_syncs`] asked for, when its turn comes.
pub(crate) fn sync_failure() -> io::Result<()> {
    match SYNCS.get() {
        (0, 0) => Ok(()),
        (0, failing) => {
            SYNCS.set((0, failing.saturating_sub(1)));
            Err(io::Error::other("a sync made to fail"))
        }
        (passing, failing) => {
            SYNCS.set((passing.saturating_sub(1), failing));
            Ok(())
        }
    }
}

thread_local! {
    /// Whether the next removal of a record on this thread fails.
    static REMOVAL: Cell<bool> = const { Cell::new(false) };
}

/// Makes the next removal of a record on this thread fail.
pub(crate) fn fail_removal() {
    REMOVAL.set(true);
}

/// The failure [`fail_removal`] asked for, once.
pub(crate) fn removal_failure() -> io::Result<()> {
    if REMOVAL.replace(false) {
        Err(io::Error::other("a removal made to fail"))
    } else {
        Ok(())
    }
}

pub(crate) const OWNER: &[u8] = b"correct horse";
pub(crate) const DURESS: &[u8] = b"battery staple";
pub(crate) const OTHER: &[u8] = b"wrong guess";

/// Other bytes on every call, the same in every run.
pub(crate) struct Source(pub(crate) u64);

impl Entropy for Source {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = self.0.to_le_bytes()[7];
        }
        Ok(())
    }
}

/// A profile whose owner's password is [`OWNER`], its epoch read, with a key of external data its
/// stored key wraps.
pub(crate) struct Made {
    pub(crate) profile: Profile,
    pub(crate) params: PasswordParams,
    pub(crate) epoch_key: [u8; 32],
    pub(crate) wrapped: [u8; RECORD_LEN],
    pub(crate) data: [u8; 32],
}

/// The slots of a [`Made`]'s epoch, and memory for a derivation.
pub(crate) struct Work {
    pub(crate) memory: Vec<MemoryBlock>,
    pub(crate) slots: [Slot; 6],
    pub(crate) epoch: Epoch,
}

impl Work {
    pub(crate) fn new(params: &PasswordParams) -> Self {
        Self {
            memory: vec![MemoryBlock::new(); params.memory_blocks()],
            slots: [const { Slot::empty() }; 6],
            epoch: Epoch::empty(),
        }
    }
}

pub(crate) fn made(root: &Path, stand: &mut Stand, seed: u64) -> Made {
    let mut source = Source(seed);
    let mut profile = Profile::create(root, stand, false).unwrap();
    let mut epoch_key = [0; 32];
    profile.epoch(stand, &mut epoch_key).unwrap();
    let params = PasswordParams::new(65_536, 3, &mut source).unwrap();
    let mut work = Work::new(&params);
    let mut slots = Slots::new(&mut work.slots, &mut work.epoch, 0, &mut epoch_key.clone());
    let stored = slots
        .generate(Purpose::Wrap, KeyLength::Bytes64, &mut source)
        .unwrap();
    let created = slots
        .generate(Purpose::ExternalData, KeyLength::Bytes32, &mut source)
        .unwrap();
    let mut wrapped = [0; RECORD_LEN];
    slots
        .wrap(created, stored, b"data", &mut source, &mut wrapped)
        .unwrap();
    let mut data = [0; 32];
    slots
        .reveal32(created, Position::First, Purpose::ExternalData, &mut data)
        .unwrap();
    profile
        .create_entries(
            &mut slots,
            stand,
            stored,
            &mut OWNER.to_vec(),
            &params,
            &mut work.memory,
            &mut source,
        )
        .unwrap();
    Made {
        profile,
        params,
        epoch_key,
        wrapped,
        data,
    }
}

/// Where the system refuses a watched key: in the secure element alone, or anywhere.
#[derive(Clone, Copy)]
pub(crate) enum Refusal {
    InStrongBox,
    Anywhere,
}

/// Where a test's profile starts: without a password under duress, with [`DURESS`], or with
/// [`DURESS`] set to destroy.
#[derive(Clone, Copy)]
pub(crate) enum Start {
    Plain,
    Duress,
    Destroy,
}

/// A profile made once for all the tests that start from it: its files and its keys.
pub(crate) struct Template {
    id: Id,
    files: Vec<(OsString, Vec<u8>)>,
    keys: BTreeMap<String, [u8; 32]>,
    keys_made: u8,
    params: PasswordParams,
    wrapped: [u8; RECORD_LEN],
    data: [u8; 32],
}

fn template(start: Start) -> &'static Template {
    static TEMPLATES: [OnceLock<Template>; 3] = [const { OnceLock::new() }; 3];
    TEMPLATES[start as usize].get_or_init(|| {
        let root = dir(&format!("template-{}", start as usize));
        let mut stand = Stand::new();
        let made = made(&root, &mut stand, 100);
        if let Start::Duress | Start::Destroy = start {
            let mut work = Work::new(&made.params);
            let mut slots = Slots::new(
                &mut work.slots,
                &mut work.epoch,
                0,
                &mut made.epoch_key.clone(),
            );
            made.profile
                .set_duress(
                    &mut slots,
                    &mut stand,
                    &mut OWNER.to_vec(),
                    &mut DURESS.to_vec(),
                    matches!(start, Start::Destroy),
                    &made.params,
                    &mut work.memory,
                    &mut Source(99),
                )
                .unwrap();
        }
        let files = std::fs::read_dir(&made.profile.dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect();
        Template {
            id: made.profile.id(),
            files,
            keys: stand.keys.clone(),
            keys_made: stand.made,
            params: made.params,
            wrapped: made.wrapped,
            data: made.data,
        }
    })
}

/// A copy under `root` of the profile `start` names, its keys in `stand`: its passwords are not
/// derived again, which takes seconds in an unoptimised build.
pub(crate) fn copied(root: &Path, stand: &mut Stand, start: Start) -> Made {
    let template = template(start);
    let home = root.join(template.id.to_string());
    std::fs::create_dir(&home).unwrap();
    for (name, bytes) in &template.files {
        std::fs::write(home.join(name), bytes).unwrap();
    }
    stand.keys.extend(template.keys.clone());
    stand.made = stand.made.max(template.keys_made);
    let mut profile = Profile::open(root, template.id).unwrap();
    let mut epoch_key = [0; 32];
    profile.epoch(stand, &mut epoch_key).unwrap();
    Made {
        profile,
        params: template.params,
        epoch_key,
        wrapped: template.wrapped,
        data: template.data,
    }
}

/// Whether every one of the six slots is free: nothing an operation left behind holds one.
pub(crate) fn all_free(slots: &mut Slots<'_>) -> bool {
    let mut source = Source(77);
    let taken: Vec<_> = (0..6)
        .map_while(|_| {
            slots
                .generate(Purpose::Wrap, KeyLength::Bytes32, &mut source)
                .ok()
        })
        .collect();
    let free = taken.len() == 6;
    for handle in taken {
        slots.release(handle).unwrap();
    }
    free
}

/// The names in `dir`, in order.
pub(crate) fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}
