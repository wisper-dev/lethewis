// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! What the tests of every module stand on: a keystore in memory and directories of their own.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::keystore::{Failure, Keystore, Level};

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
    pub(crate) refuse_delete: Option<Failure>,
    pub(crate) refuse_aliases: Option<Failure>,
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
            generated: Vec::new(),
            deleted: Vec::new(),
        }
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
        if let Some(failure) = self.refuse_delete {
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A directory named after the test that asks for it, which the test harness names its thread
/// after, so that tests running at once never share one.
pub(crate) fn dir(name: &str) -> Dir {
    let test = std::thread::current()
        .name()
        .unwrap_or_default()
        .replace("::", "-");
    let dir = std::env::temp_dir().join(format!(
        "lethewis-android-{}-{test}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

thread_local! {
    /// How many syncs of a directory pass on this thread, then how many fail.
    static SYNCS: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
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

/// The names in `dir`, in order.
pub(crate) fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}
