// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Signs that the device was tampered with, in one file of a fixed size: for each sign a tag of the
//! reading the owner accepted and a tag of what is to happen when a reading differs. Both are keyed
//! by the chip's answer to a challenge of this module, so a judgement needs the device but no
//! password. The file holds no value to read: a tag is compared with the tags of every reading or
//! action in question.
//!
//! Only the owner's password writes the file through this library. The key of the tags needs no
//! password, so code that reaches the chip reads what each sign does and writes the file itself:
//! what guards it is the platform's hold on the application's files and on the chip's key.

use lethewis_core::{
    Entropy, EntropyError, Error as CoreError, MemoryBlock, PasswordParams, Slots,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::epoch::Written;
use crate::keystore::Keystore;
use crate::profile::{Error, Profile, answer_of, fill_random, read_file, same_mac, write_file};

/// The file of the signs watched, one for the profile: its tags hold no epoch, and a change of
/// epoch leaves them as they are.
pub(crate) const GUARDS: &str = "guards";

const CHALLENGE_LABEL: &[u8; 24] = b"lethewis guard challenge";
const KEY_LABEL: &[u8; 23] = b"lethewis guard tag key ";
const READING_LABEL: &[u8; 22] = b"lethewis guard reading";
const UNACCEPTED_LABEL: &[u8; 25] = b"lethewis guard unaccepted";
const ACTION_LABEL: &[u8; 21] = b"lethewis guard action";
const ALONE_LABEL: &[u8; 20] = b"lethewis guard alone";
const SALT_LEN: usize = 32;

/// How many signs a profile can watch.
pub const SIGN_COUNT: usize = 4;

/// The size of the tags of one sign in the file, in bytes.
const WATCH_LEN: usize = 64;

pub(crate) const GUARDS_LEN: usize = SALT_LEN + SIGN_COUNT * WATCH_LEN + 32;

// The layout is written and read sign by sign, so a sign added fails to compile until it has its
// place there.
const _: [(); 4] = [(); SIGN_COUNT];

/// A sign that the device, or what the system holds about it, is not as the owner left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    /// The fingerprints enrolled and the lock screen. The reading tells whether a key of the chip
    /// that enrolling one invalidates still answers: a key that is gone answers nothing, which is
    /// itself the reading to give.
    Fingerprints,
    /// How many times the device has started.
    Boots,
    /// Whether the system allows debugging over USB.
    Debugging,
    /// The cards of the subscriptions in the device.
    Cards,
}

/// The signs in the order of a reading and of a verdict.
pub const SIGNS: [Sign; SIGN_COUNT] = [
    Sign::Fingerprints,
    Sign::Boots,
    Sign::Debugging,
    Sign::Cards,
];

/// What is to happen when a sign's reading differs from the one accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Action {
    /// Nothing: the sign is not watched.
    #[default]
    Ignore,
    /// The caller is told, and decides.
    Report,
    /// The profile is to be destroyed, as [`Verdict::destroy`] says.
    Destroy,
}

/// Every action, so that a judgement compares them all. An action added needs a code in
/// [`Action::code`], which fails to compile without one.
const ACTIONS: [Action; 3] = [Action::Ignore, Action::Report, Action::Destroy];

/// What the readings of the signs say, in the order of [`SIGNS`]: for each sign the bytes the
/// caller measured, of any length, or none for a sign it could not read at all.
///
/// A reading tells what was measured, a sign now unreadable included; a sign given none is judged
/// of nothing, and [`Verdict::unread`] leaves it to the caller.
pub type Readings<'a> = [Option<&'a [u8]>; SIGN_COUNT];

/// What a judgement of the signs found, each in the order of [`SIGNS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The signs whose reading differs from the one accepted.
    pub changed: [bool; SIGN_COUNT],
    /// The signs with no reading accepted, which nothing is compared with. A sign watched always
    /// has one, so these are signs the owner has never watched or has stopped watching.
    pub unaccepted: [bool; SIGN_COUNT],
    /// The signs that are watched and were given no reading: nothing is judged of them.
    pub unread: [bool; SIGN_COUNT],
    /// The signs that changed and whose action is [`Action::Report`].
    pub report: [bool; SIGN_COUNT],
    /// Whether the profile is to be destroyed: two signs of [`Action::Destroy`] changed, or one
    /// where the owner allowed one alone.
    pub destroy: bool,
    /// Whether the file holds a tag of no action this library writes: it was changed, and the signs
    /// of it are judged as [`Action::Ignore`].
    pub damaged: bool,
}

/// The key of the tags, from the chip's answer to the challenge of this module.
type GuardKey = Zeroizing<[u8; 32]>;

/// What the file of the signs holds.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Guards {
    salt: [u8; SALT_LEN],
    signs: [Watch; SIGN_COUNT],
    /// The tag of whether one sign alone destroys the profile.
    alone: [u8; 32],
}

/// What one sign holds: the tag of the reading accepted and the tag of its action.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Watch {
    accepted: [u8; 32],
    action: [u8; 32],
}

/// What a judgement found of one sign.
#[derive(Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "what one sign was found to be, each answer on its own"
)]
struct Found {
    changed: bool,
    unaccepted: bool,
    unread: bool,
    report: bool,
    /// It changed and is to destroy the profile, if enough signs are.
    destroying: bool,
    /// Its action is a tag of none this library writes.
    damaged: bool,
}

impl Found {
    const fn nothing() -> Self {
        Self {
            changed: false,
            unaccepted: false,
            unread: false,
            report: false,
            destroying: false,
            damaged: false,
        }
    }
}

/// What a judgement finds of `sign`, whose tags are `watch`.
fn judge_sign(
    key: &GuardKey,
    salt: &[u8; SALT_LEN],
    sign: Sign,
    watch: &Watch,
    readings: &Readings<'_>,
) -> Found {
    let action = action_of(key, salt, sign, watch);
    let mut found = Found {
        damaged: action.is_none(),
        ..Found::nothing()
    };
    let action = action.unwrap_or_default();
    let mut nothing = unaccepted_tag(key, salt, sign);
    found.unaccepted = same_mac(&nothing, &watch.accepted);
    nothing.zeroize();
    match readings.get(sign.at()).copied().flatten() {
        Some(reading) => {
            let mut tag = accepted_tag(key, salt, sign, reading);
            // Without a reading accepted there is nothing for this one to differ from.
            found.changed = !found.unaccepted && !same_mac(&tag, &watch.accepted);
            tag.zeroize();
            found.report = found.changed && action == Action::Report;
            found.destroying = found.changed && action == Action::Destroy;
        }
        None => found.unread = action != Action::Ignore,
    }
    found
}

impl Profile {
    /// Judges the signs: compares each reading with the one the owner accepted and tells what is to
    /// happen. It needs the chip but no password, and writes nothing, so a sign keeps firing until
    /// [`Profile::accept_signs`] takes its reading.
    ///
    /// The work does not tell what any action is: every action of every sign is compared.
    ///
    /// # Errors
    ///
    /// [`Error::Damaged`] for a file of another length, as [`Profile::verify`] for the chip, or the
    /// file system's failure.
    pub fn judge(
        &self,
        keystore: &mut impl Keystore,
        readings: &Readings<'_>,
    ) -> Result<Verdict, Error> {
        // The chip first: a replaced key is told, whatever the file holds.
        let key = self.guard_key(keystore)?;
        let guards = self.read_guards()?;
        let mut judged = [Found::nothing(); SIGN_COUNT];
        for ((found, sign), watch) in judged.iter_mut().zip(SIGNS).zip(&guards.signs) {
            *found = judge_sign(&key, &guards.salt, sign, watch, readings);
        }
        let alone = alone_of(&key, &guards);
        let destroying = judged.iter().filter(|found| found.destroying).count();
        Ok(Verdict {
            changed: judged.map(|found| found.changed),
            unaccepted: judged.map(|found| found.unaccepted),
            unread: judged.map(|found| found.unread),
            report: judged.map(|found| found.report),
            destroy: destroying >= 2 || (destroying == 1 && alone == Some(true)),
            damaged: alone.is_none() || judged.iter().any(|found| found.damaged),
        })
    }

    /// Sets what happens when each sign's reading differs, with the owner's password `owner`, and
    /// takes `readings` as accepted. With `alone`, one sign of [`Action::Destroy`] destroys the
    /// profile; without it two must have changed. `owner` is wiped. `slots` must not hold the
    /// stored key, which the core holds once only.
    ///
    /// It writes the file whole, so it also repairs one that was changed. Every sign watched needs
    /// its reading in the same call: a sign the caller cannot read is set to [`Action::Ignore`]
    /// first, and watched again once it reads.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassword`], [`Error::Unread`] for a sign watched and given no reading,
    /// [`Error::NoEpoch`], or the core's refusal, the keystore's or the file system's; the file
    /// then stays as it was. [`Error::Unsynced`] when it changed, but a crash may undo it.
    #[expect(
        clippy::too_many_arguments,
        reason = "what the signs do, the readings and a derivation's inputs"
    )]
    pub fn set_guards(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        actions: [Action; SIGN_COUNT],
        alone: bool,
        readings: &Readings<'_>,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        self.owner_given(slots, keystore, owner, params, memory)?;
        let key = self.guard_key(keystore)?;
        let guards = made_guards(&key, actions, alone, readings, entropy)?;
        self.write_guards(&guards)
    }

    /// Takes `readings` as accepted, with the owner's password `owner`: the signs of them fire no
    /// more. What each sign does is kept, and the tags are written anew with a fresh salt, so every
    /// sign watched needs a reading. `owner` is wiped. `slots` must not hold the stored key, which
    /// the core holds once only.
    ///
    /// # Errors
    ///
    /// As [`Profile::set_guards`], and [`Error::Damaged`] for a file of another length or one
    /// holding a tag of no action: what it keeps it must first be able to read.
    #[expect(
        clippy::too_many_arguments,
        reason = "the readings and a derivation's inputs, as the core takes them"
    )]
    pub fn accept_signs(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        readings: &Readings<'_>,
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        self.owner_given(slots, keystore, owner, params, memory)?;
        let guards = self.read_guards()?;
        let key = self.guard_key(keystore)?;
        let (actions, alone) = settings(&key, &guards)?;
        let guards = made_guards(&key, actions, alone, readings, entropy)?;
        self.write_guards(&guards)
    }

    /// What each sign does, with the owner's password `owner`, and whether one sign alone destroys
    /// the profile. `owner` is wiped. `slots` must not hold the stored key, which the core holds
    /// once only.
    ///
    /// # Errors
    ///
    /// As [`Profile::accept_signs`], and nothing is written.
    pub fn guards(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<([Action; SIGN_COUNT], bool), Error> {
        self.owner_given(slots, keystore, owner, params, memory)?;
        let guards = self.read_guards()?;
        let key = self.guard_key(keystore)?;
        settings(&key, &guards)
    }

    /// Checks `owner` against the owner's way in, and wipes it.
    fn owner_given(
        &self,
        slots: &mut Slots<'_>,
        keystore: &mut impl Keystore,
        owner: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<(), Error> {
        let opened = self.owner_only(slots, keystore, owner, params, memory);
        owner.zeroize();
        opened
    }

    /// The key of the tags, after [`Profile::verify`].
    fn guard_key(&self, keystore: &mut impl Keystore) -> Result<GuardKey, Error> {
        self.verify(keystore)?;
        let mut key: GuardKey = Zeroizing::new([0; 32]);
        answered_key(&self.alias, keystore, &mut key)?;
        Ok(key)
    }

    fn read_guards(&self) -> Result<Guards, Error> {
        // One byte more tells a longer file.
        let mut bytes = [0; GUARDS_LEN + 1];
        let length = read_file(&self.dir.join(GUARDS), &mut bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::Damaged
            } else {
                Error::from(error)
            }
        })?;
        let guards = bytes.get(..length).and_then(parse_guards);
        bytes.zeroize();
        guards.ok_or(Error::Damaged)
    }

    fn write_guards(&self, guards: &Guards) -> Result<(), Error> {
        write_file(&self.dir, GUARDS, &guards.bytes()).map_err(|written| match written {
            Written::Before(kind) => Error::Io(kind),
            Written::After(kind) => Error::Unsynced(kind),
        })
    }
}

/// The file of a profile that watches no sign, for [`Profile::create`]: every action is
/// [`Action::Ignore`] and no reading is accepted, so a sign watched later fires until the owner
/// accepts its reading.
pub(crate) fn fresh_guards(
    alias: &str,
    keystore: &mut impl Keystore,
) -> Result<[u8; GUARDS_LEN], Error> {
    let mut key: GuardKey = Zeroizing::new([0; 32]);
    answered_key(alias, keystore, &mut key)?;
    let actions = [Action::Ignore; SIGN_COUNT];
    let guards = made_guards(&key, actions, false, &[None; SIGN_COUNT], &mut System)?;
    Ok(guards.bytes())
}

/// The platform's source of random bytes, for a file written where the caller gives none.
struct System;

impl Entropy for System {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        fill_random(dest).map_err(|_| EntropyError)
    }
}

/// The file for `actions` and `alone`, with `readings` accepted, in a fresh salt.
fn made_guards(
    key: &GuardKey,
    actions: [Action; SIGN_COUNT],
    alone: bool,
    readings: &Readings<'_>,
    entropy: &mut impl Entropy,
) -> Result<Guards, Error> {
    let mut guards = Guards {
        salt: [0; SALT_LEN],
        signs: [Watch {
            accepted: [0; 32],
            action: [0; 32],
        }; SIGN_COUNT],
        alone: [0; 32],
    };
    entropy
        .fill(&mut guards.salt)
        .map_err(|_| Error::Core(CoreError::EntropyFailed))?;
    let salt = guards.salt;
    for ((watch, sign), action) in guards.signs.iter_mut().zip(SIGNS).zip(actions) {
        watch.action = action_tag(key, &salt, sign, action);
        // Every tag is written under the fresh salt, so a sign keeps nothing of its own: without a
        // reading to accept, one that is watched would fire at the next judgement.
        watch.accepted = match readings.get(sign.at()).copied().flatten() {
            Some(reading) => accepted_tag(key, &salt, sign, reading),
            None if action == Action::Ignore => unaccepted_tag(key, &salt, sign),
            None => return Err(Error::Unread),
        };
    }
    guards.alone = alone_tag(key, &guards.salt, alone);
    Ok(guards)
}

/// Writes into `key` the key of the tags, from the chip's answer to the challenge of this module.
fn answered_key(
    alias: &str,
    keystore: &mut impl Keystore,
    key: &mut GuardKey,
) -> Result<(), Error> {
    let challenge: [u8; 32] = Sha256::digest(CHALLENGE_LABEL).into();
    let mut answer = [0; 32];
    let answered = answer_of(alias, keystore, &challenge, &mut answer);
    // Only an answer makes a key: without one, every device would share it.
    if answered.is_ok() {
        Sha256::new()
            .chain_update(KEY_LABEL)
            .chain_update(answer.as_slice())
            .finalize_into((&mut **key).into());
    }
    answer.zeroize();
    answered
}

/// The action of `sign`, or none for a tag of no action this library writes. Every action is
/// compared, with no early exit.
fn action_of(key: &GuardKey, salt: &[u8; SALT_LEN], sign: Sign, watch: &Watch) -> Option<Action> {
    let mut found = None;
    for action in ACTIONS {
        let mut tag = action_tag(key, salt, sign, action);
        if same_mac(&tag, &watch.action) {
            found = found.or(Some(action));
        }
        tag.zeroize();
    }
    found
}

/// What each sign does and whether one alone destroys the profile, as the file holds them.
///
/// A tag of no action, or of neither answer about one sign alone, is [`Error::Damaged`]: writing
/// the file anew would make what was changed the owner's own setting.
fn settings(key: &GuardKey, guards: &Guards) -> Result<([Action; SIGN_COUNT], bool), Error> {
    let [first, second, third, fourth] = SIGNS.map(|sign| {
        let watch = guards.signs.get(sign.at())?;
        action_of(key, &guards.salt, sign, watch)
    });
    let actions = [
        first.ok_or(Error::Damaged)?,
        second.ok_or(Error::Damaged)?,
        third.ok_or(Error::Damaged)?,
        fourth.ok_or(Error::Damaged)?,
    ];
    Ok((actions, alone_of(key, guards).ok_or(Error::Damaged)?))
}

/// Whether one sign alone destroys the profile, or none for a tag of neither answer.
fn alone_of(key: &GuardKey, guards: &Guards) -> Option<bool> {
    let mut found = None;
    for alone in [false, true] {
        let mut tag = alone_tag(key, &guards.salt, alone);
        if same_mac(&tag, &guards.alone) {
            found = found.or(Some(alone));
        }
        tag.zeroize();
    }
    found
}

/// The tag of the reading `reading` of `sign`. The reading goes in as its digest, so that a reading
/// of any length gives a message of one length. A hash of the key and a message whose parts are of
/// known lengths serves as a MAC, and unlike HMAC its state is wiped.
fn accepted_tag(key: &GuardKey, salt: &[u8; SALT_LEN], sign: Sign, reading: &[u8]) -> [u8; 32] {
    let mut digest: [u8; 32] = Sha256::digest(reading).into();
    let tag = Sha256::new()
        .chain_update(key.as_slice())
        .chain_update(READING_LABEL)
        .chain_update(salt)
        .chain_update([sign.code()])
        .chain_update(digest)
        .finalize()
        .into();
    digest.zeroize();
    tag
}

/// The tag of no reading accepted for `sign`. Its label is not the one readings are tagged under,
/// so no reading gives this tag.
fn unaccepted_tag(key: &GuardKey, salt: &[u8; SALT_LEN], sign: Sign) -> [u8; 32] {
    Sha256::new()
        .chain_update(key.as_slice())
        .chain_update(UNACCEPTED_LABEL)
        .chain_update(salt)
        .chain_update([sign.code()])
        .finalize()
        .into()
}

fn action_tag(key: &GuardKey, salt: &[u8; SALT_LEN], sign: Sign, action: Action) -> [u8; 32] {
    Sha256::new()
        .chain_update(key.as_slice())
        .chain_update(ACTION_LABEL)
        .chain_update(salt)
        .chain_update([sign.code(), action.code()])
        .finalize()
        .into()
}

fn alone_tag(key: &GuardKey, salt: &[u8; SALT_LEN], alone: bool) -> [u8; 32] {
    Sha256::new()
        .chain_update(key.as_slice())
        .chain_update(ALONE_LABEL)
        .chain_update(salt)
        .chain_update([u8::from(alone)])
        .finalize()
        .into()
}

impl Sign {
    /// Where the sign lies in a reading and in a verdict.
    #[must_use]
    pub const fn at(self) -> usize {
        match self {
            Self::Fingerprints => 0,
            Self::Boots => 1,
            Self::Debugging => 2,
            Self::Cards => 3,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Fingerprints => 1,
            Self::Boots => 2,
            Self::Debugging => 3,
            Self::Cards => 4,
        }
    }
}

impl Action {
    const fn code(self) -> u8 {
        match self {
            Self::Ignore => 1,
            Self::Report => 2,
            Self::Destroy => 3,
        }
    }
}

impl Watch {
    /// A sign's tags as written: the tag of the reading accepted, then that of its action.
    fn bytes(&self) -> [u8; WATCH_LEN] {
        let mut bytes = [0; WATCH_LEN];
        if let Some((accepted, action)) = bytes.split_first_chunk_mut::<32>()
            && let Ok(action) = <&mut [u8; 32]>::try_from(action)
        {
            *accepted = self.accepted;
            *action = self.action;
        }
        bytes
    }
}

impl Guards {
    /// The file as written: the salt, then each sign's tags in the order of [`SIGNS`], then the tag
    /// of whether one sign alone destroys the profile.
    fn bytes(&self) -> [u8; GUARDS_LEN] {
        let [first, second, third, fourth] = self.signs;
        let mut bytes = [0; GUARDS_LEN];
        if let Some((salt, rest)) = bytes.split_first_chunk_mut::<SALT_LEN>()
            && let Some((one, rest)) = rest.split_first_chunk_mut::<WATCH_LEN>()
            && let Some((two, rest)) = rest.split_first_chunk_mut::<WATCH_LEN>()
            && let Some((three, rest)) = rest.split_first_chunk_mut::<WATCH_LEN>()
            && let Some((four, rest)) = rest.split_first_chunk_mut::<WATCH_LEN>()
            && let Ok(alone) = <&mut [u8; 32]>::try_from(rest)
        {
            *salt = self.salt;
            *one = first.bytes();
            *two = second.bytes();
            *three = third.bytes();
            *four = fourth.bytes();
            *alone = self.alone;
        }
        bytes
    }
}

/// The signs of the file `bytes`; none for a file of another length. Taken sign by sign, with no
/// loop: under the proofs a loop over a piece of a length known only at run time unwinds past that
/// length.
fn parse_guards(bytes: &[u8]) -> Option<Guards> {
    let (salt, rest) = bytes.split_first_chunk::<SALT_LEN>()?;
    let (one, rest) = rest.split_first_chunk::<WATCH_LEN>()?;
    let (two, rest) = rest.split_first_chunk::<WATCH_LEN>()?;
    let (three, rest) = rest.split_first_chunk::<WATCH_LEN>()?;
    let (four, alone) = rest.split_first_chunk::<WATCH_LEN>()?;
    Some(Guards {
        salt: *salt,
        signs: [
            watch_of(one)?,
            watch_of(two)?,
            watch_of(three)?,
            watch_of(four)?,
        ],
        alone: <[u8; 32]>::try_from(alone).ok()?,
    })
}

/// A sign's tags as written.
fn watch_of(bytes: &[u8; WATCH_LEN]) -> Option<Watch> {
    let (accepted, action) = bytes.split_first_chunk::<32>()?;
    Some(Watch {
        accepted: *accepted,
        action: <[u8; 32]>::try_from(action).ok()?,
    })
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

#[cfg(test)]
mod tests {
    use std::fs;

    use lethewis_core::{Entropy, EntropyError, Erasure, Slots};

    use super::{
        Action, GUARDS, GUARDS_LEN, GuardKey, Readings, SALT_LEN, SIGN_COUNT, SIGNS, Sign, Verdict,
        WATCH_LEN, Zeroizing, answered_key, made_guards, parse_guards, settings,
    };
    use crate::keystore::Failure;
    use crate::profile::{Error, Profile, RECORD};
    use crate::stand::{
        DURESS, Made, OTHER, OWNER, Source, Stand, Start, Work, all_free, copied, dir, entries,
        fail_syncs,
    };
    use crate::sweep;

    const UNREAD: Readings<'static> = [None; SIGN_COUNT];
    const WATCHED: [Action; SIGN_COUNT] = [Action::Report; SIGN_COUNT];
    const IGNORED: [Action; SIGN_COUNT] = [Action::Ignore; SIGN_COUNT];

    /// A reading of every sign, each telling the signs apart.
    fn first() -> Readings<'static> {
        [Some(b"one"), Some(b"two"), Some(b"three"), Some(b"four")]
    }

    /// The readings of [`first`] with that of `sign` another.
    fn changed(sign: Sign) -> Readings<'static> {
        let mut readings = first();
        if let Some(reading) = readings.get_mut(sign.at()) {
            *reading = Some(b"other");
        }
        readings
    }

    /// A source of random bytes that fails after `0` fills.
    struct Failing(u32);

    impl Entropy for Failing {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            if self.0 == 0 {
                return Err(EntropyError);
            }
            self.0 = self.0.saturating_sub(1);
            Source(1).fill(dest)
        }
    }

    fn tag_key(profile: &Profile, stand: &mut Stand) -> GuardKey {
        let mut key: GuardKey = Zeroizing::new([0; 32]);
        answered_key(&profile.alias, stand, &mut key).unwrap();
        key
    }

    /// Writes the file of the signs of `profile`, as its owner would.
    fn seed(
        profile: &Profile,
        stand: &mut Stand,
        actions: [Action; SIGN_COUNT],
        alone: bool,
        readings: &Readings<'_>,
    ) {
        let key = tag_key(profile, stand);
        let guards = made_guards(&key, actions, alone, readings, &mut Source(3)).unwrap();
        profile.write_guards(&guards).unwrap();
    }

    fn file(profile: &Profile) -> Vec<u8> {
        fs::read(profile.dir.join(GUARDS)).unwrap()
    }

    fn written(profile: &Profile, bytes: &[u8]) {
        fs::write(profile.dir.join(GUARDS), bytes).unwrap();
    }

    /// Where the tags of `sign` lie in the file.
    fn watch_at(sign: Sign) -> usize {
        SALT_LEN.saturating_add(sign.at().saturating_mul(WATCH_LEN))
    }

    /// Where the tag of the action of `sign` lies in the file.
    fn action_at(sign: Sign) -> usize {
        watch_at(sign).saturating_add(32)
    }

    fn set_guards(
        made: &Made,
        stand: &mut Stand,
        owner: &[u8],
        actions: [Action; SIGN_COUNT],
        alone: bool,
        readings: &Readings<'_>,
    ) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let set = made.profile.set_guards(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            actions,
            alone,
            readings,
            &made.params,
            &mut work.memory,
            &mut Source(7),
        );
        assert!(all_free(&mut slots));
        set
    }

    fn accept_signs(
        made: &Made,
        stand: &mut Stand,
        owner: &[u8],
        readings: &Readings<'_>,
    ) -> Result<(), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let accepted = made.profile.accept_signs(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            readings,
            &made.params,
            &mut work.memory,
            &mut Source(11),
        );
        assert!(all_free(&mut slots));
        accepted
    }

    fn guards(
        made: &Made,
        stand: &mut Stand,
        owner: &[u8],
    ) -> Result<([Action; SIGN_COUNT], bool), Error> {
        let mut work = Work::new(&made.params);
        let mut slots = Slots::new(
            &mut work.slots,
            &mut work.epoch,
            0,
            &mut made.epoch_key.clone(),
        );
        let read = made.profile.guards(
            &mut slots,
            stand,
            &mut owner.to_vec(),
            &made.params,
            &mut work.memory,
        );
        assert!(all_free(&mut slots));
        read
    }

    #[test]
    fn a_new_profile_holds_a_file_of_signs_that_watches_none() {
        assert_eq!(GUARDS_LEN, 320);
        let root = dir("new");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        assert_eq!(file(&profile).len(), GUARDS_LEN);
        // Nothing is accepted yet, so there is nothing for a reading to differ from.
        assert_eq!(
            profile.judge(&mut stand, &first()).unwrap(),
            Verdict {
                changed: [false; SIGN_COUNT],
                unaccepted: [true; SIGN_COUNT],
                unread: [false; SIGN_COUNT],
                report: [false; SIGN_COUNT],
                destroy: false,
                damaged: false,
            }
        );
    }

    #[test]
    fn the_file_holds_the_salt_then_each_sign_then_the_tag_of_one_alone() {
        let root = dir("layout");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let key = tag_key(&profile, &mut stand);
        let guards = made_guards(&key, WATCHED, true, &first(), &mut Source(3)).unwrap();
        let bytes = guards.bytes();
        assert_eq!(bytes.get(..SALT_LEN), Some(guards.salt.as_slice()));
        for (sign, watch) in SIGNS.into_iter().zip(guards.signs) {
            let at = watch_at(sign);
            let action = action_at(sign);
            assert_eq!(
                bytes.get(at..action),
                Some(watch.accepted.as_slice()),
                "{sign:?}"
            );
            assert_eq!(
                bytes.get(action..action.saturating_add(32)),
                Some(watch.action.as_slice()),
                "{sign:?}"
            );
        }
        assert_eq!(
            bytes.get(GUARDS_LEN.saturating_sub(32)..),
            Some(guards.alone.as_slice())
        );
        assert!(parse_guards(&bytes) == Some(guards));
    }

    #[test]
    fn a_reading_accepted_does_not_change_and_another_does() {
        let root = dir("accepted");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        seed(&profile, &mut stand, WATCHED, false, &first());
        assert_eq!(
            profile.judge(&mut stand, &first()).unwrap().changed,
            [false; SIGN_COUNT]
        );
        for sign in SIGNS {
            let verdict = profile.judge(&mut stand, &changed(sign)).unwrap();
            let only = |at: usize| at == sign.at();
            assert_eq!(verdict.changed, [0, 1, 2, 3].map(only), "{sign:?}");
            assert_eq!(verdict.report, [0, 1, 2, 3].map(only), "{sign:?}");
            assert!(!verdict.damaged, "{sign:?}");
        }
    }

    #[test]
    fn the_tags_of_one_sign_are_no_other_sign_s() {
        let root = dir("bound");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        // One reading for two signs, and what they do differs: only their tags tell them apart.
        let same: Readings<'static> = [Some(b"same"), Some(b"same"), Some(b"same"), Some(b"same")];
        let actions = [
            Action::Destroy,
            Action::Ignore,
            Action::Ignore,
            Action::Ignore,
        ];
        seed(&profile, &mut stand, actions, true, &same);
        assert_eq!(
            profile.judge(&mut stand, &same).unwrap().changed,
            [false; SIGN_COUNT]
        );
        // The tags of the first two signs, swapped: neither pair is read as its sign's.
        let mut bytes = file(&profile);
        for at in 0..WATCH_LEN {
            let first = watch_at(Sign::Fingerprints).saturating_add(at);
            let second = watch_at(Sign::Boots).saturating_add(at);
            bytes.swap(first, second);
        }
        written(&profile, &bytes);
        let verdict = profile.judge(&mut stand, &same).unwrap();
        assert!(verdict.damaged);
        assert_eq!(verdict.changed, [true, true, false, false]);
        assert!(!verdict.destroy);
    }

    #[test]
    fn a_sign_not_watched_is_not_reported() {
        let root = dir("ignored");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        seed(&profile, &mut stand, IGNORED, true, &first());
        let verdict = profile.judge(&mut stand, &changed(Sign::Boots)).unwrap();
        assert_eq!(verdict.changed, [false, true, false, false]);
        assert_eq!(verdict.report, [false; SIGN_COUNT]);
        assert!(!verdict.destroy);
    }

    #[test]
    fn a_sign_watched_and_unread_is_told_and_an_empty_reading_is_one() {
        let root = dir("unread");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let actions = [
            Action::Report,
            Action::Ignore,
            Action::Destroy,
            Action::Ignore,
        ];
        seed(&profile, &mut stand, actions, false, &first());
        let verdict = profile.judge(&mut stand, &UNREAD).unwrap();
        assert_eq!(verdict.unread, [true, false, true, false]);
        assert_eq!(verdict.changed, [false; SIGN_COUNT]);
        assert!(!verdict.destroy);
        // No reading at all and a reading of no bytes are not the same.
        let mut readings = first();
        readings[Sign::Fingerprints.at()] = Some(b"");
        let verdict = profile.judge(&mut stand, &readings).unwrap();
        assert_eq!(verdict.unread, [false; SIGN_COUNT]);
        assert_eq!(verdict.changed, [true, false, false, false]);
        let accepted = [Some(b"".as_slice()), None, None, None];
        seed(&profile, &mut stand, IGNORED, false, &accepted);
        assert_eq!(
            profile.judge(&mut stand, &accepted).unwrap().changed,
            [false; SIGN_COUNT]
        );
    }

    #[test]
    fn two_signs_destroy_the_profile_and_one_does_not() {
        let root = dir("two");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let actions = [
            Action::Ignore,
            Action::Destroy,
            Action::Report,
            Action::Destroy,
        ];
        seed(&profile, &mut stand, actions, false, &first());
        assert!(
            !profile
                .judge(&mut stand, &changed(Sign::Boots))
                .unwrap()
                .destroy
        );
        // A sign that only reports does not count towards the two.
        let mut readings = changed(Sign::Boots);
        readings[Sign::Debugging.at()] = Some(b"else");
        assert!(!profile.judge(&mut stand, &readings).unwrap().destroy);
        readings[Sign::Cards.at()] = Some(b"else");
        assert!(profile.judge(&mut stand, &readings).unwrap().destroy);
    }

    #[test]
    fn one_sign_destroys_the_profile_where_the_owner_allowed_it() {
        let root = dir("alone");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let actions = [
            Action::Ignore,
            Action::Destroy,
            Action::Ignore,
            Action::Ignore,
        ];
        for (alone, destroys) in [(false, false), (true, true)] {
            seed(&profile, &mut stand, actions, alone, &first());
            let verdict = profile.judge(&mut stand, &changed(Sign::Boots)).unwrap();
            assert_eq!(verdict.destroy, destroys, "{alone}");
            assert!(
                !profile.judge(&mut stand, &first()).unwrap().destroy,
                "{alone}"
            );
        }
    }

    #[test]
    fn a_tag_of_no_action_is_told_and_watches_nothing() {
        let root = dir("damaged");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        seed(&profile, &mut stand, WATCHED, false, &first());
        let mut bytes = file(&profile);
        bytes[action_at(Sign::Boots)] ^= 1;
        written(&profile, &bytes);
        let verdict = profile.judge(&mut stand, &changed(Sign::Boots)).unwrap();
        assert!(verdict.damaged);
        assert_eq!(verdict.changed, [false, true, false, false]);
        assert_eq!(verdict.report, [false; SIGN_COUNT]);
    }

    #[test]
    fn a_tag_of_neither_answer_of_one_sign_alone_is_told() {
        let root = dir("neither");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let actions = [Action::Destroy; SIGN_COUNT];
        seed(&profile, &mut stand, actions, true, &first());
        let mut bytes = file(&profile);
        let last = bytes.len().saturating_sub(1);
        bytes[last] ^= 1;
        written(&profile, &bytes);
        let verdict = profile.judge(&mut stand, &changed(Sign::Boots)).unwrap();
        assert!(verdict.damaged);
        // One sign alone reads as neither allowed nor refused, so nothing is destroyed.
        assert!(!verdict.destroy);
    }

    #[test]
    fn a_file_of_signs_changed_is_refused_to_its_owner() {
        let root = dir("refused");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        seed(&profile, &mut stand, WATCHED, true, &first());
        let key = tag_key(&profile, &mut stand);
        let whole = file(&profile);
        assert_eq!(
            settings(&key, &parse_guards(&whole).unwrap()),
            Ok((WATCHED, true))
        );
        // A tag the owner's call cannot read would become a setting of their own if written anew.
        for at in [action_at(Sign::Cards), whole.len().saturating_sub(1)] {
            let mut bytes = whole.clone();
            bytes[at] ^= 1;
            let guards = parse_guards(&bytes).unwrap();
            assert_eq!(settings(&key, &guards), Err(Error::Damaged), "{at}");
        }
    }

    #[test]
    fn a_file_of_signs_of_another_length_is_damaged() {
        let root = dir("length");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let whole = file(&profile);
        for length in [0, GUARDS_LEN.saturating_sub(1)] {
            written(&profile, whole.get(..length).unwrap());
            assert_eq!(profile.judge(&mut stand, &first()), Err(Error::Damaged));
        }
        let mut longer = whole.clone();
        longer.push(0);
        written(&profile, &longer);
        assert_eq!(profile.judge(&mut stand, &first()), Err(Error::Damaged));
        written(&profile, &whole);
        assert!(profile.judge(&mut stand, &first()).is_ok());
    }

    #[test]
    fn a_file_of_signs_gone_is_damaged() {
        let root = dir("gone");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        fs::remove_file(profile.dir.join(GUARDS)).unwrap();
        assert_eq!(profile.judge(&mut stand, &first()), Err(Error::Damaged));
    }

    #[test]
    fn a_file_of_the_length_written_but_of_other_bytes_is_told() {
        let root = dir("random");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let mut bytes = [0; GUARDS_LEN];
        Source(13).fill(&mut bytes).unwrap();
        written(&profile, &bytes);
        let verdict = profile.judge(&mut stand, &first()).unwrap();
        assert!(verdict.damaged);
        assert_eq!(verdict.changed, [true; SIGN_COUNT]);
        assert!(!verdict.destroy);
    }

    #[test]
    fn a_judgement_writes_nothing() {
        let root = dir("quiet");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        seed(&profile, &mut stand, WATCHED, false, &first());
        let before = file(&profile);
        profile.judge(&mut stand, &changed(Sign::Boots)).unwrap();
        assert_eq!(file(&profile), before);
    }

    #[test]
    fn the_signs_written_anew_differ_every_time() {
        let root = dir("salt");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let key = tag_key(&profile, &mut stand);
        let mut source = Source(5);
        let one = made_guards(&key, WATCHED, false, &first(), &mut source).unwrap();
        let other = made_guards(&key, WATCHED, false, &first(), &mut source).unwrap();
        assert_ne!(one.bytes(), other.bytes());
    }

    #[test]
    fn a_sign_set_aside_has_no_reading_accepted() {
        let root = dir("aside");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        seed(&profile, &mut stand, WATCHED, false, &first());
        // Set aside without a reading, the sign keeps none accepted.
        let mut readings = first();
        readings[Sign::Boots.at()] = None;
        seed(&profile, &mut stand, IGNORED, false, &readings);
        let verdict = profile.judge(&mut stand, &first()).unwrap();
        assert_eq!(verdict.unaccepted, [false, true, false, false]);
        assert_eq!(verdict.changed, [false; SIGN_COUNT]);
    }

    #[test]
    fn a_sign_watched_and_given_no_reading_is_refused() {
        let root = dir("nothing");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let key = tag_key(&profile, &mut stand);
        let mut readings = first();
        readings[Sign::Boots.at()] = None;
        for actions in [WATCHED, [Action::Destroy; SIGN_COUNT]] {
            assert_eq!(
                made_guards(&key, actions, false, &readings, &mut Source(1)).err(),
                Some(Error::Unread)
            );
        }
        // A sign not watched needs none.
        assert!(made_guards(&key, IGNORED, false, &UNREAD, &mut Source(1)).is_ok());
    }

    #[test]
    fn the_signs_outlive_a_change_of_epoch() {
        let root = dir("epoch");
        let mut stand = Stand::new();
        let mut profile = Profile::create(&root, &mut stand, false).unwrap();
        seed(&profile, &mut stand, WATCHED, false, &first());
        let before = profile.judge(&mut stand, &changed(Sign::Boots)).unwrap();
        let bytes = file(&profile);
        profile.next_epoch(&mut stand, false, &mut [0; 32]).unwrap();
        assert_eq!(file(&profile), bytes);
        assert_eq!(
            profile.judge(&mut stand, &changed(Sign::Boots)).unwrap(),
            before
        );
    }

    #[test]
    fn a_source_of_random_bytes_that_fails_is_told() {
        let root = dir("source");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let key = tag_key(&profile, &mut stand);
        // The salt is the only random part of the file.
        assert_eq!(
            made_guards(&key, WATCHED, false, &first(), &mut Failing(0)).err(),
            Some(Error::Core(lethewis_core::Error::EntropyFailed))
        );
        assert!(made_guards(&key, WATCHED, false, &first(), &mut Failing(1)).is_ok());
    }

    #[test]
    fn a_chip_that_refuses_the_signs_leaves_no_profile() {
        let root = dir("refusing");
        // The root's tag and the pointer are answered; the signs are not.
        let mut stand = Stand {
            refuse_mac: Some((2, Failure::Locked)),
            ..Stand::new()
        };
        assert_eq!(
            Profile::create(&root, &mut stand, false).unwrap_err(),
            Error::Keystore(Failure::Locked)
        );
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_file_of_signs_written_but_not_synced_is_told() {
        let root = dir("unsynced");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let key = tag_key(&profile, &mut stand);
        let guards = made_guards(&key, IGNORED, false, &first(), &mut Source(3)).unwrap();
        fail_syncs(0, 1);
        let written = profile.write_guards(&guards);
        fail_syncs(0, 0);
        assert_eq!(written, Err(Error::Unsynced(std::io::ErrorKind::Other)));
        // The file is there all the same, so the signs are the ones just written.
        assert_eq!(file(&profile), guards.bytes());
    }

    #[test]
    fn a_replaced_chip_is_told_before_the_signs() {
        let root = dir("chip");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        fs::remove_file(profile.dir.join(GUARDS)).unwrap();
        stand.keys.insert(profile.alias.clone(), [9; 32]);
        assert_eq!(profile.judge(&mut stand, &first()), Err(Error::ChipChanged));
    }

    #[test]
    fn the_signs_of_another_profile_are_not_read() {
        let root = dir("another");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        let other = Profile::create(&root, &mut stand, false).unwrap();
        seed(&other, &mut stand, WATCHED, true, &first());
        written(&profile, &file(&other));
        let verdict = profile.judge(&mut stand, &first()).unwrap();
        assert!(verdict.damaged);
        assert_eq!(verdict.changed, [true; SIGN_COUNT]);
    }

    #[test]
    fn destroying_a_profile_leaves_no_file_of_signs() {
        let root = dir("destroyed");
        let mut stand = Stand::new();
        let profile = Profile::create(&root, &mut stand, false).unwrap();
        assert_eq!(profile.destroy(&mut stand), Ok(Erasure::BestEffort));
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_creation_that_cannot_write_the_signs_leaves_nothing() {
        let root = dir("unwritten");
        let mut stand = Stand::new();
        // Syncs of the root, of the root of epoch 0 and of the pointer pass; the signs' fails.
        fail_syncs(3, 1);
        assert_eq!(
            Profile::create(&root, &mut stand, false).unwrap_err(),
            Error::Io(std::io::ErrorKind::Other)
        );
        // Four answers of the chip: the record's check and tag were never asked for.
        assert_eq!(stand.macs, 3);
        assert_eq!(stand.names(), [] as [&str; 0]);
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn a_sweep_removes_the_file_of_signs_a_crash_left() {
        let root = dir("swept");
        let mut stand = Stand::new();
        let id = Profile::create(&root, &mut stand, false).unwrap().id();
        fs::remove_file(root.join(id.to_string()).join(RECORD)).unwrap();
        sweep(&root, &mut stand).unwrap();
        assert_eq!(entries(&root), [] as [String; 0]);
    }

    #[test]
    fn only_the_owners_password_sets_and_accepts_the_signs() {
        let root = dir("owner");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Duress);
        let before = file(&made.profile);
        // Neither another password nor the one under duress manages the signs.
        for password in [OTHER, DURESS] {
            assert_eq!(
                set_guards(&made, &mut stand, password, WATCHED, true, &first()),
                Err(Error::WrongPassword)
            );
            assert_eq!(file(&made.profile), before);
        }
        assert_eq!(guards(&made, &mut stand, DURESS), Err(Error::WrongPassword));
        assert_eq!(
            accept_signs(&made, &mut stand, OTHER, &first()),
            Err(Error::WrongPassword)
        );
        assert_eq!(file(&made.profile), before);
    }

    #[test]
    fn the_owner_sets_what_a_sign_does_and_accepts_its_reading() {
        let root = dir("set");
        let mut stand = Stand::new();
        let made = copied(&root, &mut stand, Start::Plain);
        let watching = [
            Action::Ignore,
            Action::Destroy,
            Action::Ignore,
            Action::Report,
        ];
        set_guards(&made, &mut stand, OWNER, watching, true, &first()).unwrap();
        assert_eq!(guards(&made, &mut stand, OWNER).unwrap(), (watching, true));
        // The readings given are accepted, and another destroys the profile at once.
        let verdict = made.profile.judge(&mut stand, &first()).unwrap();
        assert!(!verdict.destroy && !verdict.damaged);
        assert!(
            made.profile
                .judge(&mut stand, &changed(Sign::Boots))
                .unwrap()
                .destroy
        );
        // Set anew without one sign alone: two signs must change from now on.
        set_guards(&made, &mut stand, OWNER, watching, false, &first()).unwrap();
        assert_eq!(guards(&made, &mut stand, OWNER).unwrap(), (watching, false));
        assert!(
            !made
                .profile
                .judge(&mut stand, &changed(Sign::Boots))
                .unwrap()
                .destroy
        );
        set_guards(&made, &mut stand, OWNER, watching, true, &first()).unwrap();
        // Accepted anew, the reading that fired fires no more, and what each sign does is kept.
        accept_signs(&made, &mut stand, OWNER, &changed(Sign::Boots)).unwrap();
        assert!(
            !made
                .profile
                .judge(&mut stand, &changed(Sign::Boots))
                .unwrap()
                .destroy
        );
        assert!(made.profile.judge(&mut stand, &first()).unwrap().destroy);
    }
}
