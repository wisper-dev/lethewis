// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The native methods of `com.alanwisper.lethewis.test.Tests`, the tests on a device. Only a build
//! for the tests has them.

use core::ptr;
use core::time::Duration;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::{fs, thread};

use jni_sys::{JNIEnv, jboolean, jclass, jint, jstring};
use lethewis_android::{
    Erasure, Error, Failure, Id, Keys, Keystore, Level, Profile, Root, Unheld, sweep,
};
use lethewis_core::{
    Entropy, EntropyError, Epoch, KeyLength, MemoryBlock, PasswordParams, Purpose, Slot, Slots,
};

use crate::keystore::JniKeystore;

/// The key of the first test case of RFC 4231, which the Java side imports before the tests.
const KNOWN: &str = "lethewis-test/rfc4231";
/// The HMAC-SHA256 of `Hi There` under that key, twenty bytes 0x0b.
const KNOWN_ANSWER: [u8; 32] = [
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
];
/// The file under the directory of the tests that names the profile kept across a lock.
const KEPT: &str = "kept";
/// The directory of profiles under the directory of the tests.
const PROFILES: &str = "profiles";
/// The file under the directory of the tests that tells the keystore was reached before it stops.
const REACHED: &str = "reached";

/// The keys the tests of `Wiper` hold.
static HELD: Mutex<Option<Arc<Keys<()>>>> = Mutex::new(None);

/// Runs the tests `test` under `root`, a directory of the app, on a system of API level `api`.
/// Returns `passed` when every check holds, the first that failed otherwise, and null when the
/// bridge itself fails.
#[allow(unsafe_code)]
// SAFETY: no other symbol of the library has this name, and the JVM calls it with this signature.
#[unsafe(no_mangle)]
extern "system" fn Java_com_alanwisper_lethewis_test_Tests_run(
    env: *mut JNIEnv,
    _class: jclass,
    root: jstring,
    api: jint,
    test: jstring,
) -> jstring {
    // SAFETY: the JVM calls a native method with the environment of the current thread, valid
    // until it returns.
    let Ok(mut keystore) = (unsafe { JniKeystore::find(env) }) else {
        return ptr::null_mut();
    };
    let outcome = match (keystore.text(root), keystore.text(test), u32::try_from(api)) {
        (Some(root), Some(test), Ok(api)) => run(Path::new(&root), &mut keystore, api, &test),
        _ => Err("the arguments are not as the runner passes them".to_owned()),
    };
    let report = match outcome {
        Ok(()) => "passed".to_owned(),
        Err(failure) => failure.replace(|c: char| !c.is_ascii(), "?"),
    };
    keystore.string(&report).unwrap_or(ptr::null_mut())
}

/// Calls JNI with an exception pending, which `CheckJNI` stops the process for.
#[allow(unsafe_code)]
// SAFETY: no other symbol of the library has this name, and the JVM calls it with this signature.
#[unsafe(no_mangle)]
extern "system" fn Java_com_alanwisper_lethewis_test_Tests_misuse(
    env: *mut JNIEnv,
    _class: jclass,
) {
    // SAFETY: the JVM calls a native method with the environment of the current thread, valid
    // until it returns.
    let Ok(keystore) = (unsafe { JniKeystore::find(env) }) else {
        return;
    };
    let functions = keystore.table();
    // SAFETY: the environment is valid, no exception is pending, and the name ends in NUL.
    let class = unsafe { (functions.FindClass)(env, c"java/lang/IllegalStateException".as_ptr()) };
    if class.is_null() {
        keystore.thrown();
        return;
    }
    // SAFETY: as above, and `class` is a class of throwables.
    unsafe { (functions.ThrowNew)(env, class, c"pending".as_ptr()) };
    // SAFETY: deliberately broken: JNI forbids this call with an exception pending, the misuse
    // the test proves CheckJNI catches.
    unsafe { (functions.NewStringUTF)(env, c"after".as_ptr()) };
    keystore.thrown();
}

/// Holds keys with one key loaded, for the tests of `Wiper`, in place of any held before. Returns
/// `passed`, what failed, or null when the bridge itself fails.
#[allow(unsafe_code)]
// SAFETY: no other symbol of the library has this name, and the JVM calls it with this signature.
#[unsafe(no_mangle)]
extern "system" fn Java_com_alanwisper_lethewis_test_Tests_hold(
    env: *mut JNIEnv,
    _class: jclass,
) -> jstring {
    // SAFETY: the JVM calls a native method with the environment of the current thread, valid
    // until it returns.
    let Ok(keystore) = (unsafe { JniKeystore::find(env) }) else {
        return ptr::null_mut();
    };
    let report = match hold() {
        Ok(()) => "passed".to_owned(),
        Err(failure) => failure.replace(|c: char| !c.is_ascii(), "?"),
    };
    keystore.string(&report).unwrap_or(ptr::null_mut())
}

/// Whether the keys `hold` made still answer.
#[allow(unsafe_code)]
// SAFETY: no other symbol of the library has this name, and the JVM calls it with this signature.
#[unsafe(no_mangle)]
extern "system" fn Java_com_alanwisper_lethewis_test_Tests_held(
    _env: *mut JNIEnv,
    _class: jclass,
) -> jboolean {
    held().is_some_and(|keys| keys.call(|_, ()| ()).is_ok())
}

/// Runs a call of `millis` milliseconds on the keys `hold` made; tells whether it ran.
#[allow(unsafe_code)]
// SAFETY: no other symbol of the library has this name, and the JVM calls it with this signature.
#[unsafe(no_mangle)]
extern "system" fn Java_com_alanwisper_lethewis_test_Tests_busy(
    _env: *mut JNIEnv,
    _class: jclass,
    millis: jint,
) -> jboolean {
    let millis = u64::try_from(millis).unwrap_or(0);
    held().is_some_and(|keys| {
        keys.call(move |_, ()| thread::sleep(Duration::from_millis(millis)))
            .is_ok()
    })
}

fn held() -> Option<Arc<Keys<()>>> {
    HELD.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn hold() -> Result<(), String> {
    let keys =
        Keys::start::<4>(0, &mut [7; 32], ()).map_err(|error| format!("holding: {error}"))?;
    keys.call(|slots, ()| slots.import32(Purpose::Wrap, &mut [9; 32]).map(|_| ()))
        .map_err(|error| format!("loading: {error}"))?
        .map_err(|error| format!("loading: {error}"))?;
    *HELD.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(keys));
    Ok(())
}

fn check(holds: bool, what: &str) -> Result<(), String> {
    if holds { Ok(()) } else { Err(what.to_owned()) }
}

/// The tests `test`: `all` with the device unlocked, or one step of a profile kept across a lock,
/// `before-lock`, `locked` and `after-lock`, or across a keystore that stops, `before-stop`,
/// `stopping`, `stopped`, `restarted` and `after-stop`.
fn run(root: &Path, keystore: &mut JniKeystore<'_>, api: u32, test: &str) -> Result<(), String> {
    check(
        keystore.api_level() == api,
        &format!("API level {} for {api}", keystore.api_level()),
    )?;
    let home = root.join(PROFILES);
    match test {
        "all" => {
            // The runner never starts `Wiper`, so no keys are held.
            let unwatched = Keys::start::<1>(0, &mut [1; 32], ()).err();
            check(
                unwatched == Some(Unheld::Unwatched),
                &format!("keys held before the screen is watched: {unwatched:?}"),
            )?;
            empty(&home)?;
            known(keystore)?;
            let expected = keystore_alone(keystore)?;
            profiles(&home, keystore, api, expected)?;
            epochs(&home, keystore)?;
            duress(&home, keystore)?;
            remove(root)
        }
        "before-lock" | "before-stop" => {
            empty(&home)?;
            let profile = Profile::create(&home, keystore, true)
                .map_err(|error| format!("creating: {error}"))?;
            fs::write(root.join(KEPT), profile.id().to_string())
                .map_err(|error| format!("keeping the profile: {error}"))?;
            answers(&profile, keystore)
        }
        "locked" => {
            let profile = kept(root)?;
            let mut out = [0; 32];
            let answered = profile.answer(keystore, &[1; 32], &mut out);
            let root_answered = keystore
                .mac(
                    &format!("lethewis/{}/root/0", profile.id()),
                    b"data",
                    &mut out,
                )
                .map_err(Error::Keystore);
            // Below API 35 the keys are not bound to the lock screen, so they answer.
            let expected = if api >= 35 {
                Err(Error::Keystore(Failure::Locked))
            } else {
                Ok(())
            };
            check(
                answered == expected && root_answered == expected,
                &format!("a locked device answers: {answered:?} {root_answered:?}"),
            )
        }
        "stopping" => {
            let profile = kept(root)?;
            answers(&profile, keystore)?;
            fs::write(root.join(REACHED), b"")
                .map_err(|error| format!("telling the keystore was reached: {error}"))?;
            stops(&profile, keystore)
        }
        "stopped" => {
            let profile = kept(root)?;
            let verified = profile.verify(keystore);
            check(
                matches!(
                    verified,
                    Err(Error::Keystore(Failure::Transient | Failure::Unknown))
                ),
                &format!("a keystore that stopped verifies: {verified:?}"),
            )?;
            let mut out = [0; 32];
            let missing = keystore.mac("lethewis-test/missing", b"data", &mut out);
            check(
                matches!(missing, Err(Failure::Transient | Failure::Unknown)),
                &format!("a keystore that stopped and a missing key: {missing:?}"),
            )
        }
        "restarted" => {
            let profile = kept(root)?;
            let verified = profile.verify(keystore);
            // From API 35 the keys work only while unlocked, and the keystore waits for an unlock.
            let expected = if api >= 35 {
                Err(Error::Keystore(Failure::Locked))
            } else {
                Ok(())
            };
            check(
                verified == expected,
                &format!("a keystore that started again verifies: {verified:?}"),
            )
        }
        "after-lock" | "after-stop" => {
            let profile = kept(root)?;
            answers(&profile, keystore)?;
            destroyed(profile, keystore).map(|_| ())?;
            remove(root)
        }
        other => Err(format!("no tests named {other}")),
    }
}

fn empty(root: &Path) -> Result<(), String> {
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root).map_err(|error| format!("the directory: {error}"))
}

fn remove(root: &Path) -> Result<(), String> {
    fs::remove_dir_all(root).map_err(|error| format!("removing the directory: {error}"))
}

fn alias(id: Id) -> String {
    format!("lethewis/{id}/chip")
}

/// Destroys the profile and checks it leaves no key.
fn destroyed(profile: Profile, keystore: &mut JniKeystore<'_>) -> Result<Erasure, String> {
    let id = profile.id();
    let erasure = profile
        .destroy(keystore)
        .map_err(|error| format!("destroying: {error}"))?;
    let listed = keystore.aliases(&format!("lethewis/{id}/"));
    check(
        listed == Ok(Vec::new()),
        &format!("the keys after a destruction: {listed:?}"),
    )?;
    Ok(erasure)
}

/// Other bytes on every call, the same in every run.
struct Source(u64);

impl Entropy for Source {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = self.0.to_le_bytes().last().copied().unwrap_or(0);
        }
        Ok(())
    }
}

/// A password under duress set to destroy opens its profile and deletes the keys of another from
/// the keystore, where the owner's password deletes nothing.
fn duress(home: &Path, keystore: &mut JniKeystore<'_>) -> Result<(), String> {
    let mut source = Source(1);
    let mut profile =
        Profile::create(home, keystore, true).map_err(|error| format!("creating: {error}"))?;
    let other = Profile::create(home, keystore, true)
        .map_err(|error| format!("creating: {error}"))?
        .id();
    let mut epoch_key = [0; 32];
    let number = profile
        .epoch(keystore, &mut epoch_key)
        .map_err(|error| format!("reading the epoch: {error}"))?
        .number;
    let params = PasswordParams::new(65_536, 3, &mut source)
        .map_err(|error| format!("the parameters: {error}"))?;
    let mut memory = vec![MemoryBlock::new(); params.memory_blocks()];
    let (mut slot_memory, mut epoch) = ([const { Slot::empty() }; 6], Epoch::empty());
    let mut slots = Slots::new(&mut slot_memory, &mut epoch, number, &mut epoch_key);
    let stored = slots
        .generate(Purpose::Wrap, KeyLength::Bytes64, &mut source)
        .map_err(|error| format!("the stored key: {error}"))?;
    profile
        .create_entries(
            &mut slots,
            keystore,
            stored,
            &mut b"owner".to_vec(),
            &params,
            &mut memory,
            &mut source,
        )
        .map_err(|error| format!("making the ways in: {error}"))?;
    slots
        .release(stored)
        .map_err(|error| format!("releasing: {error}"))?;
    profile
        .set_duress(
            &mut slots,
            keystore,
            &mut b"owner".to_vec(),
            &mut b"duress".to_vec(),
            true,
            &params,
            &mut memory,
            &mut source,
        )
        .map_err(|error| format!("setting the password under duress: {error}"))?;
    for (password, what, kept) in [
        (b"owner".as_slice(), "the owner's", true),
        (b"duress", "under duress", false),
        (b"owner", "the owner's again", false),
    ] {
        let stored = profile
            .enter(
                &mut slots,
                keystore,
                &mut password.to_vec(),
                &params,
                &mut memory,
            )
            .map_err(|error| format!("entering with the password {what}: {error}"))?;
        slots
            .release(stored)
            .map_err(|error| format!("releasing: {error}"))?;
        let left = keystore.aliases(&format!("lethewis/{other}/"));
        check(
            left.as_ref().is_ok_and(|left| left.is_empty() != kept),
            &format!("the keys of the other profile after the password {what}: {left:?}"),
        )?;
    }
    check(
        Profile::open(home, other).err() == Some(Error::NotFound),
        "the other profile opens after the password under duress",
    )?;
    sweep(home, keystore).map_err(|error| format!("sweeping: {error}"))?;
    destroyed(profile, keystore).map(|_| ())
}

/// The profile the step before kept.
fn kept(root: &Path) -> Result<Profile, String> {
    let id =
        fs::read_to_string(root.join(KEPT)).map_err(|error| format!("the kept id: {error}"))?;
    let id = Id::parse(&id).ok_or("the kept id is not one")?;
    Profile::open(&root.join(PROFILES), id).map_err(|error| format!("opening: {error}"))
}

/// Verifies the profile until the keystore stops meanwhile, which reads as no lost key.
fn stops(profile: &Profile, keystore: &mut JniKeystore<'_>) -> Result<(), String> {
    for _ in 0..300 {
        match profile.verify(keystore) {
            Ok(()) => thread::sleep(Duration::from_millis(200)),
            Err(error) => {
                return check(
                    matches!(
                        error,
                        Error::Keystore(Failure::Transient | Failure::Unknown)
                    ),
                    &format!("a keystore that stops verifies: {error:?}"),
                );
            }
        }
    }
    Err("the keystore did not stop".to_owned())
}

fn answers(profile: &Profile, keystore: &mut JniKeystore<'_>) -> Result<(), String> {
    let mut out = [0; 32];
    profile
        .answer(keystore, &[1; 32], &mut out)
        .map_err(|error| format!("answering: {error}"))
}

/// A record whose unlocking was turned the other way is found by the chip's key.
fn changed(root: &Path, id: Id, keystore: &mut JniKeystore<'_>) -> Result<(), String> {
    let file = root.join(id.to_string()).join("profile");
    let written = fs::read(&file).map_err(|error| format!("reading the record: {error}"))?;
    let mut changed = written.clone();
    let flags = changed.get_mut(5).ok_or("a record too short")?;
    *flags ^= 1;
    fs::write(&file, &changed).map_err(|error| format!("changing the record: {error}"))?;
    let verified = Profile::open(root, id).map(|profile| profile.verify(keystore));
    fs::write(&file, &written).map_err(|error| format!("restoring the record: {error}"))?;
    check(
        verified == Ok(Err(Error::Damaged)),
        &format!("a changed record: {verified:?}"),
    )
}

/// The answer to known data under a known key passes the bridge as it is.
fn known(keystore: &mut JniKeystore<'_>) -> Result<(), String> {
    let mut out = [0; 32];
    let answered = keystore.mac(KNOWN, b"Hi There", &mut out);
    keystore
        .delete(KNOWN)
        .map_err(|failure| format!("deleting the known key: {failure}"))?;
    check(
        answered == Ok(()) && out == KNOWN_ANSWER,
        &format!("the known answer: {answered:?} {out:02x?}"),
    )
}

/// The keystore through the bridge; returns where the key of a profile is to be held.
fn keystore_alone(keystore: &mut JniKeystore<'_>) -> Result<Level, String> {
    let alias = "lethewis-test/alone";
    let gone = keystore.delete(alias);
    check(gone == Ok(()), &format!("deleting a missing key: {gone:?}"))?;
    let held = keystore.contains(alias);
    check(held == Ok(false), &format!("a missing key: {held:?}"))?;
    let mut out = [0x5a; 32];
    let answered = keystore.mac(alias, b"data", &mut out);
    check(
        answered == Err(Failure::Absent),
        &format!("a missing key answers: {answered:?}"),
    )?;
    check(out == [0x5a; 32], "a failed answer changed the output")?;
    let probes = keystore.aliases("lethewis/probe");
    check(
        probes == Ok(Vec::new()),
        &format!("a key left by a probe: {probes:?}"),
    )?;
    let strong = keystore.generate(alias, true, false);
    check(
        matches!(
            strong,
            Ok(Level::StrongBox) | Err(Failure::StrongBoxUnavailable)
        ),
        &format!("the secure element: {strong:?}"),
    )?;
    if strong.is_ok() {
        keystore
            .delete(alias)
            .map_err(|failure| format!("deleting: {failure}"))?;
    }
    let level = keystore
        .generate(alias, false, false)
        .map_err(|failure| format!("generating: {failure}"))?;
    check(
        level != Level::StrongBox,
        "a key outside the secure element is in it",
    )?;
    let held = keystore.contains(alias);
    check(held == Ok(true), &format!("a key made: {held:?}"))?;
    let (mut first, mut again, mut other) = ([0; 32], [0; 32], [0; 32]);
    for (data, out) in [
        (b"same", &mut first),
        (b"same", &mut again),
        (b"else", &mut other),
    ] {
        keystore
            .mac(alias, data, out)
            .map_err(|failure| format!("answering: {failure}"))?;
    }
    check(first == again, "two answers to the same data differ")?;
    check(first != other, "answers to different data are the same")?;
    keystore
        .delete(alias)
        .map_err(|failure| format!("deleting: {failure}"))?;
    let held = keystore.contains(alias);
    check(held == Ok(false), &format!("a deleted key: {held:?}"))?;
    Ok(if strong.is_ok() {
        Level::StrongBox
    } else {
        level
    })
}

fn profiles(
    root: &Path,
    keystore: &mut JniKeystore<'_>,
    api: u32,
    expected: Level,
) -> Result<(), String> {
    let created =
        Profile::create(root, keystore, true).map_err(|error| format!("creating: {error}"))?;
    let id = created.id();
    check(
        created.level() == expected,
        &format!("the profile's key is at {:?}", created.level()),
    )?;
    check(
        created.unlocked_only() == (api >= 35),
        "unlocked only, by API level",
    )?;
    let busy = Profile::open(root, id).err();
    check(
        busy == Some(Error::Busy),
        &format!("a second opening: {busy:?}"),
    )?;
    drop(created);
    let profile = Profile::open(root, id).map_err(|error| format!("opening: {error}"))?;
    profile
        .verify(keystore)
        .map_err(|error| format!("verifying: {error}"))?;
    let (mut first, mut again, mut other) = ([0; 32], [0; 32], [0; 32]);
    for (challenge, out) in [
        ([1; 32], &mut first),
        ([1; 32], &mut again),
        ([2; 32], &mut other),
    ] {
        profile
            .answer(keystore, &challenge, out)
            .map_err(|error| format!("answering: {error}"))?;
    }
    check(first == again, "two answers to one challenge differ")?;
    check(first != other, "answers to two challenges are the same")?;
    drop(profile);
    changed(root, id, keystore)?;
    let profile = Profile::open(root, id).map_err(|error| format!("opening: {error}"))?;
    let alias = alias(id);
    keystore
        .delete(&alias)
        .map_err(|failure| format!("deleting: {failure}"))?;
    let lost = profile.verify(keystore);
    check(
        lost == Err(Error::Keystore(Failure::Absent)),
        &format!("a lost key: {lost:?}"),
    )?;
    keystore
        .generate(&alias, false, profile.unlocked_only())
        .map_err(|failure| format!("replacing: {failure}"))?;
    let replaced = profile.verify(keystore);
    check(
        replaced == Err(Error::ChipChanged),
        &format!("a replaced key: {replaced:?}"),
    )?;
    destroyed(profile, keystore).map(|_| ())
}

/// The roots of epochs on the keystore of the device: a change, an erasure, what an unfinished
/// change leaves, a key only the listing finds, and a destruction.
fn epochs(root: &Path, keystore: &mut JniKeystore<'_>) -> Result<(), String> {
    let created =
        Profile::create(root, keystore, true).map_err(|error| format!("creating: {error}"))?;
    let id = created.id();
    drop(created);
    // In the order of the names: the system lists them in its own.
    let names = |keystore: &mut JniKeystore<'_>| {
        keystore
            .aliases(&format!("lethewis/{id}/"))
            .map(|mut names| {
                names.sort();
                names
            })
    };
    let (mut profile, first) = epoch(root, id, keystore, 0)?;
    let mut second = [0; 32];
    let next = profile
        .next_epoch(keystore, true, &mut second)
        .map_err(|error| format!("the next epoch: {error}"))?;
    check(next.number == 1 && second != first, "the next epoch's key")?;
    let mut roots = profile.roots(keystore);
    check(roots.switch(1).is_ok(), "switching")?;
    let expected = if next.previous.secure() {
        Erasure::BestEffort
    } else {
        Erasure::NotErased
    };
    let erased = roots.erase(0);
    check(erased == expected, &format!("erasing: {erased:?}"))?;
    let listed = names(keystore);
    let wanted = Ok(vec![
        format!("lethewis/{id}/chip"),
        format!("lethewis/{id}/root/1"),
    ]);
    check(
        listed == wanted,
        &format!("the keys after a change: {listed:?}"),
    )?;
    drop(profile);
    let (mut profile, again) = epoch(root, id, keystore, 1)?;
    check(again == second, "the key of the epoch read again")?;
    // A change cut short leaves the root of epoch 2, and a key with no file only the listing
    // finds; the next reading erases both, the second with its level unknown.
    profile
        .next_epoch(keystore, true, &mut [0; 32])
        .map_err(|error| format!("a change cut short: {error}"))?;
    drop(profile);
    keystore
        .generate(&format!("lethewis/{id}/root/7"), false, false)
        .map_err(|failure| format!("a key with no file: {failure}"))?;
    let mut profile = Profile::open(root, id).map_err(|error| format!("opening: {error}"))?;
    let current = profile
        .epoch(keystore, &mut [0; 32])
        .map_err(|error| format!("reading after a change cut short: {error}"))?;
    check(
        current.number == 1 && current.swept == Some(Erasure::NotErased),
        &format!("what a change cut short left: {current:?}"),
    )?;
    let listed = names(keystore);
    check(
        listed == wanted,
        &format!("the keys after a change cut short: {listed:?}"),
    )?;
    let erasure = destroyed(profile, keystore)?;
    check(erasure == expected, &format!("a destruction: {erasure:?}"))?;
    check(
        !root.join(id.to_string()).exists(),
        "the directory after a destruction",
    )?;
    let swept = sweep(root, keystore);
    check(swept == Ok(None), &format!("a sweep of nothing: {swept:?}"))
}

/// Opens the profile `id`, reads its epoch, and checks the number.
fn epoch(
    root: &Path,
    id: Id,
    keystore: &mut JniKeystore<'_>,
    number: u64,
) -> Result<(Profile, [u8; 32]), String> {
    let mut profile = Profile::open(root, id).map_err(|error| format!("opening: {error}"))?;
    let mut key = [0; 32];
    let current = profile
        .epoch(keystore, &mut key)
        .map_err(|error| format!("reading the epoch: {error}"))?;
    check(
        current.number == number && current.swept.is_none(),
        &format!("the epoch: {current:?}"),
    )?;
    Ok((profile, key))
}
