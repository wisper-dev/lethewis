// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The native methods of `com.alanwisper.lethewis.test.Tests`, the tests on a device. Only a build
//! for the tests has them.

use core::ptr;
use std::fs;
use std::path::Path;

use jni_sys::{JNIEnv, jclass, jint, jstring};
use lethewis_android::{Error, Failure, Id, Keystore, Level, Profile};

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
    let outcome = match (
        text(&keystore, root),
        text(&keystore, test),
        u32::try_from(api),
    ) {
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

/// The string `string` as UTF-8, if it is one.
#[allow(unsafe_code)]
fn text(keystore: &JniKeystore<'_>, string: jstring) -> Option<String> {
    if string.is_null() {
        return None;
    }
    let functions = keystore.table();
    let env = keystore.env();
    // SAFETY: the environment is valid, no exception is pending, and `string` is a string.
    let characters = unsafe { (functions.GetStringLength)(env, string) };
    // SAFETY: as above.
    let length = unsafe { (functions.GetStringUTFLength)(env, string) };
    let mut bytes = vec![0_u8; usize::try_from(length).ok()?.checked_add(1)?];
    // SAFETY: as above; `bytes` takes the modified UTF-8 of all `characters` and the NUL after it.
    unsafe {
        (functions.GetStringUTFRegion)(env, string, 0, characters, bytes.as_mut_ptr().cast());
    }
    if keystore.thrown() {
        return None;
    }
    bytes.truncate(usize::try_from(length).ok()?);
    String::from_utf8(bytes).ok()
}

fn check(holds: bool, what: &str) -> Result<(), String> {
    if holds { Ok(()) } else { Err(what.to_owned()) }
}

/// The tests `test`: `all` with the device unlocked, or one step of a profile kept across a lock:
/// `before-lock`, `locked` and `after-lock`.
fn run(root: &Path, keystore: &mut JniKeystore<'_>, api: u32, test: &str) -> Result<(), String> {
    check(
        keystore.api_level() == api,
        &format!("API level {} for {api}", keystore.api_level()),
    )?;
    match test {
        "all" => {
            empty(root)?;
            known(keystore)?;
            let expected = keystore_alone(keystore)?;
            profiles(root, keystore, api, expected)?;
            remove(root)
        }
        "before-lock" => {
            empty(root)?;
            let profile = Profile::create(root, keystore, true)
                .map_err(|error| format!("creating: {error}"))?;
            fs::write(root.join(KEPT), profile.id().to_string())
                .map_err(|error| format!("keeping the profile: {error}"))?;
            answers(&profile, keystore)
        }
        "locked" => {
            let profile = kept(root)?;
            let mut out = [0; 32];
            let answered = profile.answer(keystore, &[1; 32], &mut out);
            // Below API 35 the key is not bound to the lock screen, so it answers.
            let expected = if api >= 35 {
                Err(Error::Keystore(Failure::Locked))
            } else {
                Ok(())
            };
            check(
                answered == expected,
                &format!("a locked device answers: {answered:?}"),
            )
        }
        "after-lock" => {
            let profile = kept(root)?;
            answers(&profile, keystore)?;
            keystore
                .delete(&alias(profile.id()))
                .map_err(|failure| format!("deleting: {failure}"))?;
            drop(profile);
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

/// The profile the step before kept.
fn kept(root: &Path) -> Result<Profile, String> {
    let id =
        fs::read_to_string(root.join(KEPT)).map_err(|error| format!("the kept id: {error}"))?;
    let id = Id::parse(&id).ok_or("the kept id is not one")?;
    Profile::open(root, id).map_err(|error| format!("opening: {error}"))
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
    keystore
        .delete(&alias)
        .map_err(|failure| format!("deleting: {failure}"))?;
    Ok(())
}
