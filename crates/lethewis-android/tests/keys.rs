// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Keys held by a thread of their own. A binary apart from the tests of profiles: a process these
//! tests start would hold the lock of a profile for a moment, and a test of profiles find it busy.

#![cfg(any(target_os = "linux", target_os = "android"))]
// Clippy takes only the `#[test]` functions of a test binary for tests, not their helpers.
#![expect(
    clippy::unwrap_used,
    reason = "a test stops at what it does not expect"
)]

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::FileExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread;
use std::time::Duration;

use lethewis_android::{Kept, Keys, Unheld, allow_keys, settle_keys, wipe_keys};
use lethewis_core::{Handle, Purpose};
use zeroize::Zeroize;

/// What the calls of the tests keep: how many there were, and the handles they loaded.
struct Counted;

struct Count<'a> {
    calls: u32,
    handles: Vec<Handle<'a>>,
    keep: Option<Arc<Keys<Counted>>>,
}

impl Kept for Counted {
    type Held<'a> = Count<'a>;

    fn hold<'a>(self) -> Count<'a> {
        Count {
            calls: 0,
            handles: Vec::new(),
            keep: None,
        }
    }
}

/// The tests keep their keys only under this mask, so that a search of memory finds no copy of
/// their own.
const MASK: [u8; 32] = [0x5a; 32];

/// Taken by each test that holds keys in the shared process: an Android app's process locks
/// four pages of 16 KiB at most.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs the test `name` again in a process of its own, unless this is that process; tells
/// whether it is.
fn own_process(name: &str) -> bool {
    if env::var_os("LETHEWIS_KEYS_PROCESS").is_some() {
        return true;
    }
    let output = Command::new(env::current_exe().unwrap())
        .args(["--exact", name])
        .env("LETHEWIS_KEYS_PROCESS", "1")
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && report.contains("1 passed"),
        "{report}"
    );
    false
}

/// The key of `seed`, under the mask.
fn masked(seed: u8) -> [u8; 32] {
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        let index = u8::try_from(index).unwrap_or(0);
        *byte = seed.wrapping_mul(31).wrapping_add(index.wrapping_mul(97)) ^ 0xc3;
    }
    key
}

fn start(seed: u8) -> Keys<Counted> {
    allow_keys(true);
    let masked = masked(seed);
    let mut key = [0; 32];
    for (byte, (&hidden, &mask)) in key.iter_mut().zip(masked.iter().zip(MASK.iter())) {
        *byte = hidden ^ mask;
    }
    let keys = Keys::start::<4>(7, &mut key, Counted).unwrap();
    assert_eq!(key, [0; 32]);
    keys
}

/// Imports the key of `seed` into a slot on the keys' thread.
fn import(keys: &Keys<Counted>, seed: u8) {
    let masked = masked(seed);
    keys.call(move |slots, count| {
        let mut key = [0; 32];
        for (byte, (&hidden, &mask)) in key.iter_mut().zip(masked.iter().zip(MASK.iter())) {
            *byte = hidden ^ mask;
        }
        count.handles.push(slots.import32(Purpose::Wrap, &mut key)?);
        Ok::<(), lethewis_core::Error>(())
    })
    .unwrap()
    .unwrap();
}

#[test]
fn calls_reach_the_same_slots_and_what_they_keep_one_after_another() {
    let _one = one_at_a_time();
    let keys = start(1);
    import(&keys, 11);
    let released = keys
        .call(|slots, count| {
            count.calls += 1;
            let handle = count.handles.pop().unwrap();
            (slots.release(handle), slots.release(handle), count.calls)
        })
        .unwrap();
    assert_eq!(
        released,
        (Ok(()), Err(lethewis_core::Error::StaleHandle), 1)
    );
}

#[test]
fn a_wipe_refuses_every_later_call() {
    let _one = one_at_a_time();
    let keys = start(2);
    keys.call(|_, _| ()).unwrap();
    keys.wipe();
    assert_eq!(keys.call(|_, _| ()), Err(Unheld::Wiped));
}

#[test]
fn a_call_under_way_returns_before_the_wipe() {
    let _one = one_at_a_time();
    let keys = start(3);
    let (started, waiting) = mpsc::channel();
    let (finish, finishing) = mpsc::channel::<()>();
    thread::scope(|scope| {
        let running = scope.spawn(|| {
            keys.call(move |_, count| {
                started.send(()).unwrap();
                finishing.recv().unwrap();
                count.calls
            })
        });
        waiting.recv().unwrap();
        keys.wipe();
        let settled = settle_keys(Duration::from_millis(100));
        let (refused, refusal) = mpsc::channel();
        let shared = &keys;
        scope.spawn(move || refused.send(shared.call(|_, _| ())).unwrap());
        let later = refusal.recv_timeout(Duration::from_secs(5));
        // Released before any check, so that a failed one does not leave the call waiting.
        finish.send(()).unwrap();
        assert!(!settled, "the wipe cut the call short");
        assert_eq!(
            later,
            Ok(Err(Unheld::Wiped)),
            "a call after the wipe waited"
        );
        assert_eq!(running.join().unwrap(), Ok(0));
    });
    assert!(
        settle_keys(Duration::from_secs(5)),
        "the wipe did not follow the call"
    );
}

#[test]
fn calls_waiting_behind_the_wipe_are_refused() {
    let _one = one_at_a_time();
    let keys = start(4);
    let (started, waiting) = mpsc::channel();
    let (finish, finishing) = mpsc::channel::<()>();
    thread::scope(|scope| {
        let running = scope.spawn(|| {
            keys.call(move |_, _| {
                started.send(()).unwrap();
                finishing.recv().unwrap();
            })
        });
        waiting.recv().unwrap();
        let queued = scope.spawn(|| keys.call(|_, _| ()));
        // The second call is sent before the wipe: it waits behind the first.
        thread::sleep(Duration::from_millis(100));
        keys.wipe();
        finish.send(()).unwrap();
        assert_eq!(running.join().unwrap(), Ok(()));
        assert_eq!(queued.join().unwrap(), Err(Unheld::Wiped));
    });
}

#[test]
fn a_call_that_panics_ends_the_keys() {
    let _one = one_at_a_time();
    let keys = start(5);
    assert_eq!(
        keys.call(|_, _| -> u8 { panic!("deliberately") }),
        Err(Unheld::Wiped)
    );
    assert_eq!(keys.call(|_, _| ()), Err(Unheld::Wiped));
}

#[test]
fn a_call_from_inside_a_call_is_refused() {
    let _one = one_at_a_time();
    let keys = Arc::new(start(12));
    let inner = Arc::clone(&keys);
    let (answer, answered) = mpsc::channel();
    // Apart, so that a call waiting for itself fails the test instead of hanging it.
    let caller = thread::spawn(move || answer.send(keys.call(move |_, _| inner.call(|_, _| ()))));
    let answer = answered.recv_timeout(Duration::from_secs(5));
    if answer.is_ok() {
        // Its drop of the keys ends before the next test.
        caller.join().unwrap().unwrap();
    }
    assert_eq!(answer, Ok(Ok(Err(Unheld::Inside))));
}

/// What a test keeps: it takes a while to drop, as the keys' thread ends.
struct Slow;

struct Sleeper;

impl Drop for Sleeper {
    fn drop(&mut self) {
        thread::sleep(Duration::from_millis(200));
    }
}

impl Kept for Slow {
    type Held<'a> = Sleeper;

    fn hold<'a>(self) -> Self::Held<'a> {
        Sleeper
    }
}

#[test]
fn a_drop_returns_only_once_the_keys_are_wiped() {
    let _one = one_at_a_time();
    allow_keys(true);
    let keys = Keys::start::<1>(0, &mut [1; 32], Slow).unwrap();
    keys.wipe();
    // A timeout past what the clock counts waits as long as the wipe takes; apart, so that a wait
    // that never ends fails the test instead of hanging it.
    let (answer, answered) = mpsc::channel();
    thread::spawn(move || answer.send(settle_keys(Duration::MAX)));
    assert_eq!(answered.recv_timeout(Duration::from_secs(10)), Ok(true));
    drop(keys);
    drop(Keys::start::<1>(0, &mut [1; 32], Slow).unwrap());
    assert!(
        settle_keys(Duration::ZERO),
        "the drop returned before the keys ended"
    );
}

#[test]
fn every_refusal_reads_differently_and_keys_show_nothing() {
    let all = [
        Unheld::Wiped,
        Unheld::Unwatched,
        Unheld::Away,
        Unheld::Inside,
        Unheld::Memory(lethewis_locked::Error::Lock(12)),
        Unheld::Thread(io::ErrorKind::OutOfMemory),
    ];
    let texts: HashSet<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), all.len());
    assert!(texts.iter().all(|text| !text.is_empty()));
    let _one = one_at_a_time();
    assert_eq!(format!("{:?}", start(13)), "Keys { .. }");
}

/// Run in a process of its own: the wipe reaches every key of the process.
#[test]
fn wiping_the_process_reaches_every_key() {
    if !own_process("wiping_the_process_reaches_every_key") {
        return;
    }
    let (first, second) = (start(6), start(7));
    wipe_keys();
    assert_eq!(first.call(|_, _| ()), Err(Unheld::Wiped));
    assert_eq!(second.call(|_, _| ()), Err(Unheld::Wiped));
    let third = start(8);
    assert_eq!(third.call(|_, count| count.calls), Ok(0));
}

/// Run in a process of its own: what the process allows is shared.
#[test]
fn keys_are_neither_held_nor_kept_while_the_app_is_away() {
    if !own_process("keys_are_neither_held_nor_kept_while_the_app_is_away") {
        return;
    }
    let first = start(14);
    allow_keys(false);
    assert_eq!(first.call(|_, _| ()), Err(Unheld::Wiped));
    let mut key = [1; 32];
    assert_eq!(Keys::start::<1>(0, &mut key, ()).err(), Some(Unheld::Away));
    assert_eq!(key, [1; 32]);
    allow_keys(true);
    assert_eq!(start(15).call(|_, count| count.calls), Ok(0));
}

/// Run in a process of its own: what the process allows is shared.
#[test]
fn keys_started_as_the_app_goes_away_are_wiped_or_refused() {
    if !own_process("keys_started_as_the_app_goes_away_are_wiped_or_refused") {
        return;
    }
    for _ in 0..500 {
        allow_keys(true);
        let away = thread::spawn(|| allow_keys(false));
        let started = Keys::start::<1>(0, &mut [1; 32], ());
        away.join().unwrap();
        if let Ok(keys) = started {
            assert_eq!(keys.call(|_, ()| ()), Err(Unheld::Wiped));
        }
    }
}

/// Run in a process of its own: it wipes every key of the process and watches for panics.
#[test]
fn keys_dropped_on_their_own_thread_end_without_waiting_for_themselves() {
    if !own_process("keys_dropped_on_their_own_thread_end_without_waiting_for_themselves") {
        return;
    }
    let panicked = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&panicked);
    std::panic::set_hook(Box::new(move |_| seen.store(true, Ordering::SeqCst)));
    let keys = Arc::new(start(16));
    let inner = Arc::clone(&keys);
    keys.call(move |_, count| count.keep = Some(inner)).unwrap();
    // The last reference is now among what the calls keep, dropped on the keys' own thread.
    drop(keys);
    wipe_keys();
    assert!(settle_keys(Duration::from_secs(5)), "the keys did not end");
    assert!(
        !panicked.load(Ordering::SeqCst),
        "a drop waited for its own thread"
    );
}

/// Run in a process of its own: on Android nothing is held before the Java layer watches.
#[test]
fn keys_are_held_on_android_only_once_the_screen_is_watched() {
    if !own_process("keys_are_held_on_android_only_once_the_screen_is_watched") {
        return;
    }
    let mut key = [1; 32];
    let started = Keys::start::<1>(0, &mut key, ());
    if cfg!(target_os = "android") {
        assert_eq!(started.err(), Some(Unheld::Unwatched));
        assert_eq!(key, [1; 32]);
    } else {
        assert!(started.is_ok());
    }
    allow_keys(true);
    assert!(Keys::start::<1>(0, &mut [1; 32], ()).is_ok());
}

/// Whether memory of this process still holds either half of the key of `seed`, compared under
/// the mask.
fn found(seed: u8) -> bool {
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    let memory = fs::File::open("/proc/self/mem").unwrap();
    let wanted = masked(seed);
    let halves = [wanted.get(..16).unwrap(), wanted.get(16..).unwrap()];
    let mut bytes = Vec::new();
    let mut hit = false;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(permissions)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        // Only memory the process writes can hold a copy; the kernel's own pages do not read.
        if !permissions.starts_with("rw") || line.contains("[vvar") {
            continue;
        }
        bytes.resize(usize::try_from(end.checked_sub(start).unwrap()).unwrap(), 0);
        if memory.read_exact_at(&mut bytes, start).is_err() {
            continue;
        }
        hit |= bytes.windows(16).any(|window| {
            halves.iter().any(|half| {
                window
                    .iter()
                    .zip(half.iter())
                    .zip(MASK.iter())
                    .all(|((&byte, &hidden), &mask)| byte ^ mask == hidden)
            })
        });
        // The copy read holds what it found; the next search would find it again.
        bytes.zeroize();
        if hit {
            break;
        }
    }
    hit
}

#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "the pad is a large array on the stack"
)]
fn below_pad<R>(code: impl FnOnce() -> R) -> R {
    let pad = std::hint::black_box([0x11_u8; 64 * 1024]);
    let result = code();
    std::hint::black_box(&pad);
    result
}

/// Run in a process of its own, so that no other test's keys are in its memory.
#[test]
fn wiped_keys_are_nowhere_in_the_memory_of_the_process() {
    if !own_process("wiped_keys_are_nowhere_in_the_memory_of_the_process") {
        return;
    }
    // Started under a pad, so that the calls after it do not write over the stack it used.
    let keys = below_pad(|| start(9));
    assert!(found(9), "the search does not see the epoch key held");
    drop(keys);
    assert!(!found(9), "the epoch key outlived the drop");
    let keys = start(11);
    import(&keys, 10);
    assert!(found(10), "the search does not see the key held");
    wipe_keys();
    assert!(settle_keys(Duration::from_secs(5)), "the wipe did not end");
    assert!(!found(10), "a key outlived the wipe");
    assert!(!found(11), "the epoch key outlived the wipe");
    drop(keys);
}
