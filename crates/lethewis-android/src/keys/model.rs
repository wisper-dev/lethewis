// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The keys under interleavings of their threads that the PCT scheduler of shuttle picks.
//!
//! Records are atomics of `std`, which are no points of the schedule: what a call records is the
//! state at the moment the keys' thread decided to run it.

// Clippy takes only the `#[test]` functions for tests, not the models they run.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a model stops at what it does not expect"
)]

use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool as Record, AtomicUsize, Ordering::SeqCst};

use shuttle::thread;

use super::{Kept, Keys, Unheld, allow_keys, settle_keys, wipe_keys};

/// Sets its record once what the calls keep is dropped, just before the slots and their memory.
struct Watched(Arc<Record>);

struct Dropped(Arc<Record>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, SeqCst);
    }
}

impl Kept for Watched {
    type Held<'a> = Dropped;

    fn hold<'a>(self) -> Self::Held<'a> {
        Dropped(self.0)
    }
}

/// Schedules of each model; PCT finds a bug that needs at most `DEPTH` orderings among them with
/// a probability bounded from below by the number of threads and steps.
const RUNS: usize = 100_000;
const DEPTH: usize = 3;

/// Runs `model` under PCT and fails unless it ran every time.
fn explore(model: fn()) {
    let runs = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&runs);
    shuttle::check_pct(
        move || {
            counted.fetch_add(1, SeqCst);
            model();
        },
        RUNS,
        DEPTH,
    );
    assert_eq!(runs.load(SeqCst), RUNS);
}

fn start(dropped: &Arc<Record>) -> Result<Keys<Watched>, Unheld> {
    Keys::start::<1>(0, &mut [1; 32], Watched(Arc::clone(dropped)))
}

fn call_and_wipe() {
    let dropped = Arc::new(Record::new(false));
    let keys = Arc::new(start(&dropped).unwrap());
    let wiped = Arc::new(Record::new(false));
    let ran = Arc::new(Record::new(false));
    let late = Arc::new(Record::new(false));
    let caller = {
        let (keys, wiped, ran, late) = (
            Arc::clone(&keys),
            Arc::clone(&wiped),
            Arc::clone(&ran),
            Arc::clone(&late),
        );
        thread::spawn(move || {
            keys.call(move |_, _| {
                ran.store(true, SeqCst);
                late.store(wiped.load(SeqCst), SeqCst);
            })
        })
    };
    keys.wipe();
    wiped.store(true, SeqCst);
    let after = Arc::new(Record::new(false));
    let refused = {
        let after = Arc::clone(&after);
        keys.call(move |_, _| after.store(true, SeqCst))
    };
    assert_eq!(refused, Err(Unheld::Wiped));
    assert!(settle_keys(Duration::MAX));
    assert!(
        dropped.load(SeqCst),
        "settled before what the calls kept was dropped"
    );
    assert_eq!(caller.join().unwrap().is_ok(), ran.load(SeqCst));
    assert!(!late.load(SeqCst), "a call started after the wipe returned");
    assert!(!after.load(SeqCst), "a call asked after the wipe ran");
}

#[test]
fn a_call_runs_before_the_wipe_or_never() {
    explore(call_and_wipe);
}

fn start_as_the_app_leaves() {
    let dropped = Arc::new(Record::new(false));
    let starter = {
        let dropped = Arc::clone(&dropped);
        thread::spawn(move || start(&dropped))
    };
    allow_keys(false);
    match starter.join().unwrap() {
        Err(Unheld::Away) => assert!(!dropped.load(SeqCst)),
        Ok(keys) => {
            assert_eq!(keys.call(|_, _| ()), Err(Unheld::Wiped));
            assert!(settle_keys(Duration::MAX));
            assert!(
                dropped.load(SeqCst),
                "settled before what the calls kept was dropped"
            );
        }
        Err(other) => panic!("{other}"),
    }
}

#[test]
fn keys_started_as_the_app_leaves_are_refused_or_wiped() {
    explore(start_as_the_app_leaves);
}

fn drop_while_wiped_and_settled() {
    let dropped = Arc::new(Record::new(false));
    let keys = start(&dropped).unwrap();
    let wiper = thread::spawn(wipe_keys);
    let settler = thread::spawn(|| settle_keys(Duration::MAX));
    drop(keys);
    assert!(
        dropped.load(SeqCst),
        "a drop returned before what the calls kept was dropped"
    );
    wiper.join().unwrap();
    assert!(settler.join().unwrap());
}

#[test]
fn a_drop_returns_once_the_keys_are_gone() {
    explore(drop_while_wiped_and_settled);
}

fn settle_during_a_call() {
    let dropped = Arc::new(Record::new(false));
    let keys = Arc::new(start(&dropped).unwrap());
    let finished = Arc::new(Record::new(false));
    let caller = {
        let (keys, finished) = (Arc::clone(&keys), Arc::clone(&finished));
        thread::spawn(move || {
            keys.call(move |_, _| {
                // The rest of the process may run while the call is under way.
                thread::yield_now();
                finished.store(true, SeqCst);
            })
        })
    };
    allow_keys(false);
    assert!(settle_keys(Duration::MAX));
    let finished_by_then = finished.load(SeqCst);
    assert!(
        dropped.load(SeqCst),
        "settled before what the calls kept was dropped"
    );
    if caller.join().unwrap().is_ok() {
        assert!(
            finished_by_then,
            "settled before the call under way returned"
        );
    }
}

#[test]
fn a_settle_returns_after_the_call_under_way() {
    explore(settle_during_a_call);
}
