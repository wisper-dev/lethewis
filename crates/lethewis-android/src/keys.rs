// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;
use core::time::Duration;
use std::io;
use std::sync::{Arc, PoisonError, Weak};
use std::time::Instant;

#[cfg(all(test, shuttle))]
use shuttle::{
    sync::atomic::{AtomicBool, Ordering},
    sync::mpsc::{self, Receiver, Sender},
    sync::{Condvar, Mutex, MutexGuard},
    thread::{self, JoinHandle, ThreadId},
};
#[cfg(not(all(test, shuttle)))]
use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::mpsc::{self, Receiver, Sender},
    sync::{Condvar, Mutex, MutexGuard},
    thread::{self, JoinHandle, ThreadId},
};

use lethewis_core::{Epoch, Slot, Slots};
use lethewis_locked::Locked;
use zeroize::Zeroize;

/// Whether this process may hold keys now, and the keys it holds.
struct Process {
    /// Whether the Java layer reports for this process. On Android nothing else would wipe keys.
    watched: bool,
    /// Whether keys may be held, as the Java layer last reported.
    allowed: bool,
    held: Vec<Weak<Shared>>,
}

impl Process {
    const STARTED: Self = Self {
        watched: !cfg!(target_os = "android"),
        allowed: !cfg!(target_os = "android"),
        held: Vec::new(),
    };
}

#[cfg(not(all(test, shuttle)))]
static PROCESS: Mutex<Process> = Mutex::new(Process::STARTED);

// Each run of a model starts from a process of its own.
#[cfg(all(test, shuttle))]
shuttle::lazy_static! {
    static ref PROCESS: Mutex<Process> = Mutex::new(Process::STARTED);
}

fn process() -> MutexGuard<'static, Process> {
    PROCESS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Why keys are not held, or a call did not reach them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unheld {
    /// The keys were wiped, or their thread ended.
    Wiped,
    /// On Android, before the Java layer's `Wiper.start`: nothing would wipe the keys.
    Unwatched,
    /// The device is off or locked, or the app neither shows an activity nor runs a foreground
    /// service of its own.
    Away,
    /// A call of the keys from inside one of their calls, which would wait for itself.
    Inside,
    /// The memory for the keys could not be locked.
    Memory(lethewis_locked::Error),
    /// No thread could be started for the keys.
    Thread(io::ErrorKind),
}

impl fmt::Display for Unheld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wiped => f.write_str("the keys were wiped"),
            Self::Unwatched => f.write_str("nothing watches the screen to wipe the keys"),
            Self::Away => f.write_str("the app is away from the screen"),
            Self::Inside => f.write_str("a call of the keys from inside one of their calls"),
            Self::Memory(error) => write!(f, "the memory for the keys was refused: {error}"),
            Self::Thread(kind) => write!(f, "no thread for the keys: {kind}"),
        }
    }
}

impl std::error::Error for Unheld {}

/// What the calls of [`Keys`] keep beside the slots from one to the next, such as the profile and
/// the handles of keys loaded.
pub trait Kept: Send + 'static {
    /// What the calls see, beside slots whose memory lives for `'a`: handles of them may be in it.
    type Held<'a>;

    /// Makes what the calls see, on the keys' thread, before the first call.
    fn hold<'a>(self) -> Self::Held<'a>;
}

impl Kept for () {
    type Held<'a> = ();

    fn hold<'a>(self) -> Self::Held<'a> {}
}

/// The keys of an open profile: [`Slots`] in locked memory, held by a thread of their own with
/// what the calls keep beside them. Every call runs on that thread, one at a time.
///
/// On Android keys are held only while the device is on and unlocked, and the app shows an activity
/// or runs a foreground service of its own. The Java layer's `Wiper` reports that; once it ends,
/// every [`Keys`] of the process is wiped.
///
/// A wipe, by that, by [`Keys::wipe`], [`wipe_keys`] or a drop, wipes the slots and their memory
/// once the call under way returns, and refuses every later call.
///
/// The thread is the library's: a call that reaches the keystore through JNI attaches it to the JVM
/// first.
pub struct Keys<K: Kept> {
    shared: Arc<Shared>,
    calls: Sender<Message<K>>,
    thread: Option<JoinHandle<()>>,
    owner: ThreadId,
}

/// What the keys share with the process.
struct Shared {
    wiped: AtomicBool,
    /// Wakes the thread, so that it ends without waiting for a call.
    wake: Box<dyn Fn() + Send + Sync>,
    /// Whether the thread ended, with the slots and their memory wiped; calls are sent under it.
    ended: Mutex<bool>,
    ending: Condvar,
}

/// A call, for slots and what is kept whose memory lives for `'a`.
type Call<K> = Box<dyn for<'a, 'b> FnOnce(&'b mut Slots<'a>, &'b mut <K as Kept>::Held<'a>) + Send>;

enum Message<K: Kept> {
    Call(Call<K>),
    Wipe,
}

/// The memory a [`Slots`] keeps its keys in, with the key of its epoch until `Slots::new` takes it.
struct Memory<const N: usize> {
    slots: [Slot; N],
    epoch: Epoch,
    key: [u8; 32],
}

impl Shared {
    fn wipe(&self) {
        self.wiped.store(true, Ordering::Release);
        (self.wake)();
    }

    /// Waits until the thread ended, or until `deadline` if there is one; tells whether it ended.
    fn ended_by(&self, deadline: Option<Instant>) -> bool {
        let mut ended = self.ended.lock().unwrap_or_else(PoisonError::into_inner);
        while !*ended {
            ended = match deadline {
                Some(deadline) => {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        return false;
                    };
                    self.ending
                        .wait_timeout(ended, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => self
                    .ending
                    .wait(ended)
                    .unwrap_or_else(PoisonError::into_inner),
            };
        }
        true
    }
}

impl<K: Kept> Keys<K> {
    /// Starts a thread holding `N` slots in locked memory, in the epoch numbered `number`, whose
    /// key it takes from `key` and wipes, as `Slots::new` does; what `kept` holds goes with them.
    /// The memory takes whole pages, and an Android app's process locks 64 KiB in all.
    ///
    /// # Errors
    ///
    /// On Android [`Unheld::Unwatched`] before `Wiper.start`, and [`Unheld::Away`]; then
    /// [`Unheld::Memory`] or [`Unheld::Thread`]. `key` is then left as it was.
    pub fn start<const N: usize>(number: u64, key: &mut [u8; 32], kept: K) -> Result<Self, Unheld> {
        // Held until the keys are listed, so that a report of the app going away reaches them.
        let mut process = process();
        if !process.watched {
            return Err(Unheld::Unwatched);
        }
        if !process.allowed {
            return Err(Unheld::Away);
        }
        let mut memory = Locked::new(Memory::<N> {
            slots: [const { Slot::empty() }; N],
            epoch: Epoch::empty(),
            key: [0; 32],
        })
        .map_err(Unheld::Memory)?;
        memory.key.copy_from_slice(key);
        let (calls, received) = mpsc::channel();
        let waker = calls.clone();
        let shared = Arc::new(Shared {
            wiped: AtomicBool::new(false),
            wake: Box::new(move || {
                // A thread that ended has nothing left to wipe.
                let _ = waker.send(Message::Wipe);
            }),
            ended: Mutex::new(false),
            ending: Condvar::new(),
        });
        let watched = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("lethewis-keys".to_owned())
            .spawn(move || serve(memory, number, kept, &received, &watched))
            .map_err(|error| Unheld::Thread(error.kind()))?;
        key.zeroize();
        process.held.retain(|shared| shared.strong_count() > 0);
        process.held.push(Arc::downgrade(&shared));
        drop(process);
        Ok(Self {
            shared,
            calls,
            owner: thread.thread().id(),
            thread: Some(thread),
        })
    }

    /// Runs `call` on the keys' thread and returns what it returns. What `call` takes with it and
    /// what it returns pass through the heap and are not wiped there.
    ///
    /// # Errors
    ///
    /// [`Unheld::Inside`] from inside a call of these keys. [`Unheld::Wiped`] once the keys are
    /// wiped, also when that happens before `call` starts, or when `call` panics and unwinds.
    pub fn call<R: Send + 'static>(
        &self,
        call: impl for<'a, 'b> FnOnce(&'b mut Slots<'a>, &'b mut K::Held<'a>) -> R + Send + 'static,
    ) -> Result<R, Unheld> {
        if thread::current().id() == self.owner {
            return Err(Unheld::Inside);
        }
        // Asked after the wipe, a call is refused at once rather than behind the one under way.
        if self.shared.wiped.load(Ordering::Acquire) {
            return Err(Unheld::Wiped);
        }
        let (answer, answered) = mpsc::sync_channel(1);
        {
            // A call sent before the thread ends is refused there, and none is sent after.
            let ended = self
                .shared
                .ended
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *ended {
                return Err(Unheld::Wiped);
            }
            self.calls
                .send(Message::Call(Box::new(move |slots, held| {
                    // The caller stops waiting only once the keys are gone.
                    let _ = answer.send(call(slots, held));
                })))
                .map_err(|_| Unheld::Wiped)?;
        }
        answered.recv().map_err(|_| Unheld::Wiped)
    }

    /// Wipes the keys once the call under way returns, and refuses every later call.
    pub fn wipe(&self) {
        self.shared.wipe();
    }
}

impl<K: Kept> Drop for Keys<K> {
    /// Wipes the keys and waits for their thread to end, unless dropped on that thread: then it
    /// ends once the call under way returns.
    fn drop(&mut self) {
        self.shared.wiped.store(true, Ordering::Release);
        // A thread that ended has nothing left to wipe.
        let _ = self.calls.send(Message::Wipe);
        if let Some(thread) = self.thread.take()
            && self.owner != thread::current().id()
        {
            // A call that panicked ended the thread already, and its caller was told.
            let _ = thread.join();
        }
    }
}

impl<K: Kept> fmt::Debug for Keys<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys").finish_non_exhaustive()
    }
}

/// Tells that the keys' thread ended, once all it held is dropped. The calls sent to it before are
/// refused, their callers told as the answers drop, and none is sent after.
struct Ended<'s, K: Kept> {
    shared: &'s Shared,
    calls: &'s Receiver<Message<K>>,
}

impl<K: Kept> Drop for Ended<'_, K> {
    fn drop(&mut self) {
        let mut ended = self
            .shared
            .ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let refused: Vec<Message<K>> = self.calls.try_iter().collect();
        *ended = true;
        drop(ended);
        self.shared.ending.notify_all();
        // Dropped outside the lock: what a call takes with it may run code of its own as it drops.
        drop(refused);
    }
}

/// The keys' thread: runs the calls until a wipe. Then it drops what they kept, the slots, which
/// wipes them, the memory, which wipes its pages, and last tells it ended.
fn serve<K: Kept, const N: usize>(
    memory: Locked<Memory<N>>,
    number: u64,
    kept: K,
    calls: &Receiver<Message<K>>,
    shared: &Shared,
) {
    let _ended = Ended { shared, calls };
    let mut memory = memory;
    let Memory { slots, epoch, key } = &mut *memory;
    let mut slots = Slots::new(slots, epoch, number, key);
    let mut held = kept.hold();
    for message in calls {
        match message {
            // A call sent before the wipe was asked waits behind it, and is refused too.
            Message::Call(call) if !shared.wiped.load(Ordering::Acquire) => {
                call(&mut slots, &mut held);
            }
            _ => break,
        }
    }
}

/// Wipes every [`Keys`] of this process, each once the call under way returns.
pub fn wipe_keys() {
    for shared in process().held.iter().filter_map(Weak::upgrade) {
        shared.wipe();
    }
}

/// Waits up to `timeout` for every wiped [`Keys`] of this process to end, its slots and memory
/// wiped; tells whether all did. A timeout past what the clock counts waits as long as it takes.
#[must_use]
pub fn settle_keys(timeout: Duration) -> bool {
    let deadline = Instant::now().checked_add(timeout);
    let wiped: Vec<Arc<Shared>> = process()
        .held
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|shared| shared.wiped.load(Ordering::Acquire))
        .collect();
    wiped.iter().all(|shared| shared.ended_by(deadline))
}

/// For the Java layer, through `lethewis-jni`: whether keys may be held now. A refusal wipes every
/// [`Keys`] of the process.
#[doc(hidden)]
pub fn allow_keys(allowed: bool) {
    let mut process = process();
    process.watched = true;
    process.allowed = allowed;
    if !allowed {
        for shared in process.held.iter().filter_map(Weak::upgrade) {
            shared.wipe();
        }
    }
}

#[cfg(all(test, shuttle))]
mod model;
