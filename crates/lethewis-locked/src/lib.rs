// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! [`Locked`] holds a value, such as the memory of a set of slots, in pages of its own: locked in
//! RAM, out of swap, core dumps and forked processes. Dropping it wipes the pages before they go
//! back to the system. Only on Linux and Android, and not under Kani; elsewhere the crate is empty.

#![cfg(all(any(target_os = "linux", target_os = "android"), not(kani)))]
#![deny(missing_docs, unused_crate_dependencies)]

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::sync::atomic::{Ordering, compiler_fence};
use std::io;

/// The smallest page of the systems served, so every mapping is aligned to it.
const SMALLEST_PAGE: usize = 4096;

/// Why a value could not be locked, with the system's error number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The system gave no pages.
    Map(i32),
    /// The pages could not be kept out of core dumps and forked processes.
    Advise(i32),
    /// The pages could not be locked in RAM: a process may lock only so much, counted in whole
    /// pages, and the process of an Android app 64 KiB in all.
    Lock(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Map(number) => write!(f, "the system gave no pages: error {number}"),
            Self::Advise(number) => {
                write!(
                    f,
                    "the pages could not be kept out of dumps and forks: error {number}"
                )
            }
            Self::Lock(number) => write!(f, "the pages could not be locked in RAM: error {number}"),
        }
    }
}

impl std::error::Error for Error {}

/// A value in pages of its own, locked in RAM, out of core dumps and forked processes; dropping it
/// drops the value, then wipes the pages and gives them back. Only the bytes of `T` are there: what
/// they point to, such as the contents of a `Vec`, is not.
pub struct Locked<T> {
    value: NonNull<T>,
    /// The length of the value, at least 1; the system maps, locks and gives back whole pages.
    len: usize,
    owns: PhantomData<T>,
}

// SAFETY: a `Locked<T>` owns its value alone, as a `Box<T>` does.
#[allow(unsafe_code)]
unsafe impl<T: Send> Send for Locked<T> {}

// SAFETY: as above; a shared `Locked<T>` gives only a shared `T`.
#[allow(unsafe_code)]
unsafe impl<T: Sync> Sync for Locked<T> {}

impl<T> Locked<T> {
    /// Moves `value` into pages of its own, locked and kept out of core dumps and forks before it
    /// is written. The bytes the move leaves behind, on the stack or elsewhere, are the caller's.
    ///
    /// # Errors
    ///
    /// The step the system refused; `value` is then dropped where it is.
    #[allow(unsafe_code)]
    pub fn new(value: T) -> Result<Self, Error> {
        const { assert!(align_of::<T>() <= SMALLEST_PAGE) };
        let len = size_of::<T>().max(1);
        let pages = map(len)?;
        if let Err(error) = advise(pages, len).and_then(|()| lock(pages, len)) {
            unmap(pages, len);
            return Err(error);
        }
        let value_at = pages.cast::<T>();
        // SAFETY: the mapping is writable, at least `size_of::<T>()` long and aligned to a page,
        // so to `T`, and nothing else refers to it.
        unsafe { value_at.write(value) };
        Ok(Self {
            value: value_at,
            len,
            owns: PhantomData,
        })
    }
}

impl<T> Deref for Locked<T> {
    type Target = T;

    #[allow(unsafe_code)]
    fn deref(&self) -> &T {
        // SAFETY: the value is written in `new` and dropped only with `self`, which the borrow
        // keeps alive.
        unsafe { self.value.as_ref() }
    }
}

impl<T> DerefMut for Locked<T> {
    #[allow(unsafe_code)]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and the borrow of `self` is unique.
        unsafe { self.value.as_mut() }
    }
}

impl<T> Drop for Locked<T> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // Set first, so that the pages are wiped and given back even if the value's drop panics.
        let _pages = Pages {
            start: self.value.cast(),
            len: self.len,
        };
        // SAFETY: the value is written in `new`, and dropped only here.
        unsafe { ptr::drop_in_place(self.value.as_ptr()) };
    }
}

/// The mapping of a [`Locked`], wiped and given back when dropped.
struct Pages {
    start: NonNull<u8>,
    len: usize,
}

impl Drop for Pages {
    fn drop(&mut self) {
        wipe(self.start, self.len);
        #[cfg(test)]
        tests::given_back(self.start, self.len);
        unmap(self.start, self.len);
    }
}

#[allow(unsafe_code)]
fn map(len: usize) -> Result<NonNull<u8>, Error> {
    // SAFETY: a new private mapping where the system chooses touches no memory of the program.
    let pages = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if pages == libc::MAP_FAILED {
        return Err(Error::Map(errno()));
    }
    NonNull::new(pages.cast()).ok_or(Error::Map(libc::ENOMEM))
}

#[allow(unsafe_code)]
fn advise(pages: NonNull<u8>, len: usize) -> Result<(), Error> {
    for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
        // SAFETY: the mapping is this crate's, and the advice changes only what a core dump or a
        // forked process gets of it.
        let advised = unsafe { libc::madvise(pages.as_ptr().cast(), len, advice) };
        if advised != 0 {
            return Err(Error::Advise(errno()));
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn lock(pages: NonNull<u8>, len: usize) -> Result<(), Error> {
    // SAFETY: the mapping is this crate's, and locking changes only where its pages are kept.
    let locked = unsafe { libc::mlock(pages.as_ptr().cast(), len) };
    if locked == 0 {
        Ok(())
    } else {
        Err(Error::Lock(errno()))
    }
}

/// Writes zeros over the mapping, each write one the compiler keeps.
#[allow(unsafe_code)]
fn wipe(pages: NonNull<u8>, len: usize) {
    for offset in 0..len {
        let byte = pages.as_ptr().wrapping_add(offset);
        // SAFETY: the byte is in the mapping, which is writable and holds no value any more.
        unsafe { byte.write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Gives the mapping back; nothing may refer to it any more.
#[allow(unsafe_code)]
fn unmap(pages: NonNull<u8>, len: usize) {
    // SAFETY: the mapping is this crate's and no reference into it is left. A failure leaves it
    // mapped, locked and wiped.
    let _ = unsafe { libc::munmap(pages.as_ptr().cast(), len) };
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::ptr::NonNull;
    use std::panic::{self, AssertUnwindSafe};
    use std::process::Command;
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::{env, fs};

    use super::{Error, Locked, SMALLEST_PAGE, errno};

    /// Tests that look at the mappings of the process take turns, so that none sees another's.
    static MAPPINGS: Mutex<()> = Mutex::new(());

    /// Set in the process a test starts again with a smaller limit on locked memory.
    const LIMITED: &str = "LETHEWIS_LOCKED_LIMITED";

    thread_local! {
        /// Whether the last mapping given back on this thread was all zeros.
        static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
    }

    /// Records whether the pages are all zeros as they go back to the system.
    #[allow(unsafe_code)]
    pub(super) fn given_back(pages: NonNull<u8>, len: usize) {
        // SAFETY: the mapping is still there and readable, and nothing writes it meanwhile.
        let bytes = unsafe { core::slice::from_raw_parts(pages.as_ptr(), len) };
        WIPED.set(Some(bytes.iter().all(|&byte| byte == 0)));
    }

    /// A mapping as the kernel reports it in `/proc/self/smaps`.
    struct Mapping {
        start: usize,
        end: usize,
        size: usize,
        locked: usize,
        flags: Vec<String>,
    }

    fn mappings() -> Vec<Mapping> {
        let smaps = fs::read_to_string("/proc/self/smaps").unwrap();
        let mut found: Vec<Mapping> = Vec::new();
        for line in smaps.lines() {
            let mut words = line.split_whitespace();
            let first = words.next().unwrap_or_default();
            if let Some((start, end)) = first.split_once('-') {
                found.push(Mapping {
                    start: usize::from_str_radix(start, 16).unwrap(),
                    end: usize::from_str_radix(end, 16).unwrap(),
                    size: 0,
                    locked: 0,
                    flags: Vec::new(),
                });
                continue;
            }
            let last = found.last_mut().unwrap();
            match first {
                "Size:" => last.size = bytes(words.next()),
                "Locked:" => last.locked = bytes(words.next()),
                "VmFlags:" => last.flags = words.map(str::to_owned).collect(),
                _ => {}
            }
        }
        found
    }

    /// The bytes in a size `/proc/self/smaps` gives in KiB.
    fn bytes(kib: Option<&str>) -> usize {
        kib.unwrap()
            .parse::<usize>()
            .unwrap()
            .checked_mul(1024)
            .unwrap()
    }

    /// The locked mapping that holds `address`, if any.
    fn locked_at(address: usize) -> Option<Mapping> {
        mappings().into_iter().find(|mapping| {
            mapping.start <= address
                && address < mapping.end
                && mapping.flags.iter().any(|flag| flag == "lo")
        })
    }

    struct Counted {
        drops: Rc<Cell<u32>>,
        bytes: [u8; 5000],
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            self.drops.set(self.drops.get().saturating_add(1));
        }
    }

    #[test]
    fn the_value_is_in_locked_pages_out_of_core_dumps_and_forks() {
        let _turn = MAPPINGS.lock().unwrap();
        let mut locked = Locked::new([7_u8; 5000]).unwrap();
        locked[4999] = 9;
        assert_eq!(locked[..4999], [7; 4999]);
        assert_eq!(locked[4999], 9);
        let address = locked.as_ptr().addr();
        assert!(address.is_multiple_of(SMALLEST_PAGE));
        let mapping = locked_at(address).unwrap();
        assert!(address.checked_add(5000).unwrap() <= mapping.end);
        assert_eq!(mapping.locked, mapping.size);
        assert!(mapping.flags.iter().any(|flag| flag == "dd"));
        assert!(mapping.flags.iter().any(|flag| flag == "dc"));
    }

    #[test]
    fn dropping_drops_the_value_once_and_gives_the_pages_back_wiped() {
        let _turn = MAPPINGS.lock().unwrap();
        let drops = Rc::new(Cell::new(0));
        let locked = Locked::new(Counted {
            drops: Rc::clone(&drops),
            bytes: [0xa5; 5000],
        })
        .unwrap();
        assert_eq!(locked.bytes, [0xa5; 5000]);
        let address = locked.bytes.as_ptr().addr();
        WIPED.set(None);
        drop(locked);
        assert_eq!(drops.get(), 1);
        assert_eq!(WIPED.get(), Some(true));
        assert!(locked_at(address).is_none());
    }

    #[test]
    fn values_beyond_the_limit_on_locked_memory_are_refused_and_dropped() {
        const NAME: &str =
            "tests::values_beyond_the_limit_on_locked_memory_are_refused_and_dropped";
        if env::var_os(LIMITED).is_none() {
            let child = Command::new(env::current_exe().unwrap())
                .args(["--exact", NAME])
                .env(LIMITED, "1")
                .output()
                .unwrap();
            assert!(child.status.success(), "{child:?}");
            assert!(
                String::from_utf8_lossy(&child.stdout).contains("1 passed"),
                "{child:?}"
            );
            return;
        }
        let drops = Rc::new(Cell::new(0));
        // 4 KiB is less than the value takes, two pages of 4 KiB or one of 16 KiB.
        for (limit, refusal) in [(4096, libc::ENOMEM), (0, libc::EPERM)] {
            let lowered = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            // SAFETY: setrlimit reads the limit given; this process runs this test alone.
            #[allow(unsafe_code)]
            let set = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const lowered) };
            assert_eq!(set, 0);
            let refused = Locked::new(Counted {
                drops: Rc::clone(&drops),
                bytes: [0; 5000],
            });
            assert!(
                matches!(refused, Err(Error::Lock(number)) if number == refusal),
                "{limit}"
            );
        }
        assert_eq!(drops.get(), 2);
    }

    struct Panicking([u8; 64]);

    impl Drop for Panicking {
        fn drop(&mut self) {
            panic!("a drop that fails");
        }
    }

    #[test]
    fn a_value_whose_drop_panics_still_has_its_pages_wiped_and_given_back() {
        let _turn = MAPPINGS.lock().unwrap();
        let locked = Locked::new(Panicking([0xa5; 64])).unwrap();
        let address = locked.0.as_ptr().addr();
        WIPED.set(None);
        assert!(panic::catch_unwind(AssertUnwindSafe(|| drop(locked))).is_err());
        assert_eq!(WIPED.get(), Some(true));
        assert!(locked_at(address).is_none());
    }

    #[test]
    #[allow(unsafe_code)]
    fn an_error_carries_the_number_the_system_gave() {
        // SAFETY: closing no descriptor touches nothing.
        let closed = unsafe { libc::close(-1) };
        assert_eq!(closed, -1);
        assert_eq!(errno(), libc::EBADF);
    }

    #[test]
    fn every_error_reads_differently() {
        let errors = [
            Error::Map(12),
            Error::Advise(22),
            Error::Lock(1),
            Error::Lock(12),
        ];
        let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
        for (index, text) in texts.iter().enumerate() {
            assert!(!texts[..index].contains(text), "{text}");
        }
    }
}
