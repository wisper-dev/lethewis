// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The guard where the operating system can report data-independent timing on aarch64.

use core::arch::asm;

/// The bit of `PSTATE.DIT` in its register.
const DIT: u64 = 1 << 24;

pub(super) fn supported() -> bool {
    detect()
}

#[allow(unsafe_code)]
pub(super) fn active() -> bool {
    // SAFETY: the operating system reports the feature.
    supported() && unsafe { read() } & DIT != 0
}

#[allow(unsafe_code)]
pub(super) fn switch_on() -> bool {
    // SAFETY: the operating system reports the feature.
    if !supported() || unsafe { read() } & DIT != 0 {
        return false;
    }
    // SAFETY: as above.
    unsafe { write(DIT) };
    true
}

/// Called only after `switch_on` switched the mode on, so the feature is reported.
#[allow(unsafe_code)]
pub(super) fn switch_off() {
    // SAFETY: the feature is reported, since the mode was switched on.
    unsafe { write(0) };
}

/// Reads the register of `PSTATE.DIT`.
///
/// # Safety
///
/// The operating system reports the feature: elsewhere the instruction is undefined.
#[allow(unsafe_code)]
unsafe fn read() -> u64 {
    let value: u64;
    // SAFETY: the feature is reported, so the register exists and user code may read it; reading
    // changes nothing.
    unsafe {
        asm!("mrs {}, S3_3_C4_C2_5", out(reg) value, options(nostack, preserves_flags));
    }
    value
}

/// Writes `PSTATE.DIT`.
///
/// # Safety
///
/// The operating system reports the feature: elsewhere the instruction is undefined.
#[allow(unsafe_code)]
unsafe fn write(value: u64) {
    // SAFETY: the feature is reported, so the register exists and user code may write it; only the
    // DIT bit is defined there. The barriers make the instructions that follow run in the new mode.
    // The assembly is not declared free of effects on memory, so the compiler moves no memory
    // access and no call with side effects across it.
    unsafe {
        asm!(
            "msr S3_3_C4_C2_5, {}",
            "dsb nsh",
            "isb",
            in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
use auxv::detect;
#[cfg(target_vendor = "apple")]
use sysctl::detect;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod auxv {
    #[allow(unsafe_code)]
    pub(super) fn detect() -> bool {
        // SAFETY: getauxval only reads the auxiliary vector the kernel gave this process; an
        // entry that is missing reads as zero.
        let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
        hwcap & libc::HWCAP_DIT != 0
    }
}

#[cfg(target_vendor = "apple")]
mod sysctl {
    /// Any error of the operating system, including a name it does not know, reads as absent.
    #[allow(unsafe_code)]
    pub(super) fn detect() -> bool {
        let mut value: u32 = 0;
        let mut size = size_of::<u32>();
        // SAFETY: the name ends in NUL; `value` and `size` are valid for writes of the size
        // given; the null pointer and zero length set nothing.
        let status = unsafe {
            libc::sysctlbyname(
                c"hw.optional.arm.FEAT_DIT".as_ptr(),
                (&raw mut value).cast(),
                &raw mut size,
                core::ptr::null_mut(),
                0,
            )
        };
        crate::reported::present(status, size, value)
    }
}
