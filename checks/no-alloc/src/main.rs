// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![no_std]
#![no_main]
#![deny(unused_crate_dependencies)]
#![allow(
    linker_messages,
    reason = "built and never run, so the missing entry point does not matter"
)]

use lethewis_core as _;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
