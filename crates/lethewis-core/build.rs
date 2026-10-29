// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Sets `lethewis_unoptimised` without optimisation, where the hash and the cipher use several
//! times more stack and the wipes reach deeper. A build that optimises this crate but not the hash
//! and the cipher sets it itself.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("OPT_LEVEL").as_deref() == Ok("0") {
        println!("cargo::rustc-cfg=lethewis_unoptimised");
    }
}
