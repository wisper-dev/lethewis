// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Tells the library whether it is built without optimisation: the hash and the cipher then use
//! several times more stack, and the wipes after them have to reach deeper. A build that optimises
//! this crate but not the hash and cipher code it calls sets `--cfg lethewis_unoptimised` itself.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("OPT_LEVEL").as_deref() == Ok("0") {
        println!("cargo::rustc-cfg=lethewis_unoptimised");
    }
}
