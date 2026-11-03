// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Profiles on Android. A profile keeps its files in a directory of profiles alone, under one named
//! `no_backup`, and an HMAC-SHA256 key in the Android keystore answers the core's challenge: the
//! key that opens the profile needs both the password and this device. Each epoch has a root of its
//! own, a key in the keystore and random bytes beside it, which [`Profile::roots`] keeps for the
//! core.
//!
//! The keystore is reached through [`Keystore`]; `lethewis-jni` implements it on a device. Every
//! call blocks, the chip's ones for up to hundreds of milliseconds, so none belongs on the main
//! thread.

#![deny(missing_docs, unused_crate_dependencies)]
// Line coverage is judged on proof code only, so Kani counts it nowhere else.
#![cfg_attr(kani, feature(coverage_attribute), coverage(off))]

mod destroy;
mod epoch;
mod keystore;
mod profile;
#[cfg(test)]
mod stand;

pub use destroy::sweep;
pub use epoch::{Next, Opened, Roots};
pub use keystore::{Failure, Keystore, Level};
pub use lethewis_core::{Erasure, Root};
pub use profile::{Error, Id, Profile};

// Used only by the stand-in keystore of the tests.
#[cfg(test)]
use hmac as _;
