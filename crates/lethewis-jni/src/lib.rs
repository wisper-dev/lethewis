// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The bridge of the library to its Java layer on Android, `com.alanwisper.lethewis.Keystore`:
//! [`JniKeystore`] gives `lethewis-android` the keystore of the device through JNI, on the thread
//! of the call.
//!
//! An app calls the library from its own native methods, where the JVM hands over a JNI
//! environment. A thread the app starts itself is attached by the app, which then passes a global
//! reference to the class taken on a thread of the JVM: elsewhere `FindClass` sees only the
//! system's classes.

#![deny(missing_docs, unused_crate_dependencies)]

mod codes;
#[cfg(feature = "device-tests")]
mod device;
mod keystore;

pub use jni_sys;
pub use keystore::JniKeystore;
