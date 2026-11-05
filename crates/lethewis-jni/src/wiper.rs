// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The native methods of `com.alanwisper.lethewis.Wiper`.

use core::time::Duration;

use jni_sys::{JNIEnv, jboolean, jclass, jint};

#[allow(unsafe_code)]
// SAFETY: no other symbol of the library has this name, and the JVM calls it with this signature.
#[unsafe(no_mangle)]
extern "system" fn Java_com_alanwisper_lethewis_Wiper_allow(
    _env: *mut JNIEnv,
    _class: jclass,
    allowed: jboolean,
) {
    lethewis_android::allow_keys(allowed);
}

#[allow(unsafe_code)]
// SAFETY: no other symbol of the library has this name, and the JVM calls it with this signature.
#[unsafe(no_mangle)]
extern "system" fn Java_com_alanwisper_lethewis_Wiper_settle(
    _env: *mut JNIEnv,
    _class: jclass,
    millis: jint,
) {
    let millis = u64::try_from(millis).unwrap_or(0);
    // Keys still under way after that are wiped once their call returns.
    let _ = lethewis_android::settle_keys(Duration::from_millis(millis));
}
