// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis.test;

import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/** The tests on a device, written in Rust in lethewis-jni. */
final class Tests {
    private Tests() {}

    /** Puts into the keystore the key of the first test case of RFC 4231, which the tests use. */
    static void importKnownKey() throws Exception {
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        store.setEntry(
                "lethewis-test/rfc4231",
                new KeyStore.SecretKeyEntry(
                        new SecretKeySpec(key, KeyProperties.KEY_ALGORITHM_HMAC_SHA256)),
                new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).build());
    }

    /**
     * Runs the tests {@code test} under {@code root} on a system of API level {@code api}; returns
     * {@code passed}, or what failed.
     */
    static native String run(String root, int api, String test);

    /** Breaks a rule of JNI, for which CheckJNI must stop the process. */
    static native void misuse();
}
