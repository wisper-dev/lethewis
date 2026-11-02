// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis;

import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.StrongBoxUnavailableException;
import android.security.keystore.UserNotAuthenticatedException;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.UnrecoverableKeyException;

/** The tests of the Java layer alone: which failure each exception of the platform names. */
public final class KeystoreTests {
    private KeystoreTests() {}

    /** Returns {@code passed}, or the first exception named wrong. */
    public static String run() {
        Throwable[] thrown = {
            new UnrecoverableKeyException("invalidated"),
            caused(new UnrecoverableKeyException("failed"), new ProviderException("busy")),
            new KeyPermanentlyInvalidatedException(),
            caused(new InvalidKeyException("init"), new UserNotAuthenticatedException()),
            new StrongBoxUnavailableException(),
            new ProviderException("other"),
        };
        int[] named = {
            Keystore.ABSENT,
            Keystore.TRANSIENT,
            Keystore.ABSENT,
            Keystore.LOCKED,
            Keystore.STRONG_BOX_UNAVAILABLE,
            Keystore.TRANSIENT,
        };
        for (int i = 0; i < thrown.length; i++) {
            int failure = Keystore.failure(thrown[i]);
            if (failure != named[i]) {
                return thrown[i] + " named " + failure;
            }
        }
        return "passed";
    }

    private static Throwable caused(Throwable thrown, Throwable cause) {
        thrown.initCause(cause);
        return thrown;
    }
}
