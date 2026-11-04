// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis;

import android.os.Build;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.StrongBoxUnavailableException;
import android.security.keystore.UserNotAuthenticatedException;
import java.lang.reflect.Constructor;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.UnrecoverableKeyException;

/** The tests of the Java layer alone: which failure each exception of the platform names. */
public final class KeystoreTests {
    private KeystoreTests() {}

    /** Returns {@code passed}, or the first exception named wrong. */
    public static String run() throws Exception {
        Throwable[] thrown = {
            new UnrecoverableKeyException("invalidated"),
            caused(new UnrecoverableKeyException("failed"), new ProviderException("busy")),
            new KeyPermanentlyInvalidatedException(),
            caused(new InvalidKeyException("init"), new UserNotAuthenticatedException()),
            new StrongBoxUnavailableException(),
            new ProviderException("other"),
        };
        // Below API 31 the system throws this only for stored details without their algorithm.
        int[] named = {
            Build.VERSION.SDK_INT >= 31 ? Keystore.ABSENT : Keystore.UNKNOWN_FAILURE,
            Keystore.UNKNOWN_FAILURE,
            Keystore.ABSENT,
            Keystore.LOCKED,
            Keystore.STRONG_BOX_UNAVAILABLE,
            Keystore.UNKNOWN_FAILURE,
        };
        for (int i = 0; i < thrown.length; i++) {
            int failure = Keystore.failure(thrown[i]);
            if (failure != named[i]) {
                return thrown[i] + " named " + failure;
            }
        }
        String absent = absent();
        if (!"passed".equals(absent)) {
            return absent;
        }
        return Build.VERSION.SDK_INT >= 31 ? "passed" : missing();
    }

    /**
     * Below API 31, a key the keystore does not find is missing only once it shows it works, and
     * only if it still does not find the key then.
     */
    private static String missing() {
        String alias = "lethewis-test/missing";
        byte[] out = new byte[32];
        Keystore.delete(alias);
        int failing = Keystore.mac(alias, new byte[1], out, failing(new ProviderException("down")));
        int found = Keystore.mac(alias, new byte[1], out, making(alias));
        int deleted = Keystore.delete(alias);
        if (failing != Keystore.UNKNOWN_FAILURE || found != Keystore.OK || deleted != Keystore.OK) {
            return "a key not found below API 31: " + failing + " " + found + " " + deleted;
        }
        return "passed";
    }

    /** A missing key is one only while the keystore shows it works, however its check fails. */
    private static String absent() {
        int working = Keystore.absent(failing(null));
        int failing = Keystore.absent(failing(new ProviderException("not running")));
        int invalidated = Keystore.absent(failing(new KeyPermanentlyInvalidatedException()));
        if (working != Keystore.ABSENT
                || failing != Keystore.UNKNOWN_FAILURE
                || invalidated != Keystore.UNKNOWN_FAILURE) {
            return "a missing key with its check: " + working + " " + failing + " " + invalidated;
        }
        return "passed";
    }

    /**
     * The failures of the keystore from API 33, made as the keystore makes them from its own codes:
     * locked, a system error, no key, a damaged one, busy hardware and a bad key blob. Its class is
     * hidden from apps, so the run that calls this lifts the checks of hidden interfaces.
     */
    public static String platform() throws Exception {
        Constructor<?> make =
                Class.forName("android.security.KeyStoreException")
                        .getConstructor(int.class, String.class);
        int[][] codes = {
            {2, Keystore.LOCKED},
            {4, Keystore.TRANSIENT},
            {7, Keystore.ABSENT},
            {8, Keystore.CORRUPTED},
            {-48, Keystore.TRANSIENT},
            {-33, Keystore.UNKNOWN_FAILURE},
        };
        for (int[] code : codes) {
            Throwable thrown =
                    caused(
                            new UnrecoverableKeyException("failed"),
                            (Throwable) make.newInstance(code[0], "made by the tests"));
            int failure = Keystore.failure(thrown);
            if (failure != code[1]) {
                return "the keystore's code " + code[0] + " named " + failure;
            }
        }
        return "passed";
    }

    /** A check that makes a key under {@code alias}, as a keystore that came back would find. */
    private static Keystore.Check making(final String alias) {
        return new Keystore.Check() {
            @Override
            public void run() {
                if (Keystore.generate(alias, false, false) < 0) {
                    throw new IllegalStateException("the key was not made");
                }
            }
        };
    }

    /** A check that throws {@code thrown}, or returns if it is null. */
    private static Keystore.Check failing(final Exception thrown) {
        return new Keystore.Check() {
            @Override
            public void run() throws Exception {
                if (thrown != null) {
                    throw thrown;
                }
            }
        };
    }

    private static Throwable caused(Throwable thrown, Throwable cause) {
        thrown.initCause(cause);
        return thrown;
    }
}
