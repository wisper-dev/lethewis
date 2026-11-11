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

    /** Gives the keystore the application, as {@code Wiper.start} does, without watching. */
    public static void use(android.content.Context context) {
        Keystore.use(context.getApplicationContext());
    }

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
        String answers = answers();
        if (!"passed".equals(answers)) {
            return answers;
        }
        String lacking = lacking();
        if (!"passed".equals(lacking)) {
            return lacking;
        }
        return Build.VERSION.SDK_INT >= 31 ? "passed" : missing();
    }

    /**
     * The answers of a BiometricManager: success and nothing enrolled, then a sensor unusable now,
     * none the system knows, one awaiting an update, and a code no system defines. From API 30 no
     * strong sensor is for good only beside a weak one the system knows, with one kind of sensor.
     */
    private static String answers() {
        int[] codes = {0, 11, 1, 12, 15, 99};
        int[] read = {
            Keystore.READY,
            Keystore.NOTHING_ENROLLED,
            Keystore.NOT_NOW,
            Keystore.NOT_NOW,
            Keystore.NOT_NOW,
            Keystore.NOT_NOW,
        };
        for (int i = 0; i < codes.length; i++) {
            if (Keystore.answer(codes[i]) != read[i]) {
                return "the biometric answer " + codes[i] + " read as " + Keystore.answer(codes[i]);
            }
        }
        // A strong answer, a weak one, 1 for one kind of sensor, and how they read.
        int[][] paired = {
            {12, 11, 1, Keystore.NEVER},
            {12, 0, 1, Keystore.NEVER},
            {12, 1, 1, Keystore.NEVER},
            {12, 11, 0, Keystore.NOT_NOW},
            {12, 12, 1, Keystore.NOT_NOW},
            {11, 0, 1, Keystore.NOTHING_ENROLLED},
            {0, 0, 0, Keystore.READY},
        };
        for (int[] pair : paired) {
            int answer = Keystore.answer(pair[0], pair[1], pair[2] == 1);
            if (answer != pair[3]) {
                return "the biometric answers " + pair[0] + ", " + pair[1] + " read as " + answer;
            }
        }
        return "passed";
    }

    /**
     * What the device lacks, in the order its owner would mend it: a sensor, a secure lock screen,
     * then what the sensor says. A sensor that fails to answer leaves the rest told.
     */
    private static String lacking() {
        Exception denied = new SecurityException("USE_BIOMETRIC");
        boolean[] sensed = {false, true, true, true, true, true, true};
        boolean[] secure = {true, false, false, false, true, true, true};
        Keystore.Sensor[] sensors = {
            sensor(Keystore.READY, null),
            sensor(Keystore.NEVER, null),
            sensor(Keystore.NOTHING_ENROLLED, null),
            sensor(Keystore.READY, denied),
            sensor(Keystore.READY, denied),
            sensor(Keystore.NOTHING_ENROLLED, null),
            sensor(Keystore.READY, null),
        };
        int[] read = {
            Keystore.NEVER,
            Keystore.NEVER,
            Keystore.NO_LOCK_SCREEN,
            Keystore.NO_LOCK_SCREEN,
            Keystore.UNKNOWN_FAILURE,
            Keystore.NOTHING_ENROLLED,
            Keystore.READY,
        };
        for (int i = 0; i < read.length; i++) {
            int lacking = Keystore.lacking(sensed[i], secure[i], sensors[i]);
            if (lacking != read[i]) {
                return "the device's case " + i + " read as " + lacking;
            }
        }
        return "passed";
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

    /** A sensor that answers {@code answer}, or throws {@code thrown} if it is not null. */
    private static Keystore.Sensor sensor(final int answer, final Exception thrown) {
        return new Keystore.Sensor() {
            @Override
            public int ask() throws Exception {
                if (thrown != null) {
                    throw thrown;
                }
                return answer;
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
