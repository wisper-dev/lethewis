// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.security.keystore.UserNotAuthenticatedException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Enumeration;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 * The Android keystore as LetheWis uses it: HMAC-SHA256 keys under names. Only the native code of
 * lethewis-jni calls it; every method returns a level of storage, a result or a failure as a code,
 * or a list of names, and throws nothing of its own.
 */
final class Keystore {
    static final int OK = 0;
    static final int STRONG_BOX = 1;
    static final int TRUSTED_ENVIRONMENT = 2;
    static final int UNKNOWN_SECURE = 3;
    static final int SOFTWARE = 4;
    static final int UNKNOWN = 5;
    static final int KEPT = 6;
    static final int GONE = 7;
    static final int READY = 8;
    static final int NO_LOCK_SCREEN = 9;
    static final int NOTHING_ENROLLED = 10;
    static final int NOT_NOW = 11;
    static final int NEVER = 12;
    static final int REFUSED = 13;
    static final int TRANSIENT = -1;
    static final int LOCKED = -2;
    static final int ABSENT = -3;
    static final int CORRUPTED = -4;
    static final int STRONG_BOX_UNAVAILABLE = -5;
    static final int UNKNOWN_FAILURE = -6;

    private static final String PROVIDER = "AndroidKeyStore";
    private static final String PROBE = "lethewis/probe";

    /** The application, which {@link Wiper#start} gives, for what the keystore does not answer. */
    private static volatile Context app;

    private Keystore() {}

    static void use(Context context) {
        app = context;
    }

    static int apiLevel() {
        return Build.VERSION.SDK_INT;
    }

    static int contains(String alias) {
        return contains(alias, PROBE_KEY);
    }

    /**
     * As {@link #contains(String)}, with {@code working} to confirm that there is no such key: the
     * platform reads a keystore that failed as one without the key, and says nothing of it.
     */
    static int contains(String alias, Check working) {
        try {
            if (store().containsAlias(alias)) {
                return 1;
            }
            int probe = probed(working);
            return probe == OK ? 0 : explained(UNKNOWN_FAILURE, probe);
        } catch (Exception e) {
            return failure(e, working);
        }
    }

    static int generate(String alias, boolean strongBox, boolean unlocked) {
        // Android 9 ignores a request for the secure element on keys of this kind.
        if (strongBox && Build.VERSION.SDK_INT < 29) {
            return STRONG_BOX_UNAVAILABLE;
        }
        try {
            KeyGenParameterSpec.Builder spec =
                    new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                            .setIsStrongBoxBacked(strongBox);
            if (unlocked) {
                spec.setUnlockedDeviceRequired(true);
            }
            KeyGenerator generator =
                    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER);
            generator.init(spec.build());
            return level(generator.generateKey(), strongBox);
        } catch (Exception e) {
            return failure(e, PROBE_KEY);
        }
    }

    /**
     * Creates a key under {@code alias} that enrolling a fingerprint, or removing the secure lock
     * screen, makes unusable for good. It is never used, only asked after. Returns its level, or
     * {@link #REFUSED} where the system refuses such a key on this device.
     */
    static int generateWatched(String alias, boolean strongBox) {
        // Android 9 ignores a request for the secure element on keys of this kind.
        if (strongBox && Build.VERSION.SDK_INT < 29) {
            return STRONG_BOX_UNAVAILABLE;
        }
        try {
            KeyGenParameterSpec spec =
                    new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                            .setIsStrongBoxBacked(strongBox)
                            .setUserAuthenticationRequired(true)
                            .setInvalidatedByBiometricEnrollment(true)
                            .build();
            KeyGenerator generator =
                    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER);
            generator.init(spec);
            return level(generator.generateKey(), strongBox);
        } catch (InvalidAlgorithmParameterException e) {
            // The system refuses the specification on a device with no secure lock screen, or no
            // biometric enrolled strong enough to invalidate the key.
            return REFUSED;
        } catch (Exception e) {
            return failure(e, PROBE_KEY);
        }
    }

    /**
     * What the device lacks for a key {@link #generateWatched} would make, or {@link #READY} where
     * it lacks nothing. Only the making decides. Asking needs the context {@link Wiper#start}
     * gives; without the app's permission USE_BIOMETRIC the sensor does not answer.
     */
    static int unwatchable() {
        final Context context = app;
        if (context == null) {
            return UNKNOWN_FAILURE;
        }
        try {
            KeyguardManager keyguard =
                    (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            final int sensors = sensors(context.getPackageManager());
            return lacking(
                    sensors > 0,
                    keyguard.isDeviceSecure(),
                    new Sensor() {
                        @Override
                        public int ask() throws Exception {
                            return sensor(context, sensors == 1);
                        }
                    });
        } catch (Exception e) {
            return failure(e);
        }
    }

    /** What the sensor answers of such a key. */
    interface Sensor {
        int ask() throws Exception;
    }

    /**
     * What the device lacks, in the order its owner would mend it: a sensor, a secure lock screen,
     * then what the sensor says. A sensor that fails to answer leaves the rest told.
     */
    static int lacking(boolean sensed, boolean secure, Sensor sensor) {
        if (!sensed) {
            return NEVER;
        }
        int answer;
        try {
            answer = sensor.ask();
        } catch (Exception e) {
            answer = failure(e);
        }
        if (answer == NEVER) {
            return NEVER;
        }
        return secure ? answer : NO_LOCK_SCREEN;
    }

    private static int sensor(Context context, boolean alone) throws Exception {
        if (Build.VERSION.SDK_INT >= 30) {
            return Api30.sensor(context, alone);
        }
        if (Build.VERSION.SDK_INT >= 29) {
            return Api29.sensor(context);
        }
        return fingerprints(context);
    }

    /**
     * How many kinds of sensor such a key may be bound to the device has: a fingerprint's alone on
     * Android 9, a face's and an iris's as well from Android 10.
     */
    private static int sensors(PackageManager features) {
        int sensors = features.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) ? 1 : 0;
        if (Build.VERSION.SDK_INT >= 29) {
            if (features.hasSystemFeature(PackageManager.FEATURE_FACE)) {
                sensors++;
            }
            if (features.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
                sensors++;
            }
        }
        return sensors;
    }

    /**
     * Android 9 binds such a key to fingerprints alone. Its FingerprintManager is gone from the SDK
     * this builds with, so it is reached by name.
     */
    private static int fingerprints(Context context) throws Exception {
        Object sensor = context.getSystemService("fingerprint");
        if (sensor == null || !asked(sensor, "isHardwareDetected")) {
            return NOT_NOW;
        }
        return asked(sensor, "hasEnrolledFingerprints") ? READY : NOTHING_ENROLLED;
    }

    private static boolean asked(Object sensor, String method) throws Exception {
        return (Boolean) sensor.getClass().getMethod(method).invoke(sensor);
    }

    /**
     * {@link #KEPT} while the key {@code alias} would work once the owner authenticates,
     * {@link #GONE} once it is gone or the system has made it unusable, or a failure. A keystore
     * that says neither is a failure: a key of unknown state is never reported as kept.
     */
    static int watched(String alias) {
        try {
            Key key = store().getKey(alias, null);
            // Below API 31 a keystore that fails reads as one without the key, and so does a
            // locked device for a key the owner authenticates for: it must never read as gone.
            if (key == null && Build.VERSION.SDK_INT < 31) {
                if (locked()) {
                    return LOCKED;
                }
                int absent = absent(PROBE_KEY);
                return absent == ABSENT ? GONE : absent;
            }
            if (key == null) {
                return GONE;
            }
            Mac mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256);
            mac.init(key);
            return KEPT;
        } catch (UserNotAuthenticatedException e) {
            // This key asks for the owner at every use, and only a key the system still accepts
            // gets that far.
            return KEPT;
        } catch (Exception e) {
            int code = failure(e, PROBE_KEY);
            return code == ABSENT ? GONE : code;
        }
    }

    static int mac(String alias, byte[] data, byte[] out) {
        return mac(alias, data, out, PROBE_KEY);
    }

    /** As {@link #mac(String, byte[], byte[])}, with {@code working} to confirm a missing key. */
    static int mac(String alias, byte[] data, byte[] out, Check working) {
        try {
            Key key = store().getKey(alias, null);
            // Below API 31 a keystore that fails reads as one without the key.
            if (key == null && Build.VERSION.SDK_INT < 31) {
                int absent = absent(working);
                if (absent != ABSENT) {
                    return absent;
                }
                key = store().getKey(alias, null);
            }
            if (key == null) {
                return ABSENT;
            }
            Mac mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256);
            mac.init(key);
            mac.update(data);
            byte[] answer = mac.doFinal();
            try {
                System.arraycopy(answer, 0, out, 0, answer.length);
            } finally {
                Arrays.fill(answer, (byte) 0);
            }
            return OK;
        } catch (Exception e) {
            return failure(e, working);
        }
    }

    /**
     * The names that begin with {@code prefix}, each followed by a new line; null if the keystore
     * throws. A keystore that fails without throwing lists fewer names.
     */
    static String aliases(String prefix) {
        try {
            StringBuilder names = new StringBuilder();
            for (Enumeration<String> all = store().aliases(); all.hasMoreElements(); ) {
                String alias = all.nextElement();
                if (alias.startsWith(prefix)) {
                    names.append(alias).append('\n');
                }
            }
            return names.toString();
        } catch (Exception e) {
            return null;
        }
    }

    static int delete(String alias) {
        try {
            store().deleteEntry(alias);
            return OK;
        } catch (Exception e) {
            // No key of its own here: a destruction lists the names first, and one made after
            // would stay behind it.
            return failure(e);
        }
    }

    /** A call that returns only from a keystore that works, and reaches no call of this class. */
    interface Check {
        void run() throws Exception;
    }

    /** A missing key, once {@code working} shows the keystore working. */
    static int absent(Check working) {
        int probe = probed(working);
        return probe == OK ? ABSENT : explained(UNKNOWN_FAILURE, probe);
    }

    /**
     * Whether the device is locked, which a key the owner authenticates for needs it not to be.
     * Without the context {@link Wiper#start} gives it answers that it is: a key of that kind is
     * then never called gone.
     */
    private static boolean locked() {
        Context context = app;
        if (context == null) {
            return true;
        }
        KeyguardManager keyguard =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return keyguard == null || keyguard.isDeviceLocked();
    }

    /** {@link #OK} where {@code working} returns, or what its failure is. */
    private static int probed(Check working) {
        try {
            working.run();
            return OK;
        } catch (Exception e) {
            return failure(e);
        }
    }

    /**
     * What a failure of the code {@code code} is, by {@code probe}, what a key of the keystore's
     * own answered: {@link #OK} where it was made. A keystore that cannot make such a key has not
     * served the request, so trying later may work. Only the device being locked is of the
     * keystore and not of that key; the key's own loss says nothing of another's.
     *
     * <p>A keystore that works leaves a failure unexplained: a loss and a race look alike, and
     * only the system tells them apart.
     */
    static int explained(int code, int probe) {
        if (code != UNKNOWN_FAILURE || probe == OK) {
            return code;
        }
        return probe == LOCKED ? LOCKED : TRANSIENT;
    }

    /** Makes a key and deletes it; one a crash leaves holds nothing, and the next replaces it. */
    private static final Check PROBE_KEY =
            new Check() {
                @Override
                public void run() throws Exception {
                    KeyGenerator generator =
                            KeyGenerator.getInstance(
                                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER);
                    generator.init(
                            new KeyGenParameterSpec.Builder(PROBE, KeyProperties.PURPOSE_SIGN)
                                    .build());
                    generator.generateKey();
                    store().deleteEntry(PROBE);
                }
            };

    private static KeyStore store() throws Exception {
        KeyStore store = KeyStore.getInstance(PROVIDER);
        store.load(null);
        return store;
    }

    // Below API 31 the system tells only whether a key is in secure hardware; a key made there is
    // in the secure element if it was asked for, as the generation fails otherwise.
    @SuppressWarnings("deprecation")
    private static int level(SecretKey key, boolean strongBox) throws Exception {
        KeyInfo info =
                (KeyInfo)
                        SecretKeyFactory.getInstance(key.getAlgorithm(), PROVIDER)
                                .getKeySpec(key, KeyInfo.class);
        if (Build.VERSION.SDK_INT >= 31) {
            return Api31.level(info);
        }
        if (!info.isInsideSecureHardware()) {
            return SOFTWARE;
        }
        return strongBox ? STRONG_BOX : TRUSTED_ENVIRONMENT;
    }

    /**
     * As {@link #failure(Throwable)}, with a key of the keystore's own to ask where the system
     * named nothing. A failure the system named stands as it is, even where this library has no
     * code for it: the system said it would not pass.
     */
    static int failure(Throwable thrown, Check working) {
        int code = failure(thrown);
        if (code != UNKNOWN_FAILURE || named(thrown)) {
            return code;
        }
        return explained(code, probed(working));
    }

    /** Whether the system named this failure, as it does from API 33 with its own exception. */
    private static boolean named(Throwable thrown) {
        if (Build.VERSION.SDK_INT < 33) {
            return false;
        }
        for (Throwable cause = thrown; cause != null; cause = cause.getCause()) {
            if (Api33.named(cause)) {
                return true;
            }
        }
        return false;
    }

    static int failure(Throwable thrown) {
        for (Throwable cause = thrown; cause != null; cause = cause.getCause()) {
            if (cause instanceof StrongBoxUnavailableException) {
                return STRONG_BOX_UNAVAILABLE;
            }
            if (cause instanceof UserNotAuthenticatedException) {
                return LOCKED;
            }
            if (cause instanceof KeyPermanentlyInvalidatedException) {
                return ABSENT;
            }
            // From API 31 a failure to read a key comes with its cause; one without stands for a
            // key the system made unusable, or whose stored details lost their algorithm.
            if (Build.VERSION.SDK_INT >= 31
                    && cause instanceof UnrecoverableKeyException
                    && cause.getCause() == null) {
                return ABSENT;
            }
            if (Build.VERSION.SDK_INT >= 33) {
                int code = Api33.code(cause);
                if (code != OK) {
                    return code;
                }
            }
        }
        return UNKNOWN_FAILURE;
    }

    /** The answer of a BiometricManager; its constants are compiled in, so any level runs it. */
    static int answer(int code) {
        switch (code) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return READY;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return NOTHING_ENROLLED;
            // A sensor unusable now, none the system knows yet, one awaiting an update, or a code
            // of a later system.
            default:
                return NOT_NOW;
        }
    }

    /**
     * The answers of a BiometricManager from API 30, for a strong biometric and for a weak one. No
     * strong sensor is for good only beside a weak one the system knows, on a device {@code alone}
     * with one kind of sensor: the system tells of the first sensor it cannot use, and of none
     * while its sensors start.
     */
    static int answer(int strong, int weak, boolean alone) {
        if (alone
                && strong == BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE
                && weak != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE) {
            return NEVER;
        }
        return answer(strong);
    }

    /** Calls that exist from API 29, apart so that older systems never load them. */
    private static final class Api29 {
        // Android 10 binds such a key to any fingerprint or face, as this asks.
        @SuppressWarnings("deprecation")
        static int sensor(Context context) {
            BiometricManager biometrics = context.getSystemService(BiometricManager.class);
            return biometrics == null ? NOT_NOW : answer(biometrics.canAuthenticate());
        }
    }

    /** Calls that exist from API 30, apart so that older systems never load them. */
    private static final class Api30 {
        // From Android 11 such a key needs a strong biometric, as the keystore checks.
        static int sensor(Context context, boolean alone) {
            BiometricManager biometrics = context.getSystemService(BiometricManager.class);
            if (biometrics == null) {
                return NOT_NOW;
            }
            return answer(
                    biometrics.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG),
                    biometrics.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK),
                    alone);
        }
    }

    /** Calls that exist from API 31, apart so that older systems never load them. */
    private static final class Api31 {
        static int level(KeyInfo info) {
            switch (info.getSecurityLevel()) {
                case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                    return STRONG_BOX;
                case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                    return TRUSTED_ENVIRONMENT;
                case KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE:
                    return UNKNOWN_SECURE;
                case KeyProperties.SECURITY_LEVEL_SOFTWARE:
                    return SOFTWARE;
                default:
                    return UNKNOWN;
            }
        }
    }

    /** Calls that exist from API 33, apart so that older systems never load them. */
    private static final class Api33 {
        static boolean named(Throwable cause) {
            return cause instanceof android.security.KeyStoreException;
        }

        static int code(Throwable cause) {
            if (!(cause instanceof android.security.KeyStoreException)) {
                return OK;
            }
            android.security.KeyStoreException failure = (android.security.KeyStoreException) cause;
            if (failure.requiresUserAuthentication()) {
                return LOCKED;
            }
            if (failure.isTransientFailure()) {
                return TRANSIENT;
            }
            switch (failure.getNumericErrorCode()) {
                case android.security.KeyStoreException.ERROR_KEY_DOES_NOT_EXIST:
                    return ABSENT;
                case android.security.KeyStoreException.ERROR_KEY_CORRUPTED:
                    return CORRUPTED;
                // The keystore's own failure, a service that died among them.
                case android.security.KeyStoreException.ERROR_INTERNAL_SYSTEM_ERROR:
                    return TRANSIENT;
                default:
                    return UNKNOWN_FAILURE;
            }
        }
    }
}
