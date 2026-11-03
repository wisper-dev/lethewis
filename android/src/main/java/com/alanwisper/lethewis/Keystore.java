// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.security.keystore.UserNotAuthenticatedException;
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
    static final int TRANSIENT = -1;
    static final int LOCKED = -2;
    static final int ABSENT = -3;
    static final int CORRUPTED = -4;
    static final int STRONG_BOX_UNAVAILABLE = -5;

    private static final String PROVIDER = "AndroidKeyStore";

    private Keystore() {}

    static int apiLevel() {
        return Build.VERSION.SDK_INT;
    }

    static int contains(String alias) {
        try {
            return store().containsAlias(alias) ? 1 : 0;
        } catch (Exception e) {
            return failure(e);
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
            return failure(e);
        }
    }

    static int mac(String alias, byte[] data, byte[] out) {
        try {
            Key key = store().getKey(alias, null);
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
            return failure(e);
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
            return failure(e);
        }
    }

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
            // key the system made unusable.
            if (cause instanceof UnrecoverableKeyException && cause.getCause() == null) {
                return ABSENT;
            }
            if (Build.VERSION.SDK_INT >= 33) {
                int code = Api33.code(cause);
                if (code != OK) {
                    return code;
                }
            }
        }
        return TRANSIENT;
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
                default:
                    return TRANSIENT;
            }
        }
    }
}
