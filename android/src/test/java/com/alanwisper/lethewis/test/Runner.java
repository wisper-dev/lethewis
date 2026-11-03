// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis.test;

import android.app.Activity;
import android.app.Instrumentation;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Bundle;
import com.alanwisper.lethewis.KeystoreTests;
import java.io.File;

/**
 * Runs the tests of the library on a device: {@code am instrument -w -r -e api LEVEL} reports
 * {@code passed} and code -1 when they hold, LEVEL being the system's own. {@code -e test} picks
 * the tests: {@code all} by default, or one step of a profile kept across a lock of the device,
 * {@code before-lock}, {@code locked} and {@code after-lock}, or across a keystore that stops,
 * {@code before-stop}, {@code stopping}, {@code stopped}, {@code restarted} and {@code after-stop}.
 * {@code -e test platform} checks the failures of the keystore from API 33, with the checks of
 * hidden interfaces lifted. With {@code -e test misuse} it breaks a rule of JNI instead, and the
 * process must not survive it.
 */
public final class Runner extends Instrumentation {
    private Bundle arguments;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments;
        start();
    }

    @Override
    public void onStart() {
        Bundle results = new Bundle();
        String outcome;
        try {
            outcome = run(arguments.getString("test", "all"));
        } catch (Throwable thrown) {
            outcome = thrown.toString();
        }
        boolean passed = "passed".equals(outcome);
        results.putString("result", outcome == null ? "no result" : outcome);
        finish(passed ? Activity.RESULT_OK : Activity.RESULT_CANCELED, results);
    }

    private String run(String test) throws Exception {
        System.loadLibrary("lethewis_jni");
        if ("misuse".equals(test)) {
            Tests.misuse();
            return "the misuse of JNI went unnoticed";
        }
        if ("platform".equals(test)) {
            return KeystoreTests.platform();
        }
        Context context = getTargetContext();
        KeyguardManager keyguard =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        boolean locked = "locked".equals(test);
        // The device locks and unlocks a moment after the keys that ask for it.
        for (int tries = 0; keyguard.isDeviceLocked() != locked && tries < 50; tries++) {
            Thread.sleep(200);
        }
        if (keyguard.isDeviceLocked() != locked) {
            return locked ? "the device is not locked" : "the device is locked";
        }
        if ("all".equals(test)) {
            String java = KeystoreTests.run();
            if (!"passed".equals(java)) {
                return java;
            }
            Tests.importKnownKey();
        }
        File root = new File(context.getNoBackupFilesDir(), "lethewis-tests");
        return Tests.run(root.getPath(), Integer.parseInt(arguments.getString("api")), test);
    }
}
