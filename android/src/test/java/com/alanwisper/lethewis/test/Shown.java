// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis.test;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.SystemClock;
import com.alanwisper.lethewis.Wiper;
import java.io.File;
import java.io.FileOutputStream;

/**
 * Holds keys for the tests of {@link Wiper}, started by {@code am start -e test TEST}: {@code
 * hidden} alone, {@code service} with a foreground service, {@code service-ends} with one that ends
 * twenty seconds after it starts and calls {@link Wiper#check}, {@code service-ends-silently} with
 * one that does not, {@code proximity} with the screen held off by the proximity sensor, {@code
 * busy} with a call of the keys under way, or {@code over-lock} shown over the lock screen.
 *
 * <p>Under {@code no_backup/lethewis-tests} it writes {@code reached} once keys are held, {@code
 * wiped} once they are gone, {@code refusal} with the reason each time new ones are refused, and
 * {@code again} once keys are held again, after {@code late} with the milliseconds since the
 * unlock, 0 without one; {@code turned} when made again by a turn of the screen, or {@code failed}
 * with the reason. With {@code busy} it writes {@code busy} as the call starts, and {@code check}
 * with the milliseconds {@link Wiper#check} took a second after the screen went off and whether the
 * call was still under way as it returned.
 */
public final class Shown extends Activity {
    /** How long the call under way of {@code busy} runs. */
    private static final int BUSY_MS = 6000;

    /** Whether this process holds keys already: an activity made again on a turn holds none. */
    private static boolean holding;

    private static PowerManager.WakeLock proximity;

    /** Whether the call of {@code busy} is under way. */
    private static volatile boolean busy;

    /** When the device was last unlocked, 0 if never. */
    private static volatile long unlocked;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        System.loadLibrary("lethewis_jni");
        Wiper.start(this);
        final File root = new File(getNoBackupFilesDir(), "lethewis-tests");
        if (holding) {
            write(new File(root, "turned"), "");
            return;
        }
        holding = true;
        registerReceiver(
                new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        unlocked = SystemClock.elapsedRealtime();
                    }
                },
                new IntentFilter(Intent.ACTION_USER_PRESENT));
        final String test = getIntent().getStringExtra("test");
        final PowerManager power = (PowerManager) getSystemService(POWER_SERVICE);
        if (test.startsWith("service")) {
            startForegroundService(
                    new Intent(this, Kept.class)
                            .putExtra("ends", test.startsWith("service-ends"))
                            .putExtra("check", "service-ends".equals(test)));
        }
        if ("proximity".equals(test)) {
            proximity =
                    power.newWakeLock(
                            PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK, "lethewis:proximity");
            proximity.acquire();
        }
        if ("over-lock".equals(test)) {
            setShowWhenLocked(true);
        }
        new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    String held = Tests.hold();
                                    for (int tries = 0; !"passed".equals(held); tries++) {
                                        if (tries == 100) {
                                            write(new File(root, "failed"), String.valueOf(held));
                                            return;
                                        }
                                        Thread.sleep(100);
                                        held = Tests.hold();
                                    }
                                    write(new File(root, "reached"), "");
                                    if ("busy".equals(test)) {
                                        timeCheck(power, root);
                                        busy = true;
                                        write(new File(root, "busy"), "");
                                        Tests.busy(BUSY_MS);
                                        busy = false;
                                    }
                                    while (Tests.held()) {
                                        Thread.sleep(50);
                                    }
                                    write(new File(root, "wiped"), "");
                                    for (String again = Tests.hold();
                                            !"passed".equals(again);
                                            again = Tests.hold()) {
                                        write(new File(root, "refusal"), String.valueOf(again));
                                        Thread.sleep(200);
                                    }
                                    long since = unlocked;
                                    long late =
                                            since == 0 ? 0 : SystemClock.elapsedRealtime() - since;
                                    write(new File(root, "late"), String.valueOf(late));
                                    write(new File(root, "again"), "");
                                } catch (InterruptedException e) {
                                    write(new File(root, "failed"), e.toString());
                                }
                            }
                        })
                .start();
    }

    /**
     * Times {@link Wiper#check} a second after the screen goes off, while the call is under way.
     */
    private static void timeCheck(final PowerManager power, final File root) {
        new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    while (power.isInteractive()) {
                                        Thread.sleep(10);
                                    }
                                    // By then the event of the screen has reached Wiper.
                                    Thread.sleep(1000);
                                    long start = SystemClock.elapsedRealtime();
                                    Wiper.check();
                                    long took = SystemClock.elapsedRealtime() - start;
                                    boolean during = busy;
                                    write(new File(root, "check"), took + " " + during);
                                } catch (InterruptedException e) {
                                    write(new File(root, "failed"), e.toString());
                                }
                            }
                        })
                .start();
    }

    /** Writes {@code file} whole: the host sees it only once its text is in. */
    static void write(File file, String text) {
        try {
            file.getParentFile().mkdirs();
            File part = new File(file.getPath() + ".part");
            FileOutputStream out = new FileOutputStream(part);
            try {
                out.write(text.getBytes("UTF-8"));
            } finally {
                out.close();
            }
            if (!part.renameTo(file)) {
                part.delete();
            }
        } catch (Exception e) {
            // The host then finds no file and reports the test as failed.
        }
    }
}
