// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.app.KeyguardManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.PowerManager;
import android.os.Process;
import java.util.concurrent.CountDownLatch;

/**
 * Tells lethewis-android when this process may hold keys: while the device is on and unlocked, and
 * the app shows an activity or runs a foreground service of its own in this process. Once that
 * ends, every {@code Keys} of the process is wiped, and none starts until it holds again.
 */
public final class Wiper {
    /**
     * How often the process is checked while the screen is on and the app shows an activity or
     * runs a foreground service of its own.
     */
    private static final long CHECK_MS = 2000;
    /** How long the device is kept awake after the screen goes off, for the keys to be wiped. */
    private static final int SETTLE_MS = 4000;

    private static Wiper started;

    private final PowerManager power;
    private final KeyguardManager keyguard;
    private final ActivityManager activities;
    /** Everything below is read and written on this thread only. */
    private final Handler work;

    private boolean screenOn;
    /** Activities started and not stopped. */
    private int shown;
    /** Whether the last activity stopped only to start again in a new configuration. */
    private boolean turning;
    private boolean allowed;

    private final Runnable check =
            new Runnable() {
                @Override
                public void run() {
                    update();
                }
            };

    private Wiper(Context app, Handler work) {
        power = (PowerManager) app.getSystemService(Context.POWER_SERVICE);
        keyguard = (KeyguardManager) app.getSystemService(Context.KEYGUARD_SERVICE);
        activities = (ActivityManager) app.getSystemService(Context.ACTIVITY_SERVICE);
        this.work = work;
    }

    /**
     * Starts watching, once per process: call it from {@code Application.onCreate}, before any
     * activity starts and after loading the native library that holds lethewis-jni. Until then no
     * keys are held; once it returns, they are as the process is.
     */
    public static synchronized void start(Context context) {
        if (started != null) {
            return;
        }
        // A missing native library fails here, before anything is registered.
        allow(false);
        Application app = (Application) context.getApplicationContext();
        HandlerThread thread = new HandlerThread("lethewis-wiper");
        thread.start();
        Handler work = new Handler(thread.getLooper());
        final Wiper wiper = new Wiper(app, work);
        IntentFilter events = new IntentFilter();
        events.addAction(Intent.ACTION_SCREEN_OFF);
        events.addAction(Intent.ACTION_SCREEN_ON);
        events.addAction(Intent.ACTION_USER_PRESENT);
        app.registerReceiver(
                new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        boolean off = Intent.ACTION_SCREEN_OFF.equals(intent.getAction());
                        wiper.screen(!off);
                        if (off) {
                            // The broadcast keeps the device awake until it is finished.
                            final PendingResult broadcast = goAsync();
                            new Thread(
                                            new Runnable() {
                                                @Override
                                                public void run() {
                                                    settle(SETTLE_MS);
                                                    broadcast.finish();
                                                }
                                            },
                                            "lethewis-settle")
                                    .start();
                        }
                    }
                },
                events,
                null,
                work);
        app.registerActivityLifecycleCallbacks(
                new Application.ActivityLifecycleCallbacks() {
                    @Override
                    public void onActivityStarted(Activity activity) {
                        wiper.post(1, false);
                    }

                    @Override
                    public void onActivityStopped(Activity activity) {
                        wiper.post(-1, activity.isChangingConfigurations());
                    }

                    @Override
                    public void onActivityCreated(Activity activity, Bundle state) {}

                    @Override
                    public void onActivityResumed(Activity activity) {}

                    @Override
                    public void onActivityPaused(Activity activity) {}

                    @Override
                    public void onActivitySaveInstanceState(Activity activity, Bundle state) {}

                    @Override
                    public void onActivityDestroyed(Activity activity) {}
                });
        // Read once the receiver is registered, so that no change of the screen is missed.
        wiper.now(
                new Runnable() {
                    @Override
                    public void run() {
                        wiper.screenOn = wiper.power.isInteractive();
                        wiper.update();
                    }
                });
        started = wiper;
    }

    /**
     * Checks at once whether this process may hold keys. Call it after {@code startForeground}
     * returns in a service started while the app shows nothing, and from the {@code onDestroy} of
     * a foreground service. Without it such a service holds no keys until the screen or an
     * activity changes, and keys outlive a service by up to two seconds.
     */
    public static void check() {
        Wiper wiper;
        synchronized (Wiper.class) {
            wiper = started;
        }
        if (wiper != null) {
            wiper.now(wiper.check);
        }
    }

    /** Runs {@code task} on the thread of the watch and waits for it. */
    private void now(final Runnable task) {
        if (Looper.myLooper() == work.getLooper()) {
            task.run();
            return;
        }
        final CountDownLatch done = new CountDownLatch(1);
        work.post(
                new Runnable() {
                    @Override
                    public void run() {
                        task.run();
                        done.countDown();
                    }
                });
        boolean interrupted = false;
        while (done.getCount() > 0) {
            try {
                done.await();
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** On the thread of the watch: the screen went on or off, or the device was unlocked. */
    private void screen(boolean on) {
        screenOn = on && power.isInteractive();
        update();
    }

    /** From the main thread: an activity started, or stopped, perhaps to start again. */
    private void post(final int change, final boolean turns) {
        work.post(
                new Runnable() {
                    @Override
                    public void run() {
                        shown = Math.max(0, shown + change);
                        turning = turns;
                        // An event of the screen held back from the process may not have come yet.
                        screenOn = power.isInteractive();
                        update();
                    }
                });
    }

    /** On the thread of the watch: tells lethewis-android what the process may hold now. */
    private void update() {
        work.removeCallbacks(check);
        boolean onScreen = shown > 0 || turning;
        boolean service = !onScreen && screenOn && foregroundService();
        if (screenOn && (onScreen || service)) {
            // Neither a lock with the screen on nor the end of a service is announced, and an
            // unlock may be announced before the device counts as unlocked.
            work.postDelayed(check, CHECK_MS);
        }
        boolean now = screenOn && !keyguard.isDeviceLocked() && (onScreen || service);
        if (now != allowed) {
            allowed = now;
            allow(now);
        }
    }

    /**
     * Whether a service of this process runs in the foreground. A process kept running only by
     * another app's binding does not count.
     */
    @SuppressWarnings("deprecation")
    private boolean foregroundService() {
        // The system still lists the caller's own services.
        for (ActivityManager.RunningServiceInfo service :
                activities.getRunningServices(Integer.MAX_VALUE)) {
            if (service.foreground && service.pid == Process.myPid()) {
                return true;
            }
        }
        return false;
    }

    private static native void allow(boolean allowed);

    private static native void settle(int millis);
}
