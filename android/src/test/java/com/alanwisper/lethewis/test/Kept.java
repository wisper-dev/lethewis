// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

package com.alanwisper.lethewis.test;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import com.alanwisper.lethewis.Wiper;
import java.io.File;

/**
 * A foreground service that keeps the process of {@link Shown} running, and may end on its own. One
 * asked to check calls {@link Wiper#check} as it ends and writes {@code checked}: {@code wiped}, or
 * {@code held} if keys still answer. One asked to check at the start calls it once in the
 * foreground.
 */
public final class Kept extends Service {
    /** How long a service asked to end runs. */
    private static final long ENDS_MS = 20000;

    private boolean check;

    @Override
    public int onStartCommand(Intent intent, int flags, int id) {
        NotificationManager notifications = getSystemService(NotificationManager.class);
        notifications.createNotificationChannel(
                new NotificationChannel("kept", "kept", NotificationManager.IMPORTANCE_LOW));
        startForeground(
                1,
                new Notification.Builder(this, "kept")
                        .setContentTitle("kept")
                        .setSmallIcon(android.R.drawable.ic_lock_lock)
                        .build());
        if (intent != null && intent.getBooleanExtra("check-start", false)) {
            Wiper.check();
        }
        check = intent != null && intent.getBooleanExtra("check", false);
        if (intent != null && intent.getBooleanExtra("ends", false)) {
            new Handler(Looper.getMainLooper())
                    .postDelayed(
                            new Runnable() {
                                @Override
                                public void run() {
                                    stopSelf();
                                }
                            },
                            ENDS_MS);
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        if (check) {
            Wiper.check();
            Shown.write(
                    new File(new File(getNoBackupFilesDir(), "lethewis-tests"), "checked"),
                    Tests.held() ? "held" : "wiped");
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
