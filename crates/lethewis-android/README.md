# lethewis-android

The Android platform of LetheWis. A profile keeps its files in a directory of profiles alone, under
one named `no_backup`, as `Context.getNoBackupFilesDir()` is.

A key in the Android keystore answers the core's challenge. The key that opens the profile then
needs both the password and this device.

Each epoch has a root of its own: a key in the keystore and random bytes beside it. A change of
epoch erases the old root by best effort.

`Keys` holds the keys of an open profile in locked memory, on a thread of their own.

On Android it holds them only on an unlocked device, while the app shows or runs its own
foreground service. The Java layer's `Wiper` tells it when.

A profile opens with the owner's password, or with a password under duress, which may destroy the
other profiles.

`lethewis-jni` reaches the keystore on a device.

Licensed under AGPL-3.0-only; the text is in the package. A commercial licence without the AGPL's
obligations is available: <hi@alanwisper.com>.
