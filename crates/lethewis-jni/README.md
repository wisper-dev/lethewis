# lethewis-jni

The bridge of LetheWis to its Java layer on Android, `com.alanwisper.lethewis`. It gives
`lethewis-android` the keystore of the device through JNI, on the thread of the call.

Through it `Wiper` wipes the keys of the process.

One of the three crates of the workspace with unsafe code. A reason stands before every block.

Licensed under AGPL-3.0-only; the text is in the package. A commercial licence without the AGPL's
obligations is available: <hi@alanwisper.com>.
