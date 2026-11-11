#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# Builds the library for Android and tests it on an emulator named in android/versions.sh: the
# Rust tests of the workspace through adb, and the tests on the device through the Java layer,
# shrunk by R8 with the rules an app gets, under CheckJNI. Checks the shared library of
# lethewis-jni for both targets: aligned to 16 KiB, without the natives of the tests.
#
# Needs ANDROID_HOME with the pieces of android/versions.sh (scripts/android-sdk.sh), a Rust
# toolchain with the Android targets, a JDK, and /dev/kvm.
set -euo pipefail
shopt -s inherit_errexit

usage() {
  echo "usage: android.sh <emulator>, one of android/versions.sh's ANDROID_IMAGES" >&2
  exit 2
}
[ $# -eq 1 ] || usage
emulator=$1
root=$(git rev-parse --show-toplevel)
cd "$root"
# shellcheck source=scripts/android-env.sh
source scripts/android-env.sh
[ -n "${ANDROID_IMAGES[$emulator]:-}" ] || usage
image=${ANDROID_IMAGES[$emulator]%%|*}

target=${CARGO_TARGET_DIR:-$root/target}
work=$target/android-$emulator
tools=$ANDROID_HOME/build-tools/$ANDROID_BUILD_TOOLS
android_jar=$ANDROID_HOME/platforms/$ANDROID_PLATFORM/android.jar
package=com.alanwisper.lethewis.test
port=5554
export ANDROID_SERIAL=emulator-$port
# Set once the emulator on the port is known to be this one.
ours=
rm -rf "$work"
mkdir -p "$work"

step() {
  printf '\n=== %s ===\n' "$1"
}

# adb, given SECONDS to finish: a call to a guest that died never returns.
adb_for() {
  local seconds=$1
  shift
  timeout "$seconds" adb "$@"
}

# A new virtual phone each run, from the image alone.
start_emulator() {
  local avd_home=${ANDROID_AVD_HOME:-${ANDROID_USER_HOME:-$HOME/.android}/avd}
  local name=lethewis-$emulator
  rm -rf "$avd_home/$name.avd"
  mkdir -p "$avd_home/$name.avd"
  printf 'avd.ini.encoding=UTF-8\npath=%s\n' "$avd_home/$name.avd" >"$avd_home/$name.ini"
  cat >"$avd_home/$name.avd/config.ini" <<EOF
avd.ini.encoding=UTF-8
abi.type=x86_64
hw.cpu.arch=x86_64
hw.cpu.ncore=2
hw.ramSize=2G
disk.dataPartition.size=4G
hw.lcd.width=320
hw.lcd.height=640
hw.lcd.density=160
hw.sensors.proximity=yes
image.sysdir.1=$image/
PlayStore.enabled=no
EOF
  ANDROID_AVD_HOME=$avd_home emulator -avd "$name" -port "$port" -no-window -no-audio \
    -no-boot-anim -no-snapshot -wipe-data -no-metrics -gpu swiftshader -accel on \
    >"$work/emulator.log" 2>&1 &
  emulator_pid=$!
  trap stop_emulator EXIT
}

# Keeps the device's log of a failed run, then stops the emulator.
stop_emulator() {
  local status=$?
  if [ "$status" -ne 0 ] && [ -n "$ours" ]; then
    adb_for 60 logcat -d >"$work/logcat.log" 2>/dev/null || true
    echo "android: the device's log is in $work/logcat.log; its end:" >&2
    tail -100 "$work/logcat.log" >&2
  fi
  kill "$emulator_pid" 2>/dev/null || return 0
  local waited=0
  while kill -0 "$emulator_pid" 2>/dev/null && [ "$waited" -lt 30 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  kill -9 "$emulator_pid" 2>/dev/null || true
  wait "$emulator_pid" 2>/dev/null || true
}

booted() {
  local deadline=$((SECONDS + 300)) pages name
  while true; do
    if ! kill -0 "$emulator_pid" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then
      echo "android: the emulator did not boot" >&2
      tail -20 "$work/emulator.log" >&2
      return 1
    fi
    # A shell opened while adbd restarts during boot never returns.
    if [ "$(adb_for 10 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then
      break
    fi
    sleep 2
  done
  # Another emulator may hold the port, and this one may have failed to take it.
  name=$(adb_for 10 emu avd name | tr -d '\r')
  if [ "${name%%$'\n'*}" != "lethewis-$emulator" ]; then
    echo "android: the emulator on port $port is not lethewis-$emulator" >&2
    return 1
  fi
  ours=1
  api=$(adb_for 10 shell getprop ro.build.version.sdk | tr -d '\r')
  # Entry 6 of the auxiliary vector, AT_PAGESZ.
  pages=$(adb_for 10 exec-out cat /proc/self/auxv | od -An -td8 -w16 | awk '$1 == 6 { print $2 }')
  echo "Android $(adb_for 10 shell getprop ro.build.version.release | tr -d '\r'),"\
    "API level $api, pages of $pages bytes"
  if [ "$pages" != "${ANDROID_PAGES[$emulator]}" ]; then
    echo "android: pages of ${ANDROID_PAGES[$emulator]} bytes expected" >&2
    return 1
  fi
}

# Every LOAD segment aligned to 16 KiB.
aligned() {
  local wrong
  wrong=$(llvm-readelf --program-headers --wide "$1" | awk '$1 == "LOAD" && $NF != "0x4000"')
  if [ -n "$wrong" ]; then
    echo "android: $1 has segments not aligned to 16 KiB:" >&2
    echo "$wrong" >&2
    return 1
  fi
}

# The natives of the library a build exports, by name.
natives() {
  llvm-nm --dynamic --defined-only "$1" | awk '$3 ~ /^Java_/ {print $3}' | LC_ALL=C sort
}

library() {
  local triple=$1
  shift
  cargo rustc -p lethewis-jni --release --locked --target "$triple" --crate-type cdylib "$@"
  echo "$target/$triple/release/liblethewis_jni.so"
}

# Prints locked or unlocked as the system reports the device for the current user, or nothing
# while it does not tell.
lock_state() {
  local state
  state=$(adb_for 30 shell dumpsys trust | tr -d '\r') || true
  if grep -q '(current).*deviceLocked=1' <<<"$state"; then
    echo locked
  elif grep -q '(current).*deviceLocked=0' <<<"$state"; then
    echo unlocked
  fi
}

lock() {
  local _
  adb_for 30 shell input keyevent KEYCODE_WAKEUP
  # The power button locks at once a device with a PIN.
  adb_for 30 shell input keyevent KEYCODE_POWER
  for _ in $(seq 20); do
    if [ "$(lock_state)" = locked ]; then
      return
    fi
    sleep 1
  done
  echo "android: the device did not lock" >&2
  exit 1
}

# A PIN typed before its field shows is lost, so it is typed again until the device unlocks.
unlock() {
  local _
  for _ in 1 2 3 4 5; do
    adb_for 30 shell input keyevent KEYCODE_WAKEUP
    sleep 1
    adb_for 30 shell wm dismiss-keyguard
    sleep 2
    adb_for 30 shell input text "$pin"
    adb_for 30 shell input keyevent KEYCODE_ENTER
    sleep 2
    if [ "$(lock_state)" = unlocked ]; then
      return
    fi
  done
  echo "android: the device did not unlock" >&2
  exit 1
}

# Stops or starts the keystore service, as root, and waits until the system reports it as $2, and
# a service that runs as registered.
keystore() {
  local service interface _
  service=$([ "$api" -ge 31 ] && echo keystore2 || echo keystore)
  interface=$([ "$api" -ge 31 ] && echo android.system.keystore2.IKeystoreService/default ||
    echo android.security.keystore)
  adb_for 30 shell "$1" "$service"
  for _ in $(seq 20); do
    if [ "$(adb_for 10 shell getprop "init.svc.$service" | tr -d '\r')" = "$2" ] &&
      { [ "$2" = stopped ] || grep -q ': found' <<<"$(adb_for 10 shell service check "$interface")"; }; then
      return
    fi
    sleep 1
  done
  echo "android: the keystore is not $2" >&2
  exit 1
}

# The files the activity of the tests writes, under the app's own directory.
shown_files=no_backup/lethewis-tests

# Whether the activity of the tests wrote the file $1.
wrote() {
  adb_for 10 shell run-as "$package" ls "$shown_files/$1" >/dev/null 2>&1
}

# Waits up to $2 seconds for the activity of the tests to write the file $1.
writes() {
  local _
  for _ in $(seq $(($2 * 5))); do
    wrote "$1" && return
    sleep 0.2
  done
  return 1
}

# Starts the activity of the tests for the test $1 and waits until it holds keys.
show() {
  adb_for 30 shell am force-stop "$package"
  adb_for 30 shell run-as "$package" rm -rf "$shown_files"
  adb_for 30 shell am start -n "$package/.Shown" --es test "$1" >/dev/null
  if ! writes reached 30; then
    echo "android: no keys were held for $1:" >&2
    adb_for 10 shell run-as "$package" cat "$shown_files/failed" >&2 || true
    exit 1
  fi
}

# Fails if the keys are gone $2 seconds later; $1 says what should have kept them.
kept() {
  sleep "$2"
  if wrote wiped; then
    echo "android: the keys were wiped despite $1" >&2
    exit 1
  fi
}

# Fails unless the keys are gone within $2 seconds; $1 says what should have wiped them.
wiped() {
  if ! writes wiped "$2"; then
    echo "android: the keys outlived $1" >&2
    exit 1
  fi
}

# Fails if keys are held again $2 seconds later, or were not refused as away; $1 says what should
# have refused them.
refused() {
  local refusal
  sleep "$2"
  if wrote again; then
    echo "android: keys were held again despite $1" >&2
    exit 1
  fi
  refusal=$(adb_for 10 shell run-as "$package" cat "$shown_files/refusal" 2>/dev/null) || true
  if ! grep -q 'away from the screen' <<<"$refusal"; then
    echo "android: no refusal as away during $1: ${refusal:-none}" >&2
    exit 1
  fi
}

# Waits up to $1 seconds for the screen to go off.
dark() {
  local _ display
  for _ in $(seq $(($1 * 2))); do
    display=$(adb_for 30 shell dumpsys display | tr -d '\r')
    grep -q 'mScreenState=OFF' <<<"$display" && return
    sleep 0.5
  done
  return 1
}

# Fails unless keys are held again within $2 seconds; $1 says what should allow them.
again() {
  if ! writes again "$2"; then
    echo "android: no keys were held again after $1" >&2
    exit 1
  fi
}

# Locks the device as the lockdown of the power menu does, leaving the screen on.
lockdown() {
  local _
  adb_for 30 shell cmd lock_settings require-strong-auth STRONG_AUTH_REQUIRED_AFTER_USER_LOCKDOWN
  for _ in $(seq 20); do
    if [ "$(lock_state)" = locked ]; then
      return
    fi
    sleep 1
  done
  echo "android: the device did not lock down" >&2
  exit 1
}

# Turns the screen to the rotation $1, 0 for portrait or 1 for landscape.
turn() {
  adb_for 30 shell settings put system accelerometer_rotation 0
  adb_for 30 shell settings put system user_rotation "$1"
}

# Runs the tests named $1 on the device, with the options of am instrument after it; on a failure
# prints the report.
instrument() {
  local test=$1 report
  shift
  report=$(adb_for 600 shell am instrument -w -r "$@" -e test "$test" -e api "$api" \
    "$package/.Runner" | tr -d '\r') || true
  grep -E '^INSTRUMENTATION_(RESULT|CODE)' <<<"$report" || true
  if ! grep -qx 'INSTRUMENTATION_RESULT: result=passed' <<<"$report" ||
    ! grep -qx 'INSTRUMENTATION_CODE: -1' <<<"$report"; then
    echo "android: the tests on the device failed: $test" >&2
    echo "$report" >&2
    exit 1
  fi
}

start_emulator

# The natives of Wiper, which every build has.
wiper=$'Java_com_alanwisper_lethewis_Wiper_allow\nJava_com_alanwisper_lethewis_Wiper_settle'

step "the library without the tests"
for triple in x86_64-linux-android aarch64-linux-android; do
  so=$(library "$triple")
  aligned "$so"
  exported=$(natives "$so")
  if [ "$exported" != "$wiper" ]; then
    echo "android: $so exports other natives:" >&2
    echo "$exported" >&2
    exit 1
  fi
done

step "the library of the tests"
so=$(library x86_64-linux-android --features device-tests)
aligned "$so"
exported=$(natives "$so")
expected=$wiper$'\nJava_com_alanwisper_lethewis_test_Tests_busy'
expected+=$'\nJava_com_alanwisper_lethewis_test_Tests_held\nJava_com_alanwisper_lethewis_test_Tests_hold'
expected+=$'\nJava_com_alanwisper_lethewis_test_Tests_misuse\nJava_com_alanwisper_lethewis_test_Tests_run'
if [ "$exported" != "$expected" ]; then
  echo "android: the library of the tests exports other natives:" >&2
  echo "$exported" >&2
  exit 1
fi
mkdir -p "$work/staged/lib/x86_64"
cp "$so" "$work/staged/lib/x86_64/"

step "the package of the tests"
mapfile -t sources < <(find android/src/main/java android/src/test/java -name '*.java' | sort)
mkdir -p "$work/classes"
# Source and target 8 are the newest javac lets compile against android.jar alone, with none of
# the JDK's own classes in sight.
javac -Xlint:all,-options -Werror -source 8 -target 8 -bootclasspath "$android_jar" \
  -d "$work/classes" "${sources[@]}"
(cd "$work/classes" && zip -q -X -r ../classes.jar .)
"$tools/aapt2" link -o "$work/unsigned.apk" --manifest android/src/test/AndroidManifest.xml \
  -I "$android_jar" --proguard "$work/manifest.pro"
mkdir -p "$work/dex"
java -cp "$tools/lib/d8.jar" com.android.tools.r8.R8 --release --min-api 28 \
  --lib "$android_jar" --pg-conf android/proguard.txt --pg-conf android/src/test/proguard.txt \
  --pg-conf "$work/manifest.pro" --output "$work/dex" "$work/classes.jar"
(cd "$work/dex" && zip -q -X ../unsigned.apk classes.dex)
(cd "$work/staged" && zip -q -X -0 -r ../unsigned.apk lib)
"$tools/zipalign" -f -P 16 4 "$work/unsigned.apk" "$work/aligned.apk"
"$tools/zipalign" -c -P 16 4 "$work/aligned.apk"
keytool -genkeypair -keystore "$work/test.p12" -storetype PKCS12 -storepass lethewis \
  -alias test -keyalg EC -groupname secp256r1 -dname CN=test -validity 1 -noprompt 2>/dev/null
"$tools/apksigner" sign --ks "$work/test.p12" --ks-pass pass:lethewis \
  --out "$work/tests.apk" "$work/aligned.apk"

step "the emulator boots"
booted

step "the Rust tests on the emulator"
cargo test --workspace --all-features --locked --target x86_64-linux-android
cargo test --workspace --all-features --locked --target x86_64-linux-android --release

step "the tests on the device"
adb_for 120 install -r -t "$work/tests.apk" >/dev/null
instrument all
instrument context
# The keystore's own failures, whose class apps do not reach.
if [ "$api" -ge 33 ]; then
  instrument platform --no-hidden-api-checks
fi

step "the chip's key on a locked device"
instrument before-lock
pin=1111
adb_for 30 shell locksettings set-pin "$pin" >/dev/null
lock
instrument locked
unlock
instrument after-lock

step "keys leave with the app"
show hidden
kept "the app on the screen" 2
turn 1
if ! writes turned 10; then
  echo "android: the screen did not turn" >&2
  exit 1
fi
kept "a turn of the screen" 2
turn 0
kept "a turn of the screen" 3
adb_for 30 shell input keyevent KEYCODE_HOME
wiped "leaving the screen" 5
refused "the app off the screen" 4
adb_for 30 shell am start-foreground-service -n "$package/.Kept" >/dev/null
# The control of Wiper.check below: nothing looks for a service started while nothing shows.
refused "a foreground service started while the app shows nothing, before Wiper.check" 4
adb_for 30 shell am start-foreground-service -n "$package/.Kept" --ez check-start true >/dev/null
again "Wiper.check at the start of a foreground service" 5
show busy
if ! writes busy 10; then
  echo "android: the call of the keys did not start" >&2
  exit 1
fi
lock
if ! writes check 15; then
  echo "android: Wiper.check did not return with the screen off" >&2
  exit 1
fi
checked=$(adb_for 10 shell run-as "$package" cat "$shown_files/check")
if ! [[ $checked =~ ^([0-9]+)\ true$ ]]; then
  echo "android: Wiper.check was not timed during the call: ${checked:-nothing}" >&2
  exit 1
fi
if [ "${BASH_REMATCH[1]}" -ge 1000 ]; then
  echo "android: Wiper.check waited ${BASH_REMATCH[1]} ms for the wipe behind a call under way" >&2
  exit 1
fi
wiped "the screen going off during a call" 10
unlock
again "unlocking with the app on the screen" 10
late=$(adb_for 10 shell run-as "$package" cat "$shown_files/late")
if ! [[ $late =~ ^[0-9]+$ ]] || [ "$late" -ge 1000 ]; then
  echo "android: keys were held again ${late:-never} ms after the unlock" >&2
  exit 1
fi
# Android 9 cannot lock from the shell with the screen on.
if [ "$api" -gt 28 ]; then
  show hidden
  kept "the app on the screen" 2
  lockdown
  wiped "a lockdown with the app on the screen" 3
  unlock
  again "unlocking with the app on the screen" 10
  show over-lock
  kept "the app over the lock screen" 2
  lockdown
  wiped "a lockdown under the app over the lock screen" 4
  unlock
  again "unlocking under the app over the lock screen" 10
  show service
  adb_for 30 shell input keyevent KEYCODE_HOME
  kept "a foreground service" 3
  lockdown
  wiped "a lockdown with a foreground service" 4
  unlock
  again "unlocking with a foreground service" 10
fi
show service
adb_for 30 shell input keyevent KEYCODE_HOME
kept "a foreground service" 5
# Off by its timeout the device locks five seconds later: only the screen's own event wipes in time.
adb_for 30 shell settings put secure lock_screen_lock_after_timeout 5000
adb_for 30 shell svc power stayon false
adb_for 30 shell settings put system screen_off_timeout 15000
if ! dark 30; then
  echo "android: the screen did not time out" >&2
  exit 1
fi
wiped "the screen going off" 2
adb_for 30 shell settings put system screen_off_timeout 1800000
for _ in $(seq 20); do
  [ "$(lock_state)" = locked ] && break
  sleep 1
done
unlock
show service
adb_for 30 shell input keyevent KEYCODE_HOME
kept "a foreground service" 3
lock
wiped "the screen going off" 3
adb_for 30 shell input keyevent KEYCODE_WAKEUP
refused "the lock screen" 4
unlock
again "unlocking with a foreground service" 10
show service-ends
adb_for 30 shell input keyevent KEYCODE_HOME
kept "a foreground service" 3
if ! writes checked 30 ||
  [ "$(adb_for 10 shell run-as "$package" cat "$shown_files/checked")" != wiped ]; then
  echo "android: the keys outlived Wiper.check at the end of the foreground service" >&2
  exit 1
fi
show service-ends-silently
adb_for 30 shell input keyevent KEYCODE_HOME
kept "a foreground service" 3
wiped "the end of the foreground service" 30
show proximity
adb_for 30 emu sensor set proximity 5
sleep 1
adb_for 30 emu sensor set proximity 0
if ! dark 10; then
  echo "android: the proximity sensor did not turn the screen off" >&2
  exit 1
fi
kept "the screen held off by the proximity sensor" 5
adb_for 30 emu sensor set proximity 5
adb_for 30 shell am force-stop "$package"
# The next step waits for a file of the same name.
adb_for 30 shell run-as "$package" rm -rf "$shown_files"

step "a keystore that stopped is no lost key"
instrument before-stop
adb_for 60 root >/dev/null
adb_for 60 wait-for-device
# A process that reached the keystore before it stops, and one that starts after.
instrument stopping &
stopping=$!
reached=/data/user/0/$package/no_backup/lethewis-tests/reached
for _ in $(seq 60); do
  adb_for 10 shell ls "$reached" >/dev/null 2>&1 && break
  sleep 1
done
keystore stop stopped
wait "$stopping" || exit 1
instrument stopped
keystore start running
adb_for 60 unroot >/dev/null
adb_for 60 wait-for-device
# Keys that work only while the device is unlocked wait for an unlocking after a restart.
instrument restarted
lock
unlock
instrument after-stop
adb_for 30 shell locksettings clear --old "$pin" >/dev/null

step "CheckJNI stops a misuse of JNI"
adb_for 10 logcat -c
report=$(adb_for 120 shell am instrument -w -r -e test misuse "$package/.Runner" |
  tr -d '\r') || true
if grep -q '^INSTRUMENTATION_RESULT: result=' <<<"$report"; then
  echo "android: the process survived a misuse of JNI:" >&2
  echo "$report" >&2
  exit 1
fi
log=$(adb_for 60 logcat -d)
if ! grep -q 'JNI DETECTED ERROR IN APPLICATION' <<<"$log"; then
  echo "android: CheckJNI did not report the misuse" >&2
  exit 1
fi
echo "stopped by CheckJNI"
adb_for 60 uninstall "$package" >/dev/null

printf '\nall Android tests passed on %s\n' "$emulator"
