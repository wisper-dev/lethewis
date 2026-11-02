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
  llvm-nm --dynamic --defined-only "$1" | awk '$3 ~ /^Java_/ {print $3}' | sort
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

# Runs the tests named on the device; on a failure prints the report.
instrument() {
  local report
  report=$(adb_for 600 shell am instrument -w -r -e test "$1" -e api "$api" "$package/.Runner" |
    tr -d '\r') || true
  grep -E '^INSTRUMENTATION_(RESULT|CODE)' <<<"$report" || true
  if ! grep -qx 'INSTRUMENTATION_RESULT: result=passed' <<<"$report" ||
    ! grep -qx 'INSTRUMENTATION_CODE: -1' <<<"$report"; then
    echo "android: the tests on the device failed: $1" >&2
    echo "$report" >&2
    exit 1
  fi
}

start_emulator

step "the library without the tests"
for triple in x86_64-linux-android aarch64-linux-android; do
  so=$(library "$triple")
  aligned "$so"
  exported=$(natives "$so")
  if [ -n "$exported" ]; then
    echo "android: $so exports natives of the tests" >&2
    exit 1
  fi
done

step "the library of the tests"
so=$(library x86_64-linux-android --features device-tests)
aligned "$so"
exported=$(natives "$so")
expected=$'Java_com_alanwisper_lethewis_test_Tests_misuse\nJava_com_alanwisper_lethewis_test_Tests_run'
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

step "the chip's key on a locked device"
instrument before-lock
pin=1111
adb_for 30 shell locksettings set-pin "$pin" >/dev/null
lock
instrument locked
unlock
instrument after-lock
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
