# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# shellcheck shell=bash
# Sourced with ANDROID_HOME set: points Cargo at the NDK of android/versions.sh for both Android
# targets, and runs the tests of x86_64-linux-android on the emulator through adb. Every variable
# naming an SDK or an NDK names these, whatever the machine set before.

android_root=$(git rev-parse --show-toplevel)
# shellcheck source=android/versions.sh
source "$android_root/android/versions.sh"
export ANDROID_SDK_ROOT=$ANDROID_HOME
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/$ANDROID_NDK_VERSION
export ANDROID_NDK_ROOT=$ANDROID_NDK_HOME
unset ANDROID_NDK ANDROID_NDK_LATEST_HOME
android_llvm=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
# The lowest API level Rust supports: a call newer than that fails the link, not a phone.
for android_arch in x86_64 aarch64; do
  export "CARGO_TARGET_${android_arch^^}_LINUX_ANDROID_LINKER=$android_llvm/$android_arch-linux-android21-clang"
  export "CC_${android_arch}_linux_android=$android_llvm/$android_arch-linux-android21-clang"
  export "AR_${android_arch}_linux_android=$android_llvm/llvm-ar"
done
export CARGO_TARGET_X86_64_LINUX_ANDROID_RUNNER=$android_root/scripts/on-emulator.sh
export PATH=$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$android_llvm:$PATH
