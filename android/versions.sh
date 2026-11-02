# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

# shellcheck shell=bash disable=SC2034
# The Android tools the library is built and tested with, by exact version. Each archive with its
# place in the SDK, the SHA-1 the SDK repository lists for it, and its SHA-256 taken when pinned.

ANDROID_NDK_VERSION=30.0.16248370
ANDROID_BUILD_TOOLS=37.0.0
ANDROID_PLATFORM=android-37.0
ANDROID_REPOSITORY=https://dl.google.com/android/repository

# place in the SDK | archive | SHA-1 | SHA-256
ANDROID_PACKAGES=(
  "platform-tools|platform-tools_r37.0.1-linux.zip|477254aa5f903c15cf51001717bdf347fb6b53e0|d230f13842f60f782a8645f9c813f8f845bf36089ea7289f28c48f17979313f1"
  "emulator|emulator-linux_x64-16740729.zip|f41f9e31eb5ca64926603c03265c50bbc0ff4172|cbc7c3cfb83220b8a0f9c513fdab557712e74d339ec19ddffa43f23350ae9bdd"
  "ndk/30.0.16248370|android-ndk-r30-linux.zip|5107f898313790e449e87eee2183d9a20602dee9|753611f410d002cfcd3f3dc2ef49aad532089d3180b436c060a90bf0fcb64df2"
  "build-tools/37.0.0|build-tools_r37_linux.zip|70954e99f4c3d9d46ee70fa32624672fe7cd6ebe|01af179347cbcd9c208b7f8171f7b21f6dd1d2f85bcd15e88caa51d5d7b86060"
  "platforms/android-37.0|platform-37.0_r02.zip|ed8ebf7f8822a4de5686d427f237d2fa30ff7410|840b23e827f96e64aea4c89a1194aac3dc5f6bad37edb231c5c795d890330e8d"
)

# The system images of the emulators by the name scripts/android.sh takes, and the size of a page
# their programs are given.
declare -A ANDROID_IMAGES=(
  [28]="system-images/android-28/google_apis/x86_64|sys-img/google_apis/x86_64-28_r11.zip|1d93bd994e29c4e9bbe71fd9c278addc5418cbee|57fcdae393eac7dbe4bf854093e18d225ca7bfb9746321de70f01c5faa0c37ed"
  [37-16k]="system-images/android-37.0/google_apis_ps16k/x86_64|sys-img/google_apis/x86_64-ps16k-37.0_r08.zip|3e04f6c168a573640e63fdd8afd71a3c4d947f64|94936d2fb7d8bd1d0c2411510ca7e06ce93184695cad8a43fea036660ffb972d"
)
declare -A ANDROID_PAGES=([28]=4096 [37-16k]=16384)
