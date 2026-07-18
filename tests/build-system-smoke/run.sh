#!/usr/bin/env bash
# 用发布包内的 CMake toolchain 与 ndk-build 各构建一次最小共享库。
set -euo pipefail
NDK_ARG="${1:?用法: run.sh <ndk-dir> <host>}"
HOST="${2:-linux-x86_64}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT

if [[ ! -d "$NDK_ARG" ]]; then
  echo "[error] NDK 目录不存在: $NDK_ARG" >&2
  exit 1
fi
NDK="$(cd "$NDK_ARG" && pwd -P)"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
if [[ ! -f "$TOOLCHAIN" ]]; then
  echo "[error] CMake toolchain 不存在: $TOOLCHAIN" >&2
  exit 1
fi

cmake -S "$HERE" -B "$OUT/cmake" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_NDK="$NDK" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-21
cmake --build "$OUT/cmake"

NDK_BUILD="$NDK/ndk-build"
case "$HOST" in windows-*) NDK_BUILD="$NDK/ndk-build.cmd" ;; esac
"$NDK_BUILD" -B \
  NDK_PROJECT_PATH="$HERE" \
  APP_BUILD_SCRIPT="$HERE/Android.mk" \
  NDK_APPLICATION_MK="$HERE/Application.mk" \
  NDK_OUT="$OUT/ndk-obj" \
  NDK_LIBS_OUT="$OUT/ndk-libs"

echo "[ok] CMake toolchain 与 ndk-build 均可构建 arm64-v8a"
