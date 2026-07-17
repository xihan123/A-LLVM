#!/usr/bin/env bash
# run.sh — 用（可能已覆盖的）NDK clang 为四种 Android ABI 编译 hello.c，
# 校验产出的是对应架构的有效 ELF。阶段 1b 由 build.yml 调用。
#   run.sh <ndk-dir> <host>
set -euo pipefail
NDK="${1:?用法: run.sh <ndk-dir> <host>}"
HOST="${2:-linux-x86_64}"
API=21
EXT=""; case "$HOST" in windows-*) EXT=".exe" ;; esac
CLANG="$NDK/toolchains/llvm/prebuilt/$HOST/bin/clang${EXT}"
READELF="$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-readelf${EXT}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(mktemp -d)"
fail=0

# ABI -> target triple -> 期望 ELF Machine 字样
declare -A TRIPLE=(
  [arm64-v8a]="aarch64-linux-android$API"
  [armeabi-v7a]="armv7a-linux-androideabi$API"
  [x86]="i686-linux-android$API"
  [x86_64]="x86_64-linux-android$API"
)
declare -A MACH=(
  [arm64-v8a]="AArch64"
  [armeabi-v7a]="ARM"
  [x86]="Intel 80386"
  [x86_64]="Advanced Micro Devices X86-64"
)

echo "[info] clang: $("$CLANG" --version | head -n1)"
for abi in arm64-v8a armeabi-v7a x86 x86_64; do
  so="$OUT/lib-$abi.so"
  "$CLANG" --target="${TRIPLE[$abi]}" -shared -fPIC -O2 -o "$so" "$HERE/hello.c"
  got="$("$READELF" -h "$so" | awk -F: '/Machine/{gsub(/^[ \t]+/,"",$2); print $2}')"
  if [[ "$got" == *"${MACH[$abi]}"* ]]; then
    echo "[ok]   $abi -> $got"
  else
    echo "[FAIL] $abi 期望 ${MACH[$abi]}，实得 $got"; fail=1
  fi
done
rm -rf "$OUT"
exit $fail
