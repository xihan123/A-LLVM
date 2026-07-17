#!/usr/bin/env bash
# check_layout.sh — 校验（重打包后的）NDK 目录结构完整、可被 Gradle/CMake 使用。
#   check_layout.sh <ndk-dir> <host>
set -euo pipefail
NDK="${1:?用法: check_layout.sh <ndk-dir> <host>}"
HOST="${2:-linux-x86_64}"
PREBUILT="$NDK/toolchains/llvm/prebuilt/$HOST"
# Windows host 的工具链二进制带 .exe 后缀
EXT=""
case "$HOST" in
  windows-*) EXT=".exe" ;;
esac
fail=0
need() { if [[ ! -e "$1" ]]; then echo "[FAIL] 缺失: $1" >&2; fail=1; else echo "[ok] $1" >&2; fi; }

need "$NDK/source.properties"
need "$NDK/build/cmake/android.toolchain.cmake"
case "$HOST" in
  windows-*) need "$NDK/ndk-build.cmd" ;;
  *)         need "$NDK/ndk-build" ;;
esac
need "$PREBUILT/bin/clang${EXT}"
need "$PREBUILT/bin/clang++${EXT}"
need "$PREBUILT/bin/ld.lld${EXT}"

# resource dir（取任一 major）
if ! ls -d "$PREBUILT"/lib/clang/*/ >/dev/null 2>&1; then
  echo "[FAIL] 缺失 clang resource dir: $PREBUILT/lib/clang/<major>/" >&2; fail=1
else
  echo "[ok] resource dir 存在" >&2
fi

# Pkg.Revision 必须保留
if grep -q '^Pkg.Revision' "$NDK/source.properties"; then
  echo "[ok] Pkg.Revision: $(grep '^Pkg.Revision' "$NDK/source.properties")" >&2
else
  echo "[FAIL] source.properties 缺少 Pkg.Revision" >&2; fail=1
fi

# 我们的标识应存在
grep -q '^Ndkp.OurTag' "$NDK/source.properties" \
  && echo "[ok] Ndkp.OurTag 存在" >&2 \
  || { echo "[FAIL] 未找到 Ndkp.OurTag（make_release_meta 未运行？）" >&2; fail=1; }
need "$NDK/NDKP-build-info.json"
need "$NDK/NDKP-patch-report.json"
need "$NDK/LICENSES/NDKP-GPL-3.0.txt"
need "$NDK/LICENSES/LLVM-UIUC.txt"
need "$NDK/LICENSES/LIBTOMCRYPT-UNLICENSE.txt"

exit $fail
