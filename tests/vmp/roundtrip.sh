#!/usr/bin/env bash
# Build an arm64 semantic test; optionally execute it on the specified adb device.
set -euo pipefail
NDK="${1:?usage: roundtrip.sh <ndk> <host> [adb serial]}"
HOST="${2:?host required}"
SERIAL="${3:-}"
EXT=""; case "$HOST" in windows-*) EXT=.exe ;; esac
CLANG="$NDK/toolchains/llvm/prebuilt/$HOST/bin/clang$EXT"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(mktemp -d)"
REMOTE="/data/local/tmp/ndkp-vmp-$(basename "$OUT")"
cleanup() {
  rm -rf "$OUT"
  if [[ -n "$SERIAL" ]]; then
    MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell rm -f "$REMOTE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
COMMON=(--target=aarch64-linux-android21 -O2 -fno-vectorize -fno-slp-vectorize)
"$CLANG" "${COMMON[@]}" -DREFERENCE -c "$DIR/concurrent.c" -o "$OUT/reference.o"
"$CLANG" "${COMMON[@]}" -c "$DIR/concurrent_driver.c" -o "$OUT/driver.o"
for mode in plain vmp selfcheck; do
  FLAGS=()
  if [[ "$mode" != plain ]]; then
    FLAGS=(-mllvm -irobf-vmp -mllvm '-irobf-vm_functions=compute;recurse;callback_roundtrip')
  fi
  if [[ "$mode" == selfcheck ]]; then FLAGS+=(-mllvm -irobf-selfcheck); fi
  "$CLANG" "${COMMON[@]}" "${FLAGS[@]}" -c "$DIR/concurrent.c" -o "$OUT/vmp.o"
  # The interpreter calls libc++ exception helpers even when the input is C.
  "$CLANG" --driver-mode=g++ -static-libstdc++ "${COMMON[@]}" \
    "$OUT/driver.o" "$OUT/reference.o" "$OUT/vmp.o" -o "$OUT/test"
  if [[ -n "$SERIAL" ]]; then
    LOCAL_EXE="$OUT/test"
    if command -v cygpath >/dev/null 2>&1; then LOCAL_EXE="$(cygpath -m "$LOCAL_EXE")"; fi
    MSYS_NO_PATHCONV=1 adb -s "$SERIAL" push "$LOCAL_EXE" "$REMOTE" >/dev/null
    MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell chmod 700 "$REMOTE"
    MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell timeout 120 "$REMOTE"
    echo "[ok] $mode: eight threads, recursion, VM/native/VM callbacks"
  else
    echo "[ok] $mode: arm64 compile/link (device execution requires adb serial)"
  fi
done
