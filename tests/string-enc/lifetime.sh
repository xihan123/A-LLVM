#!/usr/bin/env bash
# Native host semantic checks; the unmodified driver retains and checks pointers.
set -euo pipefail
CLANG="${1:?usage: lifetime.sh <clang> [target flags...]}"; shift
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
THREAD_FLAGS=()
case "$("$CLANG" "$@" -dumpmachine)" in
  *windows*|*mingw*) EXE="$OUT/test.exe" ;;
  *) EXE="$OUT/test"; THREAD_FLAGS=(-pthread) ;;
esac
"$CLANG" "$@" -O2 "${THREAD_FLAGS[@]}" -c "$DIR/lifetime_driver.c" -o "$OUT/driver.o"
for opt in O0 O2 Oz; do
  for mode in plain cse perkey; do
    FLAGS=()
    if [[ "$mode" != plain ]]; then FLAGS=(-mllvm -irobf-cse); fi
    if [[ "$mode" == perkey ]]; then FLAGS+=(-mllvm -irobf-cse-perkey); fi
    "$CLANG" "$@" "-$opt" "${FLAGS[@]}" -c "$DIR/lifetime.c" -o "$OUT/fixture.o"
    "$CLANG" "$@" "${THREAD_FLAGS[@]}" "$OUT/driver.o" "$OUT/fixture.o" -o "$EXE"
    for attempt in 1 2 3; do "$EXE"; done
    echo "[ok] $opt/$mode: escaped strings, shared identity, aggregate initialization, 16 threads"
  done
done
