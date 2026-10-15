#!/usr/bin/env bash
set -euo pipefail
CLANG="${1:?usage: roundtrip.sh <clang> [target flags...]}"; shift
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
cat > "$OUT/constants.c" <<'EOF'
#include <stdint.h>
uint64_t integer(uint64_t x) { return x * UINT64_C(0x123456789abcdef) + 37; }
double floating(double x) { return x * 1.5 - 2.25; }
EOF
cat > "$OUT/check.c" <<'EOF'
#include <stdint.h>
uint64_t integer(uint64_t);
double floating(double);
int main(void) {
  for (int i = -100; i <= 100; ++i) {
    uint64_t x = (uint64_t)i;
    if (integer(x) != x * UINT64_C(0x123456789abcdef) + 37) return 1;
    if (floating(i) != i * 1.5 - 2.25) return 2;
  }
  return 0;
}
EOF
EXE="$OUT/check"
case "$("$CLANG" "$@" -dumpmachine)" in *windows*|*mingw*) EXE+=.exe ;; esac
"$CLANG" "$@" -O2 -c "$OUT/check.c" -o "$OUT/check.o"
for opt in O0 O2 Oz; do
  for level in 1 2 3; do
    "$CLANG" "$@" "-$opt" -mllvm -irobf-cie -mllvm "-level-cie=$level" \
      -mllvm -irobf-cfe -mllvm "-level-cfe=$level" -c "$OUT/constants.c" -o "$OUT/constants.o"
    "$CLANG" "$@" "$OUT/check.o" "$OUT/constants.o" -o "$EXE"
    "$EXE"
    echo "[ok] $opt/level=$level: integer and floating-point semantics"
  done
done
