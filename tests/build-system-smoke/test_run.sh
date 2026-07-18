#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

WORK="$TMP/work dir"
FAKE_BIN="$TMP/bin"
FAKE_NDK="$WORK/fake-ndk"
CMAKE_CALLS="$TMP/cmake-calls"
NDK_BUILD_CALLS="$TMP/ndk-build-calls"
mkdir -p "$FAKE_BIN" "$FAKE_NDK/build/cmake"
: > "$FAKE_NDK/build/cmake/android.toolchain.cmake"

cat > "$FAKE_BIN/cmake" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "$CMAKE_CALLS"
EOF
chmod +x "$FAKE_BIN/cmake"

cat > "$FAKE_NDK/ndk-build" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$NDK_BUILD_CALLS"
EOF
chmod +x "$FAKE_NDK/ndk-build"

(
  cd "$WORK"
  PATH="$FAKE_BIN:$PATH" \
    CMAKE_CALLS="$CMAKE_CALLS" \
    NDK_BUILD_CALLS="$NDK_BUILD_CALLS" \
    bash "$ROOT/tests/build-system-smoke/run.sh" ./fake-ndk linux-x86_64
)

EXPECTED_NDK="$(cd "$FAKE_NDK" && pwd -P)"
grep -Fx -- "-DCMAKE_TOOLCHAIN_FILE=$EXPECTED_NDK/build/cmake/android.toolchain.cmake" "$CMAKE_CALLS"
grep -Fx -- "-DANDROID_NDK=$EXPECTED_NDK" "$CMAKE_CALLS"
test -s "$NDK_BUILD_CALLS"

: > "$CMAKE_CALLS"
if (
  cd "$WORK"
  PATH="$FAKE_BIN:$PATH" CMAKE_CALLS="$CMAKE_CALLS" \
    bash "$ROOT/tests/build-system-smoke/run.sh" ./missing-ndk linux-x86_64
) >/dev/null 2>&1; then
  echo "run.sh unexpectedly accepted a missing NDK directory" >&2
  exit 1
fi
test ! -s "$CMAKE_CALLS"

echo "[ok] build-system smoke runner resolves and validates the NDK path"
