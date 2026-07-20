#!/usr/bin/env bash
# check.sh — 验证开启 -irobf-cse 后，敏感明文不出现在最终 ELF 中。阶段 1c 由 build.yml 调用。
#   check.sh <ndk-dir> <host>
set -euo pipefail
NDK="${1:?用法: check.sh <ndk-dir> <host>}"
HOST="${2:-linux-x86_64}"
EXT=""; case "$HOST" in windows-*) EXT=".exe" ;; esac
CLANG="$NDK/toolchains/llvm/prebuilt/$HOST/bin/clang${EXT}"
STRINGS="$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-strings${EXT}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../abi-smoke" && pwd)/hello.c"
NEEDLE="NDKP_SECRET_STRING_do_not_leak"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
fail=0

for opt in O0 O2 Oz; do
  # 基线：不加开关，明文应存在（确认各优化级别样本有效）
  "$CLANG" --target=aarch64-linux-android21 -shared -fPIC "-$opt" \
    -o "$OUT/plain-$opt.so" "$SRC"
  if "$STRINGS" "$OUT/plain-$opt.so" | grep -q "$NEEDLE"; then
    echo "[ok]   -$opt 基线含明文（样本有效）"
  else
    echo "[FAIL] -$opt 基线未见明文，测试样本无效"; fail=1
  fi

  # 开启字符串加密，明文应消失
  "$CLANG" --target=aarch64-linux-android21 -shared -fPIC "-$opt" \
    -mllvm -irobf -mllvm -irobf-cse -o "$OUT/enc-$opt.so" "$SRC"
  if "$STRINGS" "$OUT/enc-$opt.so" | grep -q "$NEEDLE"; then
    echo "[FAIL] -$opt 开启 -irobf-cse 后仍能在 ELF 中找到明文"; fail=1
  else
    echo "[ok]   -$opt 开启 -irobf-cse 后明文已消失"
  fi

  # 强化1：per-string ChaCha8 派生密钥（-irobf-cse-perkey，密钥不内联），明文应消失
  "$CLANG" --target=aarch64-linux-android21 -shared -fPIC "-$opt" \
    -mllvm -irobf -mllvm -irobf-cse -mllvm -irobf-cse-perkey \
    -o "$OUT/perkey-$opt.so" "$SRC"
  if "$STRINGS" "$OUT/perkey-$opt.so" | grep -q "$NEEDLE"; then
    echo "[FAIL] -$opt 开启 -irobf-cse-perkey 后仍能在 ELF 中找到明文"; fail=1
  else
    echo "[ok]   -$opt 开启 -irobf-cse-perkey 后明文已消失"
  fi

  # 强化2：包名绑定（-irobf-cse-bind），构建应成功且明文应消失
  "$CLANG" --target=aarch64-linux-android21 -shared -fPIC "-$opt" \
    -mllvm -irobf -mllvm -irobf-cse -mllvm -irobf-cse-bind \
    -mllvm -irobf-cse-bind-package=com.ndkp.test \
    -o "$OUT/bind-$opt.so" "$SRC"
  if "$STRINGS" "$OUT/bind-$opt.so" | grep -q "$NEEDLE"; then
    echo "[FAIL] -$opt 开启 -irobf-cse-bind 后仍能在 ELF 中找到明文"; fail=1
  else
    echo "[ok]   -$opt 开启 -irobf-cse-bind 后明文已消失"
  fi
done

exit $fail
