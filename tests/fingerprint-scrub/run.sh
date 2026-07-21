#!/usr/bin/env bash
# run.sh — 验证 release 模式（未开 -irobf-debug，默认）去指纹：
#   1) VMP 解释器调试串（vm-entry / [vm-debug]…）在最终 ELF 中消失；开 -irobf-debug 时保留。
#   2) 自曝段名 .AProtect.* 改名为 .s0/.s1/.s2/.s3（保留段标志）；开 -irobf-debug 时保留原名。
# 用法：run.sh <ndk-dir> <host>
set -euo pipefail
NDK="${1:?用法: run.sh <ndk-dir> <host>}"
HOST="${2:-linux-x86_64}"
EXT=""; case "$HOST" in windows-*) EXT=".exe" ;; esac
BIN="$NDK/toolchains/llvm/prebuilt/$HOST/bin"
CLANG="$BIN/clang${EXT}"
STRINGS="$BIN/llvm-strings${EXT}"
READELF="$BIN/llvm-readelf${EXT}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../abi-smoke" && pwd)/hello.c"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
fail=0

TGT="--target=aarch64-linux-android21 -shared -fPIC -O2"
VMP="-mllvm -irobf -mllvm -irobf-vmp -mllvm -irobf-vm_functions=ndkp_secret_len"
NEEDLE='vm-entry|\[vm-debug'

# ---- 1) VMP 调试串：必须 VMP-only（不加 -irobf-cse）----
# 若同时开 -irobf-cse，字符串加密会把这些调试串一并加密 → release/debug 都测不到明文，
# 掩盖“去指纹是否生效”。故此项单独用 VMP-only 构建。
"$CLANG" $TGT $VMP                     -o "$OUT/vmp_rel.so" "$SRC"
"$CLANG" $TGT $VMP -mllvm -irobf-debug -o "$OUT/vmp_dbg.so" "$SRC"
n_rel=$("$STRINGS" "$OUT/vmp_rel.so" | grep -Ec "$NEEDLE" || true)
n_dbg=$("$STRINGS" "$OUT/vmp_dbg.so" | grep -Ec "$NEEDLE" || true)
if [ "$n_rel" -eq 0 ]; then echo "[ok]   release .so 无 VMP 调试串"; else echo "[FAIL] release .so 仍含 $n_rel 条 VMP 调试串"; fail=1; fi
if [ "$n_dbg" -gt 0 ]; then echo "[ok]   -irobf-debug .so 保留 $n_dbg 条 VMP 调试串（去指纹确为门控）"; else echo "[FAIL] -irobf-debug .so 未见 VMP 调试串，去指纹疑似无条件/失效"; fail=1; fi

# ---- 2) 段名改名：VMP+CSE 覆盖四类段（.text/.data/.bss 来自 VMP，.rodata 来自 CSE）----
FULL="$VMP -mllvm -irobf-cse"
"$CLANG" $TGT $FULL                     -o "$OUT/full_rel.so" "$SRC"
"$CLANG" $TGT $FULL -mllvm -irobf-debug -o "$OUT/full_dbg.so" "$SRC"
REL_SECS="$("$READELF" -S "$OUT/full_rel.so")"
DBG_SECS="$("$READELF" -S "$OUT/full_dbg.so")"

rel_ap=$(echo "$REL_SECS" | grep -c '\.AProtect\.' || true)
rel_sN=$(echo "$REL_SECS" | grep -Eoc '\.s[0-3]\b' || true)
dbg_ap=$(echo "$DBG_SECS" | grep -c '\.AProtect\.' || true)
if [ "$rel_ap" -eq 0 ]; then echo "[ok]   release .so 无 .AProtect.* 段名"; else echo "[FAIL] release .so 仍含 .AProtect.* 段名"; fail=1; fi
if [ "$rel_sN" -gt 0 ]; then echo "[ok]   release .so 含 $rel_sN 个改名段 .sN"; else echo "[FAIL] release .so 缺改名段 .sN"; fail=1; fi
if [ "$dbg_ap" -gt 0 ]; then echo "[ok]   -irobf-debug .so 保留 .AProtect.* 段名"; else echo "[FAIL] -irobf-debug .so 未见 .AProtect.* 段名"; fail=1; fi
# 段标志按符号种类推导、改名后不变：.s0（=.AProtect.text）应为可执行代码段 AX。
if echo "$REL_SECS" | grep -E '[[:space:]]\.s0([[:space:]]|$)' | grep -q 'AX'; then
  echo "[ok]   .s0 标志含 AX（代码段，标志随符号种类保留）"
else
  echo "[FAIL] .s0 标志非 AX"; fail=1
fi

# ---- 3) .comment 提示（非失败项）----
# 编译期只剥除本模块 llvm.ident；最终 .so 的 .comment 仍含 NDK CRT/libc++/lld 贡献，
# 且与官方 clang 同版本（非唯一指纹）。彻底清零需 link 后：llvm-strip -R .comment <输出.so>
echo "[note] .comment 彻底清零需 link 后 'llvm-strip -R .comment'（见 obfuscation/README.md）"

exit $fail
