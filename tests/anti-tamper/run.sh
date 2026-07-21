#!/usr/bin/env bash
# run.sh — 代码完整性自校验（-irobf-selfcheck）的静态冒烟验证。
#
# 自校验只对 VMP 产出的每函数字节码 blob（gv_code_seg_<fn>）生效：Pass 在编译期算出各
# blob 的 FNV-1a64 并内嵌，注入一个 ELF 构造器（ndkp_selfcheck_verify），加载期用 volatile
# 读重算并比对，不符即 kill。因 VMP 解释器为 aarch64 bitcode，无法在 x86_64 CI host 上
# 执行，故本脚本只做静态断言（符号存在性 + 构造器注册）；动态「篡改即 SIGKILL」在真机
# arm64-v8a 验证（见 tests/anti-tamper/README 说明与 DESIGN.md 的设备验证门）。
#
# 断言：
#   1) vmp+selfcheck 构建含 ndkp_selfcheck_verify / ndkp_selfcheck_one 符号；
#   2) vmp-only（无 -irobf-selfcheck）不含 —— 证明由开关门控；
#   3) selfcheck 但无 -irobf-vmp（无 blob）不含 —— 证明「自校验依赖 VMP」no-op 语义；
#   4) vmp+selfcheck 构建含 .init_array —— 证明构造器已注册（.so 无 main 也生效）。
#
# 用法：run.sh <ndk-dir> <host>
set -euo pipefail
NDK="${1:?用法: run.sh <ndk-dir> <host>}"
HOST="${2:-linux-x86_64}"
EXT=""; case "$HOST" in windows-*) EXT=".exe" ;; esac
BIN="$NDK/toolchains/llvm/prebuilt/$HOST/bin"
CLANG="$BIN/clang${EXT}"
NM="$BIN/llvm-nm${EXT}"
READELF="$BIN/llvm-readelf${EXT}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../abi-smoke" && pwd)/hello.c"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
fail=0

TGT="--target=aarch64-linux-android21 -shared -fPIC -O2"
VMP="-mllvm -irobf -mllvm -irobf-vmp -mllvm -irobf-vm_functions=ndkp_secret_len"
SELF="-mllvm -irobf-selfcheck"

"$CLANG" $TGT $VMP $SELF -o "$OUT/vmp_self.so"     "$SRC"
"$CLANG" $TGT $VMP       -o "$OUT/vmp_only.so"     "$SRC"
"$CLANG" $TGT -mllvm -irobf $SELF -o "$OUT/self_novmp.so" "$SRC"

has_sym() { "$NM" "$1" 2>/dev/null | grep -q "$2"; }

# 1) vmp+selfcheck 含自校验符号
if has_sym "$OUT/vmp_self.so" ndkp_selfcheck_verify && \
   has_sym "$OUT/vmp_self.so" ndkp_selfcheck_one; then
  echo "[ok]   vmp+selfcheck 含 ndkp_selfcheck_verify / ndkp_selfcheck_one"
else
  echo "[FAIL] vmp+selfcheck 缺自校验符号"; fail=1
fi

# 2) vmp-only 不含（开关门控）
if has_sym "$OUT/vmp_only.so" ndkp_selfcheck_verify; then
  echo "[FAIL] vmp-only 竟含 ndkp_selfcheck_verify（未受 -irobf-selfcheck 门控）"; fail=1
else
  echo "[ok]   vmp-only 无自校验符号（由 -irobf-selfcheck 门控）"
fi

# 3) selfcheck 但无 vmp（无 blob）不含（no-op 语义）
if has_sym "$OUT/self_novmp.so" ndkp_selfcheck_verify; then
  echo "[FAIL] selfcheck-无-vmp 竟含 ndkp_selfcheck_verify（应因无 blob 而 no-op）"; fail=1
else
  echo "[ok]   selfcheck-无-vmp 无自校验符号（无 blob → no-op，自校验依赖 VMP）"
fi

# 4) 构造器已注册：.init_array 存在（.so 无 main 亦生效）
if "$READELF" -S "$OUT/vmp_self.so" | grep -q '\.init_array'; then
  echo "[ok]   vmp+selfcheck 含 .init_array（构造器已注册，加载期即校验）"
else
  echo "[FAIL] vmp+selfcheck 缺 .init_array（构造器未注册）"; fail=1
fi

echo "[note] 动态「篡改字节码 → SIGKILL」在真机 arm64-v8a 验证（见 DESIGN.md 设备验证门）"
exit $fail
