#!/usr/bin/env bash
#
# gen_vm_bitcode.sh — 生成 VMP 解释器 bitcode 头 vm.h（按 ABI）。
#
# 维护者工具，非发布路径：用一个能交叉出 LLVM bitcode 的 clang（如官方 NDK 的
# clang）把 obfuscation/aVMPInterpreter/aVMPInterpreter.cpp 编成目标 ABI 的 .bc，
# 再转成上游同格式的字节数组头（binary_ir_length + binary_ir_data[]），覆盖写入
# 两个 overlay 的 include/aVMP/vm.h。
#
# 用法: scripts/gen_vm_bitcode.sh <clang> [abi_tag]
#   <clang>   交叉编译器（须支持 --target=<triple> -emit-llvm）
#   abi_tag   aarch64|arm|x86|x86_64（默认 aarch64；垂直切片只需 aarch64）
#
set -euo pipefail

CLANG="${1:?usage: gen_vm_bitcode.sh <clang> [abi_tag]}"
ABI="${2:-aarch64}"
here="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$here/obfuscation/aVMPInterpreter/aVMPInterpreter.cpp"

case "$ABI" in
  aarch64) TRIPLE=aarch64-linux-android21 ;;
  arm)     TRIPLE=armv7a-linux-androideabi21 ;;
  x86)     TRIPLE=i686-linux-android21 ;;
  x86_64)  TRIPLE=x86_64-linux-android21 ;;
  *) echo "unknown abi: $ABI (want aarch64|arm|x86|x86_64)" >&2; exit 2 ;;
esac

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# 解释器自身实现 Itanium 异常模型（含 try/catch），必须用 -fexceptions 编译；
# -fno-exceptions 只针对被虚拟化的用户代码，不适用于解释器本体。
"$CLANG" --target="$TRIPLE" -frtti -fexceptions -O2 -fno-inline \
  -emit-llvm -c "$SRC" -o "$tmp/vm.bc"

len=$(wc -c < "$tmp/vm.bc")
out="$tmp/vm.h"
{
  echo '#include <string>'
  echo '#include <vector>'
  echo
  echo "static const int binary_ir_length = $len;"
  echo 'static const char binary_ir_data[] ='
  od -An -v -tx1 "$tmp/vm.bc" | awk 'NF{printf "\""; for(i=1;i<=NF;i++)printf "\\x%s",$i; printf "\"\n"}'
  echo ';'
  echo
  echo 'static std::vector<char> get_binary_ir() {'
  echo '    return std::vector<char>(binary_ir_data, binary_ir_data + binary_ir_length);'
  echo '}'
} > "$out"

for major in 20 21; do
  cp -f "$out" "$here/obfuscation/llvm-$major/include/aVMP/vm.h"
done
echo "wrote vm.h ($len bytes bitcode, $ABI / $TRIPLE) into both overlays"
