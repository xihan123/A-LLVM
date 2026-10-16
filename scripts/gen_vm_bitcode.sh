#!/usr/bin/env bash
# 将解释器编译为 bitcode，写入所选 LLVM overlay 的 vm.h。
# 用法: scripts/gen_vm_bitcode.sh <clang> [abi_tag] [20|21|all]
# clang 需配置 Android sysroot；ABI 默认 aarch64，支持 arm、x86、x86_64。
set -euo pipefail

CLANG="${1:?usage: gen_vm_bitcode.sh <clang> [abi_tag] [20|21|all]}"
ABI="${2:-aarch64}"
MAJOR="${3:-all}"
here="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$here/obfuscation/aVMPInterpreter/aVMPInterpreter.cpp"

case "$MAJOR" in
  all) majors=(20 21) ;;
  20|21) majors=("$MAJOR") ;;
  *) echo "unknown overlay: $MAJOR (want 20|21|all)" >&2; exit 2 ;;
esac
# 新 LLVM 生成的属性可能无法被旧 bitcode reader 读取。
producer=$("$CLANG" -dumpversion)
producer=${producer%%.*}
[[ "$producer" =~ ^[0-9]+$ ]] || { echo "cannot determine clang major" >&2; exit 2; }
for major in "${majors[@]}"; do
  if (( producer > major )); then
    echo "LLVM $producer bitcode cannot target LLVM $major; use an older clang or select one overlay" >&2
    exit 2
  fi
done

case "$ABI" in
  aarch64) TRIPLE=aarch64-linux-android21 ;;
  arm)     TRIPLE=armv7a-linux-androideabi21 ;;
  x86)     TRIPLE=i686-linux-android21 ;;
  x86_64)  TRIPLE=x86_64-linux-android21 ;;
  *) echo "unknown abi: $ABI (want aarch64|arm|x86|x86_64)" >&2; exit 2 ;;
esac

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# 解释器包含 try/catch，需要保留异常支持。
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

for major in "${majors[@]}"; do
  cp -f "$out" "$here/obfuscation/llvm-$major/include/aVMP/vm.h"
done
echo "wrote vm.h ($len bytes bitcode, $ABI / $TRIPLE) into overlays: ${majors[*]}"
