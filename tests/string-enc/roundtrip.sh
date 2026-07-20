#!/usr/bin/env bash
# roundtrip.sh — 验证 -irobf-cse-perkey 的编码器（pass 编译期 C++）与解码器（发射到
# 运行期的 IR）ChaCha8/SplitMix64 逐字节一致：编译一个打印已知明文串的程序、开启
# perkey、运行、比对 stdout 必须 == 明文。若两侧算法漂移，运行期会解出乱码、测试失败。
#
# 与 check.sh 互补：check.sh 交叉编到 aarch64 只验「最终 ELF 无明文」（静态），本脚本
# 在「能本机编译并运行」的环境验运行期语义（动态镜像兜底）。包名绑定（bind）需 Android
# 运行期 /proc/self/cmdline，其语义留待设备/模拟器，故此处只测 perkey。
#
#   用法: roundtrip.sh <clang> [<额外 clang 参数...>]
#   例:   roundtrip.sh /path/to/clang                       # 默认目标即本机
#         roundtrip.sh clang.exe --target=x86_64-pc-windows-msvc
set -euo pipefail
CLANG="${1:?用法: roundtrip.sh <clang> [额外 clang 参数...]}"; shift || true
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET="NDKP_ROUNDTRIP_secret_2b7f"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT

EXE="$OUT/rt"
case "$("$CLANG" -dumpmachine 2>/dev/null || true)" in
  *windows*|*mingw*) EXE="$OUT/rt.exe" ;;
esac

"$CLANG" "$@" -O2 \
  -mllvm -irobf -mllvm -irobf-cse -mllvm -irobf-cse-perkey \
  -o "$EXE" "$DIR/roundtrip.c"

GOT="$("$EXE")"
if [ "$GOT" = "$SECRET" ]; then
  echo "[ok]   -irobf-cse-perkey 运行期解密 == 明文：$SECRET"
  exit 0
else
  echo "[FAIL] -irobf-cse-perkey 往返不符：期望 '$SECRET'，实得 '$GOT'"
  exit 1
fi
