#!/usr/bin/env bash
# run.sh — APK 签名证书绑定（-irobf-cert-bind）的静态冒烟验证。
#
# 证书绑定把"运行期 APK 签名证书 SHA-256 派生的混合值"折进 CSE 字符串 pepper 与 VMP 函数
# 密钥；运行期证书读取由 app 侧链接 runtime/ndkp_apkcert.cpp 提供（定义 ndkp_certbind_mix）。
# NDK clang -shared 默认 -Wl,--no-undefined，故开 -irobf-cert-bind 的构建必须一起编入该
# helper，否则链接期 undefined symbol: ndkp_certbind_mix —— 本测试即按真实集成方式链接它。
#
# 因运行期读证书 / VMP 解释器需真机 arm64 APK 环境，本脚本只做静态断言（符号存在性 + 构造
# 器注册 + 明文不泄漏 + 构建期 fail-closed）；动态「换签名 → 乱码 / rc=137」在真机验证
# （见 DESIGN.md 设备验证门）。
#
# 断言：
#   1) cse+cert-bind 构建含注入的运行期基座符号 ndkp_certbind_init / ndkp_cert_lo；
#   2) cse-only（无 -irobf-cert-bind）不含 —— 证明由开关门控；
#   3) cse+cert-bind 构建含 .init_array —— 证明加载期构造器已注册；
#   4) cse+cert-bind 后敏感明文已从 ELF 消失；
#   5) vmp+cert-bind 构建含 ndkp_certbind_init —— 证明 VMP 密钥折入路径也建了基座；
#   6) -irobf-cert-bind 但缺 -irobf-cert-file ⇒ 构建 fail-closed（clang 非零退出）。
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
STRINGS="$BIN/llvm-strings${EXT}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT/tests/abi-smoke/hello.c"
HELPER="$ROOT/runtime/ndkp_apkcert.cpp"
INC="$ROOT/runtime"
NEEDLE="NDKP_SECRET_STRING_do_not_leak"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
fail=0

TGT="--target=aarch64-linux-android21 -shared -fPIC -O2"

# 构建期期望证书：临时自签证书的 DER（内容无所谓，只需是 32B-SHA-256 得出的稳定 DER）。
# 无 openssl 则跳过（CI host 一般都有）。
CERT="$OUT/cert.der"
if ! command -v openssl >/dev/null 2>&1; then
  echo "[skip] 未找到 openssl，无法生成测试证书 DER，跳过证书绑定测试"; exit 0
fi
# 私钥写到临时文件：Windows 原生 openssl 不接受 -keyout /dev/null。
if ! openssl req -x509 -newkey rsa:2048 -keyout "$OUT/key.pem" -nodes -days 1 \
      -subj "/CN=ndkp-cert-bind-test" -outform DER -out "$CERT" >/dev/null 2>&1 \
   || [[ ! -s "$CERT" ]]; then
  echo "[FAIL] openssl 未能生成测试证书 DER"; exit 1
fi

# Git Bash/MSYS 不会转换「= 后」的路径；传给原生 clang.exe 时需 Windows 路径。
# -I 也拆成独立参数，让 MSYS 自动转换 include 目录（-I/path 整段不会被转换）。
CERT_FOR_CLANG="$CERT"
INC_FOR_CLANG="$INC"
case "$HOST" in
  windows-*)
    if command -v cygpath >/dev/null 2>&1; then
      CERT_FOR_CLANG="$(cygpath -m "$CERT")"
      INC_FOR_CLANG="$(cygpath -m "$INC")"
    fi
    ;;
esac
# 单独引住 -irobf-cert-file=…，避免路径含空格时被词法拆开。
CERTBIND_ARGS=(-mllvm -irobf-cert-bind -mllvm "-irobf-cert-file=${CERT_FOR_CLANG}")

# 编入 helper（提供 ndkp_certbind_mix）以满足 --no-undefined，即真实集成方式。
"$CLANG" $TGT -mllvm -irobf -mllvm -irobf-cse "${CERTBIND_ARGS[@]}" -I "$INC_FOR_CLANG" \
  -o "$OUT/cse_cert.so" "$SRC" "$HELPER"
# cse-only 无需 helper（不引用 ndkp_certbind_mix）。
"$CLANG" $TGT -mllvm -irobf -mllvm -irobf-cse \
  -o "$OUT/cse_only.so" "$SRC"
# vmp + cert-bind：VMP 密钥折入路径亦应建运行期基座。
"$CLANG" $TGT -mllvm -irobf -mllvm -irobf-vmp \
  -mllvm -irobf-vm_functions=ndkp_secret_len "${CERTBIND_ARGS[@]}" -I "$INC_FOR_CLANG" \
  -o "$OUT/vmp_cert.so" "$SRC" "$HELPER"

has_sym() { "$NM" "$1" 2>/dev/null | grep -q "$2"; }

# 1) cse+cert-bind 含注入的运行期基座符号
if has_sym "$OUT/cse_cert.so" ndkp_certbind_init && \
   has_sym "$OUT/cse_cert.so" ndkp_cert_lo; then
  echo "[ok]   cse+cert-bind 含 ndkp_certbind_init / ndkp_cert_lo"
else
  echo "[FAIL] cse+cert-bind 缺证书绑定运行期基座符号"; fail=1
fi

# 2) cse-only 不含（开关门控）
if has_sym "$OUT/cse_only.so" ndkp_certbind_init; then
  echo "[FAIL] cse-only 竟含 ndkp_certbind_init（未受 -irobf-cert-bind 门控）"; fail=1
else
  echo "[ok]   cse-only 无证书绑定符号（由 -irobf-cert-bind 门控）"
fi

# 3) 构造器已注册：.init_array 存在
if "$READELF" -S "$OUT/cse_cert.so" | grep -q '\.init_array'; then
  echo "[ok]   cse+cert-bind 含 .init_array（加载期构造器已注册）"
else
  echo "[FAIL] cse+cert-bind 缺 .init_array（构造器未注册）"; fail=1
fi

# 4) 明文不泄漏
if "$STRINGS" "$OUT/cse_cert.so" | grep -q "$NEEDLE"; then
  echo "[FAIL] cse+cert-bind 后仍能在 ELF 中找到明文"; fail=1
else
  echo "[ok]   cse+cert-bind 后明文已消失"
fi

# 5) vmp+cert-bind 亦建基座
if has_sym "$OUT/vmp_cert.so" ndkp_certbind_init; then
  echo "[ok]   vmp+cert-bind 含 ndkp_certbind_init（VMP 密钥折入路径已建基座）"
else
  echo "[FAIL] vmp+cert-bind 缺 ndkp_certbind_init"; fail=1
fi

# 6) 缺 -irobf-cert-file ⇒ 构建 fail-closed（预期 clang 非零退出）
if "$CLANG" $TGT -mllvm -irobf -mllvm -irobf-cse -mllvm -irobf-cert-bind -I "$INC_FOR_CLANG" \
     -o "$OUT/nofile.so" "$SRC" "$HELPER" >/dev/null 2>&1; then
  echo "[FAIL] -irobf-cert-bind 缺 -irobf-cert-file 竟构建成功（应 fail-closed）"; fail=1
else
  echo "[ok]   -irobf-cert-bind 缺 -irobf-cert-file 构建失败（fail-closed）"
fi

echo "[note] 动态「换签名 → 字符串/VMP 乱码」在真机 arm64-v8a 验证（见 DESIGN.md 设备验证门）"
exit $fail
