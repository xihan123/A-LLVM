#!/usr/bin/env bash
# roundtrip.sh — 证书绑定 fold 语义往返：验证 pass 构建期折入的证书混合值与运行期折入的
# 逐字节一致（两侧都用 le64(sha) 派生），且 XOR 抵消正确 —— 即「正确证书 → 正确解密」。
#
# 真实运行期读证书（apkcert.h 双源共识）需 Android APK 环境，无法在 CI host 上跑；故这里
# 用一个 stub 替换 ndkp_certbind_mix：stub 只读指定 DER 文件、按与 pass/runtime 相同的公式
# 算混合值。mix(stub)==mix(build) ⇒ 两侧折入抵消 ⇒ 输出应 == 明文（正例）。把 stub 换成
# 返回 (0,0)（模拟换签名/缺证书）⇒ 不抵消 ⇒ 输出乱码（负例，fail-closed）。
#
# 与 tests/cert-bind/run.sh 互补：run.sh 交叉编到 aarch64 只验静态（符号门控/fail-closed/
# 无明文）；本脚本在「能本机编译并运行」的环境验 fold 数学（构建↔运行期镜像）。
#
#   用法: roundtrip.sh <clang> [额外 clang 参数...]
#   例:   roundtrip.sh /path/to/clang
set -euo pipefail
CLANG="${1:?用法: roundtrip.sh <clang> [额外 clang 参数...]}"; shift || true
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
RT="$ROOT/tests/string-enc/roundtrip.c"
INC="$ROOT/runtime"
SECRET="NDKP_ROUNDTRIP_secret_2b7f"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT

command -v openssl >/dev/null 2>&1 || { echo "[skip] 无 openssl，跳过证书绑定往返"; exit 0; }
CERT="$OUT/cert.der"
# 私钥写临时文件：Windows 原生 openssl 不接受 -keyout /dev/null。
if ! openssl req -x509 -newkey rsa:2048 -keyout "$OUT/key.pem" -nodes -days 1 \
      -subj "/CN=ndkp-cert-roundtrip" -outform DER -out "$CERT" >/dev/null 2>&1 \
   || [[ ! -s "$CERT" ]]; then
  echo "[FAIL] openssl 未能生成测试证书 DER"; exit 1
fi

# stub：按与 pass（ObfuscationPassManager ensureCertMix）/ runtime（ndkp_apkcert.cpp）相同的
# le64 公式，从指定 DER 文件算证书混合值。独立转写以便交叉校验编码期公式。
cat > "$OUT/stub.cpp" <<'EOF'
#include <cstdint>
#include <cstdio>
#include "sha256.h"   // stringarmor::sha2::sha256
static uint64_t le64(const uint8_t *b) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= (uint64_t)b[i] << (8 * i);
  return v;
}
extern "C" void ndkp_certbind_mix(uint64_t *lo, uint64_t *hi) {
#ifdef NDKP_STUB_ZERO
  *lo = 0; *hi = 0;                    // 模拟换签名/缺证书 → fail-closed
#else
  FILE *f = fopen(NDKP_CERT_PATH, "rb");
  if (!f) { *lo = 0; *hi = 0; return; }
  static uint8_t buf[1 << 16];
  size_t n = fread(buf, 1, sizeof buf, f);
  fclose(f);
  uint8_t sha[32];
  stringarmor::sha2::sha256(buf, n, sha);
  *lo = le64(sha) ^ le64(sha + 16);
  *hi = le64(sha + 8) ^ le64(sha + 24);
#endif
}
EOF

EXE="$OUT/rt"; EXEB="$OUT/rtbad"
IS_WIN=0
case "$("$CLANG" -dumpmachine 2>/dev/null || true)" in
  *windows*|*mingw*) EXE="$OUT/rt.exe"; EXEB="$OUT/rtbad.exe"; IS_WIN=1 ;;
esac

# Git Bash/MSYS 不会转换「= 后」的路径；原生 Windows clang/fopen 需要 Windows 路径。
CERT_NATIVE="$CERT"
INC_NATIVE="$INC"
if [[ "$IS_WIN" -eq 1 ]] && command -v cygpath >/dev/null 2>&1; then
  CERT_NATIVE="$(cygpath -m "$CERT")"
  INC_NATIVE="$(cygpath -m "$INC")"
fi
CB_ARGS=(-mllvm -irobf -mllvm -irobf-cse -mllvm -irobf-cert-bind \
  -mllvm "-irobf-cert-file=${CERT_NATIVE}")
fail=0

# 正例：stub 返回与构建期相同的混合值 → 抵消 → 正确解密。
"$CLANG" "$@" -O2 "${CB_ARGS[@]}" -I "$INC_NATIVE" -DNDKP_CERT_PATH="\"${CERT_NATIVE}\"" \
  -o "$EXE" "$RT" "$OUT/stub.cpp"
GOT="$("$EXE")"
if [ "$GOT" = "$SECRET" ]; then
  echo "[ok]   证书匹配：运行期解密 == 明文：$SECRET"
else
  echo "[FAIL] 证书匹配却往返不符：期望 '$SECRET'，实得 '$GOT'"; fail=1
fi

# 负例：stub 返回 (0,0)（换签名/缺证书）→ 不抵消 → 应乱码（不得等于明文）。
"$CLANG" "$@" -O2 "${CB_ARGS[@]}" -I "$INC_NATIVE" -DNDKP_STUB_ZERO \
  -o "$EXEB" "$RT" "$OUT/stub.cpp"
GOTB="$("$EXEB" || true)"
if [ "$GOTB" = "$SECRET" ]; then
  echo "[FAIL] 错证书竟解出明文（fail-closed 失效）"; fail=1
else
  echo "[ok]   错/缺证书解出乱码（fail-closed 成立）"
fi

exit $fail
