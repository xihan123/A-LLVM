#!/usr/bin/env bash
# overlay_ndk.sh — 用自建的 clang/lld 二进制，按白名单覆盖官方 NDK 的工具链 bin/。
#
#   overlay_ndk.sh --built <ninja build 根> --ndk <NDK 根> --host <host> --major <N> [--dry-run]
#
# 只替换 bin/ 下白名单内的可执行文件，保留官方 sysroot / 平台头 / libc++ /
# 各 ABI 的 compiler-rt runtime（仅当 LLVM major 一致时安全，调用方须校验）。
# 覆盖前把原文件打包备份到 <prebuilt>/bin.orig.tar。
set -euo pipefail

BUILT=""; NDK=""; HOST="linux-x86_64"; MAJOR=""; DRYRUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --built) BUILT="$2"; shift 2 ;;
    --ndk)   NDK="$2"; shift 2 ;;
    --host)  HOST="$2"; shift 2 ;;
    --major) MAJOR="$2"; shift 2 ;;
    --dry-run) DRYRUN=1; shift ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done
[[ -n "$BUILT" && -n "$NDK" && -n "$MAJOR" ]] || { echo "用法见脚本头注释" >&2; exit 2; }

SRC_BIN="$BUILT/bin"
DST_PREBUILT="$NDK/toolchains/llvm/prebuilt/$HOST"
DST_BIN="$DST_PREBUILT/bin"
[[ -d "$SRC_BIN" ]] || { echo "[error] 自建 bin 不存在：$SRC_BIN" >&2; exit 1; }
[[ -d "$DST_BIN" ]] || { echo "[error] NDK bin 不存在：$DST_BIN" >&2; exit 1; }

# 白名单：随混淆 pass 一起构建、会影响产物的宿主工具。
# Windows host 的 NDK 与自建产物二进制带 .exe 后缀，按 host 追加。
EXT=""
case "$HOST" in
  windows-*) EXT=".exe" ;;
esac
ALLOW=(
  "clang${EXT}" "clang++${EXT}" "clang-${MAJOR}${EXT}" "clang-cpp${EXT}"
  "lld${EXT}" "ld.lld${EXT}" "ld64.lld${EXT}" "lld-link${EXT}" "wasm-ld${EXT}"
  "llvm-strip${EXT}" "llvm-objcopy${EXT}"
)

echo "[info] overlay: $SRC_BIN -> $DST_BIN (host=$HOST major=$MAJOR dry_run=$DRYRUN)" >&2

# 备份原始 bin 白名单（首次）
BACKUP="$DST_PREBUILT/bin.orig.tar"
if [[ $DRYRUN -eq 0 && ! -f "$BACKUP" ]]; then
  ( cd "$DST_BIN" && tar cf "$BACKUP" $(for f in "${ALLOW[@]}"; do [[ -e "$f" || -L "$f" ]] && echo "$f"; done) 2>/dev/null ) || true
  echo "[ok] 已备份原始 bin 白名单 -> $BACKUP" >&2
fi

copied=0
for name in "${ALLOW[@]}"; do
  if [[ -e "$SRC_BIN/$name" || -L "$SRC_BIN/$name" ]]; then
    if [[ $DRYRUN -eq 1 ]]; then
      echo "[dry]  会覆盖 $name" >&2
    else
      rm -f "$DST_BIN/$name"
      cp -a "$SRC_BIN/$name" "$DST_BIN/$name"   # 保留符号链接结构
      echo "[ok]   覆盖 $name" >&2
    fi
    copied=$((copied+1))
  fi
done
echo "[info] 命中 $copied 个白名单文件" >&2

# 资源目录 include（内置头随 clang 版本变化时更新；runtime 库保留官方）
SRC_RES="$BUILT/lib/clang/$MAJOR/include"
DST_RES="$DST_PREBUILT/lib/clang/$MAJOR/include"
if [[ -d "$SRC_RES" && -d "$DST_RES" && $DRYRUN -eq 0 ]]; then
  cp -a "$SRC_RES/." "$DST_RES/"
  echo "[ok] 更新 resource include" >&2
fi

if [[ $DRYRUN -eq 0 ]]; then
  echo "[verify] $("$DST_BIN/clang${EXT}" --version | head -n1)" >&2
fi
echo "[done] NDK 覆盖完成" >&2
