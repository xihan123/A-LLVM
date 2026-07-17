#!/usr/bin/env bash
# apply_overlay.sh — 把按 LLVM major 适配的混淆 overlay 叠加到 llvm-project 源码树。
#
#   apply_overlay.sh --llvm-src <llvm-project 根> --major <N> [--repo-root <repo>]
#
# obfuscation/llvm-<N>/ 存在时：
#   - 将 Transforms/Obfuscation/ 拷入 llvm/lib/Transforms/Obfuscation/
#   - 将 include/ 拷入 llvm/include/llvm/Transforms/Obfuscation/（若提供）
#   - 应用 registration.patch（注册到 PassBuilderPipelines / CMakeLists / Options.td / AArch64）
# 不存在时：视为「无混淆的原样构建」（阶段 1a/1b），直接跳过并返回 0。
set -euo pipefail

LLVM_SRC=""
MAJOR=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --llvm-src) LLVM_SRC="$2"; shift 2 ;;
    --major)    MAJOR="$2"; shift 2 ;;
    --repo-root) REPO_ROOT="$2"; shift 2 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

[[ -n "$LLVM_SRC" && -n "$MAJOR" ]] || { echo "用法：apply_overlay.sh --llvm-src <dir> --major <N>" >&2; exit 2; }
[[ -d "$LLVM_SRC/llvm" ]] || { echo "[error] 不是 llvm-project 源码树：$LLVM_SRC" >&2; exit 1; }

OVERLAY="$REPO_ROOT/obfuscation/llvm-$MAJOR"
if [[ ! -d "$OVERLAY" ]]; then
  echo "[info] 未找到 overlay：$OVERLAY —— 按无混淆原样构建。" >&2
  exit 0
fi

echo "[info] 应用混淆 overlay：$OVERLAY -> $LLVM_SRC" >&2

if [[ -d "$OVERLAY/Transforms/Obfuscation" ]]; then
  mkdir -p "$LLVM_SRC/llvm/lib/Transforms/Obfuscation"
  cp -a "$OVERLAY/Transforms/Obfuscation/." "$LLVM_SRC/llvm/lib/Transforms/Obfuscation/"
  echo "[ok] 拷贝 Obfuscation 源文件" >&2
fi
if [[ -d "$OVERLAY/include" ]]; then
  mkdir -p "$LLVM_SRC/llvm/include/llvm/Transforms/Obfuscation"
  cp -a "$OVERLAY/include/." "$LLVM_SRC/llvm/include/llvm/Transforms/Obfuscation/"
  echo "[ok] 拷贝 Obfuscation 头文件" >&2
fi

if [[ -f "$OVERLAY/registration.patch" ]]; then
  echo "[info] 应用 registration.patch" >&2
  git -C "$LLVM_SRC" apply --check "$OVERLAY/registration.patch" \
    || { echo "[error] registration.patch 无法干净应用（llvm major=$MAJOR 需适配）" >&2; exit 1; }
  git -C "$LLVM_SRC" apply "$OVERLAY/registration.patch"
  echo "[ok] registration.patch 已应用" >&2
fi

echo "[done] overlay 应用完成 (major=$MAJOR)" >&2
