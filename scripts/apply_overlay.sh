#!/usr/bin/env bash
# apply_overlay.sh — 把按 LLVM major 适配的混淆 overlay 叠加到 llvm-project 源码树。
#
#   apply_overlay.sh --llvm-src <llvm-project 根> --major <N> [--repo-root <repo>]
#
# obfuscation/llvm-<N>/ 存在时：
#   - 按内容同步源文件和头文件，保留未变化文件的 mtime，删除清单中的过期文件
#   - 应用 registration.patch；已完整应用时跳过，其他状态失败
# 缺少 overlay 源文件目录或注册补丁时失败；repack 模式不调用本脚本。
set -euo pipefail

LLVM_SRC=""
MAJOR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --llvm-src) LLVM_SRC="$2"; shift 2 ;;
    --major)    MAJOR="$2"; shift 2 ;;
    --repo-root) REPO_ROOT="$2"; shift 2 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

[[ -n "$LLVM_SRC" && -n "$MAJOR" ]] || { echo "用法：apply_overlay.sh --llvm-src <dir> --major <N>" >&2; exit 2; }
[[ "$MAJOR" =~ ^[0-9]+$ ]] || { echo "[error] major 必须为整数" >&2; exit 2; }
[[ -d "$LLVM_SRC/llvm" ]] || { echo "[error] 不是 llvm-project 源码树：$LLVM_SRC" >&2; exit 1; }

OVERLAY="$REPO_ROOT/obfuscation/llvm-$MAJOR"
[[ -d "$OVERLAY/Transforms/Obfuscation" ]] \
  || { echo "[error] 缺少 overlay 源文件目录：$OVERLAY" >&2; exit 1; }
[[ -s "$OVERLAY/registration.patch" ]] \
  || { echo "[error] 缺少或为空的 registration.patch：$OVERLAY" >&2; exit 1; }
# git -C 后仍使用调用目录下 --repo-root 对应的绝对路径。
OVERLAY="$(cd "$OVERLAY" && pwd)"

echo "[info] 应用混淆 overlay：$OVERLAY -> $LLVM_SRC" >&2

APPLY_PATCH=false
if git -C "$LLVM_SRC" apply --check "$OVERLAY/registration.patch" 2>/dev/null; then
  APPLY_PATCH=true
elif git -C "$LLVM_SRC" apply --reverse --check "$OVERLAY/registration.patch" 2>/dev/null; then
  echo "[ok] registration.patch 已完整应用，跳过" >&2
else
  git -C "$LLVM_SRC" apply --check "$OVERLAY/registration.patch" >&2 || true
  echo "[error] registration.patch 无法干净应用或完整反向检查（llvm major=$MAJOR 需适配）" >&2
  exit 1
fi

python "$SCRIPT_DIR/sync_overlay.py" --llvm-src "$LLVM_SRC" --overlay "$OVERLAY"

if [[ "$APPLY_PATCH" = true ]]; then
  git -C "$LLVM_SRC" apply "$OVERLAY/registration.patch"
  echo "[ok] registration.patch 已应用" >&2
fi

echo "[done] overlay 应用完成 (major=$MAJOR)" >&2
