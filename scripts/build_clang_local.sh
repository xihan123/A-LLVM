#!/usr/bin/env bash
# build_clang_local.sh — 本地编译补丁 clang 并覆盖 NDK（开发用，等价于 CI build 模式的
# 本机版；默认增量，重复执行安全）。
#
#   bash scripts/build_clang_local.sh [选项]
#
# 典型用法：
#   首次冷构建：  bash scripts/build_clang_local.sh --init
#                （浅克隆 llvm-project 到 NDK 的 base commit；HTTP(S)_PROXY 会被 git 使用）
#   改 overlay 后：bash scripts/build_clang_local.sh            # overlay -> 增量 ninja -> 覆盖 NDK
#   构建并回归：  bash scripts/build_clang_local.sh --test      # 附带 CI build 模式的全部测试套件
#
# 前置条件：
#   - 已解压的官方 NDK（--ndk-dir，默认自动发现仓库根下 android-ndk-*）
#   - Windows（Git Bash 下运行）：Visual Studio 含 C++ 工具集 + CMake 在 PATH；
#     脚本用 vswhere 定位 vcvarsall 与 VS 自带 Ninja
#   - Linux：cmake / ninja / clang 已安装
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

NDK_DIR=""
LLVM_SRC="$REPO_ROOT/llvm-project"
BUILD_DIR="$REPO_ROOT/build"
HOST=""
TARGETS="AArch64;ARM;X86"
MAJOR=""
INIT=0
RUN_TESTS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ndk-dir)   NDK_DIR="$2"; shift 2 ;;
    --llvm-src)  LLVM_SRC="$2"; shift 2 ;;
    --build-dir) BUILD_DIR="$2"; shift 2 ;;
    --host)      HOST="$2"; shift 2 ;;
    --targets)   TARGETS="$2"; shift 2 ;;
    --major)     MAJOR="$2"; shift 2 ;;
    --init)      INIT=1; shift ;;
    --test)      RUN_TESTS=1; shift ;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数：$1（--help 查看用法）" >&2; exit 2 ;;
  esac
done

# ---------------- 宿主与工具链发现 ----------------

if [[ -z "$HOST" ]]; then
  case "$(uname -s)" in
    Linux) HOST="linux-x86_64" ;;
    MINGW*|MSYS*|CYGWIN*) HOST="windows-x86_64" ;;
    *) echo "[error] 不支持的宿主：$(uname -s)" >&2; exit 1 ;;
  esac
fi
IS_WINDOWS=0
[[ "$HOST" == windows-* ]] && IS_WINDOWS=1

if [[ -z "$NDK_DIR" ]]; then
  NDK_DIR="$(find "$REPO_ROOT" -maxdepth 1 -type d -name 'android-ndk-*' | head -n1 || true)"
  [[ -n "$NDK_DIR" ]] || { echo "[error] 未找到 NDK，请用 --ndk-dir 指定（或把解压后的 android-ndk-* 放在仓库根）" >&2; exit 1; }
fi
NDK_DIR="$(cd "$NDK_DIR" && pwd -P)"
[[ -d "$NDK_DIR/toolchains/llvm/prebuilt/$HOST" ]] \
  || { echo "[error] NDK 缺少 $HOST prebuilt 目录：$NDK_DIR" >&2; exit 1; }

command -v cmake >/dev/null || { echo "[error] cmake 不在 PATH" >&2; exit 1; }
command -v python >/dev/null || { echo "[error] python 不在 PATH" >&2; exit 1; }

VCVARS=""
EXTRA_PATH=""
if [[ $IS_WINDOWS -eq 1 ]]; then
  VSWHERE="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
  [[ -x "$VSWHERE" ]] || { echo "[error] 找不到 vswhere（需安装 Visual Studio）" >&2; exit 1; }
  VS_PATH="$("$VSWHERE" -latest -products '*' \
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)"
  [[ -n "$VS_PATH" ]] || { echo "[error] vswhere 未找到含 C++ 工具集的 Visual Studio" >&2; exit 1; }
  VS_PATH="$(cygpath -u "$VS_PATH")"
  VCVARS="$VS_PATH/VC/Auxiliary/Build/vcvarsall.bat"
  [[ -f "$VCVARS" ]] || { echo "[error] 缺少 vcvarsall.bat：$VCVARS" >&2; exit 1; }
  VS_NINJA="$VS_PATH/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja"
  [[ -x "$VS_NINJA/ninja.exe" ]] && EXTRA_PATH="$VS_NINJA"
  echo "[info] Visual Studio: $VS_PATH"
fi
# 测试套件（build-system-smoke）也需要 ninja；Windows 下把 VS 自带的加入 PATH。
[[ -n "$EXTRA_PATH" ]] && export PATH="$EXTRA_PATH:$PATH"
command -v ninja >/dev/null \
  || { echo "[error] ninja 不在 PATH（Windows 需 VS 自带 Ninja 或自行安装）" >&2; exit 1; }

# ---------------- LLVM 基线与 overlay ----------------

LOC_JSON="$(python "$SCRIPT_DIR/locate_llvm.py" --ndk-dir "$NDK_DIR" --host "$HOST")"
BASE_COMMIT="$(printf '%s' "$LOC_JSON" | python -c 'import sys,json;print(json.load(sys.stdin)["base_commit"] or "")')"
LOC_MAJOR="$(printf '%s' "$LOC_JSON" | python -c 'import sys,json;print(json.load(sys.stdin)["llvm_major"] or "")')"
[[ -n "$BASE_COMMIT" ]] || { echo "[error] base commit 为空，拒绝构建" >&2; exit 1; }
[[ -n "$LOC_MAJOR" ]] || { echo "[error] 未能从 NDK 解析 llvm_major" >&2; exit 1; }
if [[ -z "$MAJOR" ]]; then MAJOR="$LOC_MAJOR"; fi
[[ "$MAJOR" == "$LOC_MAJOR" ]] \
  || { echo "[error] --major=$MAJOR 与 NDK 实际 LLVM major=$LOC_MAJOR 不一致" >&2; exit 1; }
echo "[info] NDK=$NDK_DIR host=$HOST llvm_major=$MAJOR base=$BASE_COMMIT"

[[ -d "$REPO_ROOT/obfuscation/llvm-$MAJOR/Transforms/Obfuscation" ]] \
  || { echo "[error] 缺少 LLVM $MAJOR overlay，请先适配（见 obfuscation/README.md）" >&2; exit 1; }

if [[ ! -d "$LLVM_SRC/llvm" ]]; then
  if [[ $INIT -ne 1 ]]; then
    echo "[error] $LLVM_SRC 不存在；首次使用请加 --init（浅克隆 base commit，可用 HTTPS_PROXY 代理）" >&2
    exit 1
  fi
  echo "[info] 浅克隆 llvm-project @ $BASE_COMMIT（走 HTTP(S)_PROXY，若有）"
  git init -q "$LLVM_SRC"
  git -C "$LLVM_SRC" remote add origin https://github.com/llvm/llvm-project.git
  git -C "$LLVM_SRC" fetch -q --depth=1 origin "$BASE_COMMIT"
  git -C "$LLVM_SRC" reset -q --hard FETCH_HEAD
fi

LLVM_SRC="$(cd "$LLVM_SRC" && pwd -P)"
ACTUAL_COMMIT="$(git -C "$LLVM_SRC" rev-parse HEAD)"
[[ "$ACTUAL_COMMIT" == "$BASE_COMMIT" ]] \
  || { echo "[error] LLVM HEAD=$ACTUAL_COMMIT 与 NDK Base revision=$BASE_COMMIT 不一致" >&2; exit 1; }

echo "[info] 应用混淆 overlay（增量同步，重复执行安全）"
bash "$SCRIPT_DIR/apply_overlay.sh" --llvm-src "$LLVM_SRC" --major "$MAJOR"

# ---------------- 配置与增量编译 ----------------

BUILD="$BUILD_DIR"
LLVM_CMAKE="$LLVM_SRC/llvm"

if [[ $IS_WINDOWS -eq 1 ]]; then
  # MSVC 环境在 bash 里不可 source；每次同步配置，避免复用错误源码或旧参数。
  EXTRA_LINE=""
  if [[ -n "$EXTRA_PATH" ]]; then
    EXTRA_LINE="set \"PATH=$(cygpath -w "$EXTRA_PATH");%PATH%\""
  fi
  TMPBAT="$REPO_ROOT/.build_clang_local.bat"
  trap 'rm -f "$TMPBAT"' EXIT
  cat > "$TMPBAT" <<BAT
@echo off
call "$(cygpath -w "$VCVARS")" x64 || exit /b 1
$EXTRA_LINE
cd /d "$(cygpath -w "$REPO_ROOT")"
cmake -S "$(cygpath -w "$LLVM_CMAKE")" -B "$(cygpath -w "$BUILD")" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DLLVM_ENABLE_ASSERTIONS=OFF ^
  -DCMAKE_C_COMPILER=cl ^
  -DCMAKE_CXX_COMPILER=cl ^
  -DLLVM_OBFUSCATION_LINK_INTO_TOOLS=ON ^
  -DLLVM_ENABLE_PROJECTS=clang ^
  "-DLLVM_TARGETS_TO_BUILD=$TARGETS" || exit /b 1
ninja -C "$(cygpath -w "$BUILD")" clang clang-resource-headers || exit /b 1
BAT
  cmd //c "$(cygpath -w "$TMPBAT")"
else
  cmake -S "$LLVM_CMAKE" -B "$BUILD" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DLLVM_OBFUSCATION_LINK_INTO_TOOLS=ON \
    -DLLVM_ENABLE_PROJECTS=clang \
    "-DLLVM_TARGETS_TO_BUILD=$TARGETS"
  ninja -C "$BUILD" clang clang-resource-headers
fi

CLANG_BIN="$BUILD/bin/clang"
[[ $IS_WINDOWS -eq 1 ]] && CLANG_BIN="$CLANG_BIN.exe"
[[ -x "$CLANG_BIN" ]] || { echo "[error] 编译产物缺失：$CLANG_BIN" >&2; exit 1; }
echo "[info] $("$CLANG_BIN" --version | head -n1)"

# ---------------- 覆盖 NDK ----------------

echo "[info] 用自建 clang 覆盖 NDK"
bash "$SCRIPT_DIR/overlay_ndk.sh" --built "$BUILD" --ndk "$NDK_DIR" --host "$HOST" --major "$MAJOR"

# ---------------- 可选：回归测试 ----------------

if [[ $RUN_TESTS -eq 1 ]]; then
  case "$HOST" in
    windows-x86_64) T="x86_64-pc-windows-msvc" ;;
    *)              T="x86_64-unknown-linux-gnu" ;;
  esac
  FAIL=0
  for t in string-enc/roundtrip string-enc/lifetime constant-enc/roundtrip cert-bind/roundtrip; do
    echo "===== host: $t ====="
    bash "$REPO_ROOT/tests/$t.sh" "$CLANG_BIN" --target="$T" || FAIL=1
  done
  for t in package-layout/check_layout abi-smoke/run build-system-smoke/run \
           string-enc/check fingerprint-scrub/run anti-tamper/run \
           cert-bind/run vmp/roundtrip; do
    echo "===== ndk: $t ====="
    bash "$REPO_ROOT/tests/$t.sh" "$NDK_DIR" "$HOST" || FAIL=1
  done
  [[ $FAIL -eq 0 ]] && echo "[ok] 全部测试通过" || { echo "[FAIL] 存在失败用例" >&2; exit 1; }
fi

echo "[done] 完成。后续：改 obfuscation/llvm-$MAJOR 后重跑本脚本（增量），再重新构建 APK"
