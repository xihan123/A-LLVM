![A-LLVM](https://socialify.git.ci/xihan123/A-LLVM/image?description=1&language=1&name=1&owner=1&pattern=Solid&theme=Auto)

[![license](https://img.shields.io/github/license/xihan123/A-LLVM.svg)](./LICENSE)
[![Checks](https://github.com/xihan123/A-LLVM/actions/workflows/checks.yml/badge.svg)](https://github.com/xihan123/A-LLVM/actions/workflows/checks.yml)
[![Patch Check](https://github.com/xihan123/A-LLVM/actions/workflows/patch-check.yml/badge.svg)](https://github.com/xihan123/A-LLVM/actions/workflows/patch-check.yml)
[![Discover](https://github.com/xihan123/A-LLVM/actions/workflows/discover.yml/badge.svg)](https://github.com/xihan123/A-LLVM/actions/workflows/discover.yml)

# A-LLVM

## 项目简介

本项目根据 Android NDK Release 中记录的上游 LLVM 版本构建带混淆 pass 的 clang/lld，再覆盖到官方 NDK 中打包发布。自动发现支持 Stable、Beta 和 RC。

> 产物是第三方 Custom NDK，不是 Google 官方构建。采用 GPL-3.0。

设计见 [DESIGN.md](./DESIGN.md)，开发约定见 [CONTRIBUTING.md](./CONTRIBUTING.md)，进度见 [ROADMAP.md](./ROADMAP.md)。

## 主要功能

- 按 NDK 包内的 LLVM `Base revision` 构建对应 clang/lld；
- 支持字符串加密、控制流平坦化、间接跳转/调用和常量加密；
- 保留官方 NDK 的 sysroot、libc++、compiler-rt 和构建脚本；
- 为 Linux 和 Windows Host 生成独立 NDK 包；
- 通过 GitHub Actions 自动发现、构建、测试和发布。

## 版本命名

`r30-30.0.15729638-beta2-p2` 由 NDK 主版本 `r30`、内部版本 `30.0.15729638`、通道 `beta2` 和 patchset `p2` 组成。产物名为 `android-ndk-<tag>-<host>.zip`。

## 使用产物

下载 Release 中对应 Host 的 zip，解压后配置到 Gradle、CMake 或 ndk-build。包布局与官方 NDK 兼容；自建 clang 不包含全部 Android 下游补丁，不能视为官方编译器的等价替代。

混淆通过 `-mllvm` 参数或 `include/ndkp.h` 中的注解宏启用。

CMake 示例：

```cmake
target_compile_options(mylib PRIVATE
  -mllvm -irobf-cse        # 字符串加密
  -mllvm -irobf-fla        # 控制流平坦化
  -mllvm -irobf-indbr      # 间接跳转
)
```

ndk-build（`Android.mk`）：`LOCAL_CFLAGS += -mllvm -irobf-cse -mllvm -irobf-fla`

注解（仅对指定函数启用，需配合对应总开关）：

```c
#include "ndkp.h"
NDKP_STR_ENCRYPT void secret() { const char* k = "token"; /* ... */ }
```

一期开关：`-irobf-cse`（字符串）、`-irobf-cie`/`-irobf-cfe`（整/浮点常量）、`-irobf-fla`、`-irobf-indbr`/`-icall`/`-indgv`。不加任何开关时 overlay 不主动变换 IR；这不代表自建 clang 与官方 Android Clang 完全一致。AArch64 后端机器码混淆（`-aarch64-obfuscate-*`）与 VMP（`-irobf-vmp`）属后续阶段。

## 构建流程

- 自动：`discover.yml` 每日 03:17 UTC 检查，发现新版本后并行构建各 Host；全部通过后聚合为一次不可变 Release。
- 手动：Actions → `discover` → Run workflow，可覆盖 `channels` / `hosts` / `force` / `mode`。
  - `mode=repack`：仅原样重打包官方 NDK（快速打通流水线，阶段 1a）。
  - `mode=build`：自建 patched clang 覆盖（默认）；缺少对应 LLVM major overlay 时失败。
- 单版本验证：直接跑 `build` workflow（`workflow_dispatch`），填 `ndk_tag`（如 `r27d`）与 `internal`（如 `27.3.13750724`）；该流程只生成 artifact，不发布 Release。

本地干跑发现逻辑（仅需 Python 3，无第三方依赖）：

```bash
python scripts/discover_ndk.py --dry-run --channels stable,beta,rc
```

## 项目结构

```
.github/workflows/  discover.yml（发现+聚合发布） build.yml（可复用 Host 构建）
config/             channels.json（通道）  patchset.env（PATCHSET_VERSION）
obfuscation/        llvm-<major>/（按 LLVM 大版本的混淆 overlay，1c 落地）
scripts/            discover_ndk / locate_llvm / apply_overlay / overlay_ndk / make_release_meta
include/ndkp.h      用户注解宏
tests/              package-layout / string-enc / abi-smoke / build-system-smoke / discover
```

## 当前状态

阶段 0、1a 已就绪；1b/1c 已完成代码和本地验证，但 GitHub Actions 端到端尚未跑通。VMP、后端扩展和 macOS 尚未实现，见 [ROADMAP.md](./ROADMAP.md)。

## 许可证

项目新增代码使用 GPL-3.0，见 [`LICENSE`](./LICENSE)。overlay 中的上游代码保留原始许可，见 [`LICENSES/`](./LICENSES/)。LLVM/Clang 主体为 Apache-2.0 with LLVM Exceptions。
