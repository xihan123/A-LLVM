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
- 支持函数级虚拟化（VMP）与反分析检测注入（反调试/Root/模拟器/反转储/maps 隐藏）；
- 支持代码完整性自校验（`-irobf-selfcheck`）与 APK 签名证书绑定（`-irobf-cert-bind`：把签名证书折进字符串/VMP 密钥，换签名或重打包即解密失败）；
- 保留官方 NDK 的 sysroot、libc++、compiler-rt 和构建脚本；
- 为 Linux 和 Windows Host 生成独立 NDK 包；
- 通过 GitHub Actions 自动发现、构建、测试和发布。

## 版本命名

`r30-30.0.15729638-beta2` 由 NDK 主版本 `r30`、内部版本 `30.0.15729638` 和通道 `beta2` 组成。产物名为 `android-ndk-<tag>-<host>.zip`。（可选的 patchset 后缀 `-p1`/`-p2` 默认关闭，仅在同一 NDK 版本因 overlay 变化需重新发布时启用。）

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

一期开关：`-irobf-cse`（字符串）、`-irobf-cie`/`-irobf-cfe`（整/浮点常量）、`-irobf-fla`、`-irobf-indbr`/`-icall`/`-indgv`。字符串加密可叠加强化开关 `-irobf-cse-perkey`（隐藏 pepper 派生 per-string ChaCha8 密钥，密文不再内联密钥）与 `-irobf-cse-bind`（包名绑定，`.so` 仅在目标 App 内解出明文，配合 `-irobf-cse-bind-package=<包名>`，或 `NDKP_STR_BIND` 注解）。函数级虚拟化 `-irobf-vmp` 与反分析检测 `-irobf-{idadetect,timedetect,rootdetect,vmdetect,bandump,hidemaps,fakemaps}` 已实现（详见 [obfuscation/README.md](./obfuscation/README.md)）。APK 签名证书绑定 `-irobf-cert-bind`（配合 `-irobf-cert-file=<cert.der>`）把签名证书 SHA-256 折进字符串与 VMP 密钥，换签名/重打包即 fail-closed；运行期读证书需 app 侧链接 `runtime/ndkp_apkcert.cpp`（见 [runtime/README.md](./runtime/README.md)）。不加任何开关时 overlay 不主动变换 IR；这不代表自建 clang 与官方 Android Clang 完全一致。字符串包名绑定与 VMP 已本地验证但设备语义验证前不发布；AArch64 后端机器码混淆（`-aarch64-obfuscate-*`）属后续阶段。

## 构建流程

- 自动：`discover.yml` 每日 03:17 UTC 检查，发现新版本后并行构建各 Host；全部通过后聚合为一次不可变 Release。
- 手动：Actions → `discover` → Run workflow，可覆盖 `channels` / `hosts` / `force` / `mode`。
  - `mode=repack`：仅原样重打包官方 NDK（快速打通流水线，阶段 1a）。
  - `mode=build`：自建 patched clang 覆盖（默认）；缺少对应 LLVM major overlay 时失败。
- 单版本验证：直接跑 `build` workflow（`workflow_dispatch`），默认留空 `ndk_tag` 与 `internal`，自动构建所选通道的最新版本；也可同时填写二者覆盖。该流程只生成 artifact，不发布 Release。

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

阶段 0、1a 已就绪；1b/1c 已完成代码和本地验证，但 GitHub Actions 端到端尚未跑通。VMP（`-irobf-vmp`）与反分析检测 pass 已实现并本地编译验证（VMP 待设备语义验证）。后端扩展和 macOS 尚未实现，见 [ROADMAP.md](./ROADMAP.md)。

## 许可证

项目新增代码使用 GPL-3.0，见 [`LICENSE`](./LICENSE)。overlay 中的上游代码保留原始许可，见 [`LICENSES/`](./LICENSES/)。LLVM/Clang 主体为 Apache-2.0 with LLVM Exceptions。
