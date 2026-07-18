# Android NDK 混淆工具链设计

| 项目 | 当前约束 |
| --- | --- |
| 目标 | 构建带 IR 混淆 pass 的第三方 Android NDK |
| Host | `linux-x86_64`、`windows-x86_64` |
| 构建 | GitHub Actions，CMake + Ninja |
| 已实现 | 发现、重打包、自建 clang/lld、LLVM 20/21 overlay、本地测试 |
| 待验证 | GitHub Actions 完整构建、Windows CI |
| 许可 | 项目新增代码 GPL-3.0；overlay 保留上游许可 |

## 1. 范围

流水线完成以下工作：

1. 从 Android NDK Releases 获取 Stable、Beta 和 RC 版本。
2. 从 NDK 包内读取 LLVM major 和上游 `Base revision`。
3. 按 LLVM major 应用混淆 overlay。
4. 构建 clang、lld、llvm-strip 和 llvm-objcopy。
5. 用自建工具覆盖官方 NDK 中对应的 Host 工具，保留 sysroot、libc++ 和各 ABI runtime。
6. 通过测试后打包并发布。

`Base revision` 只是官方编译器使用的上游 LLVM 基线，不包含 Google 未上游化的 Android Clang 补丁。因此产物兼容官方 NDK 的目录和构建入口，但不承诺与官方 clang 行为完全一致。

当前不做以下事项：

- 重建完整 Android NDK；
- 支持 macOS Host；
- 提供防破解保证；
- 在未完成设备验证前发布 VMP、自加密或反分析功能。

## 2. 设计约束

| 约束 | 处理方式 |
| --- | --- |
| 官方 NDK 作为发行基座 | 只覆盖受影响的 Host 工具和 clang resource headers |
| 源码版本必须可追踪 | `clang_source_info.md` 缺少 `Base revision` 时终止构建 |
| `build` 必须包含混淆 | 找不到对应 LLVM major overlay 时终止构建 |
| 默认不改变代码 | 没有开关时 overlay 不执行 IR 变换 |
| 发布不可覆盖 | 构建或参数变化时递增 patchset，生成新 tag |
| Host 发布保持一致 | 各 Host 先上传 artifact，再由一个 job 聚合发布 |

## 3. 流水线

```text
discover.yml
  Android NDK Releases API
    -> 通道过滤
    -> 读取内部版本
    -> 计算 our_tag
    -> 校验已有 Release 资产
    -> Host 构建矩阵 + tag 发布矩阵

build.yml（每个 Host）
  下载 NDK
    -> locate_llvm.py
    -> llvm-project@Base revision
    -> apply_overlay.sh
    -> CMake + Ninja
    -> overlay_ndk.sh
    -> make_release_meta.py
    -> 测试
    -> artifact

discover.yml（每个 tag）
  下载全部 Host artifact
    -> 校验资产数量
    -> 生成 SHA256SUMS
    -> 创建一次 Release
```

## 4. 仓库结构

```text
.github/workflows/     发现、构建和 patch 检查
config/                通道和 patchset
include/ndkp.h         用户注解宏
obfuscation/llvm-*/    按 LLVM major 维护的 overlay
scripts/               发现、定位、覆盖和元数据脚本
tests/                 包结构、ABI、构建系统、字符串和发现逻辑测试
README.md              用户入口
CONTRIBUTING.md        开发约定
ROADMAP.md             实现状态和待办
```

## 5. 构建

### 模式

- `repack`：不编译工具链，只写元数据并重新打包官方 NDK。
- `build`：定位上游 LLVM 基线、应用 overlay、构建并覆盖工具链。缺少 overlay 时失败。

Linux 使用 runner 自带 clang/lld 作为宿主编译器。Windows 使用 MSVC。默认构建 `AArch64;ARM;X86`，覆盖 arm64-v8a、armeabi-v7a、x86 和 x86_64。

构建只替换白名单中的 clang/lld/strip/objcopy 及 `lib/clang/<major>/include`。官方 NDK 的 sysroot、libc++、compiler-rt 和构建脚本保持不变。

LLVM major 从包内 `AndroidVersion.txt` 读取，不根据 NDK tag 推测。当前仓库维护 LLVM 20 和 21 overlay；遇到其他 major 时 `build` 失败。

## 6. 版本与发布

版本发现使用 `https://api.github.com/repos/android/ndk/releases`。默认检查最近 15 个 Release，自动处理 Stable、Beta 和 RC，Canary 默认关闭。

命名格式：

```text
tag:      r<major>[hotfix]-<internal>[-betaN|-rcN]-p<N>
artifact: android-ndk-<tag>-<host>.zip
```

示例：`r30-30.0.15729638-beta2-p2`。

去重同时检查 tag 和资产。请求的 Host zip 与 `SHA256SUMS` 全部存在时才跳过。已有 Release 缺少资产时终止自动发布，并要求递增 patchset；`force` 只重建 artifact，不覆盖 Release。

`build.yml` 只读取仓库、构建并上传 artifact，不持有 Release 写权限。只有 `discover.yml` 的聚合 job 拥有发布权限，并在全部 Host 成功后检查 tag、生成总校验文件并创建 Release。手动运行 `build.yml` 也只生成 artifact。

## 7. 混淆 overlay

目录约定：

```text
obfuscation/llvm-<major>/
  Transforms/Obfuscation/
  include/
  registration.patch
```

一期使用静态 pass plugin。`registration.patch` 只向 `llvm/lib/Transforms/CMakeLists.txt` 增加 `add_subdirectory(Obfuscation)`；插件通过 `registerOptimizerLastEPCallback` 注册，不修改 Clang Driver 或 AArch64 后端。

已实现的 `-mllvm` 开关：

- `-irobf`；
- `-irobf-cse`；
- `-irobf-cie`、`-irobf-cfe`；
- `-irobf-fla`；
- `-irobf-indbr`、`-irobf-icall`、`-irobf-indgv`。

`include/ndkp.h` 提供 `NDKP_STR_ENCRYPT`、`NDKP_FLATTEN` 和预留的 `NDKP_VMP`。当前注解仍需配合对应的命令行总开关。

AArch64 后端 `-aarch64-obfuscate-*` 尚未实现。

## 8. 发布门槛

每个 Host 在打包前执行：

- 包结构和 `Ndkp.*` 元数据检查；
- 四个 Android ABI 编链；
- CMake toolchain 构建；
- ndk-build 构建；
- `-O0`、`-O2`、`-Oz` 字符串加密扫描。

这些测试确认工具链可构建目标文件且指定明文不出现在 ELF 中。Android 运行时行为仍需设备或模拟器测试。

## 9. 元数据与许可

包内新增：

- `NDKP-build-info.json`；
- `NDKP-patch-report.json`；
- `LICENSES/NDKP-GPL-3.0.txt`；
- `LICENSES/LLVM-UIUC.txt`；
- `LICENSES/LIBTOMCRYPT-UNLICENSE.txt`；
- `source.properties` 中的 `Ndkp.*` 字段。

聚合发布生成一份覆盖全部 Host zip 的 `SHA256SUMS`。当前记录 `SOURCE_DATE_EPOCH`，但尚未完成固定随机种子和双构建一致性验证，因此不声明可复现构建。

## 10. 后续工作

实现顺序以 [ROADMAP.md](./ROADMAP.md) 为准。以下功能尚未进入发布工具链：

| 功能 | 前置条件 |
| --- | --- |
| 字符串 per-key / 包名绑定 | 运行时开销和多进程行为测试 |
| 反分析探针 | 误报测试，默认非致命 |
| 代码自校验 | 动态重定位归一化和篡改测试 |
| VMP | 函数 eligibility、各 ABI 解释器和语义测试 |
| AArch64 后端混淆 | 独立补丁和机器码测试 |
| macOS Host | runner、dmg 打包和签名处理 |

函数级 SO 自加密只保留为实验项。开始实现前必须先验证：

1. 加密函数可放入页对齐、页独占的 `PT_LOAD`；
2. 加密页不存在动态 relocation 目标；
3. Android 允许匿名页从 RW 切换到 RX；
4. 可在原虚拟地址安全替换映射，保持直接调用、函数指针和 unwind 地址有效。

任一条件不成立即停止该方案，不在正式构建中降级启用。

## 11. 风险

| 风险 | 处理 |
| --- | --- |
| LLVM 更新导致 overlay 失效 | 按 major 维护，`git apply --check` 和构建测试 |
| 免费 runner 超时或磁盘不足 | 单链接任务，必要时使用 larger/self-hosted runner |
| 缺少 Android 下游补丁 | 在文档和元数据中明确第三方构建，不承诺官方行为一致 |
| 优化后重新出现明文 | 多优化级别扫描最终 ELF |
| Release 只包含部分 Host | 聚合发布；残缺 Release 不覆盖 |
| Windows 构建差异 | 发布前完成 Windows CI 实跑 |
| 随机化影响复现 | 后续接入固定 seed 并做双构建比对 |
