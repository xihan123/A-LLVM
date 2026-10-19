# dex2c 0.1.12 / A-LLVM p17 发布准备

日期：2026-10-21。当前源码使用新坐标 `0.1.12`、新 patchset `p17`。
远端已有 `0.1.11-verify1` 和 `0.1.11`，不得覆盖。`0.1.9 / p16` 继续作为历史对照。
0.1.12 另修正最终 APK 验证任务的缓存输入，APK 文件名变化也会使报告失效。
本记录描述发布准备，不表示已上传 `0.1.12` 或 p17。

## 本版变化

- 原生 APK v2/v3 验证、固定证书身份与内容摘要；Mbed TLS 3.6.7 源码、校验清单和许可随插件分发。
- VMP / NATIVE 分层注解与选择报告，QSEG 分段容器及按需恢复。
- 插件的 `verifyApkSignature`、`segmentedData` 仍为显式开关，接入方可在 Release 同时开启。
- `verify<Variant>Dex2cApk` 核验 AGP 输出；`VerifyApkTask.apkFiles` 支持核验重新签名后的分发包。
  两种 APK 输入不能同时指定，报告绑定最终 APK、证书、DEX、SO 和容器。
- 发布脚本支持正式版本和候选后缀，拒绝 SNAPSHOT、依赖版本不一致、完整或部分覆盖发布。
- 本地 Clang 构建恢复通用 NDK 自动发现；SDK 内 NDK 可通过 `--ndk-dir` 显式指定。

## 发布顺序

1. 提交 A-LLVM 源码，使用 `discover` 的 build 模式聚合 Linux / Windows 产物。
   下游接入模块的 CI 固定依赖 `r30-30.0.16248370-p17`，需先确认该标签下两个 ZIP 和总 `SHA256SUMS` 完整。
   不允许以原版 NDK 或其他 patchset 替代。独立 build job 的产物不能冒充已聚合发布。
2. 使用同源 p17 工具链在 Windows / JDK 21 运行发布脚本。检查命令如下；准备上传时将 `--check`
   改成 `--publish`，凭据通过当前进程环境提供，按 README 的示例清理。
3. Maven 五个坐标发布并核验后，再发布下游接入模块的版本标签。

```powershell
python scripts/publish_dex2c.py --check `
  --clang 'F:\Android\Sdk\ndk\30.0.16248370\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe' `
  --ndk 'F:\Android\Sdk\ndk\30.0.16248370'
```

每次检查产生独立 `dex2c/build/release-0.1.12-*/`，其中 `manifest.json`、`check.log`、
`staging.log` 绑定该次 85 个 Maven 文件。上传后另生成 `published.json`；没有它不能声称远端已核验。

## 本次验证

- LLVM 21 注册补丁通过精确基线 `2d287f51eff2a5fbf84458a33f7fb2493cf67965` 的 `git apply --check`。
- `build_clang_local.sh --test` 通过增量 Clang 构建、主机 roundtrip、布局、ABI、构建系统、字符串、
  fingerprint、自校验、证书绑定和 VMP 回归。日志：`build/p17-release-toolchain.log`。
- overlay Python 29 项、发布脚本 15 项、依赖校验 1 项、QSEG 9 项、发现 10 项、LLVM 定位 1 项通过。
- 插件 `check` / `validatePlugins` 通过，30 项 Java/Gradle 测试无失败或跳过；完整 staging 85 个文件通过。
  本次目录：`dex2c/build/release-0.1.12-g2z5c1s6/`，`release-checks.json` 另核对 SDK Clang 与构建 Clang 摘要一致。
- 三个下游模块离线分发构建、普通 APK 与最终分发 APK 验证通过；Python 51 项，模块单元测试 97 项通过。
  分发检查覆盖签名、证书、方法包装、SO/容器回执和 16 KiB 文件对齐。以最终 JSON 报告记录具体 APK 摘要。
  分发验证证据保留在本机构建目录 `release-0.1.12-validation/summary.json`；收集目录中的 `SHA256SUMS` 绑定三个 APK。

## 适用范围与未完成项

当前面向 LLVM 21 / NDK r30 / arm64 / Android API 26+。LLVM 20 不支持 QSEG；本轮没有将其宣称为支持。
接入样例已完成 OnePlus7 上的 LSPosed 主/子进程、验签及 QSEG 语义验证；该历史证据绑定当时的候选哈希，
本轮版本与构建任务调整不等于重新执行最终 APK 的全部设备验收。

API 26 与 16 KiB 页面的实机、完整启用/禁用初始化 P95 增量、独立 QSEG 性能门槛，以及新 p17
Linux/Windows 聚合发布流程尚需完成；文件对齐通过不能替代 16 KiB 设备验证。插件默认值因此保持显式选择。
完全离线保护可被分析和恢复，不承诺持有 APK 无法还原算法或运行时数据。
