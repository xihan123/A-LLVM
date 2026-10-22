# dex2c / strings 0.1.13-strings1 发布记录

日期：2026-10-22。此版本为候选发布，dex2c 与 strings 使用同一版本。
当前完成本地 staging 与消费者验证；远端上传需 Maven 凭据，尚未声明发布成功。
发布前匿名检查确认此版本的六项坐标均无已有版本或残留文件，dex2c 远端 release 为 `0.1.12`。

## 发布内容

- 新增 `io.github.xihan123.strings`，显式选择包中的字符串抽取到 native。
- `io.github.xihan123.dex2c` 同步发布，两个插件通过共享协调器合并转换、注册、保护证据与 SO。
- 复用 hardened CSE、VMP、自校验、证书绑定与可选最终 APK 验签；Java 热缓存不进入 JNI。
- 修复并扩展最终 DEX/SO 验证，提供 Java/Kotlin 接入样例、设备与基准脚本。

发布仓库：`https://mirrors.xihan.website/repository/maven-releases/`。
共享库 group 为 `io.github.xihan123.dex2c`：`annotations`、`runtime`、`core`、`gradle-plugin`。
两个 marker 分别为：

```text
io.github.xihan123.dex2c:io.github.xihan123.dex2c.gradle.plugin:0.1.13-strings1
io.github.xihan123.strings:io.github.xihan123.strings.gradle.plugin:0.1.13-strings1
```

六项 publication 共 90 个版本文件（含校验文件），禁止覆盖已有或部分上传的版本。
上传必须通过 `scripts/publish_dex2c.py --publish`，以该次 `published.json` 为远端逐字节核验凭证。
本次重新执行 `--check`：42 项 Gradle 测试无失败或跳过，90 个 staging 文件校验通过；
证据保留在本机 `dex2c/build/release-0.1.13-strings1-bldwjbfm/manifest.json` 及同目录日志。
不改动 LLVM overlay 与底层密码运行时，沿用 LLVM 21 / NDK r30 / p17，不递增 patchset。

## 验证与适用范围

42 个 Gradle 测试、22 个 Python 测试通过；独立 Maven 消费、AGP/R8、两个插件应用顺序、
配置/构建缓存及零工具链零命中通过。设备语义、证书与密文/代码/VMP 篡改检测通过。
详细数据、证据目录与复现命令见 [字符串验证记录](STRINGS_VALIDATION.md)。

本候选面向 AGP 9 / JDK 21 / arm64-v8a / minSdk 26。API 26、16 KiB 页实际设备、Linux
消费者以及目标业务应用启动/内存/包体门槛尚未完成，不宣称正式版本验收通过。
公开证书不是秘密；运行时字符串与 Java 缓存仍可被读取。
