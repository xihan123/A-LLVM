# 字符串插件候选验证

2026-10-22，`0.1.13-strings1`。Windows / JDK 21 / Gradle 9.8.1 / AGP 9.4.1 /
Kotlin 2.4.20 / NDK `30.0.16248370` / 本仓库 LLVM 21。
未改动 LLVM overlay、CSE 格式或底层密码运行时；不递增 NDK patchset。

## 已执行

- Java 主机 CheckJNI 差分：字符串插件单独使用、与 dex2c 组合、两种加载入口顺序。
  覆盖 UTF-16/NUL/代理项、intern 身份、初始化器/构造器/接口、lambda、拼接与并发读取。
- 独立运行时边界测试：模拟 OOM 后重试、并发首次解码一次、热缓存不再解码、ClassLoader 缓存隔离。
  此项替换了 native 边界，不声称测试同一 SO 文件跨 ClassLoader 的重复加载。
- 实际 A-LLVM arm64 编译、逐记录 CSE 缓冲区与调用检查、两个 CSE VMP 入口、自校验和 post CFG。
- AGP R8 Release：唯一 Java/Kotlin/native 测试明文不出现在 DEX/SO；两种插件应用顺序、
  dex2c 单独使用、Debug 未转换、零命中、缺证书失败、增量命中、配置缓存复用及 native 构建缓存恢复。
  原版、字符串、组合、dex2c-only、开启完整验签的最终 R8 APK 均在设备上通过 CheckJNI 执行。
- 本地发布检查：42 个 Gradle 测试、22 个 Python 测试通过，Gradle 用例零失败/跳过。
  两个插件 marker 和四个库共 90 个 staging 文件通过完整性校验；独立应用从 staging 消费，
  不使用 includeBuild，也通过上述构建、R8、组合及缓存场景。没有远程上传。
- 设备报告 API 37、arm64、4 KiB 页，型号 GM1901：Java/Kotlin（含协程）D8 语义差分通过。
  字符串单独使用和组合使用都拒绝错误签名、CSE 标签/密文篡改、代码段篡改、密码入口 VM 篡改和
  跨构建密文记录替换；组合产物额外拒绝业务 VM 篡改。
- 零命中独立验证：本地 Maven 消费者不提供证书或 Clang，指定不存在的 NDK，
  PATH 仅保留 JDK 和 Windows（无 Python），禁用构建缓存，Release 构建通过。
  日志保留在 `work/strings-maven-consumer/zero-tools.log`。
- 现有 hardened CSE 设备回归通过 O0/O2/Oz、无 LTO/full/thin/mixed/VMP 组合，
  覆盖冷/热篡改、缓存访问边界、strip、常驻指针和并发；VMP 加载期与冷/热入口篡改检测通过。
  证据目录为 `work/strings-cse-recheck/`。

原始证据保留在本机 `work/strings-device/`、`work/strings-gradle-art/` 与 Gradle 测试报告。
源码中不保存设备连接地址、测试 keystore 或构建产物。

## 基准方法与结果

固定 256 条不同字符串，20 轮交错执行 baseline / strings / combined，每次启动新的 ART 进程，
开启 CheckJNI。组合样本还包含现有 Java/Kotlin dex2c 方法保护；测试循环本身留在 ART。
热路径预热 20,000 次，随后读取 2,000,000 次，包含 volatile sink 和索引分发成本。

| 指标 P50 / P95 | 原版 | 字符串插件 | 与 dex2c 组合 |
|---|---:|---:|---:|
| 首个字符串，含库加载与首次绑定 | 0.015 / 0.016 ms | 28.53 / 29.57 ms | 35.70 / 36.52 ms |
| 256 条全部首次访问，含上述首个字符串 | 0.396 / 0.426 ms | 33.92 / 34.82 ms | 41.19 / 41.98 ms |
| 热读取 | 13.71 / 16.26 ns | 22.87 / 24.29 ns | 22.77 / 24.26 ns |
| Java heap 分配增量（未扣除全部临时对象） | 64 / 96 KiB | 96 / 96 KiB | 96 / 96 KiB |
| 测试进程 PSS | 44.89 / 45.06 MiB | 45.21 / 45.38 MiB | 46.09 / 46.27 MiB |

这些数值不是 Android Activity 启动耗时，也不是跨设备保证。基准使用 D8，不与 R8 样例的
APK 大小混合比较。标准输出之后还需解密测试报告文本，未计入热读取指标。
独立 minified 样例一轮构建的 APK 大小约为 19.5 KiB（原版）、151.8 KiB（字符串）、199.7 KiB（组合）；
对应保护 SO 约 117.5 / 165.4 KiB。布局随机化会影响大小，构建耗时单次结果不作为稳定基准。

在同一参考设备、相同 fixture/CheckJNI 条件下锁定回归预算：字符串/组合的首读 P95 ≤45/55 ms，
256 条首次访问 P95 ≤50/60 ms，热读取 P95 ≤35 ns，Java heap 增量 P95 ≤160 KiB。
这是候选回归门槛，不能替代目标应用的启动、内存和包体预算。

## 复现

从仓库根目录运行，JDK 21 的 `JAVA_HOME` 已设置；设备参数必须显式指定。

```powershell
./dex2c/gradlew.bat -p dex2c check :gradle-plugin:validatePlugins `
  -Pdex2c.hostCompiler=F:/Project/android/LLVM-Patch/build/bin/clang.exe `
  -Pdex2c.ndk=F:/Android/Sdk/ndk/30.0.16248370

python tests/dex2c/strings_gradle.py --gradle dex2c/gradlew.bat `
  --sdk F:/Android/Sdk --clang build/bin/clang.exe --serial <serial> --work-dir work/strings-gradle-new
# 加 --staging <本地 Maven staging 目录> 可改为发布包消费验证。

./dex2c/gradlew.bat -p dex2c :core:prepareStringDeviceFixtures `
  -Pstrings.fixtureDirectory=F:/Project/android/LLVM-Patch/work/strings-new `
  -Pdex2c.hostCompiler=F:/Project/android/LLVM-Patch/build/bin/clang.exe `
  -Pdex2c.ndk=F:/Android/Sdk/ndk/30.0.16248370
# 再以独立目录加 -Pstrings.combined=true 生成组合 fixture。

python tests/dex2c/device.py --sdk F:/Android/Sdk --java "C:/Program Files/Java/jdk-21/bin/java.exe" `
  --serial <serial> --fixtures work/strings-new
# 对组合 fixture 同样执行，生成已签名测试 APK。

python tests/dex2c/strings_benchmark.py --adb F:/Android/Sdk/platform-tools/adb.exe `
  --serial <serial> --strings work/strings-new --combined work/strings-combined-new `
  --samples 20 --report work/strings-benchmark-new.json --enforce-reference-budgets

python tests/cse-hardened/recheck_test.py --ndk F:/Android/Sdk/ndk/30.0.16248370 `
  --clang build/bin/clang.exe --serial <serial> --work-dir work/strings-cse-recheck-new
```

`strings_gradle.py` 仅对其测试调用设置 `kotlin.internal.collectFUSMetrics=false`，避免 composite build 中
两份 Kotlin 插件统计服务的配置缓存反序列化冲突；生产插件不修改消费者的 Kotlin 统计设置。
使用本地 composite 样例直接运行 Gradle 时，遇到该冲突可为该次调用传同一 `-P` 参数。

## 发布前尚缺

API 26 和 16 KiB 页面的实际设备、目标业务应用的启动/内存/包体门槛，以及 Linux 消费者构建。
初始化后篡改及缓存边界已通过上述回归；Java 热缓存命中不进入 native，也不触发实时复验。
未执行这些验证，不上传正式版本。
