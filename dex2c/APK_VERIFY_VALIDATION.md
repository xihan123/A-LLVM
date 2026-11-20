# 0.1.11-verify1 验证记录

## 2026-11-20 APK verifier 结果完整性

`tests/apkverify/test_verify.py` 增加 schema version 1 的 `run-summary.json`。每次 CLI 运行先发布新的
`running` 状态并清空旧结果；最终摘要记录 `passed` 或 `failed`、退出时间、实际测试方法、33 个 case
计数、unittest 状态、输入前后文件身份，以及 `results.json` 精确字节的大小和 SHA-256。逐例 `results.json`
仍为顶层数组，保留 APK/证书摘要、API、host 退出码，以及适用时的 device 与 apksigner oracle 记录。
只有六个预期方法和每个预期 case 均完整且唯一、所有结果字段符合预期、输入在运行期间未变化时才会通过；
调用者还必须检查 CLI 退出码为 0。旧 `passed` 摘要不能代表新一轮结果。

隔离结果协议回归（包括普通 Python、`-O`、vendor 源文件校验及 CLI 旧成功状态失效）记录在
`work/m5-apkverify-result/development-v2/`。该回归覆盖 stubbed 的 `setUpClass` → `probe` → CLI 汇总
共享结果列表，不代表重新运行了真实 native 33 场景。此前真实 native probe 的 MinGW/mbedTLS
配置阻碍已由下方 host-only formatter gate 修复；完整 native 33 场景仍须按复跑入口单独运行。

## 2026-11-20 MinGW host formatter 兼容性

`tests/apkverify/CMakeLists.txt` 只在 `MINGW AND NOT ANDROID` 分支启用 host gate。配置检测到
`CMAKE_CROSSCOMPILING` 时立即失败，因为这个 gate 必须实际运行生成的检查程序。随后用当前配置选择的
C 与 C++ 编译器分别执行 `try_run`，显式传入 runtime、裁剪版 Mbed TLS include 目录、
`MBEDTLS_CONFIG_FILE="apkverify_mbedtls_config.h"`，以及 `MBEDTLS_PLATFORM_C`、
`MBEDTLS_PLATFORM_SNPRINTF_MACRO=snprintf`、`MBEDTLS_PLATFORM_VSNPRINTF_MACRO=vsnprintf`。
每次配置先清除四个 probe 结果变量及其 cache，不能用手工 cache 值代替编译或运行。

两个 probe 共享 `formatter_probe.c` 的 25 项检查，并分别以 C 与 C++ 编译：普通输出、刚好填充、
截断时返回完整长度、终止符和 sentinel、`n == 0` 不写入、`NULL` 加零长度、`n == 1`，以及
`va_list` 的 `vsnprintf` 路径。只有编译成功、运行返回 0 且输出严格为 25 行 `PASS <id>` 加
`SUMMARY checks=25 failures=0`，才向 `ndkp_apkcrypto` 添加这三个宏的 `PUBLIC` 定义。正式的
`apkverify_formatter_c`、`apkverify_formatter_cpp` 目标再从该库继承宏并直接运行，验证链接和消费
路径与 configure gate 一致；Android 和非 MinGW host 不创建这些目标。

本机验证使用 WinLibs MinGW-w64 x86_64 UCRT POSIX/SEH GCC/G++ 16.2.0、CMake 3.28.3、Ninja
1.13.2。已有成功构建树上的后续 configure、build 和运行记录（包括 stdout/stderr）位于
`work/m5-native-host/development-v2/`；构建目录为 `cmake-build4/`。后续 `final-build.stdout.txt`
是 `ninja: no work to do` 的 23 字节记录，不是初始 fresh build 的原始流；初始成功生成的目标
仍以该构建树中的文件为准。C 与 C++ formatter 各为 25/25，退出码 0；`apkverify_probe.exe`
无 fixture 参数时退出码 2，这是该 probe 的参数用法结果，不作为 formatter 通过条件。
`source-final/` 保存四个最终源码副本，`source-final-manifest.json` 记录大小和 SHA-256。

同一构建目录以四个故意过期的 `91/92` cache 值重新配置，仍退出 0，随后
`CMakeCache.txt` 恢复为 C/C++ `COMPILE_RESULT=TRUE`、`RUN_RESULT=0`，证实配置会重做检查。
使用 `-DCMAKE_SYSTEM_NAME=Windows` 的新目录配置退出 1，并报告
`The MinGW apkverify host requires a runnable formatter capability probe; cross-compiling is not supported`。
前三次失败配置的专用 stdout/stderr 和逐次源码快照没有单独保存；对应 configure 日志仍保留在
`cmake-build/`、`cmake-build2/`、`cmake-build3/` 的 `CMakeFiles/CMakeConfigureLog.yaml`，不对这些
尝试声称有额外的独立流证据。

日期：2026-10-21。代码与本机验证已完成，**未达到正式发布验收**。
`verifyApkSignature`、QSEG 继续默认关闭；未远程发布，未递增/覆盖正式 `0.1.9 / p16`。
工作树中原有 QSEG、LLVM overlay、解释器及 vm.h 改动保留，此候选没有新增 LLVM pass 改动。

## 环境和通过项

Windows、JDK 21、Gradle 9.8.1、AGP 9.4.1、NDK `30.0.16248370`、A-LLVM Clang 21。
设备 `192.168.43.102:5555`，OnePlus7，Android API 37、4 KiB 页面。
设备上的测试 APK/路径为专用夹具，来源测试使用新建 UUID 安装布局目录，结束后清理；不是系统安装器接受
异证书 split 的测试，也没有修改实际用户应用的安装目录。

| 项目 | 结果与范围 |
| --- | --- |
| 核心/插件 | `check :gradle-plugin:validatePlugins` 通过；27 个核心用例，包含公钥支持范围、模式优先级、旧注解、继承、Kotlin、IR receipt、缓存损坏拒绝 |
| 原生密码验证 | Windows + 实际 arm64 probe，6 组测试/33 个场景通过；六种签名算法、v2/v3、1 MiB 分块、SDK 范围、复制签名块、换证书、内容/长度/算法破坏、v1-only/v3.1/轮换拒绝 |
| 来源与状态 | 15 个设备场景通过：base/split、直接/解压 STORED/DEFLATE、异证书宿主、错误 base/sibling、缺少 base、多线程复用、初始化重入、解压 SO 替换、文件替换、验证后新增 split |
| Java/Kotlin 语义 | 原 Java/Kotlin、普通 JNI、VMP JNI 在 ART/CheckJNI 下输出一致；异常、同步、数组、浮点、递归、回调与首次并发调用 |
| NATIVE-only | 实际构建、8 线程调用、数组/回调/异常/同步及错误签名拒绝通过；没有业务 VMP 方法时跳过 post-VMP receipt 要求 |
| QSEG + 验签 | ART 三方差分通过；缺失/压缩容器、目录/块 AEAD、认证后的错误字段和非法 DEFLATE 均拒绝 |
| 最终 APK | VMP 普通夹具 8 项、QSEG 夹具 10 项通过，覆盖 apksigner、清单/证书/DEX/SO/容器替换、独立 APK 输出、重复 split 类及删除旧成功报告 |
| Gradle 消费构建 | 独立样例副本通过 Debug/R8 Release、既有 SO 共存、16 KiB 静态对齐、增量/缓存恢复、注解移除、buildTypes、缺失证书拒绝；最终候选 assemble 自动执行 verifyReleaseDex2cApk |
| LSPosed | 实际 LibXposed 102 主/子进程、独立 ClassLoader、重复注册、参数/结果/异常 Hook、已有 native 库均通过；开启新验签 |
| 相关回归 | 66 个证书来源/parser 与 mix 检查、14 个 CSE sealer、9 个 QSEG sealer、依赖摘要、四 ABI smoke、构建路径 smoke 均通过 |
| 产物分析 | MT 最终 DEX 检查和独立候选 IDB 四处 native 分析完成，参考数据库未覆盖；见下方证据 |

RSA-PSS 两个 JCA 生成的夹具由主机和设备原生实现验证通过，但未计作 SDK apksigner 交叉验证通过：
本机 JDK 21 缺少 apksig 使用的旧 `SHA256withRSA/PSS` / `SHA512withRSA/PSS` provider 名称。
其余合法基准包含 SDK apksigner 输出及与 SDK 的交叉核对。证书过期/CA 链不是 APK 固定身份策略。

## 性能和未通过项

同一 `sample/Logic.class` SHA-256：`d26ca5d701d5a1d06c692947fb76a05828205d81d00ba2731fe5d463543d38a0`。
保留 p16 原始 APK/编译器，以交替顺序采集，每组 30 对，P95 使用 nearest-rank。
工作负载为 ART/CheckJNI 中预热后 1000 轮算术、递归、字符串调用。

| 温态组 | p16 P95 | 候选 P95 | 回退 | 判断 |
| --- | --- | --- | --- | --- |
| 第一候选快照 | 1498.741 ms | 1547.242 ms | +3.24% | ≤5% |
| 最终验证器快照 | 1536.806 ms | 1492.916 ms | −2.86% | ≤5% |

两组均达标。差异受 VMP 随机构建、设备状态和采样噪声影响，微基准不覆盖接入模块的所有业务，
也**不包含完整初始化耗时**，不构成稳定加速或全面性能结论。

同源码、同证书的小型 LSPosed 样例，p16 APK 498246 bytes，候选 580166 bytes，增加 **81920 bytes / 16.44%**。
这超过最终 APK 增量 ≤5% 的要求。此数值来自实际 APK，不是 SO 大小推算。
后续已在三个真实 Release 接入模块上独立验证，最终 APK 增量均低于 1.2%，
满足各自尺寸门槛。该结果不撤销小样例的失败。

以下门槛未完成：

- 完整保护启用/禁用的初始化 P95 增量 ≤1 秒。已有 LSPosed 功能验证不等于可靠的完整 A/B 时间测量，
  不以回调累计时间替代。
- API 26 实机与 16 KiB 页面实机。用户确认没有额外设备；API 26 交叉编译/格式模拟和静态 16 KiB 对齐
  不记作真机验收。
- 其他接入模块的性能与最终 APK 增量验证；小样例的体积门槛已明确失败。

## 可复核产物

本机原始数据保留在仓库 `build/apkverify/`（忽略的构建目录）。源码树中的本记录保存结论和关键摘要；
不要把构建目录内 C++/IR、测试私钥或无符号限制的中间 SO 当作交付 APK 内容。

| 文件/目录 | 用途 |
| --- | --- |
| `security-final/results.json` | 33 个密码验证场景 |
| `runtime-origin-final/results.json` | 15 个引导与来源场景 |
| `final-fixtures-v2/device-results.json` | 最终 Java/Kotlin/普通 JNI/VMP JNI 差分 |
| `native-only/device-results.json` | NATIVE-only 差分 |
| `qseg/device-results.json` | QSEG 差分与负例 |
| `xposed-final-results.json` | 实际 LSPosed 双进程日志 |
| `warm-performance/results.json`、`warm-final/results.json` | 两组逐次性能数据、P95、输入 APK 摘要 |
| `apk-size.json` | p16 与候选样例的实际 APK 尺寸及摘要 |
| `sample-final/module/build/reports/dex2c/release/apk-verification.json` | 最终 APK 验证报告 |
| `ida-candidate-final/candidate.i64`、`analysis.json` | 独立 IDB 与限定范围反编译 |
| `mt-candidate.json` | MT 类轮廓和 install 薄包装 Smali |

候选样例 APK SHA-256：`c302c382ac7236aabeeaf9aeae8443d5b564d922b498268235f91786adcedc49`。
其中保护 SO SHA-256：`86ec8e70b359b3ca8ab148bd6fb293df23c2f0881717693b914c334c63fb4313`。
最后一组性能夹具 APK：`2adce316b6041d820aa01c5f125d9b9d182804f700d96e5aa2b950285257e703`。
p16 性能夹具 APK：`201ecf252970b48d0deff4ed6e196f1a05e8d669b9800820cbcb3aa1bc7dcf4b`。

## 复跑入口

PowerShell 中设置 `$env:JAVA_HOME` 为 JDK 21，所有 `-Pdex2c.xxx=...` 参数整体加引号。

```powershell
.\dex2c\gradlew.bat -p dex2c check :gradle-plugin:validatePlugins `
  '-Pdex2c.hostCompiler=F:/Project/android/LLVM-Patch/build/bin/clang.exe' `
  '-Pdex2c.ndk=F:/Android/Sdk/ndk/30.0.16248370'

# CMake 主机 / Android probe：tests/apkverify/CMakeLists.txt
python tests/apkverify/test_verify.py --probe <host-probe> --sdk <sdk> --java <jdk> `
  --serial <serial> --device-probe <arm64-probe> --work <new-results>
python tests/apkverify/test_vendor.py

.\dex2c\gradlew.bat -p dex2c :core:prepareDeviceFixtures `
  '-Pdex2c.hostCompiler=<clang>' '-Pdex2c.ndk=<ndk>' `
  '-Pdex2c.fixtureDirectory=<new-fixture-dir>' '-Pdex2c.verifyApkSignature=true'
# 可分别追加 '-Pdex2c.nativeOnly=true' 或 '-Pdex2c.segmentedData=true'
python tests/dex2c/device.py --sdk <sdk> --java <jdk>/bin/java.exe --serial <serial> `
  --fixtures <fixture-dir> --ndk <ndk> --clang <clang>
python tests/apkverify/device_runtime.py --sdk <sdk> --java-home <jdk> --ndk <ndk> `
  --serial <rooted-serial> --fixtures <fixture-dir> --output <new-results>
python tests/apkverify/test_final_apk.py --fixtures <fixture-dir> --java <jdk>/bin/java.exe `
  --apksigner <sdk>/build-tools/37.0.0/lib/apksigner.jar
python tests/dex2c/gradle.py --gradle dex2c/gradlew.bat --sdk <sdk> --clang <clang> `
  --work-dir <new-sample-dir> --verify-apk-signature
python tests/dex2c/xposed.py --sdk <sdk> --serial <serial> --sample-root <sample-dir> --report <report.json>
python tests/dex2c/runtime_benchmark.py --sdk <sdk> --java-home <jdk> --serial <serial> `
  --baseline-fixtures <p16-fixtures> --candidate-fixtures <candidate-fixtures> --samples 30 --output <new-results>
```

测试夹具签名材料仅供测试。正式发布必须另行满足以上门槛，使用正式签名证书并递增 patchset，不能覆盖既有产物。
