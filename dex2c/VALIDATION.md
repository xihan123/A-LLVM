# dex2c 实施与验收记录

日期：2026-10-19。dex2c 插件 0.1.0 至 0.1.3 已发布到 Maven；p11 编译器已本地构建，NDK 整包尚未发布。

## 0.1.3 / p11 原生二次混淆与去虚拟化复验

- 原问题确认：0.1.2 在 VMP 后仅执行 `-Oz`；FLA 排除解释器，导致 `.s0` 没有二次混淆。
  p11 新增 `-irobf-vmp-post`，优化后展开 switch，再对入口、VM 和 `.s0` 辅助函数使用间接跳转。
  跳转目标使用加密的函数内相对偏移表，避免通用页表的大量动态重定位；入口密钥、分发比较做 CIE。
- 编译器逐函数验证 CFG 并写 `ndkp.vmp.post`，插件复核实际分支和 receipt；缺失能力、残留 switch/
  条件 br、重复处理等情况失败退出。字节码必须前后一致；交付对象从同份验证 IR 关闭后续 IR pass 生成。
- 12 项核心、插件校验、post/strict 回归、25 项 overlay、字符串加密、四种 ABI 和 CMake/ndk-build 通过。
  49 方法 ART CheckJNI 差分、错误证书/篡改拒绝、LibXposed 双进程/隔离加载器/重复注册通过。
  R8、Debug/buildTypes、缓存恢复、删除注解和已有 SO 共存通过；QD 63 项 Android、40 项构建测试通过。
- Maven 0.1.3 的 85 个版本文件逐字节核验通过。QD 已从远程仓库复建，最终 SO 为 722,216 bytes，
  APK 为 7,044,073 bytes；相对 0.1.2 的 SO 增加 196,520 bytes。其他三个 SO 逐字节不变。
  初次通用跳转表方案为 1,085,304 bytes，相对偏移表减少了此项膨胀。大小随随机化略有变化。
- MT 和 IDA 核验最终 stripped SO；逐函数地址用同次 linked.so 辅助定位。四个 VM 的机器码无直接
  条件跳转。真机两次设置打开返回正常，APK 摘要和四个 SO 执行映射一致。最终 native 编译日志为
  8.872 秒，非稳定性能基准；设备为 API 37 / 4 KB，API 26 / 16 KB 真机仍未覆盖。
- **可恢复性边界**：0.1.2 从 APK 与 IDA 观察常量完整恢复 59,295 字节、349 块、2,319 条 VM 指令。
  从恢复结果生成直接 LLVM CFG，以旧 IR 仅作为 JNI/分发链接环境构建审计 APK，真机设置链路通过；
  此链接验证属于白盒验证，不是独立 APK-only 重链接器。
  0.1.3 远程复建产物从 APK 和 IDA 入口表达式同样完整恢复全部字节码（入口定位用构建符号辅助），
  167 条 CSE 记录仍可通过 APK 公开材料恢复并认证。二次混淆已生效，但不能据此宣称不可去虚拟化。

最终 APK SHA-256：`bf1cc76040ee4325999cea67a22645334967581339878fe60b0f8b0f19c3c18d`。
最终 SO SHA-256：`de840d289bd58721371adbcb812e819e4aa8c77eedca9b8871dd00efb72d9e6d`。
下方为历史版本的验收记录，“未做去虚拟化”等历史结论由本节更新。

## 0.1.2 DEX 特征修正与 MT / IDA 验证

- 桥接、lambda 工厂、接口辅助类、运行时类和 SO 使用稳定短名，删除转换后 class 的选择注解。
- 类型解析改为数字索引，精确类型名称放入一段 native CSE 加密数据；保留 Class 字面量以适配 LSPosed 类型重命名。
- 只导出 JNI_OnLoad，它仅注册运行时入口；业务类仍按实际 Class 懒注册。
- 核心 11 测试无跳过；49 个 Java/Kotlin 方法通过 ART CheckJNI 原 DEX / 普通 JNI / VMP JNI 差分，含类名哈希碰撞用例。
- 错证书退出 127，篡改 VM 退出 137；Debug/R8/依赖回调/native 共存/缓存恢复/注解删除/buildTypes/缺证书拒绝通过。
- QD 从远程 Maven 0.1.2 构建并安装：63 项 Android 单测、40 项构建回归通过，设置入口两次打开返回和同进程热重载通过。
- MT 最终 DEX/ZIP 的旧前缀搜索 0 命中；SettingHook 类型方法从 194 条指令/32 字符串引用缩为 69/0。
- IDA MCP 对最终 stripped SO 核对四个 432–452 bytes 入口分别调用独立 VM 与字节码自校验；证书及校验值参与 VM key。
  地址使用同次 linked.so 符号辅助定位；不能把自动分析的函数合并、unflatten 错误或基本块数量当成强度评分。
- 最终 SO 525,696 bytes，APK 6,863,849 bytes；相较 0.1.1，DEX 减少 1,760 bytes，SO 增加 22,096 bytes。
  保留每方法独立 VM；随机化使重复编译尺寸存在波动。原有其他三个 SO 逐字节不变。
- Maven 五坐标 85 个版本文件匿名逐字节核验，metadata 保留三个版本；最终安装 APK 和四个 SO 执行映射核对通过。

APK SHA-256：`0069cc39fe37437b507bf116c2f570d2c7d7467d6fe11b02bb116efbbf0a5e78`。
SO SHA-256：`4e17a2e594d7aa521fcd9a2718e65c14bbb26caab7b0886af0505573f4680521`。

强度边界：159 项生成字符串静态明文检查通过，但只使用 APK 的公开证书和 SO 派生材料，
即可离线解密并认证 167 条 CSE 记录（基线 161 条）。CSE 不提供离线密钥保密；换签名/篡改负测
不代表主动分析者无法重新派生或封装。JNI 声明、签名、Class 字面量、NDKPCSE 标记仍可见。
未做完整去虚拟化、内存 dump、API 26 或 16 KB 真机验收；本次不改编译器，仍为 p10。
详细证据位于 消费项目 的 `build/dex2c-audit/`。

## 0.1.1 保护补齐与体积验收

本次只修改 dex2c 编译/校验链路，复用 p10 现有 pass 和运行时，未变更编译器 overlay 或解释器。

- 业务 strict VMP + hardened CSE + 证书绑定 + 加载/入口字节码自校验；注册边界 FLA，JNI 辅助代码 CSE。
- `protected.raw.ll` 虚拟化后以 `-Oz` 优化，复核所有 receipt、密钥折入和 bytecode，使用最终 IR 关闭进一步 LLVM pass 生成对象；最终 SO 逐方法核对 bytecode。
- 保留每方法独立随机化解释器；sections/GC、限制导出、移除 `.comment`，link → seal → strip → verify。
- 插件携带同源运行时和 Python 封装脚本，仅要求调用方提供公开签名证书；证书/Python 可执行文件纳入 Gradle 输入。
- 核心 10 测试（未跳过）、插件校验通过；48 个 Java/Kotlin 选中方法在 ART/CheckJNI 下与原 DEX/普通 JNI 差分一致；错误签名退出 127，篡改 VM 字节码退出 137，未执行业务。
- CSE 封装 14 测试、证书读取 66 项所有权/解析及 runtime mix 检查通过。
- 独立 Gradle 样例通过 Debug、R8、依赖回调、现有 SO 共存、16 KB 对齐、缓存恢复、注解删除、buildTypes 和缺少证书拒绝；失败任务不留可打包的旧 SO。
- Maven 五个坐标的 85 个版本文件匿名逐字节验证，元数据保留 0.1.0 并指向 0.1.1。

消费项目 通过远程 Maven 0.1.1 复建（没有 includeBuild 或 staging 覆盖）并实际安装：

| 指标 | 结果 |
| --- | --- |
| 选中方法/回调 | 4 个；最终 DEX 均只保留 native 包装 |
| 本轮开始 SO → 最终 SO | 999,384 → 503,600 bytes，减少 49.61% |
| 首轮交付 APK → 新 APK | 7,339,005 → 6,814,717 bytes，减少 524,288 bytes |
| 字符串检查 | 147 个生成业务/JNI 字符串，基线全部明文可见，新 SO 均未检出 |
| ELF 导出 | 仅注册 JNI 入口，`.comment` 已移除 |
| 签名/对齐 | 证书与最终 signer 一致，CSE seal 验证通过，ELF/ZIP 16 KB 对齐 |
| 其他 native 库 | jiagu_compat、DexKit、MMKV 与旧 APK 逐字节相同 |
| 主机回归 | 63 项 Android 单元测试、40 项 Python 构建测试通过 |
| 真机 | 两次进入/返回模块设置，同进程热重载后新建入口正常，无 JNI/加载/崩溃错误 |
| 安装核验 | APK 摘要一致，通过 APK/ELF 文件偏移核对四个 SO 的执行映射 |
| 本次编译耗时 | native 阶段 7.631 秒；含依赖刷新的 Maven 复建 1 分 56 秒，非严格性能基准 |

最终 APK SHA-256：`31eace850b1862a24bc7d15659ecf7f7947c69d1c5c2f93b8d390a87bca7004b`。
SO SHA-256：`90ca07c07d8ff5d915231d481549bc0a0fdbe831edac73bded72aefc7bc6e4c3`。
原始证据在 `dex2c/build/`、`work/dex2c-hardening-gradle/`、QD 的 `build/dex2c-hardening/`。

可读 C++ 只留在构建目录；JNI 交互、标准库诊断以及运行时解密后的明文仍可观察。
证书/篡改失败会终止所在进程。未测全部 QD 业务、API 26/16 KB 真机或 Linux CI。
下方保留 0.1.0 和 p10 的首轮实施记录。

## 已实现

- 独立 Gradle 构建：annotations、runtime、core、gradle-plugin，附 Gradle 9.8.1 wrapper、Kotlin 测试和 LibXposed 102 三模块样例。
- 方法/类级 `io.github.xihan123.dex2c.annotation.dex2c`，Release 默认转换，`buildTypes` 可配置；自动选择编译器生成的回调及状态机，报告结构性排除和选择来源。
- ASM → JNI/C++，保留原方法薄包装、同步语义、签名和 Kotlin metadata；接口默认方法使用同包桥接类。显式 Java 异常边、对象/数组、基本数值转换、同步和重入已在差分样例中验证。
- AGP 公共 ScopedArtifact.CLASSES（ALL）处理应用和依赖，生成 jniLibs 和 R8 规则；按实际 Class 注册，并适配 LSPosed API 类型在运行时重命名。
- LLVM 21 `-irobf-vmp-strict`、保护 receipt，逐方法检查输出 class JAR、IR 字节码和解释器入口；从同一份已验证 IR 生成交付对象。patchset 为 p10。
- 保护报告记录方法、桥接、回调关联、排除原因、IR/object/SO SHA-256 和包体大小。转换和 native 任务支持增量及缓存恢复，删除注解不残留保护 SO。
- CI 已增加插件检查和 LLVM 21 strict/cast、Windows JNI/VMP 编译门槛；工作流通过 actionlint。

## 环境

Windows / JDK 21 / Gradle 9.8.1 / AGP 9.4.1 / Kotlin 2.4.20 / NDK 30.0.16248370 / LLVM 21。

设备：OnePlus 7（GM1901），ARM64，Android API 37，4 KB 页面，LSPosed 2.2.1（7927），LibXposed API 102。

本轮重建的 Clang 为 `F:\Project\android\LLVM-Patch\build\bin\clang.exe`。当前 NDK 安装内仍是旧 Clang，接入时应配置 `dex2c.clangExecutable` 指向上述文件，或先安装包含 p10 的工具链；旧版会被插件能力校验拒绝。

## 已通过的验证

| 检查 | 结果 |
| --- | --- |
| 核心测试 | 8/8 通过，0 跳过；包含 Java/Kotlin JNI 差分、回调选择、inline 拒绝、保护 receipt |
| ART 三方差分 | 原 DEX、普通 JNI、VMP JNI 的 Java/Kotlin 输出一致；48 个方法获 VMP receipt；CheckJNI 无警告 |
| JVM 语义样例 | 溢出/移位/负数转换、float/double、除零、数组及字段修改、异常/finally/身份、String 构造与 intern、同步、多线程、递归、回调重入 |
| 选择样例 | 方法与类注解、重载、接口默认方法、Kotlin object、捕获 lambda、匿名回调、Continuation/state machine |
| VMP strict | 成功 receipt、兼容跳过、无开关不变换、未启用 VMP 拒绝、EH 拒绝、不存在的函数拒绝、i24/i128 不支持类型拒绝 |
| Cast 回归 | 13 种整数/浮点/i1 转换，plain/VMP ARM64 真机均通过 |
| Xposed | 主进程及 worker 均返回 calculate=37、exception=-99；各进程独立宿主加载器通过；重复注册未叠加；既有 native 返回 102 |
| APK | 最终 DEX 的所有选中方法仅有注册、native 调用及 D8 同步包装；桥接均 native，无原算法体 |
| Gradle | Debug 原实现；Release/R8；依赖回调；CMake native 共存；UP-TO-DATE；native FROM-CACHE 且 SO 哈希一致；删注解移除 SO；buildTypes 切换到 Debug 生效 |
| 页面 | 保护 SO 的 ELF LOAD 段及 APK 内未压缩 SO 均满足 16 KB 对齐；4 KB 真机加载运行通过 |
| 既有 VMP | roundtrip 并发/递归/重入/global/TLS；call_frames 的 O0/O2 plain/VMP/selfcheck；memory_ops O0/O2 真机差分 |
| 工具链回归 | 字符串加密 O0/O2/Oz；arm64/arm/x86/x86_64 ABI 编链；CMake 与 ndk-build |
| 构建基础 | overlay 25 项、bitcode generator 3 项、build-system runner；LLVM 21 基线 registration.patch apply --check；插件 validatePlugins；Python 语法及 git diff --check |

真机验证期间发现并修复了 ART String 构造、VMP cast 编号映射/符号扩展，以及 LSPosed API 类型重命名造成的 JNI 注册失败。最终测试包含这些回归。

## 测量

同一台设备上的一次 ART/CheckJNI 运行，包含 ADB 和进程启动时间，不作为纯方法微基准：

| 样例 | 原 DEX | 普通 JNI | VMP JNI |
| --- | ---: | ---: | ---: |
| Java 综合语义（含 12,000 次字符串构造循环） | 1.152 s | 1.483 s | 12.328 s |
| Kotlin 回调/协程 | 1.155 s | 1.157 s | 1.178 s |

VMP 对长循环的开销明显，应按业务基准选择保护范围。

样例 Release APK：1,241,786 bytes；相同配置删除注解后：39,236 bytes，增量 1,202,550 bytes。保护 SO 为 1,189,664 bytes。Debug 包启用不同的 R8 配置，不用它计算保护开销。

独立样例副本在依赖缓存已热时：首次构建 11.125 s、增量 2.202 s、清理后缓存恢复 2.419 s。缓存恢复的 SO 哈希与原构建一致。数字受本机负载和缓存影响。

## 证据与复跑

### Maven 0.1.0 发布（2026-10-19）

- 发布配置已去除 gradle-plugin 的重复 publication，排除 kotlin-fixtures；四个库及 plugin marker 共五个坐标，包含八个二进制/源码 JAR、POM 和 Gradle metadata。
- `check :gradle-plugin:validatePlugins publishAllPublicationsToStagingRepository` 通过，核心测试 8/8、0 跳过。核对了 POM 依赖、plugin marker、JDK 8/21 目标、JNI 资源和许可文件。
- 独立 Android 消费项目分别从本地 Maven staging 和远程仓库解析 dex2c，无 includeBuild；Debug、R8 Release 均构建成功，Release 的一个方法通过 VMP 校验并打包 SO。远程消费验证先 clean 并禁用 build cache，日志记录了五个坐标的实际下载。
- 远程目标为 `https://mirrors.xihan.website/repository/maven-releases/`；发布前五个坐标的 0.1.0 产物均不存在。
- **远程发布成功**：五个坐标全部通过 Gradle Maven 发布；匿名下载 110 个文件，17 个版本产物及其校验文件与本地 staging 逐字节一致。SHA-256/SHA-512/SHA-1/MD5 和 Maven 版本 metadata 均核验通过。未覆盖已有 Release。
- 本地发布副本：`dex2c/build/maven-staging`；报告：`work/dex2c-maven-release.json`；日志：`work/dex2c-maven-staging.log`、`work/dex2c-maven-consumer-staging.log`、`work/dex2c-maven-publish.log`、`work/dex2c-maven-consumer-remote.log`。

接入及完整命令见 [README.md](README.md)。关键证据（仓库内构建目录）：

- `dex2c/core/build/device-fixtures/device-results.json`：ART 三方输出与耗时。
- `dex2c/core/build/device-fixtures/native/protection.json`：48 个方法及 IR/object/SO 哈希。
- `work/dex2c-xposed-results.json`：最新样例进程 27336、27367 的主/worker 与独立加载器日志。
- `work/dex2c-build-acceptance/results.json`：构建、缓存、注解删除、buildTypes 和大小数据。
- `work/dex2c-*.log`：各工具链、主机、Gradle 和设备测试日志。

## 明确边界

- 尚未在 16 KB 页面设备和 API 26 设备运行；本轮实机为 API 37 / 4 KB。16 KB 仅完成静态对齐检查。
- 远程 GitHub CI 尚未触发。本轮 dex2c 验收范围为 Windows / LLVM 21 / ARM64，未宣称 Linux、LLVM 20 或其他 Android ABI 支持。
- 验证使用按 消费项目 写法建立的可控宿主和 LibXposed 模块，未替换或验证生产 消费项目 APK 的全部业务。
- 动态字符串反射目标需应用维护自己的 R8 规则。构造器、初始化代码、类结构、类型解析表和 JNI 交互仍可见；仅选中的实现进入 VMP。
- dex2c 插件 0.1.0 已发布到 Maven；p10 NDK 尚未发布。本地开发 Clang 与样例 APK 已生成。
