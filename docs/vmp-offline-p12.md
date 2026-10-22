# LLVM 21 p12 离线指令语义随机化

## 目标与边界

保持完全离线，不增加服务端授权、硬件密钥、设备绑定或首次联网激活。
目标是增加每个方法的分析工作量，不保证算法不可恢复。此次仅修改 LLVM 21；
LLVM 20 行为不变。没有混淆开关时仍不进行 IR 变换。

## MT / IDA 基线

2026-10-19，MT MCP 读取 9 方法基线 APK 的 DEX 和 ELF；独立 IDA MCP 实例核对
同一 SO 的摘要并重新反编译 9 个入口。入口地址由同次构建的 linked.so 符号辅助定位，
恢复阶段只读取 APK 和入口伪代码，未读取生成的 C++、IR 或构建密钥。

- APK SHA-256：`6bdb301c0d1fbec859f572c52600a5c9390b003dfc8ee7b4dc8e1bb6672f7469`。
- SO SHA-256：`e73245e49420947241a5b4dcc433834dd2847d87bc5dbb56938d64839cde3a11`。
- 旧恢复器再次完整恢复 9/9 方法、160,110 字节、971 个基本块和 6,260 条指令。
- MT 可见受保护样例类的类型索引、注册包装和 native 桥接；这些仍能辅助定位语义。
- 工具初始状态不是此样本：默认 IDA 加载的是旧 SO，MT 原有文件也没有 9 方法基线。
  此次复核另传入基线 APK 并启用独立 IDA 实例，避免跨版本地址混用。

## 改动

旧 wire ordinal 映射由 `FunctionKey` 确定。入口密钥恢复后，公开解释器规则足以把
解密后的操作码直接解释成统一语义。原生间接分支混淆不会改变这条恢复路径。

p12 最终实现使用操作系统随机源显式初始化 `CryptoUtils`，在编译时另生成每方法随机置换，
避免 Windows 默认时间戳种子可枚举；随机源失败则拒绝编译。Sattolo 循环保证
1..28 的每个语义都与旧 key-only 映射不同；0/NOP 保持原约定。
解释器原有解码结果成为该方法私有的分发编号，克隆解释器的比较常量与 handler
边同步重写。新增置换不以一个反向数组或随机种子写入产物。

复用原有 dispatch chain、CIE 和 post-VMP 间接分支处理，不增加一层运行时映射查表。
克隆解释器缺失或分发专门化失败时编译失败，禁止退回旧语义解释器执行新字节码。
共享解释器源码及生成的 vm.h 不变，不需要重新生成 bitcode。

开启 `-irobf-debug` 的构建日志仍包含诊断映射，只应保留在开发环境。
旧通用 trace 中的数字操作码在此模式下代表私有分发编号，应结合该构建的映射解读。

## 验收方式

`tests/vmp/opcode_diversity.py` 编译两个方法、重复两次构建，验证 28 项映射是双射，
且每项都不同于仅按实际 payload key 推导的旧映射，并验证无开关不变换。
运行语义另由现有 VMP、JNI/ART、异常、重入和并发测试验证。

新产物需要先成功恢复入口密钥并识别块标签，再测试旧语义解码器。
仅因入口正则未匹配、地址错误或工具异常而失败，不算加固有效。
即使旧解码器失败，也只能证明旧规则需要适配，不能证明新映射无法恢复。

## 剩余恢复途径

分析者仍可从每个解释器的分发边识别 handler、根据操作数结构推断语义，或记录运行时行为。
payload 解密、块标签、操作数布局和 JNI 交互仍可分析；公开证书不是秘密，CSE 的既有
离线恢复边界没有改变。单纯增加加密轮数、再次平坦化或扩大保护方法数量不能解决这些边界。

## 结果

Windows x86_64、NDK 30.0.16248370、LLVM 21 Base revision
`2d287f51eff2a5fbf84458a33f7fb2493cf67965`。设备为 OnePlus 7 / API 37 / 4 KB。
此候选使用本地 dex2c 0.1.4 staging 构建；当时未发布 Maven 或 NDK Release。
以下 APK、SO 摘要及恢复对照属于发布前审查之前的候选包；显式系统随机种子修复后的
复验单独记录，不把旧候选包的体积和攻击结果当作最终源码重新构建的测量。

| 检查 | 结果 |
| --- | --- |
| 新候选入口 / 块标签 | 9 个密钥仍可恢复，971 个块标签全部匹配 |
| 旧解码器 | 基线 9/9 完整恢复；候选 0/9 通过语义格式校验 |
| 保护范围 / 字节码长度 | 同样 9 方法，各方法字节码长度与基线一致 |
| SO 大小 | 1,533,816 → 1,549,664 bytes，增加 15,848 bytes（1.03%） |
| VM 分支 | 每个 VM 仍为 594 条 IR 间接分支；既有 post receipt 校验通过 |
| 字符串 / 导出 / 对齐 | 287 个生成字符串未检出保护明文泄露；仅导出 JNI_OnLoad；ELF/APK 16 KB 对齐 |
| 其他 native 库 | DexKit、jiagu_compat、MMKV 与基线逐字节相同 |
| 真机语义 | 新编译的 55 方法 JNI 产物通过原 DEX / 普通 JNI / VMP JNI 三方差分和 CheckJNI；错误签名、篡改拒绝 |
| VM 回归 | 并发、递归、重入、全局/TLS、13 种 cast、O0/O2 调用帧和异常语义通过 |
| 工具链 | Clang 构建、21 基线 patch apply --check、25 项 overlay、15 项 dex2c Python、strict/post、新映射测试、字符串加密、四 ABI、CMake/ndk-build 通过 |
| 实际入口 | 新 APK 已安装，两次打开/返回模块设置正常，无 JNI/崩溃错误；安装摘要和四个 SO 的执行映射匹配 |

SO 体积是单次随机化构建结果，不代表固定增加量；没有进行稳定性能基准。
APK 为常规 Release（V2/V3），基线为 CI 包（V2），因此不把整包差异全部归因于本次 pass。
核心 Gradle check / validatePlugins 当时为 UP-TO-DATE；设备 fixture 已重新生成和执行。

候选 APK SHA-256：`360b8d79515265f9dec140e02667e68d051a30928092118c6196035490be227c`。
候选 SO SHA-256：`cdc5dfa6726e4980efc0a99bf5e723e7eff58c9561dd2dab0e799de335badf24`。

本机证据保存在 `work/offline-p12/`：`baseline/` 为 2026-10-19 的 IDA MCP 与恢复对照；
`candidate/` 包含 APK、SO、MT MCP 记录、IDA MCP 入口、`legacy-probe.json` 和
`hardening.json`；`art-device-results.json`、`p12-device.json`、`installed.json`
保存设备结果。编译和回归日志为 `work/offline-p12-*.log`。

没有编写适配新映射的恢复器，也没有给出攻击耗时倍数。Linux、API 26 和 16 KB
真机未覆盖；此次不是 LLVM 20 升级。结论限于旧恢复规则需要增加逐方法语义分析，
并非证明 9 个方法已不可恢复。

## 0.1.4 发布前审查复验

2026-10-19，审查发现 `CryptoUtils` 在 Windows 默认用时间戳初始化 PRNG。
最终源码改为使用 LLVM `getRandomBytes` 取得 16 字节系统随机种子，失败即终止编译。
另外修复本地构建脚本的硬编码 NDK 路径、缺少 Base revision 校验和跳过已有 CMake
配置的问题，并补充四个回归用例。Kotlin 用例加入名字含 `$lambda$` 的 private static
源码方法，确认 metadata 能区分普通 callable reference 与编译器生成的 lambda。

使用最终源码重建 Clang，随后再次增量构建，Ninja 报告 `no work to do`。复验结果：

- 25 项原有 overlay 测试及 4 项本地构建回归、15 项 dex2c Python 测试通过。
- Gradle `check` / `validatePlugins` 强制重跑，13 项测试无失败、无跳过；
  包含主机 JNI 差分与 ARM64 VMP 编译。0.1.4 staging 的五个坐标、85 个文件及校验和通过。
- 精确 LLVM 21 基线 patch 检查、新指令映射、strict/post、字符串加密、四 ABI、
  CMake 和 ndk-build 回归通过。
- 重新生成 55 方法设备产物，API 37 / 4 KB 设备的原始 DEX、普通 JNI、VMP JNI
  三方差分与 CheckJNI 通过，错误签名和篡改被拒绝。
- 独立 Android 样例的 Debug、R8 Release、依赖回调、已有 SO、16 KB 静态对齐、
  DEX 包装、增量与缓存恢复、注解删除及缺少证书拒绝通过。

复验日志位于 `work/review-p12-*.log`；Gradle 发布检查与文件清单位于
`dex2c/build/release-0.1.4-dxqk2rxx/`；设备结果位于
`dex2c/core/build/device-fixtures/device-results.json`；Android 集成结果位于
`work/review-dex2c-0.1.4-gradle/results.json`。Maven 插件不包含 Clang，p12 NDK 整包仍未发布。
本次未重做旧候选包的 MT/IDA 对照，也未覆盖 Linux、API 26 或 16 KB 真机。
