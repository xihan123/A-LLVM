# 核心增强路线图

LLVM 21 的 M1 多组 VM 指令融合实现、专项验证与原生样例已完成，让同一函数可以执行多组独立的融合指令。随后逐步增加
handler 和操作数布局的变化，缩短敏感数据的驻留时间，把完整性检查接到实际共享库入口，最后进入
AArch64 机器码层。每批交付一个可在业务产物上启用和验证的行为。

## 当前基线与范围

源码基线为 `dev` 的 `19506a4531cbe722e13df9b8625bd8b53f121c4e`；规划和对照仍保留 p22 基线，
当前工作区的 `PATCHSET_VERSION=p23` 用于 LLVM 21 M1 多组融合实现。LLVM 21 的最新 VM 核心增强
是 `523c466`（p20 单对融合）。p21/p22 和其后提交修复了严格编译、Windows 证书兼容和 QSEG 测试
路径。以当前源码和候选构建为准，早期版本的性能数据只对应当时的样本。
[补丁集版本](../config/patchset.env) · [设计记录](../DESIGN.md)

对标成熟商业保护的维度是逐方法语义差异、敏感状态驻留、自身完整性、机器码覆盖和部署成本。
这些维度用本项目的真实产物评估，厂商内部实现和强度百分比不在比较范围内。目标是提升静态分析和
运行时篡改本库的成本。产品保持离线，服务器、硬件密钥、设备绑定和联网激活均在范围外。交付 APK
含公开证书、代码和运行所需材料，因此 APK-only 保密、运行时不可提取和同进程信任根均不作为目标。

| 维度 | 仓库已有实现 | 核心缺口 |
| --- | --- | --- |
| VM 指令 | LLVM 21 逐方法系统随机 opcode 映射与私有解释器 clone、ChaCha 字节码、strict 选择、post 原生间接分支。p23 已将 p20 的单组融合扩为每函数最多四组不重叠的同块相邻整数运算，原生样例 raw/post 与真机语义通过。 | dex2c lowering 隔断相邻算术，Java 路径尚无融合收益；handler 结构和操作数布局的真实变化仍待后续阶段。 |
| 敏感数据和状态 | CSE hardened 使用 ChaCha20-Poly1305 与 HKDF-SHA-256。QSEG 按需恢复，保留 VM 内层编码，`acquire/release` 与 1 MiB LRU 约束空闲借用缓存。只有原函数为 `nounwind` 才生成 VM 主借用，原生展开未证实的路径仍固定驻留。 | CSE 和 QSEG 交付的业务字符串仍有静态存储期，Java 字符串仍可被缓存或 `intern()`。需另建受控数据接口并缩短 VM 密钥、缓存和调用帧残留。 |
| 完整性 | CSE/QSEG 可度量本 SO 全部可执行 `PT_LOAD` 的实时映射字节，已覆盖其中的解释器。已有显式低频 `integrityRecheck`。SelfCheck 的 FNV 只校验 VM 字节码。完整 APK 验签与证书提取绑定有不同覆盖。 | 让没有 CSE pool 的翻译单元也能通过本库已认证的上下文接入加载与业务入口检查。 |
| 共享库与机器码 | 多个反分析 pass 只查 `main`，无 `main` 的共享库会跳过相应注入。已有原生间接分支由 IR pass 生成。 | 面向共享库的明确接线、AArch64 后端变换。函数级 SO 机器码按需加密尚未实现。 |

`segmentedData` 和 `verifyApkSignature` 在 dex2c 插件中都默认 `false`。目标是 QDReadHook 的
合法 root / LSPosed 使用环境。继续保持各项保护显式启用，兼容宿主和框架的正常加载与调用。
验收时分别核对仓库所支持的能力、目标 APK 实际启用的路径和当前产物在真机上的结果。
[离线 opcode 记录](vmp-offline-p12.md) · [CSE](../runtime/CSE_HARDENED.md) · [QSEG](../runtime/QSEG.md) · [APK 验签](../runtime/APK_VERIFY.md) · [入口复验](../dex2c/INTEGRITY_RECHECK.md)

## 阶段与依赖

| 顺序 | 阶段 | 生产交付 | 技术依赖 |
| --- | --- | --- | --- |
| 1，首批已完成 | M1 多组 VM 融合 | 每函数有上限的多组标量融合和独立 handler；Java lowering 收益仍待实现。 | LLVM 21 p20 编码、私有 clone 和 post 链。 |
| 2 | M2 handler 与操作数布局变体 | 小范围指令族具有编译期选择的等价实现和布局。 | 共用 M1 之后的 opcode 分配与对应解码规则。 |
| 3 | M3 敏感数据借用与 VM 状态回收 | 缩短显式敏感数据、已退出帧及失效缓存的驻留时间。 | 现有 CSE/QSEG 和调用帧契约，可独立于 M1/M2。 |
| 4 | M4 共享库完整性与自保护 | 真正零 CSE pool 的翻译单元可接入加载和显式业务检查点。 | 现有验签、RX 度量和 recheck。重用 M3 借用时才依赖相应生命周期。 |
| 5 | M5 AArch64 机器码保护 | 指定函数获得真正的目标后端变换。 | 对应 NDK 的精确 LLVM 21 基线。组合 M4 时须保证最终代码摘要仍有效。 |

顺序是开发优先级。M1 首批已完成，后续批次按实际收益和代价另行安排。
LLVM 20 如需移植，单独在相应 NDK `Base revision` 上验证。解释器改动使用对应 major、已配置
Android sysroot 的 Clang 生成 `vm.h`。脚本用法为 `gen_vm_bitcode.sh <clang> [abi_tag] [20|21|all]`。
LLVM 21 的 arm64 阶段使用 `bash scripts/gen_vm_bitcode.sh /path/to/clang aarch64 21`。
第三个参数 `21` 将输出限定到 LLVM 21 overlay，省略时默认 `all`。 [生成脚本](../scripts/gen_vm_bitcode.sh)

### M1 多组 VM 融合

在 LLVM 21 `aVMP.cpp` 把单个融合描述扩成受限的集合，选定、编码和专用化使用同一组记录。
每组把两条有依赖的标量整数运算放进一个 VM 指令和私有 handler，减少一次 VM dispatch。容量和
成本以每函数上限控制，只有证明当前余量不足且收益足够时，再讨论扩展候选或 opcode 空间。
[aVMP.cpp](../obfuscation/llvm-21/Transforms/Obfuscation/aVMP/aVMP.cpp)

#### p23 实现状态

`[x]` LLVM 21 的 p23 实现已把每函数融合扩展为最多四组不重叠的相邻标量整数运算，保留每组独立语义
opcode、位宽和非交换操作数顺序，并为每组安装匹配的私有 handler。`tests/vmp/fusion.py` 已实际
核对四组上限、预留 opcode、重叠与零候选、窄整数、非交换运算、循环 PHI 和 `i64` 链，完成
protected IR → post IR → ELF 对象编链、p22 单组基线字节码长度对比，以及 ARM64 上独立原生 C
参考驱动的多组、边界和循环语义验证。

`[x]` 仓库内 `dex2c/samples/core-hardening/` 已完成 `ProtectedArithmetic.calculate(III)I` 与
`accumulate(JI)J` 的 strict VMP、post、hardened CSE、证书绑定和入口自检；最终构建成功，签名 APK 的
两项关键方法静态检查通过。同模块原生 `core_fusion_calculate` 的最终 release raw/post 均有四个融合块，
363 字节字节码完全一致且真实存在于 APK 的 `libcore_fusion.so` 中。原生路径只验收 strict VMP/post，
不声明 dex2c 的 CSE/证书保护；最终构建已去掉 `-irobf-debug`，post 中无运行时调试 helper。

`[x]` OnePlus 7 / API 37 / ARM64 / 4 KiB 页 / LSPosed 2.2.1 API 102 上，主/worker 两进程各 39 项通过：
8 dex2c int、21 long、8 native、2 非法 `rounds` 异常。`Entry` 公共 hook helper 显式设置 API 102 的
`PASSTHROUGH`，`-1`/`129` 仍检查异常类型和消息。禁用模块后两进程均 `FAIL module not active`，恢复启用
后再次各 39 项通过。构建日志为 `work/core-hardening-sample/build-passthrough.log`，设备结果为同目录的
`final-device-pass.log`、`final-disabled.log` 和 `final-restored.log`；安装包哈希与最终 APK 一致。
报告在 `validation-report.json`，APK/IR/回执冻结于 `final-artifacts/`。
[复现步骤与回执位置](../dex2c/samples/core-hardening/README.md)。

`[~]` Java/dex2c 两方法的融合数仍为 0，核心缺口是 lowering 生成的 `d2c_i`、`d2c_j`、`d2c_copy`
运行时调用隔开相邻算术。为避免默认 LLVM IR 丢弃标签造成误计数，以同一生成源和回执编译参数，仅额外
增加 `-fno-discard-value-names` 复编 `work/core-hardening-sample/dex2c-inspection.raw.ll`，确认两个私有
clone 均无融合；该 inspection IR 独立于 APK 的生成 IR。当前没有 Java 融合收益、QDReadHook 完整业务
覆盖或性能前后比较的结论。

M1 专项与原生样例已满足同一函数实际生成并执行多组融合、正常算术与独立参考结果一致的首批标准，
专用化失败终止编译由专项覆盖。覆盖限于选中的标量运算对。host/module APK 分别为 883129/326860 字节，
native/dex2c SO 分别为 31456/258536 字节；这些是随机构建的单次产物记录，不能用于性能或体积收益比较。
[VM 回归](../tests/vmp/README.md) · [设备差分](../tests/dex2c/device.py)

### M2 handler 与操作数布局变体

从 M1 的整数融合和少量标量 handler 中选一个指令族，给编译器生成的 clone 两种语义等价的实现，
并让编码器和对应读取端支持至少两种操作数排列。可以先在融合指令的同样四个字段内调整编码顺序，
再按实际收益决定是否扩大到共享解释器的其他操作。变体由编译期系统随机源选择，并与函数自身的
handler 匹配。这样改变的是执行结构与字段解释，p12 的 opcode 随机映射只改变分发编号。
[aVMP.cpp](../obfuscation/llvm-21/Transforms/Obfuscation/aVMP/aVMP.cpp) · [解释器](../obfuscation/aVMPInterpreter/aVMPInterpreter.cpp)

扩展 `opcode_diversity.py` 的跨方法、跨构建断言。规范化分发编号和符号名后，同一指令族的两种
等价 handler 实现和字段消费顺序须在 post 后及最终 SO 中仍可区分，防止变体被优化合并。用设备
差分执行两种变体，确认业务语义一致。按 `.text`、字节码和热调用开销决定是否扩大。分析者需要
适配不同实现及布局，运行时观察和逐 handler 分析仍可行。
[随机映射回归](../tests/vmp/opcode_diversity.py) · [post 回归](../tests/vmp/post.py)

### M3 敏感数据借用与 VM 状态回收

先在 `vm_restore_call_frame` 恢复调用者状态后擦除已经弹出的帧槽，处理其中的 function key 和
调度状态，再收紧离开作用域的临时解码和密钥流缓存。清理时点以嵌套调用、重入和异常传播中最后
一个有效使用者为准，避免擦除调用者的活跃帧或还要交付的结果。改动进入 LLVM 21 生成的 bitcode。
[解释器调用帧](../obfuscation/aVMPInterpreter/aVMPInterpreter.cpp#L613)

随后为显式标记的敏感记录提供作用域内的 native 缓冲区。CSE/QSEG 认证成功后开始借用，最后一次
释放立即擦除受控明文。这类缓冲区独立于 1 MiB 空闲 LRU 和静态字符串池，普通记录沿用既有策略。
如交付 `byte[]`，调用者负责擦除自己的副本。原有字符串 API 履行静态存储期、JNI 和 Java `String`
身份约定。未知原生展开路径保留固定驻留策略，直到有可验证的退出清理方案。
[CSE runtime](../runtime/ndkp_cse_runtime.cpp) · [QSEG runtime](../runtime/ndkp_qseg_runtime.cpp) · [Java 字符串运行时](../dex2c/runtime/src/main/java/io/github/xihan123/dex2c/runtime/StringRuntime.java)

完成以最后一次释放即清除受控缓冲区、退出即清除已退帧、活跃资源始终有效为准。复用 QSEG
lifetime/copy 与 VM 调用帧用例，覆盖递归、跨线程、native 回调、Java 异常、原生展开及正常返回。
比较活跃与空闲映射、峰值驻留、冷恢复和热复用成本。TLS 做线程隔离，已返回的 Java `String`、
`intern()`、调用方保存的副本和同进程读内存仍在保护边界外。
[QSEG 回归](../tests/qseg/README.md) · [调用帧回归](../tests/vmp/call_frames.py)

### M4 共享库完整性与自保护

首批让真正零 CSE pool 的翻译单元复用同一 SO 已有的认证上下文，接入加载和显式标记的低频入口。
调整 CSE pass 和 dex2c 生成接线，以确切的本库锚点和已认证的模块身份绑定指定上下文。找不到
匹配的有效上下文就拒绝配置。复用已有两种检查引擎和完整 APK 验签构造器，保留已校验的描述符局部快照。
保持合法 root、LSPosed 和其他 SO 的正常使用。
[当前空池限制](../obfuscation/llvm-21/Transforms/Obfuscation/StringEncryption.cpp#L537) · [生成注册入口](../dex2c/core/src/main/java/io/github/xihan123/dex2c/core/RuntimeLayout.java) · [复验接线契约](../dex2c/INTEGRITY_RECHECK.md)

用 pass 形成的实际零 pool 样本做对照，核对编译器生成常量也未入池。旧版在该路径拒绝构建，新版
用匹配上下文完成接线并通过正常加载和调用，缺少有效上下文或身份不符继续拒绝。复用验签与暖态
设备回归，确认本库 RX 字节改写及页权限失配各自被显式入口拒绝，并比较冷加载和低频检查成本。
检查覆盖限于本库及关联认证状态，同进程修改检查器和两次检查之间的改写窗口仍存在。
[验签设备回归](../tests/apkverify/device_runtime.py) · [暖态设备回归](../tests/dex2c/recheck_device.py)

### M5 AArch64 机器码保护

为 LLVM 21 建独立的 AArch64 后端补丁，在目标机器指令流水线挂一个显式启用的 pass。首批只对
选定 AArch64 函数做有限块布局和等价分支变换，保护边界先选无复杂展开的函数。接线与现有 IR
注册分开，保留 ABI、分支距离和重定位，处理 W^X、BTI/PAC、unwind/异常元数据和 4/16 KiB 页。
按链接得到的最终布局执行既有封装、strip 和 APK 签名。 [overlay 接线](../scripts/apply_overlay.sh)

完成以最终反汇编显示指定函数出现后端变化、ABI 和真机语义对照通过、重新封装的 CSE/QSEG 仍能
认证为准。复用 ABI、设备语义、完整性和对齐检查，记录同一 SO 的 `.text` 增量及调用成本。覆盖
限于选择的机器码函数和对应 AArch64 基线。 [ABI 回归](../tests/abi-smoke/run.sh) · [CSE 封装契约](../runtime/CSE_HARDENED.md)

函数级机器码按需加密是后续实验。前置条件是边界及重定位/展开信息可靠，Android 目标设备允许
满足 W^X 的发布与回收，能与现有 RX 摘要和签名顺序兼容，并验证页权限、指令缓存同步、并发
首次执行以及卸载。只从独立、少量选定函数试起，默认路径保持静态 RX，避免 RWX 和全库加密。

## M1 首批实现约束（已完成）

以下保留 M1 的实现与复核范围：仅修改 LLVM 21 的 VMP 编译路径并补相应回归。以 `GOVMTranslator::selectFusionCandidates`、
`handle_fused_binary` 和 `cloneVmInterpreterForFunction` 为起点。 [当前融合选择](../obfuscation/llvm-21/Transforms/Obfuscation/aVMP/aVMP.cpp#L1873)

1. 按基本块顺序选不重叠的相邻对，第一条只被相邻第二条使用。沿用 `add/sub/mul/and/or/xor`、
   同宽 `i8/i16/i32/i64` 和排除 `nsw/nuw/exact` 的约束。每函数最多四组，实际容量取本函数未用的
   `FENCE_OP`、`ATOMIC_CMPXCHG_OP`、`ATOMIC_RMW_OP`、`VAARG_OP` 数量与四的较小值。
   每组单独占用语义码并保存两个运算、位宽和操作数顺序。其余候选按普通 VM 指令编码。沿用
   `OP_TOTAL` 和现有四字段线格式，系统随机 opcode 映射仍从现有系统随机源取得种子。
2. 按选择结果跳过每组首指令，在对应尾指令发融合码。复用 PHI/back-edge 已预留的结果槽，保持
   第二条的左右操作数顺序，沿用基本块地址回填。两个 `get_fusion_specs` 调用分支均改为传入集合。
3. 私有 clone 在随机 dispatch 改写前为每组建立匹配的 handler。新增 continuation 边的 selector
   PHI 使用同类型的 0（NOP），其余 incoming 继承 NOP 边的既有值。保留 LLVM verifier 和 bridge 清理。
   已发出融合码而无法安装对应 handler 时编译失败。候选不足或没有空码时仍走正常 VM，strict 继续
   负责函数选中但无法虚拟化的错误。
4. 检查 `NativeCompiler` 的 raw IR → `-irobf-vmp-post` → final IR → 现有保护回执的调用链。
   只统计实际生成且成功专用化的融合，不为多组融合新建通用回执。用现有 VM 回归加针对性 fixture
   核对零组、多组、重叠、占用预留码和超过上限，以及窄整数、非交换运算和循环 PHI。用目标 arm64
   真机复核实际 VM 执行结果，比较同分母的字节码、dispatch、SO 大小和耗时。
   [NativeCompiler](../dex2c/core/src/main/java/io/github/xihan123/dex2c/core/NativeCompiler.java) · [strict 回归](../tests/vmp/strict.py)

## 每批验收与提交

每批先固定仓库验收示例的源码、方法清单和保护级别、NDK/ABI、工具链构建参数、插件开关、签名
配置、设备及工作负载；面向 QDReadHook 的完整业务覆盖仍单独验收。保留 p22 起点和本批未改动前的构建作对照，在相同分母上评估阶段指标。
随机编译会改变输出，若单次差异接近波动则补少量重复。先以现有业务启动、关键调用和体积的可接受
范围确定预算，记录实测值后再放宽选择上限。覆盖变化与性能变化分别核对。

每个实施批次由 Sol 6.1 实现，完成相关验证后由 Astra 独立审查，修正后按既有授权签名提交。
修改 overlay 按贡献指南核对精确基线 `git apply --check`、最小 Clang 构建和受影响的现有套件。
真机语义、宿主兼容和设备上的篡改拒绝以真实结果为准。`--compile-only` 只覆盖编链及静态路径。

影响产物的实现批次按贡献指南递增 patchset；p23/M1 已完成实现、专项验证和原生样例，本轮仅新增仓库
样例，不调整 p23。Java 融合收益、完整业务方法覆盖和性能比较仍按上面的 `[~]` 项保留边界。自动发布仍受全部 Host artifact 齐备、聚合
`SHA256SUMS`、现有发布门槛和所需设备验证约束，已有 Release 保持不可变。M2 及后续阶段不包含在
本轮实现中，发布留待当前批次通过全部门槛后按既有流程进行。
[贡献指南](../CONTRIBUTING.md) · [仓库约定](../AGENTS.md) · [聚合发布](../.github/workflows/discover.yml)
