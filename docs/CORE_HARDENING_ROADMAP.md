# 核心增强路线图

LLVM 21 的 M1 多组 VM 指令融合及 M2 首批 handler/操作数布局变体已完成本地专项与 Java/native 样例验证。
M3 的 p26 退休控制帧、p27 持久解释器缓存、p28 堆内联常量三批回收与 p29 QSEG 显式敏感 native 借用首批已完成本地专项和未改样例验证。p30 的 LLVM 21 CSE region 作用域首批已通过独立签名 fixture、旧路径回归及新增独立样例 probe。当前 p31 的 M4 将加载认证与真正零 pool TU 的检查点接到共享库，已通过本地编链和独立 SO 设备专项；M5 AArch64 机器码层仍是后续阶段。每批交付一个可在业务产物上启用和验证的行为。

## 当前基线与范围

规划保留 p22 的 `19506a4531cbe722e13df9b8625bd8b53f121c4e` 基线；M2 的 p25 实现以 `dev` 的
`b9c71b78bb11358a49f6dc6f59d61d2a8f452a78` 的 p24 为冻结对照。`PATCHSET_VERSION=p25` 在既有
多组融合与 dex2c 纯整数区段标量化之上增加每组计算与字段布局变体。p23 承接 p20 的 `523c466` 单对融合；p21/p22 和其后
提交还修复了严格编译、Windows 证书兼容和 QSEG 测试路径。以当前源码和候选构建为准，早期性能数据
只对应当时的样本。
[补丁集版本](../config/patchset.env) · [设计记录](../DESIGN.md)

M3 首批以 `3133e3589e18a11a8cb7b0a534ba7f12cc84fafd` 的 p25 代码树为冻结对照，
`PATCHSET_VERSION=p26` 增加退休控制帧的完整擦除，已通过调用帧设备专项和未改样例的启用/禁用/恢复验证。
`PATCHSET_VERSION=p27` 以 `4e68950401953c81f8501c983c011ba25a96c31a` 的 p26 为冻结对照，
回收三类持久解释器缓存，并修正 LLVM 21 融合 continuation 的出口状态提取。
`PATCHSET_VERSION=p28` 以 `117ef36e16a13295ec8277ed9682f1f5de775364` 的 p27 为冻结对照，
在三处 owned 堆内联常量缓冲的最后消费后、释放前擦除完整原分配长度，只更新 LLVM 21 bitcode。
`PATCHSET_VERSION=p29` 以 `4715d680b1e4c1efd041ffd595828533be2263b0` 的 p28 为冻结对照，
只在 QSEG runtime/header 增加独立敏感映射与配对借用，继续使用冻结的 p28 Clang；
编译器、IR/回执协议、CSE 生产路径与原样例算法和配置保持原有行为。
`PATCHSET_VERSION=p30` 以 `81337e0c3d8b7707e2cc600751eb9900d4250a0c` 的 p29 为冻结对照，
只在 LLVM 21 显式选中的普通返回、原始 nounwind 函数中接入 scoped CSE region，运行时
认证后发布独立只读映射，返回前反序全页擦除并真实 unmap。原算法和 39 项断言保持原有行为，
样例增加默认关闭的独立 `libcore_cse.so` probe；LLVM 20 只同步内部 ABI 头。
当前 `PATCHSET_VERSION=p31` 以 `1d430d1eacd1fc4568600bd07803c5201207e84a` 的 p30 为冻结对照，
增加 LLVM 21 非分段 CSE 加载登记与零 pool TU 的显式 image recheck，复用同 SO 已认证模块。

对标成熟商业保护的维度是逐方法语义差异、敏感状态驻留、自身完整性、机器码覆盖和部署成本。
这些维度用本项目的真实产物评估，厂商内部实现和强度百分比不在比较范围内。目标是提升静态分析和
运行时篡改本库的成本。产品保持离线，服务器、硬件密钥、设备绑定和联网激活均在范围外。交付 APK
含公开证书、代码和运行所需材料，因此 APK-only 保密、运行时不可提取和同进程信任根均不作为目标。

| 维度 | 仓库已有实现 | 核心缺口 |
| --- | --- | --- |
| VM 指令 | LLVM 21 逐方法随机 opcode、私有 clone、ChaCha 字节码、strict 与 post 间接分支。p23/p24 形成多组融合与 Java lowering；p25 每组首个 add/sub 可用同宽 carry/borrow，并支持 target 前后两种布局，实际 raw/post、SO 与设备语义通过。 | 当前仅有限整数融合族；完整业务覆盖、发布预算与隔离性能评估尚未完成。 |
| 敏感数据和状态 | CSE hardened 使用 ChaCha20-Poly1305 与 HKDF-SHA-256。QSEG 按需恢复，保留 VM 内层编码，普通 `acquire/release` 与 1 MiB LRU 约束空闲借用缓存。只有原函数为 `nounwind` 才生成 VM 主借用，原生展开未证实的路径仍固定驻留。p26/p27/p28 状态回收与 p29 QSEG 敏感借用已通过设备专项；p30 scoped CSE 每次调用独立认证/映射并在普通返回前反序全页擦除和 unmap，签名专项与独立样例 probe 已通过。 | 普通 CSE 字符串仍为静态存储期，Java 字符串可被缓存或 `intern()`；scoped 仅覆盖显式选中的有限 native 合同。敏感映射之外的副本、crypto 局部值、栈/寄存器/spill 仍需由其所有者处理。 |
| 完整性 | CSE/QSEG 可度量本 SO 全部可执行 `PT_LOAD` 的实时映射字节，已覆盖其中的解释器。已有显式低频 `integrityRecheck`；p31 零 pool TU 可复用同 SO 已认证模块接入加载与业务入口。SelfCheck 的 FNV 只校验 VM 字节码。完整 APK 验签与证书提取绑定有不同覆盖。 | 完整业务入口覆盖、检查器本身被同进程修改及检查与使用之间的窗口仍有限制。 |
| 共享库与机器码 | 多个反分析 pass 只查 `main`，无 `main` 的共享库会跳过相应注入。已有原生间接分支由 IR pass 生成。 | 面向共享库的明确接线、AArch64 后端变换。函数级 SO 机器码按需加密尚未实现。 |

`segmentedData` 和 `verifyApkSignature` 在 dex2c 插件中都默认 `false`。目标是 QDReadHook 的
合法 root / LSPosed 使用环境。继续保持各项保护显式启用，兼容宿主和框架的正常加载与调用。
验收时分别核对仓库所支持的能力、目标 APK 实际启用的路径和当前产物在真机上的结果。
[离线 opcode 记录](vmp-offline-p12.md) · [CSE](../runtime/CSE_HARDENED.md) · [QSEG](../runtime/QSEG.md) · [APK 验签](../runtime/APK_VERIFY.md) · [入口复验](../dex2c/INTEGRITY_RECHECK.md)

## 阶段与依赖

| 顺序 | 阶段 | 生产交付 | 技术依赖 |
| --- | --- | --- | --- |
| 1，已完成样例闭环 | M1 多组 VM 融合 | 每函数有上限的多组标量融合和独立 handler；p24 Java lowering 在真实样例中各产生四组融合。 | LLVM 21 p20 编码、私有 clone 和 post 链。 |
| 2，已完成首批本地验证 | M2 handler 与操作数布局变体 | p25 每融合组最多一个 add/sub 的等价 carry/borrow 计算与两种字段排列。 | 共用 M1 opcode、系统随机源和私有 clone；编码与解码共享规格。 |
| 3，状态回收三批与 QSEG/CSE 借用首批已完成本地验证 | M3 敏感数据借用与 VM 状态回收 | p26 擦除退休控制帧，p27 回收持久缓存，p28 回收堆内联常量，p29 增加显式 QSEG 敏感 native 借用，p30 接入 LLVM 21 普通返回的 scoped CSE region。 | 现有 CSE/QSEG、模块 guard 和调用帧契约，可独立于 M1/M2。 |
| 4，p31 首批已完成本地验证 | M4 共享库完整性与自保护 | 真正零 CSE pool 的翻译单元可接入加载和显式业务检查点。 | 现有验签、RX 度量和 recheck。重用 M3 借用时才依赖相应生命周期。 |
| 5 | M5 AArch64 机器码保护 | 指定函数获得真正的目标后端变换。 | 对应 NDK 的精确 LLVM 21 基线。组合 M4 时须保证最终代码摘要仍有效。 |

顺序是开发优先级。M1、M2 本批范围与 M3 退休控制帧、持久缓存、堆内联常量三批和 QSEG/CSE 借用首批已完成本地验证，其余批次按实际收益和代价另行安排。
LLVM 20 如需移植，单独在相应 NDK `Base revision` 上验证。解释器改动使用对应 major、已配置
Android sysroot 的 Clang 生成 `vm.h`。脚本用法为 `gen_vm_bitcode.sh <clang> [abi_tag] [20|21|all]`。
LLVM 21 的 arm64 阶段使用 `bash scripts/gen_vm_bitcode.sh /path/to/clang aarch64 21`。
第三个参数 `21` 将输出限定到 LLVM 21 overlay，省略时默认 `all`。 [生成脚本](../scripts/gen_vm_bitcode.sh)

### M1 多组 VM 融合

在 LLVM 21 `aVMP.cpp` 把单个融合描述扩成受限的集合，选定、编码和专用化使用同一组记录。
每组把两条有依赖的标量整数运算放进一个 VM 指令和私有 handler，减少一次 VM dispatch。容量和
成本以每函数上限控制，只有证明当前余量不足且收益足够时，再讨论扩展候选或 opcode 空间。
[aVMP.cpp](../obfuscation/llvm-21/Transforms/Obfuscation/aVMP/aVMP.cpp)

#### p23 / p24 实现状态

`[x]` LLVM 21 的 p23 实现已把每函数融合扩展为最多四组不重叠的相邻标量整数运算，保留每组独立语义
opcode、位宽和非交换操作数顺序，并为每组安装匹配的私有 handler。`tests/vmp/fusion.py` 已实际
核对四组上限、预留 opcode、重叠与零候选、窄整数、非交换运算、循环 PHI 和 `i64` 链，完成
protected IR → post IR → ELF 对象编链、p22 单组基线字节码长度对比，以及 ARM64 上独立原生 C
参考驱动的多组、边界和循环语义验证。

`[x]` p24 的 `CppEmitter` 只在无调用的 int/long 区段内保存标量值，真实跳转目标、handler 入口、
JNI/helper 调用与控制流出口前同步并清空缓存；调试行标签不切段。出口的保守局部读取查询包含
异常 handler 与 IINC；死数值仍调用原 helper 清理旧 JNI 引用和 uninitialized 标记。浮点、引用和
可抛异常运算沿用原路径，保留 Java 溢出、移位掩码和异常边。核心 45 项测试全部通过，含 O0 原有
fixture 与 O1 定向 fixture 的 `-Xcheck:jni` 宿主差分，覆盖同 local 的引用/int/long 复用及 category2。

`[x]` 仓库内 `dex2c/samples/core-hardening/` 已完成 `ProtectedArithmetic.calculate(III)I` 与
`accumulate(JI)J` 的 strict VMP、post、hardened CSE、证书绑定和入口自检；最终签名 APK 的两项关键
方法静态检查通过。算法、39 项断言与非 README 样例源码/配置均与冻结基线相同。真实打包 raw/post
IR 的每个私有 clone 均有四组融合，字节码在 raw/post 相同且存在于最终 dex2c SO；本节历史对照为
`ad6d19d367445be83ad5f5577caad4d89ad09b56`：

| 方法 | 基线融合组 | p24 raw/post 融合组 | 基线→p24 字节码 |
| --- | --- | --- | --- |
| `accumulate(JI)J` | 0 | 4 / 4 | 7013→4158 字节 |
| `calculate(III)I` | 0 | 4 / 4 | 3848→1351 字节 |

`NativeCompiler` 在真实 raw/post 编译中保留 value names，统计直接来自生成已打包对象的 IR。同模块
原生 `core_fusion_calculate` 仍为四组融合、363 字节字节码，其 31456 字节 `libcore_fusion.so` 与 p23
全字节相同。该原生路径只验收 strict VMP/post，不声明 dex2c 的 CSE/证书保护；构建未启用 `-irobf-debug`。

`[x]` OnePlus 7 / API 37 / ARM64 / 4 KiB 页 / LSPosed 2.2.1 API 102 上，主/worker 两进程各 39 项通过：
8 dex2c int、21 long、8 native、2 非法 `rounds` 异常。`Entry` 公共 hook helper 显式设置 API 102 的
`PASSTHROUGH`，`-1`/`129` 仍检查异常类型和消息。禁用模块后两进程均 `FAIL module not active`，恢复启用
后再次各 39 项通过，末态已启用。p24 主/worker PID 依次为 8315/8342、8392/8410、8465/8490；
安装包哈希与候选 APK 一致。构建日志为 `work/dex2c-primitive-lowering-p24/build-sample.log`，
设备结果为同目录的 `device-enabled.log`、`device-disabled.log` 和 `device-restored.log`。
报告在 `validation-report.json`，APK/真实 IR/回执冻结于 `candidate/`，原始对照保存在 `baseline/`。
[复现步骤与回执位置](../dex2c/samples/core-hardening/README.md)。

M1 专项与 Java/native 样例已满足同一函数实际生成并执行多组融合、正常算术与独立参考结果一致的
标准，专用化失败终止编译由专项覆盖。p24 host/module APK 分别为 878174/335372 字节，dex2c SO
从 258536 增至 267048 字节；字节码缩减不代表整体体积或耗时收益。覆盖限于本例选中的整数区段，
QDReadHook 完整业务覆盖及同分母性能比较仍待单独验收。上述 `work/` 文件为本地取证，不由 Gradle
自动生成，也不随 Git 提供。
[VM 回归](../tests/vmp/README.md) · [设备差分](../tests/dex2c/device.py)

### M2 handler 与操作数布局变体

`[x]` p25 的每组 `VMPFusionSpec` 用现有 `getRandomBytes` 独立选择 handler 与布局。H0 为原生运算；
H1 只替换该组首个 add/sub，其余运算和第二条左右顺序保持既有语义。计算全程使用原 `i8/i16/i32/i64`：
以操作数初始化 Accum/Pending，Pending 为零时直接退出，否则同时计算 `nextAccum = Accum ^ Pending`，
加法用 `(Accum & Pending) << 1`、减法用 `(~Accum & Pending) << 1` 更新 Pending，最多执行位宽次计算。结果按原位宽取模，
不附加 `nsw/nuw/exact`。无 add/sub 的组仅用 H0。没有伪 volatile 工作或运行期变体选择。

布局 L0 为 target/LHS/RHS/third，L1 为 LHS/RHS/third/target。target 仍为指针宽度原始字段，
其余仍用原 stateful `packValue`；编码器和 clone 解码器按同一 `fieldOrder()` 顺序依次发出与读取。
共享解释器和生成的 `vm.h` 未改。保持无开关不变换、strict 失败关闭、post 链与默认保护。
[aVMP.cpp](../obfuscation/llvm-21/Transforms/Obfuscation/aVMP/aVMP.cpp)

`[x]` Release 专项未启用 `-irobf-debug`。14 个随机候选与冻结 p24 基线均执行同一 11 函数参考驱动，
16 个融合组累计覆盖 60 种有效 H/L 组合；包括首条或次条 sub、左右顺序、窄整数、B=0、溢出、循环和
64 位最坏传播。`opcode_diversity.py` 从实际 reader CFG/数据流识别 H/L，raw/post 记录完全一致。
每轮的真实 post.s 只组装一次为 post.o，该对象直接产生设备执行的 SO。固定同一个 64 位 add/xor
组核对四种 H/L：H0 的 native add/eor 与 H1 的 and/eor/lsl/零判断/回边在实际反汇编中可区分，
对象与 SO 的整个对应 clone 非重定位指令全相等，reader 出口用实际局部符号对应；结构判断不依赖
符号名、opcode 编号或整个 clone 的哈希差异。专项库总字节码每轮均为 1585 字节。

审查发现旧 i64 向量的最终 `& y` 会掩掉部分高位错误，已补两个高位可见向量；只重编语义 driver，
复用原 15 份 SO 全部通过，设备核对的 SO 哈希未变。结果为 `semantic-highbits/results.json`。

`[x]` 未改 Java/native 样例的真实 raw/post 中，两个 dex2c 方法和 native 方法各为四组融合、一个
carry/borrow 循环。字节码分别保持 p24 的 4158/1351/363 字节，raw/post 相同且位于最终封装库。
两个 Java clone 和 native clone 的全部非重定位指令与真实对象一致，链接库与封装库对应代码全相同。
sample 对象直接从真实 final IR 编译。样例主/worker 的
启用、禁用、恢复结果分别为各 39 PASS、均 module not active、各 39 PASS，安装 APK 哈希一致。
22 个非 README 样例源文件、算法、断言和配置未改。

| 同一专项输入 / 库 | p24 | p25 本批 |
| --- | --- | --- |
| 专项 SO（保留局部符号） | 298624 字节 | 14 个候选 298384–301536 字节 |
| 专项 `.s0` 代码节 | 125236 字节 | 124372–126492 字节；`.text` 3540、`.plt` 304 不变 |
| dex2c 封装 SO / 可执行节合计 | 267048 / 209420 字节 | 268056 / 210468 字节 |
| native SO / 可执行节合计 | 31456 / 23152 字节 | 31544 / 23232 字节 |

样例 dex2c 的 `.text` 为 102392→102600，`.s0` 为 105664→106504 字节；native `.s0` 为
21852→21932 字节。随机编译还会改变原有 dispatch 和块布局，上述尺寸不作为隔离算法增量。

`[x]` 五轮固定产物交错复测使用相同 driver（哈希一致）、100 次预热和每项 2000 次调用，八项 checksum
与基线一致。计时使用冻结的原 driver；审查后补入的两个高位可见向量只做追加语义回归，不覆盖该 driver
或复测记录。下表是 CLOCK_MONOTONIC_RAW 的整段 VM 调用中位数，单位微秒：

| i64 输入 | p24 H0/L0 | p25 build2 H1/L0 | p25 build3 H0/L0 | p25 build5 H0/L1 |
| --- | --- | --- | --- | --- |
| 典型 | 3.203 | 4.270 | 4.136 | 3.805 |
| 64 轮 carry | 3.211 | 4.167 | 4.144 | 3.826 |
| 64 轮 borrow | 3.224 | 4.184 | 4.075 | 3.807 |

H1/L0 相对 p24 为 1.333/1.298/1.298 倍，但同布局 H0 也有明显差异；未绑核或锁频，整段 VM
粗计时受原有随机分发和设备状态影响，不能把约 30% 全归因 carry/borrow。八项、三个候选相对 p24 的
中位比值范围为 0.822–1.348，原始区间见报告；不据此声称性能改善或整体保护强度提升。当前预算
仅允许本批每函数原上限四组、每组最多替换一个 add/sub，未设全业务耗时 SLA；完整业务和隔离评估
通过前不扩大指令族或选择上限。运行时观察和逐 handler 分析仍可行。

本地证据在 `work/m2-variants-p25/`：`fusion-device/results.json`、`semantic-highbits/results.json`、`timing-repeat/results.json`、
`sol/machine-evidence.json` 和 `validation-report.json`；候选与 p24 对照分别在 `candidate/` 与
`baseline/`，不随 Git 提供。该 p25 批次不包含 M4/M5；M3 与当前 M4 的结果见后文，M5 仍待实施。
[随机映射回归](../tests/vmp/opcode_diversity.py) · [post 回归](../tests/vmp/post.py)

### M3 敏感数据借用与 VM 状态回收

`[x]` p26 在 `vm_restore_call_frame` 完整恢复调用者状态后，用 volatile 字节循环擦除已经
弹出的完整帧槽，包括 function key、调度状态和 padding。当前 ARM64 结构为 88 字节，
`ip` 后有 4 字节 padding。正常调用和捕获原生异常均在恢复后检查异常标记，因此共用这个清理点。
调用者数据帧、返回值、`sret` 和待传播的异常对象保持既有生命周期。改动只生成 LLVM 21 的
ARM64 bitcode；LLVM 20 未移植退休帧擦除。共用回归脚本按实际 Clang major 只为 LLVM 21 启用
新增观察、post 和 O0 的 switch/读取顺序检查；LLVM 20 的分发器使用条件链。其他 major
保留六模式语义编链及 TLS、无快照 malloc/free、入口复验和 callee 门禁。
[解释器调用帧](../obfuscation/aVMPInterpreter/aVMPInterpreter.cpp#L613)

调用帧回归在实际 IR 中追加测试访问器，直接观察唯一真实 TLS 栈；空闲槽完整填入 `0xA5`，
回调内确认真实 push 及 padding 哨兵，正常和异常 pop 后检查完整槽为零，未用邻槽保持哨兵。
嵌套回调快照全部活跃前缀，确认更深调用到达下一层，再检查活跃帧不变及深层退休槽清零；
这些观察随现有八线程、递归、重入、结构体返回和异常生命周期差分运行。O2 protected 先执行
真实 post，再追加测试访问器且禁用后续 IR passes。`--semantic-only` 只跳结构断言，冻结 p25
的 VMP/O0 与 protected/O2+post 均实际退出 38：正常 pop 后完整槽仍有残留。负例及哈希见
`work/m3-frame-wipe-p26/p25-negative-results.json`。O0/O2 × plain/VMP/VMP+SelfCheck+Entry 六种设备组合已通过，含 O2
protected 的真实 post；四个观察模式均报告 88 字节完整帧、4 字节 padding 和八线程通过。
最终原始 IR、观察 IR、对象、可执行文件与每模式设备日志保存在
`work/m3-frame-wipe-p26/final-call-frames/`，汇总为同根 `final-call-frames.log`。
LLVM 20 默认六模式编链也通过，未使用 `--semantic-only`；记录在 `llvm20-final-call-frames.log`。
这验证共用测试兼容性，未宣称 LLVM 20 已移植擦除。候选工具链的 roundtrip 12 种组合设备回归通过，
ABI、构建系统、字符串加密、strict、post 和融合编链回归也通过，同根保留各项日志。

冻结样例的真实 raw/post 均保留完整 88 字节擦除循环，11 个调用者字段先恢复。
实际 `protected.o` 的 440 字节恢复函数与 `linked.so` 的全部 64 条非重定位指令相等，
46 条重定位指令不参与该项字节比较；链接后完整函数与打包 SO 相等，打包 SO 又与 APK 内
对应库全字节一致。链接库有两个同名静态恢复函数，按长度和完整非重定位指令确定对应关系。
对象、链接库、打包库的真实反汇编与事实摘录在
`work/m3-frame-wipe-p26/sol/machine-evidence.json` 和同目录 `machine-evidence-notes.md`。

未改样例在 OnePlus 7 / API 37 / ARM64 / 4 KiB / LSPosed 2.2.1 API 102 上完成启用、禁用、恢复：
主/worker PID 依次为 10771/10800、10850/10868、10923/10949。启用和恢复各 39 项通过，禁用时
两进程均明确报告模块未激活；安装 APK 哈希与冻结候选一致，scope 前后一致，最终状态已启用。
样例算法、39 项断言、配置及 22 个非 README 源文件未改；Java 两方法仍各四组融合、4158/1351 字节
字节码，native 仍为四组、363 字节。最终签名 APK 的两项关键方法静态检查通过。
host/module APK 为 878174/337764 字节；相对 p25，module 增加 1384 字节，dex2c SO 为
268056→269440，native SO 为 31544→31600 字节。未测量 p26 擦除的独立耗时，不给出性能收益结论。
设备与产物记录分别为同根 `device-results.json`、`artifact-evidence.json`，汇总见
`validation-report.json`。[样例复现与历史对照](../dex2c/samples/core-hardening/README.md)

`[x]` p27 回收三类持久解释器缓存：ChaCha 元组、key/nonce、调度种子和块，opcode key/解码表，
以及调试布局 key/ID。实际 native 分发前与解释器统一退出点擦除完整缓存；正常返回、原生异常和
VM → native → VM 共用这些边界。新 BB 擦除完整 ChaCha 对象，材料错配先擦旧对象再 KDF；
只切换 64 字节块时保留有效材料、擦旧块及块元数据。冷缓存直接重建，命中路径保持原样，
无需保存调用者缓存副本。未清理调用者数据帧、返回值、`sret`、异常对象或编译器 spill。
共用调用帧测试已在最终 LLVM 21 完成 O0/O2 的 plain、VMP、protected 六模式设备验证，含 O2 protected 的真实 post。
新增访问器读取唯一真实 TLS 缓存及实际类型大小；只读 refill 回调观察失效后、重建前的真实内存，
命中时比对整个对象未变。正常、异常和嵌套 native 回调及返回后检查完整缓存清零，沿用八线程和原生参考差分。
材料 refill 覆盖 KDF 重建，不表示覆盖了有效旧元组错配的分支；正常生命周期在更早的边界已将缓存清空。
本批也修正 LLVM 21 融合 continuation 对不可达 NOP 边的依赖：统一退出 CFG 后，NOP 边被优化成
与正常执行相反的状态，导致 `frame_sret` 在 BB 内误读头。同一冻结 raw 的三条融合出口定点修正后，
普通与缓存观察驱动均通过；正式实现从真实标量 handler 的正常出口取状态，要求所有出口一致并验证 SSA 支配关系。
冻结 p26 的解释器、生成头、编译器及样例产物在 `work/m3-cache-wipe-p27/baseline/`，
来源为 `4e68950401953c81f8501c983c011ba25a96c31a`，清单为同根 `baseline-manifest.json`。
最终冻结 p26 的 VMP/O0 和 protected/O2+post 负例均退出 50、`bits=102`，分别观察到 KDF 前、
旧块/块元数据、native 边界及退出后的残留。未插观察器的样例 raw/post、真实对象、链接库、
打包库与 APK 已单独核对：完整 ChaCha 对象为 152 字节，含 2 字节内部 padding；
native/统一退出前另有 opcode key/map、layout key/ID 的 48 字节逐字节清零。
真实 ChaCha helper 的块替换精确擦除偏移 28–39、41、88–151 共 77 字节，保留偏移 44–87 的 key/nonce。
三个业务 clone、两个实际 ChaCha helper 和退休帧 helper 均完成全部非重定位 AArch64 指令的
对象到链接库匹配；dex2c 路径再核对函数全部字节到打包库，以及 APK 内整库字节一致。
退休帧 11 字段恢复后擦除完整 88 字节的行为和 raw/post 的四组融合结构仍保留。
未改样例在 2026-11-22 的启用/禁用/恢复三阶段，main/worker 分别各 39 项通过、明确 inactive、
再次各 39 项通过；安装包 hash 匹配、scope 不变、末态 enabled，22 个非 README 源文件未改。
模块 APK/dex2c SO/native SO 相对冻结 p26 为 337764→340260 / 269440→271936 / 31600→32640 字节；
未进行本批单独计时，不作整体性能收益结论。strict、post、fusion、字符串保护、ABI、构建系统检查
以及设备 roundtrip 的 4 个 callback 和 8 个 globals/TLS 组合通过；实际 LLVM 20 默认六模式编链也通过，
本批擦除和融合修正仍仅交付 LLVM 21。最终证据为同根 `final-call-frames.log`、
`p26-final-negative-results.json`、`candidate-artifact-evidence.json`、`device-results.json`、
`sol/machine-evidence.json` 和各专项日志。这些本地归档不随 Git 提供。
[缓存回归](../tests/vmp/README.md#p27-解释器缓存回收)

`[x]` p28 为 `store`、`insertvalue`、`extractvalue` 的三处 owned 堆内联常量，在最后消费后、
`free` 前调用 `vm_wipe_bytes`，长度分别沿用原 `malloc(var_size)` 或 `malloc(agg_size)`。
只有实际持有临时分配的指针才会擦除和释放；借用的 `data_seg`、结果槽、外部输出和返回值保持有效。
`extractvalue` 的源地址计算移入 `agg_src` 非空分支，分配失败仍先消耗完整 inline payload，再生成原有零结果并继续执行。

专用 `inline_constants.ll` 用 `noinline optnone` 保留 O0/O2 中三个首指令路径，分配长度为 17、24、31 字节。
当前 emitter 的大 `ConstantDataArray` fallback 和 `ConstantStruct` 不提供本测试所需的非零 inline 编码；
本批不修 serializer。测试先冻结真实 raw 和 O2 的真实 post，根据实际编译日志的 opcode、function key、
payload/chain seed、key/nonce 及 byte schedule 核对首指令、size/type 和零 payload，再只对唯一首 inline payload 的
密文字节 XOR 合法非零 pattern。修改只作为受控 VM 输入，不代表 emitter 新增非零聚合支持。
observer 不在解码后写 poison，只在实际对象的 `free` 前读取完整分配和前后 guard。
独立业务 oracle 检查非零输出，borrowed insert/extract 后的源继续消费，两个 borrowed store 之后又真实 extract 并输出。
每条路径还注入 `malloc` 失败，要求无 `free`、payload 被全部消费、输出与失败语义一致、后续 marker 正确。
payload 修改分支不开 SelfCheck；未修改的 VMP 和 VMP+SelfCheck+Entry 分支独立检查正常语义。
`malloc(0)` 没有动态用例，仅静态核对零长度循环和 free 契约；空 aggregate 不是有效的动态覆盖。

正式 O0/O2 真 post 的四个 pristine 与两个 observed 二进制均退出 0。两个 observed 日志各六行，
覆盖 17/24/31 字节及各一次分配失败：正常释放前完整原分配残留为 0、前后 guard 完整、业务输出正确；
失败时只尝试一次 malloc、free 为 0、零结果及后续 marker 正确。冻结 p27 的 O0/O2-post 两个动态负例均退出 60，
正常分配的完整 17/24/31 字节仍为非零，guard、业务和失败后 marker 同样正确。

正式结果目录为 `work/m3-inline-wipe-p28/memory-ops/inline-constants/`，保存 pristine raw/post、
实际对象输入、对象和二进制、逐模式设备日志与 `mutation-manifest.json`；负例在同根批次 `p27-negative/`。
`sol/machine-evidence.json` 静态追踪六个 pristine clone 的 12 个 owned 分配点，核对真实 payload 解码、
消费、独立 owned/borrowed PHI、nonnull/零长度 guard、索引从 0 逐字节到原 malloc 长度及擦除后 free。
O2 IR 和 O0/O2 后端可合并 free，汇合指针只来自 owned 分配；机器记录保留循环、范围比较和实际释放前驱。
六组 pristine/observed 对象函数字节完全一致，两个模式的 clone 合计 136,628 字节；
pristine 与 observed 两组对象到实际已执行二进制各匹配 31,346 条非重定位 ARM64 指令。
样例四份 raw/post 不含 `malloc/free`，只提供整体回归，堆动态证据来自专项的真实 VM 分配。
未改样例已在单台 OnePlus 7 / API 37 / ARM64 / 4 KiB /
LSPosed 2.2.1 API 102 完成主/worker 各 39 PASS、禁用 inactive、恢复各 39 PASS，22 个非 README 源文件未改。
LLVM 20 不进入新夹具、heap observer 或 post，只验证既有默认编链兼容性；p28 擦除只交付 LLVM 21。
无本批新性能测量，也不宣称清除所有栈、寄存器或 spill 明文。
[堆内联常量回归](../tests/vmp/README.md#p28-堆内联常量回收)

局部 crypto 工作数组、opcode 栈临时表仍属于后续生命周期工作；向量 handler 的 scratch 未扩大到启用范围。
`[x]` p29 先交付 QSEG 的显式敏感 native 缓冲区：隐藏的
`ndkp_qseg_sensitive_acquire_v1/release_v1` 接收既有合法 RX 描述符，所有块认证和解码
成功后才发布只读指针。敏感映射独立于普通 cache/pinned 映射；嵌套和跨线程借用按资源
共享引用计数，非零引用期间有效，最后一次配对 sensitive release 立即 RW、volatile
擦除全部页取整字节（含 padding），再真实 munmap，不进入 1 MiB LRU。

调用方必须在所有已知退出和异常路径上配对 sensitive release，不能用普通 release
归还，也不能在最后一次释放后使用指针。该保证只覆盖返回的敏感映射：同一资源仍可能
保留普通缓存、CSE 静态池、Java `String` / `intern()`、调用方副本或其他 crypto 临时
明文。普通 stats_v1 只计普通 get/acquire/copy cache，其 peak 不含敏感映射。
原有字符串 API 保留静态存储期、JNI 与 Java 身份约定；未知原生展开的编译器策略继续
固定驻留，不表示新 API 自动覆盖任意 native EH。

p29 未包含 CSE region 作用域接口。`decode_region_v1` 是依赖生成 guard 的编译器内部入口；
p30 的独立接线见下文，仍不能把未经核对的描述表作为通用借用接口输入。
[CSE runtime](../runtime/ndkp_cse_runtime.cpp) · [QSEG runtime](../runtime/ndkp_qseg_runtime.cpp) · [Java 字符串运行时](../dex2c/runtime/src/main/java/io/github/xihan123/dex2c/runtime/StringRuntime.java)

本批独立签名 fixture 直接执行 native 借用，覆盖完整认证、只读拒写、重入、8 线程与
owner、普通 pinned/acquire/copy 并存、末次释放后立即完整区间消失和重新认证恢复。
测试链接观察器在解码前将 padding 填成非零，生产 wipe 后直接扫描全页，再调用真实
munmap；原样版本独立执行。错证书、外层容器及末块认证失败、配对参数拒绝和受控
mmap ENOMEM 使用独立子进程与实际 waitpid。`NDKP_APK_VERIFY` 未启用，设备覆盖证书
绑定和 QSEG 认证，主机 apksigner 完整签名验证不能替代设备完整 APK 验签。
旧 lifetime O0/O2 和未改 core-hardening 主/worker 各 39 项、禁用及恢复已通过；该样例
不调用新 API。正式 `sol/scoped-fixture-final/build.json` 与 `sol/scoped-device/results.json`
位于 `work/m3-scoped-p29/`：OnePlus 7 / API37 / ARM64 / 4 KiB 的 10 例全部通过，两个
正例退出 0，拒写信号 11，配对/受控 ENOMEM/三个认证负例退出 127，padding 控制退出 123。
观察正例四次全页扫描与真实 munmap 均成功，700003/203 字节资源分别覆盖完整
700416/4096 字节映射与 413/3893 字节 padding。专项 host 12 项普通/`-O` 和 QSEG
全套 236 项通过；正式 build 不使用首次签名标签解析失败的目录。
新 API 的业务宿主、任意 native unwind、API26 真机、物理 16 KiB、Linux 与性能评估
均未扩展；同进程读内存和 APK-only 恢复仍在保护边界外。
[QSEG 回归](../tests/qseg/README.md) · [调用帧回归](../tests/vmp/call_frames.py)

#### p30 CSE region 作用域首批

`[x]` LLVM 21 的 `-irobf-cse-scoped` 默认关闭，必须同时有 hardened CSE 与
`NDKP_CSE_SCOPED` 函数注解。编译器仅接受直接不可变 byte/UTF-16 literal、标量/void 返回、
原始 nounwind 和普通出口；所有调用须直接 nounwind 且正常返回，scoped 指针消费须
`captures(none)`。局部指针存储、全局/聚合间接根、指针逃逸/返回/整数化、非 inbounds GEP、
超过 4096 字节的 literal/load/调用点/callee 对齐、EH/非局部出口、业务 VMP/post 与
segmentedData 均拒绝。nounwind 不证明隐藏 longjmp、取消、信号等路径；接入者须满足此有限合同。
独立 crypto runtime 继续使用两个 strict VMP 入口、memops、entry SelfCheck 和真实 post。

每次调用通过仍有五个 volatile 字段比较的共享 guard，使用核对后的 ModuleV1 局部快照及
本库已认证 RX region 表。认证成功、实际 RO mprotect 后才发布新映射，普通返回前按 acquire
反序 RW、volatile 擦除全部页取整长度、真实 munmap，再擦除 24 字节 lease 并置 state=2。
状态偏移 16，fresh(0) → active(1) → retired(2)；退休 lease 的 data/mapped/padding 为零，
state=2，因此不声称整个 lease 全零。未注解函数共享同 literal 时仍使用静态 DecGV/once。
模块代码摘要和包名/证书公开输入缓存不变，每次 scoped 调用重新认证其记录。
早期效果清理保留原 nounwind 证明，防止 const/pure caller 和未使用返回值删除真实生命周期。

正式 `work/m3-cse-scoped-p30/scoped-fixture-3/build.json` 和 `results.json` 来自真实执行：
O0/O2 native/bound IR、两个 crypto raw/post 入口、24 个 IR 编译拒绝例、实际 C++ 65536 对齐
拒绝例及两个 return block 的四个反序 release 均通过。OnePlus 7 / GM1901 / API37 /
ARM64 / 4096 页的 22 case 符合预期：native 七例（含 strip 与三个默认关闭控制）、原生
guard/tag 四例、四个 observer 缺陷控制，以及签名 O0/O2 主进程、O2 `:worker` 三正例和
错证书/错包名/tag/guard 四负例。正例退出 0，认证负例退出 127、无发布或业务继续，遗漏
全页擦除/unmap/RO/release 的四控制均真实触发 observer exit90。普通 observer TU 转发真实
调用，填充页 padding `0xa7`，fork/write 检查 RO，生产 wipe 后逐字节读完整映射，再检查
实际 munmap 后 mincore ENOMEM；byte/UTF-16、多 region/分支、递归、两线程及 const/pure
中继覆盖每轮 13 次映射/发布/退休。同 literal 的未注解 getter 独立保留静态存储期。

五个 APK 都经过实际 zipalign、合法签名和主机 apksigner 验证，最终 native entry 与 stripped
库全字节一致。生产 runtime 直接从实际 APK/进程双路径读取证书和包名，未启用
`NDKP_APK_VERIFY`，主机验签不等于设备完整 APK 验签。Android29 fixture 显式使用
`--no-rosegment`，使真实使用的 8 字节 Magic 与已成功的 Android26 样例一样位于认证 RX，
真正封装块保持 RW；封装器与生产常量未更改。失败目录 `scoped-fixture-1/2` 及其原始日志保留，
正式执行只绑定 compiler-freeze-3 和 fixture-freeze-4。compiler-freeze-2 仅为源码 snapshot，
不能当成执行证据；逐命令 argv/cwd/rc、stdout/stderr 与输入/产物 hash 保存在正式目录。

样例用默认关闭的 `-PcoreHardening.cseScoped=true` 增加独立 `libcore_cse.so`，绑定真实 host
进程和 module signer；原算法和 39 项断言不变。15:32:44 启用 main/worker 6852/6887 各
39 PASS + scoped probe 0；15:32:49 禁用 7040/7058 均 inactive、无 probe；15:32:53 恢复
7194/7228 再次各 39 PASS + probe 0。安装 APK hash 与冻结候选一致、scope 不变、末态 enabled。
证据为同根 `sample-artifact-evidence.json`、`sample-signature-binding.json`、`candidate/`
和 `sample-device-final/results.json`。旧普通 CSE runtime、descriptor 和 recheck 设备回归
也通过最终工具链；[复现与支持边界](../runtime/CSE_HARDENED.md#函数作用域明文p30llvm-21可选)
及 [样例结果](../dex2c/samples/core-hardening/README.md#p30-scoped-cse-probe) 分开记录。

本批只保证 owned scoped 映射和 lease 的清理。普通 CSE 静态池、Java 字符串/副本、crypto
局部值、寄存器、栈/spill 与同进程读内存仍不包含在保证内；每次映射与认证增加成本，适合
低频函数，没有新性能收益声明。API26/29 真机、物理 16 KiB 页、Linux 和完整 QDReadHook
业务未扩大覆盖。LLVM 20 未移植 scoped 编译器变换；上述 `work/` 为不随 Git 提供的本地证据。

### M4 共享库完整性与自保护

p31 候选以 `1d430d1` 的 p30 为基线，已实现 LLVM 21 非分段 CSE 的加载认证与真正零 pool TU
显式低频入口。annotation-only 标签/源文件路径不再伪装成业务记录，业务共享常量仍加密。
有池模块 102 构造器通过原五字段 volatile guard/局部快照认证原诱饵并登记本 ELF 身份；零池
103 构造器与业务 guard 用自身 RX 代码锚点寻找同库上下文，再逐个复用原 module recheck。
匹配上下文缺失、异库 anchor、描述符或缓存身份失配均失败关闭。完整 APK 验签仍先执行原
101 构造器，image 路径复用原 fd/stat 快照，不重复扫描。Java/Python 生成证据校验同步支持
真实 image guard/self anchor/103 构造器，不把注解或声明当调用。

runtime 必须以 OBJECT/static object 并入每个受保护 SO，多个库各自持有 hidden 本库状态；
公共动态 runtime 或全进程单例不支持。整个 SO 无认证 CSE payload 的显式检查仍拒绝；本批
支持零池 TU 复用同 SO 有池 TU。分段沿用原 QSEG 与空池拒绝，LLVM 20 只同步两项 hidden
ABI 声明，未移植新 pass。不检测 root、LSPosed 或其他 SO 的存在；仍拒绝本库 RX 修改。

当前 host 的 O0/O2 真零 pool 与有池构造器、无开关对照、业务共享标签、实际 IR codegen、
seal/strip 验证已有可复现 fixture，命令/哈希在 `work/m4-image-p31/`。真实 dex2c 纯整数
NATIVE 方法生成路径单独核对 native 零池与 registration 有池。OnePlus 7 / GM1901 / API 37 /
ARM64 / 4 KiB 的独立 SO 专项已完成 20 例，实际退出码保存在
`work/m4-image-p31/device-reviewfix-final/results.json`：正常与 strip 后加载、缺失上下文拒绝、
10 项暖态 RX/权限/cache/诱饵/描述符篡改、异库 anchor、两个独立 SO、外库 RWX 和并发 ctor
回调均通过。未安装新 APK 或修改全局配置；完整 APK 验签、dex2c JNI/业务 APK、root/LSPosed
宿主与性能没有本批新结果。
同进程修改检查器、任意写、检查与使用之间竞态，以及物理 16 KiB/API26/29/完整业务覆盖仍
在边界外。加载新增逐模块认证，低频入口成本随本库 RX 和模块数增长。
[核心合同](../runtime/CSE_HARDENED.md) · [零池独立回归](../tests/cse-hardened/image_recheck_test.py) · [生成入口](../dex2c/core/src/main/java/io/github/xihan123/dex2c/core/RuntimeLayout.java) · [复验接线契约](../dex2c/INTEGRITY_RECHECK.md)

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
3. 私有 clone 在随机 dispatch 改写前为每组建立匹配的 handler。p27 在安装任何融合前，先从真实
   标量二元运算 handler 的正常出口提取 continuation PHI；所有出口的 incoming 必须一致且在分发点可用。
   新增融合边沿用这些正常状态，取代早期对不可达 NOP 边及 selector 0 的依赖。保留 LLVM verifier 和 bridge 清理。
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

影响产物的实现批次按贡献指南递增 patchset；handler/布局改动使用 p25，退休控制帧擦除递增为 p26，持久缓存回收为 p27，堆内联常量回收为 p28，QSEG 显式敏感借用为 p29，LLVM 21 scoped CSE 为 p30，当前 M4 加载认证与零 pool TU 复验为 p31。历史 p23 Windows
完整 Clang [工作流 44894484357](https://github.com/xihan123/A-LLVM/actions/runs/44894484357) 已成功完成，
对应 `8cb3f4c`，不作为 p25、p26、p27、p28、p29 或 p30 的 CI 结果。p29 的
[工作流 44949515082](https://github.com/xihan123/A-LLVM/actions/runs/44949515082) 已成功，仍属于
p29 历史证据。p30 的 [工作流 45007672284](https://github.com/xihan123/A-LLVM/actions/runs/45007672284)
已成功，仍属于 p30 历史证据；当前 p31 CI 待提交后验证，本地构建与设备结果不替代 CI。
完整业务覆盖和性能比较仍保留上述边界。自动发布仍受全部 Host artifact 齐备、聚合
`SHA256SUMS`、现有发布门槛和所需设备验证约束，已有 Release 保持不可变。历史 p30 仅交付上述
CSE region 作用域合同；当前 p31 交付 M4 首批，局部 crypto 临时值回收及 M5 仍不在本批范围。发布留待当前批次
通过全部门槛后按既有流程进行。
[贡献指南](../CONTRIBUTING.md) · [仓库约定](../AGENTS.md) · [聚合发布](../.github/workflows/discover.yml)
