# QSEG 回归

主机格式与认证校验：

```powershell
python -B -m unittest discover -s tests/qseg -p 'test_*.py'
```

`compiler_lifetime.py` 使用 LLVM 21 候选编译器生成独立的普通、嵌套、递归及未知展开
fixture，只检查编译产物合同。保留原 CLI，输出目录必须全新或为空：

```powershell
python -B tests/qseg/compiler_lifetime.py --clang <候选clang.exe> `
  --cert-file <公开证书.der> --output <新的空compiler-contract目录>
```

无混淆 flags 的对照必须保持未保护，并保留预期 nounwind 和嵌套/递归调用边。保护产物
沿 wrapper 的 VM 收据、Code、RX descriptor 与 manifest 逐项绑定 ID、大小、kind 和
策略，拒绝重复 VM 行。仅接受 LLVM 21 当前生成的直接调用、无环 br/ret wrapper 形状；
未知形状失败，不能退回调用总数相等。主指针必须由目标 acquire/get 设置到 bytecode
地址；从该指针准备好直到解释器返回，主借用始终有效。SelfCheck 的同 descriptor
临时 acquire → CheckOne(ptr) → release 必须独立闭合；解释器处 lease 深度为 1，
pinned 深度为 0，所有正常返回和 resume-helper 路径均无未归还借用。两个 Code slot
只允许各自规定的一次 store；拒绝别名使用、地址逃逸、其他 descriptor 的 QSEG 调用、
未知 wrapper helper 和借用指针额外使用。memset 只接受紧邻对应 stack alloca 的 frame
零初始化。嵌套和递归的静态边须沿绑定解释器的入口 CFG、桥接入口 invoke、共享 Code
compare 的实际 false-edge chain，再到由 handler 的 funcid 参数经 store/load 绑定的
switch case；不可达的调用文本、跳过的比较和常量 selector 均不能作为证据。

真正 EH 使用独立同源 fixture：先无 flags 编译，确认目标内同时存在 personality、
invoke 和 landingpad，再 strict 编译，要求同名 EH 拒绝与 strict translation rejected
诊断同时成立。超时、启动失败或其他 nonzero 不算 EH 拒绝。未知原生展开仍使用
`pinned-unproven-unwind`，不能称为支持任意 C++ EH 的租约回收。

每条命令保留参数、cwd、exit、原始 stdout/stderr；失败写 `failure.json`，不发布
`results.json`。成功结果绑定输入源码、证书、compiler 文件、相关仓库源码、生成 IR、
manifest 与 staging bytes 的路径和 SHA256，并复核运行期间未变。仓库源码摘要不证明
候选 compiler 的构建来源。正常 Python 与 `python -O` 均执行相同显式校验。
`checkerRevision: 2` 在原有范围上收紧 slot 使用、调用白名单和入口 CFG 连接检查；
旧 v1 产物不因此成为 v2 证据，须在新的空目录重新编译。静态 CFG 连接不证明 VM opcode
或 funcid 在实际执行中的动态可达性，也不证明完整 runtime。此检查不执行 VM、设备
嵌套或 EH 路径，也不验证 OOM；这些运行时门禁
仍需独立完成，现有手写 RAII 测试也不替代它们。

三次独立标准 Java/Kotlin fixture 构建的逐目标差异门禁：

```powershell
python -B tests/qseg/build_diversity.py --expected-contract <冻结的expected-contract.json> `
  --fixtures <build-1> --fixtures <build-2> --fixtures <build-3> --output <新的diversity.json>
```

先从独立审核的预期 selection 冻结完整 `protection=vmp` 方法名单，再与固定原始
Java/Kotlin 输入对齐；不得从本次三构建的观测交集、收据计数或成功状态反推分母。
`--expected-contract` 为 JSON：`schemaVersion: 1`、`methods: [{method, symbol}, ...]`、
`inputClasses: {baseline: {class名称: SHA256, ...}, common: {class名称: SHA256, ...}}`。
`method` 使用 MethodKey 完整 owner/name、方法名和 descriptor，`symbol` 必须为
`d2c_ + SHA256(method的UTF-8字节)[:24]`。名单、class maps 均非空且不许重复。
冻结时记录名单来源文件、规范方法名单与 contract 的摘要；旧名单仅提供预期名称，
不提供本次通过证据。可导入 `class_manifest(paths)` 生成各 class 的完整字节摘要。

脚本跟随每份 `inputs.json` 的路径，支持同字节冻结 JAR；比较全部 baseline/common
`.class`，包括 Java/Kotlin 入口和依赖，不只比较 `sample/Logic.class`。若 Gradle 路径
会被后续构建重写，应在每次构建后先复制该份 baseline/protected/common JAR、核对原始
与副本摘要并保留原 inputs 及快照清单，再将该份 inputs 路径指向副本，之后才开始下一次
构建。拒 ZIP 重复 entry 和同一 classpath 的重复 class；protected 完整 class 集须与
本次 generated/classes.jar 相同，后者字节摘要须匹配保护收据。

每份构建的 selection、唯一 receipt symbols、kind1 资源分组、唯一解释器 clone 都须
完整覆盖独立名单；chunks 必须从 0 连续、无重复/冲突、大小及总量与方法收据一致。
固定 `sample.Run` 与 `kfixture.FixtureKt`，baseline/protected 各有且仅有一条结果，
同入口两模式输出相同，跨构建语义相同，且使用相同证书。

每个预期方法的 `resourceIds`、`resourceContentSha256`、`functionKeySha256`、
`dispatchCompareConstantSequenceSha256` 四项都必须各有三个不同值；任一方法任一项
不满足即失败。`resourceContentSha256` 是 QSEG 封装前的 VM 资源内容摘要，**不是外层
QSEG 密文摘要**。分派摘要仅沿 LLVM 21 raw IR 中 salt-masked compare 的实际 false-edge
chain 逐块提取常量序列，直到确认真实 fault/unreachable default，核对 load/trunc/xor/
icmp/branch 的 SSA 关联、无条件入口边、分组连通与目标；缺 salt 的首/中/尾块均拒绝。
忽略链外 xor，不能称为 semantic handler 顺序。函数 key 按整数规范化后计算摘要。
SO/容器整体摘要三份不同只作额外检查，不能替代逐方法检查。

成功报告绑定完整预期名单、contract 摘要及各构建观测；输出文件必须全新，失败不写
成功报告。此测试消费同次构建已完成的签名 APK 认证、收据审计与设备语义证据，不代替
`verify_dex2c_apk.py`、`audit_apk.py` 或设备测试，也不关闭嵌套/EH/OOM 等独立运行时门禁。

`audit_apk.py` 对最终签名 APK 核对收据、逐段认证恢复摘要、全部 SO 的 ELF/ZIP
16 KiB 对齐和容器 STORED 属性，使用方式见 `runtime/QSEG.md`。

`large_fixture.py` 在独立输出目录生成默认 14 个展开算术 VM、一个真实字符串消费方法，
通过现有 `Transformer` / `NativeCompiler` 编译，启用 QSEG 和生产 APK 签名校验。
临时 Java 入口与 Gradle init 脚本都放在输出目录，不修改生产 Java 源码或配置。
`--methods 2..24` / `--rounds 64..1024` 仅用于有界尺寸校准；源码规模不代替产物断言。
每次校准使用新的输出目录，保留失败产物。

```powershell
python tests/qseg/large_fixture.py --output <新空fixture目录> --ndk <ndk> `
  --clang <候选clang.exe> --java <JDK21的java.exe>
python tests/dex2c/device.py --fixtures <fixture目录> --sdk <AndroidSDK> `
  --java <java.exe> --serial <设备> --server-port 5038
```

第二条复用既有 D8、APK 打包/签名、CheckJNI 语义差分和认证负例，生成 `protected.apk`。
`cache_probe.py` 再运行真实 `apksigner` / selection / wrapper 静态核验及 `audit_apk.py`，
从最终 APK 认证解包取得期望摘要。它强制最大 kind1 VM 为完整连续的 `lease-v1` chunks，
且 `65536 < bytes <= 1 MiB`（按设备页取整后也必须不超过预算）；其他独立 lease VM 的
页取整映射总量必须大于 1 MiB，不计入目标。夹具过小、缺块、策略或摘要不一致均失败。

probe 使用同次构建 `linked.so` 的隐藏偏移，先逐字节比较它与最终 SO 的全部 RX
PT_LOAD 几何与内容，再核对最终 SO 中唯一的 RX descriptor。设备实际加载后重新校验
全部 RX 摘要与 descriptor，使用生产认证、解压和 lease 缓存路径；不新增调试导出。
同一进程内 8 线程首次 acquire 与主线程第 9 个 acquire 必须返回同一只读映射。
先配对释放其中 8 次，保留 1 个引用遍历其他压力资源，并核对目标整资源和每块摘要。
最后 release 后仅检查映射、统计，不再读旧指针；先断言目标仍完整 r--p 驻留，再重触
其他资源刷新 LRU。每次 acquire/release 后立即检查原目标完整页区间，在首次无任何
映射覆盖时停止后续分配，再 acquire 目标并复核完整摘要。不能以地址不同或全局
`evictions` 单独证明目标已回收。独立 write 进程必须先输出校验标记，再以 SIGSEGV 退出。

```powershell
python tests/qseg/cache_probe.py --ndk <ndk> --native <native目录> --apk <签名APK> `
  --java <java.exe> --apksigner <AndroidSDK/build-tools/37.0.0/lib/apksigner.jar> `
  --adb <adb> --serial <设备> --server-port 5038 --output <新空证据目录>
```

`native` 须与同级 `generated` 来自同一次 fixture 构建。`plan.json` 绑定最终 APK/SO、
容器、段收据、目标 ID、RX descriptor 和 chunk 摘要；`results.json` 保存目标原始页区间、
两轮压力、回收前/后/重载后的 active/idle/pinned/peak/evictions，以及独立写入拒绝结果。
只有 read 和 write 两个进程都成功满足断言才写成功结果；输出目录必须新建或为空，
防止新一轮失败遗留旧成功报告。

本 probe 直接调用生产 lease 路径，不执行业务 VM，不验证 copy、EH 或业务嵌套调用，
不代表完整宿主注入/兼容性或性能。它直接证明目标回收，不直接观察签名产物的擦零。
`lifetime_test.cpp` 的擦零观察来自带认证桩和 munmap 观测的辅助单元，不能合并成生产
签名 APK 的直接擦零证据。这里只在隔离 fixture/API37/4 KiB 设备执行；API26、真
16 KiB、Linux 和业务应用均需独立验证。

`lifetime_test.py` 的辅助单元在同一生产 runtime TU 中包装唯一的 QSEG `mmap` 调用，
默认转发真实调用。在线程启动前分别 fork 控制和注入 child；两者先成功 acquire/read/
release 一个合法资源，再明确核对目标为未映射、无引用且未 pinned 的 2 MiB kind1。
控制组真实映射并读取首尾、释放并核对映射状态清空；注入组只让该次精确参数匹配的
调用返回一次 `MAP_FAILED`，在原始 write 事件后设置 `errno=ENOMEM`，由未修改的生产
`allocate → fail` 路径退出 127。包装器自身不模拟退出。父进程使用实际 `waitpid`
状态区分 exit/signal；带本次随机 token 的有序事件必须证明 warm/cold、attempt=1、
hit=1 和 child 127，父进程及 ADB 顶层必须退出 0。意外返回会输出 `RETURNED` 并失败。

```powershell
python -B tests/qseg/lifetime_test.py --ndk <ndk> --adb <adb> --serial <设备> `
  --server-port 5037 --output <新的空lifetime证据目录>
```

O0/O2 均以 `-UNDEBUG -fno-lto` 编译并跑完新增子进程与原有生命周期测试后，且必要的
精确文件 cleanup 成功、输入和可执行文件摘要未变，才发布 `results.json`。每条命令
先保存 argv/cwd/起止时间/exit、timeout 或 launch-error，以及未解码的 stdout/stderr
字节文件；失败写 `failure.json`，保留主错误和 cleanup 错误。报告记录固定 serial/
server-port、独立远程目录及设备 model/SDK/pageSize/arch 四条原始查询。成功 schema
为 `schemaVersion: 1, checkerRevision: 1`，包含 `inputsBefore/inputsAfter`、命令记录引用
和 `runs` 中 O0/O2 的 token、`binaryBefore/binaryAfter`、stats；每份 identity 含路径、
字节数和 SHA256。可导入 `validate_run(stdout, stderr, token, page_size)` 复核单次原始
输出，或 `verify_results(output)` 复核完整报告、命令、摘要及两次执行证据。

该 ENOMEM 测试仍使用认证/APK 桩，只覆盖冷 kind1 acquire 的既有 fatal 行为；它不制造
真实地址空间或系统内存耗尽，不证明失败后的清理、recover/retry、业务 EH 或签名 APK
认证链，也不把一次受控 fault 扩展为全部 OOM 路径通过。

`copy_probe.py` 复用同一个已签名 large fixture，不重新生成夹具。它复用上述 APK
签名、wrapper、收据及认证解包检查，固定选择 203 字节 kind2 资源
`83f9a7802590faea85342a4234ccff7e`，强制单 chunk0、`copy-v1` 及完整摘要。
它还将 `protected.ll` 中的 descriptor ID/size/kind 与该资源绑定，要求真实
`call` 或 `invoke` 存在 `(offset=0,length=32,encoding=2)` 和 `(32,17,1)` 切片；
这是字节复制与 encoding 长度约束测试，不能称为 UTF16 解码。

```powershell
python tests/qseg/copy_probe.py --ndk <ndk> --native <同一native目录> --apk <同一签名APK> `
  --java <java.exe> --apksigner <AndroidSDK/build-tools/37.0.0/lib/apksigner.jar> `
  --adb <adb> --serial <设备> --server-port 5038 --output <新的空copy证据目录>
```

设备正例核对整个资源、两个真实切片、尾部、合法零长度及合法奇数 offset，逐个检查
上下 canary、摘要和 copy 返回后 active/pinned 为零。8 个线程先保留独立 buffer，
经 ready barrier 后并发 copy 并核对各自内容。随后 acquire 同一 kind2 source，
确认完整只读映射和摘要后 release；只保存原页区间整数，不再读取旧 source 指针。
用其他 kind1 lease 资源施压，每次 acquire/release 后立即观察原完整区间，首次
无任何映射覆盖即停止后续分配；未观测到完整消失或释放后立即消失均失败。
此时原 copy 的摘要和 canary 必须仍正确，再 copy 恢复并检查一致。

每个参数拒绝用例都在独立新进程先完成有效 copy 和摘要校验，输出带 case 的
`valid-copy=verified invalid-copy=attempt` 标记，随后生产路径必须退出 127：
空输出指针、kind1 descriptor、encoding 0/3、encoding2 奇数 length、offset 越界、
剩余长度越界及 UINT32_MAX length。仅退出 127、缺少标记不能算参数校验成功。
全部正负例通过且源码未变化才写 `results.json`；新旧证据使用不同空目录。
plan/results 绑定本次实际 import 的仓库 Python helpers、C++ 和头文件摘要，
另绑定最终 APK/SO/容器/收据、IR 及调用、全部 RX、header 与 probe 可执行文件。

probe 最后对自己的 15 个调用方 buffer 做 volatile 清零并直接读回，canary 保持。
这只证明 probe 自有副本，不证明 source 在 unmap 前的擦零，也不涵盖 CSE DecGV、
once 状态、Java 对象、intern/cache 或业务明文生命周期；不执行生产 wrapper。

`tests/dex2c/device.py --server-port 5038` 执行 Java/Kotlin 差分、并发、递归、重入、
错误证书及篡改拒绝。`runtime_benchmark.py` 在签名 fixture APK 间交替采样；
回调累计不代表完整注入增量。

`runtime_benchmark.py` 在两个签名 fixture APK 间交替顺序，预热后于 ART 进程内部计时
1000 次数学、递归和字符串混合工作负载；核对校验和，保存逐次结果、配对中位比及
bootstrap 95% 区间。它不包含进程启动，不代表全部宿主业务性能。

`wrapper_lifetime.py` 使用新的固定 fixture 验证真实生成 wrapper 的正常 ART/JNI
嵌套、递归与最终归还。它复用 `large_fixture.py` 的 14 个压力方法、原有 Transformer /
NativeCompiler，以及 `device.py` 的同次签名、语义差分和 14 个认证负例。
仅 fresh generated 的 registration TU 纳入测试 Probe；不修改生产代码，不新增导出。

```powershell
python -B tests/qseg/wrapper_lifetime.py build --output <新的fixture目录> `
  --ndk <r30> --clang <候选Clang21> --java <JDK21的java.exe>
python -B tests/dex2c/device.py --fixtures <同一fixture目录> --sdk <AndroidSDK> `
  --java <同一java.exe> --serial <设备> --server-port 5038
python -B tests/qseg/wrapper_lifetime.py run --fixtures <同一fixture目录> --sdk <AndroidSDK> `
  --java <同一java.exe> --serial <设备> --server-port 5038 --output <新的观察目录>
python -B tests/qseg/wrapper_lifetime.py verify --output <同一观察目录>
```

固定目标是 `sample/Run.outer(I)I`、`inner(I)I`、`recursive(II)I`；完整选中分母还包括
`work0..13(I)I` 和 `marker()I`，symbol 从完整 MethodKey 推导。raw/final IR、逐方法
收据、唯一 descriptor、staging 和最终认证 bytes 必须一致且为 `lease-v1`。aVMP 在改写
前根据 doesNotThrow 选择 lease；后续 hardened CSE 会统一清除 NoUnwind，因此记录
raw/final 的实际 nounwind 布尔值，不以该后处理属性单独推断租约。raw 的 br CFG 与
final 的三块 indirectbr CFG 都严格检查自身 descriptor 的主租约、SelfCheck 临时租约
及配对 release：解释器正常返回后，主 release 必须先于所有 return/后续 resume 分流。
这是正常返回及其后续分流的结构证明，不表示任意 native EH 已覆盖。pinned、未知 IR 形状、缺块、
目标超预算或独立压力不足均保留失败，不添加 noexcept 或降低门禁。固定 4 KiB 页、
SDK build-tools 37.0.0，正常语义输出为
`wrapper-lifetime:nested=71,recursive=342,pressure=14`。

Probe 在 seal 前编入，最终签名后才生成 `plan.json` 和有界 `plan.bin`，以 configure
导入 RX、descriptor、资源及 chunk 摘要，避免依赖最终 SO 的编译循环。配置只做配对
acquire/read/release，实际 case 期间绝不 acquire/get 目标。首次 O_ENTER、I_ENTER、E3
分别扫描完整解析的匿名 r--p 页候选，以 `/proc/self/mem` pread 到自有缓冲：前 32 字节
只筛选，full 和所有 chunk 摘要唯一匹配并复查完整页区间后固定地址。读取、解析、EOF、
关闭、权限或有界扫描失败均不算 absence/unique；活跃期不重新发现替代地址。

嵌套事件为 O_ENTER、I_ENTER、I_EXIT、O_AFTER、O_EXIT、OUT；O_AFTER 在 outer 仍
活跃时单独施压，直到 inner 的完整旧区间首次消失即停并丢旧指针。O_EXIT 再完整施压
验证 outer。`recursive(3,7)` 恰为四帧，事件为
E3,E2,E1,E0,X0,A1,X1,A2,X2,A3,X3,OUT，11 个 inside 事件各遍历全部压力资源，验证
最深处和每次返回后的续执行。active 只按独立映射计费，不能解释为递归引用数。
所有活跃目标须保持完整 r--p、full/chunk 摘要和精确 active/idle/pinned 合同；OUT 后
逐步施压至外层/递归资源旧区间完整消失，首次 absence 后不再压力分配，然后关闭 hooks
重入真实 wrapper，核对 71/342 和最终 active/pinned 为零。

新 runner 对同一个最终 APK 再记录 baseline/protected 正向命令的 exact argv、状态和
原始双流，双方都检查 CheckJNI；不依赖旧入口丢失的正向 stderr。nested/recursive
使用独立 fresh app_process 和随机 token，拒绝缺失、重复、乱序或错 token 事件。
`build.json` 绑定稳定构建子集及实际 Gradle classpath，签名/D8 产物在 run 阶段另行绑定。
只有精确文件 cleanup、设备身份和输入/产物前后复核全部成功才发布 `results.json`；
失败保存 `failure.json` 与原始证据。`verify_results(output)` 可离线重放报告与双流。

此证据的 `callRoute` 为 ART/JNI；不证明同 TU 原生 handler 直连、真实 native unwind /
EH、擦零、API26、真 16 KiB、业务宿主注入兼容性或性能。现有静态 native handler 合同
与这里的动态 ART/JNI 证据保持各自范围。

离线 verify 会从同一 fixture 的实际 selection、raw/final IR、staging、protection、
segments、最终 APK 认证解包及已记录的 llvm-nm 原始字节重建整个 plan，重新绑定精确
MethodKey/symbol、资源及 chunk、descriptor 和全部 RX 摘要，再逐字段比较保存的 plan。
仅更新 plan 与文件身份清单，不能替代其与最终签名产物和方法分母的关联。
