# QSEG 回归

主机格式与认证校验：

```powershell
python -B -m unittest discover -s tests/qseg -p 'test_*.py'
```

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
