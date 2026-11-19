# QSEG 回归

主机格式与认证校验：

```powershell
python -B -m unittest discover -s tests/qseg -p 'test_*.py'
```

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
