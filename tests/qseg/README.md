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

`tests/dex2c/device.py --server-port 5038` 执行 Java/Kotlin 差分、并发、递归、重入、
错误证书及篡改拒绝。`runtime_benchmark.py` 在签名 fixture APK 间交替采样；
回调累计不代表完整注入增量。

`runtime_benchmark.py` 在两个签名 fixture APK 间交替顺序，预热后于 ART 进程内部计时
1000 次数学、递归和字符串混合工作负载；核对校验和，保存逐次结果、配对中位比及
bootstrap 95% 区间。它不包含进程启动，不代表全部宿主业务性能。
