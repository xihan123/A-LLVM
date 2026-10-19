# QSEG 回归

主机格式与认证校验：

```powershell
python -B -m unittest discover -s tests/qseg -p 'test_*.py'
```

`audit_apk.py` 对最终签名 APK 核对收据、逐段认证恢复摘要、全部 SO 的 ELF/ZIP
16 KiB 对齐和容器 STORED 属性，使用方式见 `runtime/QSEG.md`。

`cache_probe.py` 使用同次构建的 `linked.so` 隐藏符号偏移，在设备从签名 APK 加载库；
8 线程并发首次恢复后检查地址一致和 r--p 映射，写入必须收到 SIGSEGV。
它选择最大的 VM 资源，报告 `crossChunk` 是否覆盖超过 64 KiB 的多块资源。
该测试不导出生产调试入口，也不调用宿主业务函数；实际 VM 语义由 CheckJNI 差分和
独立验证版宿主启动采样覆盖。

```powershell
python tests/qseg/cache_probe.py --ndk <ndk> --native <native目录> --apk <签名APK> `
  --adb <adb> --serial <设备> --server-port 5038 --output <证据目录>
```

`tests/dex2c/device.py --server-port 5038` 执行 Java/Kotlin 差分、并发、递归、重入、
错误证书及篡改拒绝。`runtime_benchmark.py` 在签名 fixture APK 间交替采样；
回调累计不代表完整注入增量。

`runtime_benchmark.py` 在两个签名 fixture APK 间交替顺序，预热后于 ART 进程内部计时
1000 次数学、递归和字符串混合工作负载；核对校验和，保存逐次结果、配对中位比及
bootstrap 95% 区间。它不包含进程启动，不代表全部宿主业务性能。
