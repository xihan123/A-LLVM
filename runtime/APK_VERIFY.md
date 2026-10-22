# 离线 APK 验签

发布版本 `0.1.12` / A-LLVM `p17`，面向 LLVM 21 / NDK r30、arm64、Android API 26+。
`verifyApkSignature` 继续默认关闭，由接入方显式开启。历史 `0.1.9 / p16` 保留为对照。
设备验收边界和发布顺序见 [发布记录](../dex2c/RELEASE_0.1.12.md)。

## 接入

```kotlin
dex2c {
    certificateFile.set(file("release-public.der")) // APK 签名证书，可用 DER / PEM
    verifyApkSignature.set(true)
    segmentedData.set(false)                      // QSEG 独立选择
}
```

插件只接收公开证书，规范化为 DER 后固定其 SHA-256。无需联网、CA 信任链、证书有效期判断或私钥。
本机/CI 仍需安装 JDK、Android SDK、Python 3 和对应 A-LLVM 工具链。

`verify<Variant>Dex2cApk` 自动接入该 variant 的 `assemble`，读取 AGP 最终 APK 产物，使用该项目
SDK build-tools 的 `apksigner` 验签，再核对证书、方法选择清单、DEX 薄包装、SO 和 QSEG 摘要。
不会修改或重新签名 APK。报告位于 `build/reports/dex2c/<variant>/apk-verification.json`。
重新打包的分发任务可注册 `VerifyApkTask` 并设置 `apkFiles`，复用原任务的 native/generated
目录、公开证书和 SDK 工具输入；此时不要设置 `apkDirectory`。必须在最后一次签名之后核验。
AGP 的多个独立 APK 输出分别检查；手动调用 `scripts/verify_dex2c_apk.py` 时，重复 `--apk`
默认表示一个 base/split 安装集合，`--independent-apks` 表示多个独立安装产物。
没有选中方法时报告零保护方法，保持不需要 native 编译和 Python 的路径。

## 格式与密码实现

- 支持 APK Signature Scheme v2/v3、单签名者，RSA-PSS、RSA-PKCS1-v1.5、ECDSA 的 SHA-256/512 组合。
- ECDSA 配置包含 P-256、P-384、P-521。PSS 使用相同 MGF1 摘要及与摘要等长的 salt。
  构建期拒绝该裁剪配置不支持的证书公钥：普通 RSA 公钥上限 8192 bits，或上述三种 EC 曲线。
- 核对证书 SPKI 与签名公钥、签名和摘要算法列表、v3 内外 SDK 范围，以及签名降级属性。
  各存在的 v2/v3 块都必须通过，并绑定同一证书。API 26/27 必须有 v2。
- 明确拒绝 v1-only、多签名者、轮换、v3.1、未知签名算法、ZIP64/多卷、重复签名块和畸形长度。
  签名块上限 16 MiB；单安装目录上限 128 个 APK；APK 文件大小须小于 4 GiB。
- 内容摘要按 Android 的三个区域和 1 MiB 分块计算，包含中央目录、EOCD 以及 EOCD 中央目录偏移修正。
  同一次核验复用 SHA-256/512 内容摘要；同一 DSO 生命周期内不重复完整扫描已核验 APK。
- 证书身份是完整 DER 的固定摘要。仅从被固定的 DER 提取 SPKI，不把证书自身签名算法、日期或颁发机构
  当作 APK 身份判断。因此可支持使用旧证书算法、但 APK 使用受支持算法签名的应用。
- Android 允许 signed-data 属性后存在扩展字节；这些字节仍全部参与签名验证。

Mbed TLS `3.6.7` 固定为提交 `068ff080b369adfac81509f9b57b2afabaf82dc5`，上游源包 SHA-256
`ca6bd316bbec49ef20088f39b8755fcaec0b7e45781506de55b17cd191ae6937`。
`third_party/mbedtls/MANIFEST.json` 保存逐文件校验值。仅编译 `apkverify_sources.txt` 中的 22 个 C 文件，
关闭 TLS、网络、熵源及 PSA；保留必要头文件和上游许可。Gradle 打包时检查源文件摘要，消费者解包时
再次校验资源索引。源码随 core JAR / sources JAR 分发，消费者构建不会下载 Mbed TLS。

## 来源、初始化和失败

`ndkp_apkverify.cpp` 以本 DSO 内 hidden 地址定位映射，不使用宿主 PackageManager 身份：

1. 独立 APK 直接加载时核验该 APK。标准 `/data/app/…` 或 `/mnt/expand/…/app/…` 安装布局中，
   核验所属目录全部 base/split APK，并要求存在 `base.apk`、所有证书相同。
2. 解压加载时检查磁盘 SO 与映射 inode，并把 SO 与签名 APK 中唯一匹配的 STORED/DEFLATE 条目
   按有界分块逐字节比较。拒绝独立缓存 SO、未知路径、删除的映射和多重匹配。
3. 引导单元独立编译，关闭 LTO 和混淆。优先级 101 构造函数在应用构造函数之前核验；CSE、证书混合值、
   VMP 和 QSEG 的后续入口共用状态，NATIVE-only 也不能跳过验证。
4. 互斥锁串行化发布，线程局部重入守卫遇到递归立即失败。全部文件通过且 stat 快照未变化后才发布状态。
   APK、解压 SO 和安装目录保留 fd/快照；复用时检查 inode、大小、mtime/ctime，检测替换、修改与新增 split。
5. `ndkp_verified_apk` 返回借用的 APK fd，所有权属于 DSO，卸载时关闭。调用方不得关闭它。
   不保存派生解密密钥。`ndkp_certbind_mix` 的 C ABI 保持不变。

失败执行 `exit_group(127)`，不发布可用证书/解密状态。在 LSPosed 中也会终止所在宿主进程。
关闭开关时仍使用旧的“提取证书并绑定”行为，后者不是完整 APK 验签。

## 边界

签名验证保证被读取 APK 的签名及内容一致性，提高换签和修改成本。拥有同进程任意修改、内核或 root
控制权的分析者仍可能修改验证器、内存、系统调用或观察恢复后的数据；stat 快照不是文件系统不可变性证明，
证书、VMP 材料及离线运行时均在交付物中，不承诺算法或运行时数据不可恢复。

验收及未通过项目见 [候选验证记录](../dex2c/APK_VERIFY_VALIDATION.md)。
