# 显式低频完整性复验（0.1.15-dev，未发布）

在初始化、配置提交等低频业务边界显式标记方法：

```java
@dex2c(integrityRecheck = true)
static String initialize(String value) { return "initialized:" + value; }

@dex2c(mode = ProtectionMode.NATIVE, integrityRecheck = true)
static String commit(String value) { return "committed:" + value; }
```

默认 `false`。`true` 仅允许显式方法注解，类级 `true` 拒绝构建；属性不会传播给 helper、lambda、
回调或继承根选中的其他实现，原保护级别优先级不变。要复验某个继承实现，须直接标记该实现。
存在至少一个显式复验方法时，生成的 `JNI_OnLoad` 注册边界也标记复验；该注册证据单独记录，
不能替代业务方法自己的入口覆盖。未标记方法不会增加入口复验。

接线复用现有 `ndkp.cse_recheck`，不增加后台线程、轮询或进程环境探针。p31 的 LLVM 21
非分段 pass 排除 annotation-only 标签与源码路径，允许真正零 CSE pool 的 TU：其入口和
103 加载构造器以自身 RX guard 地址复用同 SO 中 102 构造器已认证、登记的 CSE 模块。
不额外造 pool、业务常量或 sentinel。认证上下文缺失、来自其他 SO 或身份不符均失败关闭；
整个 SO 都没有认证 CSE 模块的显式检查配置不会获准运行。仅同步 runtime 不会使 LLVM 20
获得此接线；分段空池仍拒绝。详见 [运行时与部署合同](../runtime/CSE_HARDENED.md)。

## 两种已有运行时路径

- 非分段：入口 → `ndkp_cse_module_recheck` → `ndkp_cse_recheck_module_v1`。guard 对模块描述符五字段
  做 volatile 快照校验，运行时重测本 SO 的 RX 摘要和实时页面权限，认证缓存公开输入的哨兵记录。
  暖态复验不重读 APK/包名，也不重置 once 或清除已有业务明文。
- 分段：入口 → `ndkp_cse_module_recheck_v2`（可能内联）→ `ndkp_qseg_recheck`。沿用现有 QSEG 路径，
  重新测量本 SO、重新读取公开输入并检查容器摘要；不能将非分段“不重读 APK”的行为套用于此路径。
- p31 非分段零 pool：入口/103 构造器 → `ndkp_cse_image_recheck` → `ndkp_cse_recheck_image_v1`。
  runtime 要求自身与 anchor 同库，核对全部登记原描述符、逐个复用 module recheck；完整 APK
  验签启用时复查原保留的 fd/stat 快照，不重复完整内容验签。runtime OBJECT 必须并入该 SO，
  不支持公共动态 runtime；多个独立 SO 各自保存本库状态。

这些路径均同步执行，成本随本 SO RX / 对应容器大小和登记模块数增长，不承诺固定时延，不适合热路径或 signal handler。
检查范围只针对本 SO 及所用保护描述数据；不因 root、LSPosed 或其他 SO 的存在拒绝运行。
对本 SO 的真实 inline hook / RX 改写或可写执行映射会拒绝，接入方应避免把合法修改本 SO 当成允许项。
复验不是持续监控；两个入口之间的改写窗口、绕过检查、同进程任意写等边界仍存在。
它不重新认证所有业务明文缓存，也不证明整个进程没有被修改。

## 编译与最终 APK 证据

`selection.json` schema 4 逐方法记录 `integrityRecheck`，顶层记录 `registrationIntegrityRecheck`。
`NativeCompiler` 核对 VMP raw / final IR，以及 native / registration 最终 IR 的真实入口调用链；
首个非 debug/lifetime 调用必须直接抵达对应 guard / 允许内联的运行时；此前存在间接调用、其他调用、
invoke 或 inline asm 会拒绝。helper 必须存在可达的对应运行时调用，每条可达正常返回路径均经过它。
仅保留注解、声明、无调用的 helper 或错误运行时路径会使构建失败。
这些检查验证现有 pass 的有限 IR 形状和调用路径；五次 volatile load 计数不是完整的描述符数据流证明，
也不构成通用 LLVM IR 语义验证器。
零 pool guard 另要求 private/noobf、唯一一次 image runtime 调用的参数为自身直接地址、以及
103 构造器接线；元数据并不替代真实调用。回执的 `guard` 区分 image 和 module 路径，顶层
非分段 `runtime` 仍指最终复用的 module 认证引擎。Java 与最终 APK Python 验证器同步支持此形状。
最终 IR 使用 `-disable-llvm-passes` 编译，编译前后校验哈希不变。
`protection.json` schema 6（非分段）/ 7（分段）的 `integrityRecheck` 记录逐符号 guard、translation unit、
运行时路径和 IR SHA-256。无显式入口时该字段为 `null`。

冻结 requirements 可以在既有 method/protection 分母上明确要求入口与注册复验：

```json
{
  "schemaVersion": 1,
  "registrationIntegrityRecheck": true,
  "methods": [
    {"method": "sample/Run.initialize(Ljava/lang/String;)Ljava/lang/String;", "protection": "vmp", "integrityRecheck": true},
    {"method": "sample/Run.commit(Ljava/lang/String;)Ljava/lang/String;", "protection": "native-cse", "integrityRecheck": true}
  ]
}
```

方法身份采用 `selection.json` 的原始内部类名格式；继承要求仍可提供既有 `entry` 字段。
最终 APK verifier 重新核对 IR 哈希与 guard，检查冻结要求，再沿用 selection / 最终 SO 哈希、签名和
最终 DEX wrapper / bridge 验证。报告 `integrityRecheckWiring` 的通过范围仅为
`compiler-ir-and-signed-apk-static`；`capabilities.integrityRecheck` 始终保持 `device-runtime/unverified`，
静态接线通过不能宣称真实业务已通过设备攻击验收。编译器/插件来源仍受既有 provenance 限制。

## 可重复 fixture 与验收边界

```powershell
.\dex2c\gradlew.bat -p dex2c :core:test :gradle-plugin:test --no-daemon
python -m unittest discover -s tests/dex2c -p 'test_*.py'
.\dex2c\gradlew.bat -p dex2c :core:prepareDeviceFixtures `
  -Pdex2c.integrityRecheck=true -Pdex2c.fixtureDirectory=../work/m2-integrity/plain `
  -Pdex2c.ndk=<candidate-ndk> -Pdex2c.hostCompiler=<candidate-clang>
```

分段另加 `-Pdex2c.segmentedData=true` 并使用独立输出目录。fixture 有 VMP `initialize`、NATIVE `commit`
各一个显式入口和未标复验的 `hot` 对照，可用既有 `tests/dex2c/device.py` 验证正常 JNI 语义和冷态拒绝，
并生成签名的 `protected.apk`。随后复用相同 fixture 执行暖态测试：

```powershell
python tests/dex2c/recheck_device.py --sdk <sdk> --java <java> --ndk <candidate-ndk> `
  --clang <candidate-clang> --serial <serial> --fixtures <fixture-directory> `
  --work-dir work/m2-integrity/warm-plain
```

分段使用其独立 fixture 与输出目录，CLI 相同。脚本单独编译 Java driver / JNI mutation helper，
不修改、重签原 APK，也不重建受保护 SO。仅在已测量 RX 段内、所有 allocated ELF section 之外的明确
padding 做字节改写；找不到这种 padding 就拒绝测试。另一路只把相同页改为 RWX，不改变字节。
每个 case 都在同一进程先成功执行真实 VMP `initialize`、NATIVE `commit` 和 `hot`，再做 mutation，
确认 `hot` 仍成功，最后调用指定 checkpoint。八项为两项无 mutation 正常/并发调用，以及 RX 字节 / 实时
权限 mutation 下各三项 `hot`、`initialize`、`commit`；正常和 `hot` 对照须退出 0，四个攻击入口须退出 127。
JSON、命令日志保留 warm-before / mutation / hot / checkpoint 证据、页面大小和退出码；提供脚本不等于设备已通过。

冷启动改文件被旧 CSE 拒绝不能证明新的暖态接线。历史 p7 `recheck_test.py` 的非分段结果也不覆盖
本轮生成链或 QSEG 设备路径。设备、root/LSPosed 宿主、真实 16 KiB 页面及性能测量结果应按实际执行单独记录。

p31 的纯整数 NATIVE fixture 使用以下测试开关生成，`native.ll` 必须无 CSE payload，
`registration.ll` 必须保留真实有池 102 登记；实际方法与 `JNI_OnLoad` 各自进入对应 guard：

```powershell
.\dex2c\gradlew.bat -p dex2c :core:prepareDeviceFixtures `
  '-Pdex2c.zeroPoolRecheck=true' '-Pdex2c.fixtureDirectory=<absolute-output>' `
  '-Pdex2c.ndk=<candidate-ndk>' '-Pdex2c.hostCompiler=<candidate-clang>'
```

本批已有 host 真实 dex2c 编链/封装/strip 回归。独立 image SO 专项在 OnePlus 7 / GM1901 /
API 37 / ARM64 / 4 KiB 上实测 20 例，覆盖正常与 strip 后加载、缺失上下文、暖态 RX/权限/cache/
诱饵/描述符篡改、异库 anchor、多 SO 独立状态、外库 RWX 与并发构造器回调；实际退出码见
`work/m4-image-p31/device-reviewfix-final/results.json`。该结果不替代 dex2c JNI/业务 APK、
完整 APK 验签、root/LSPosed 宿主、物理 16 KiB/API26/29 或性能验证。
