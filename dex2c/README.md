# dex2c：Java/Kotlin 方法保护

候选 `0.1.13-strings1` 新增独立的 `io.github.xihan123.strings` 插件：将指定包内的 Java/Kotlin
字符串抽取到 native，业务方法继续运行在 ART，可与 dex2c 共用一个 SO。
接入与边界见 [字符串插件](STRINGS.md)，实测与待完成门槛见 [验证记录](STRINGS_VALIDATION.md)。
两款插件的共同发布范围与状态见 [0.1.13-strings1 发布记录](RELEASE_0.1.13-strings1.md)。
下文 `0.1.12` 的发布说明保留为已发布版本的记录。

独立 Gradle 构建，插件 ID 为 `io.github.xihan123.dex2c`，当前发布版本 `0.1.12`，配套 A-LLVM `p17`。标注方法的实现转换为 JNI/C++，经 A-LLVM VMP、强化字符串加密、自校验和签名证书绑定后生成 SO；原方法保留为调用 native 的薄包装。Debug 默认保持原实现，Release 转换失败会终止构建。

`segmentedData` 提供独立的 QSEG 分段容器，插件默认关闭，由接入方显式开启。
格式、加载流程及验收门槛见 [QSEG 说明](../runtime/QSEG.md)。

本版包含默认关闭的 `verifyApkSignature` 和分层注解，均由接入方按需启用。
`@dex2c` 保持 VMP 默认行为；`@dex2c(mode = ProtectionMode.NATIVE)` 选择 JNI + CSE，
`@dex2c(mode = ProtectionMode.VMP)` 显式选择 VMP。Java/Kotlin 使用同一 `ProtectionMode` 枚举。
选择优先级为方法注解、继承根规则、类注解、自动回调策略；`selection.json` 记录最终级别和生效原因。
继承根仍选择 VMP 入口、native 回调；NATIVE-only 构建受支持。显式不支持的方法拒绝构建，Release 不保留原实现备用。
完整验签、初始化顺序和最终 APK 任务见 [接入说明](../runtime/APK_VERIFY.md)，
历史测试和未满足门槛见 [候选验证记录](APK_VERIFY_VALIDATION.md)，当前发布步骤见 [0.1.12 发布记录](RELEASE_0.1.12.md)。

## 工具链

本版构建环境：Windows、JDK 21、Gradle 9.8.1、AGP 9.4.1、Kotlin 2.4.20、NDK `30.0.16248370`、LLVM 21 / patchset p17、`arm64-v8a`、minSdk 26。

NDK 中的 Clang 必须支持 `-irobf-vmp-strict`、`-irobf-vmp-post` 及对应的保护 receipt。插件通过实际编译及逐方法 IR 验证探测能力，不仅检查版本字符串。开发时可指定本仓库 `build/bin/clang.exe`，链接器、资源头文件和 sysroot 仍使用指定 NDK。p10 及更早工具链无法通过本版二次混淆检查。

0.1.4 修复 Kotlin 2.4 非 synthetic 的嵌套 lambda 选择。p12 编译器另提供离线的每方法指令映射随机化。
Maven 插件不包含 Clang；本版使用 p17，包含此前的多 VMP TU 链接修复、字符串 runtime 和 QSEG pass。

0.1.8 / p15 缓存同一 payload 块的 schedule seed，允许优化解码算术，并以 switch 分发 native 调用，
仅在选中调用后读取参数。CSE 字节材料拼装移至原生 noinline helper；derive/open 仍受 VMP 保护。
这减少了 VM 中的低层操作，保护范围存在取舍；公开证书的离线恢复边界不变。详见 [验收记录](VALIDATION.md)。

0.1.7 为每份 IR 建立一次索引，复用全部保护校验；生成 C++ 时省去不会抛异常的基本指令检查，
保留 JNI 引用复制的 OOM 和整数除零异常边。LLVM 21 p14 按实际字节码裁剪每方法解释器的无用 handler，
保留独立随机指令映射、payload 加密、非法 opcode 路径及两个字符串 VMP 入口。
样例接入实测 native 编译 86 → 25 秒量级，SO 体积减少约 37%；
这是单次构建对比，完整验证与限制见 [验收记录](VALIDATION.md)。LLVM 20 本轮未改动。

0.1.5 候选增加显式继承根选择。0.1.6 配合 A-LLVM p13 消除 VMP 跳转表文本输出的重复编号扫描，
保留全部文本 IR 校验，并将字符串密钥派生与认证解密入口纳入 VMP、自校验和 post CFG。
此候选尚未发布到远端 Maven；构建需指定本机 staging 仓库。接入及性能边界见
[CSE 运行时说明](../runtime/CSE_HARDENED.md)。

```kotlin
dex2c {
    inheritedMethods.set(setOf(
        "com.example.shared.BaseHook#startHook()V",
        "com.example.shared.BaseHook#lateInitHook()V",
    ))
}
```

跨输入 JAR 的具体子类解析到实际父类/覆写实现；该路径的入口使用 VMP，lambda、匿名类、命名方法引用和同一顶层类的普通辅助调用使用 native+CSE。旧注解仍保持 VMP 递归选择，显式注解优先。只支持父类链，接口 default 根、无匹配根、inline/reified 和无效方法直接失败。不会递归转换整个依赖库；构造器、初始化器和跨顶层普通调用必须额外审查。

`selection.json` schema 3 记录每方法策略与逐子类继承映射，`native.cpp` / `native-symbols.txt` 保存非 VM 回调；`protection.json` schema 4 绑定选择清单、实际 VM/native 符号和 SO 摘要。原生回调从单独通过 CSE 校验的 IR 生成，不进入 VM。

p16 / 0.1.9 将 16 字节认证标签的恒时比较放在原生密码原语边界，open 的认证与解密决策仍在 VM；
Android arm64 的 SHA-256 根据 HWCAP_SHA2 选择硬件指令，其他 CPU 和主机保留软件实现。
LLVM 21 的私有解释器按调用解析 TLS 地址，解码器复用该地址，保留实时状态读写与重入。
算法、轮数、认证失败处理和两个 CSE VMP 入口保持不变，没有新增派生密钥缓存。

转换与字符串封装不保证 APK-only 保密：若全部密钥材料仍可从 SO 和公开证书取得，离线恢复仍然可行。0.1.9 不包含远程敏感材料装载协议，也不宣称修复该缺口；使用者必须单独验收体积、性能和授权架构。

## 接入

在应用的 `settings.gradle.kts` 中配置 Maven 仓库（下载无需凭据）：

```kotlin
pluginManagement {
    repositories {
        maven("https://mirrors.xihan.website/repository/maven-releases/")
        google(); mavenCentral(); gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        maven("https://mirrors.xihan.website/repository/maven-releases/")
        google(); mavenCentral()
    }
}
```

应用模块：

```kotlin
plugins {
    id("com.android.application")
    id("io.github.xihan123.dex2c") version "0.1.12"
}
android {
    ndkVersion = "30.0.16248370"
    defaultConfig {
        minSdk = 26
        ndk { abiFilters += "arm64-v8a" }
    }
}
dex2c {
    buildTypes.set(setOf("release"))
    certificateFile.set(file("signing-cert.der")) // 最终 APK 签名的公开证书，DER 或 PEM
    // NDK 中已安装 p17 时无需指定。
    clangExecutable.set(file("F:/Project/android/LLVM-Patch/build/bin/clang.exe"))
}
```

`certificateFile` 必须与最终 APK 的签名证书一致（可用 keytool 导出，apksigner 核对 SHA-256）。
插件只接收公开证书，不读取或缓存私钥/签名密码；修改证书会使 native 任务缓存失效。缺少证书且有
选中方法时拒绝构建。签名轮换需要重新编译 SO；测试样例使用 debug 签名时也必须传入其公开证书。
封装使用 Python 3，默认从 PATH 查找；可通过 `pythonExecutable.set(file(".../python.exe"))` 指定。
Python 可执行文件、Clang、NDK、证书和插件所带运行时/脚本均参与任务输入。

插件自动加入应用的注解和运行时依赖。在需要注解的依赖模块中另加：

```kotlin
dependencies { compileOnly("io.github.xihan123.dex2c:annotations:0.1.12") }
```

插件应用在 application 模块；通过 AGP 公共 `ScopedArtifact.CLASSES` / `Scope.ALL` 统一处理应用及依赖模块。SO 使用生成 jniLibs 接口加入，兼容应用自己的 CMake/ndk-build，不修改它们的编译参数。

本地开发可使用 composite build（插件请求不要再带版本），或发布到 `build/maven-staging` 并将该文件仓库同时加入插件与依赖仓库。

## 发布插件

发布包含 annotations、runtime、core、gradle-plugin，以及 dex2c、strings 两个 `plugins {}` DSL plugin marker；各 Java 库附带 sources JAR、POM 和 Gradle metadata。测试模块 kotlin-fixtures 不发布。

使用仓库根目录的 `scripts/publish_dex2c.py`（Python 3.11+）。设置 JDK 21 的 `JAVA_HOME`，
准备 Windows / NDK r30 / A-LLVM p17 工具链后运行：

```powershell
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'
$clang = 'F:\Project\android\LLVM-Patch\build\bin\clang.exe'
$ndk = 'F:\Android\Sdk\ndk\30.0.16248370'
python scripts/publish_dex2c.py --check --clang $clang --ndk $ndk
```

`--check` 强制重跑主机 JNI 差分、ARM64 VMP 编译测试及插件验证；失败、跳过或缺少 JNI/VMP
测试结果均拒绝发布。随后生成六个坐标和校验文件，检查完整性。每次使用独立的
`dex2c/build/release-<版本>-<随机目录>/maven`，日志及 SHA-256 清单保留在其父目录。
此步骤不上传，也不替代下文的设备和 LSPosed 回归；编译器或运行时变更仍需先完成真机验收。

正式发布前，将 `build.gradle` 中版本递增，并同步 `Dex2cPlugin.java` 的 annotations/runtime
依赖、`samples/xposed/shared/build.gradle`、`samples/strings/build.gradle` 以及文档示例。脚本校验代码依赖版本一致，接受
`major.minor.patch` 和带候选后缀的版本（如 `0.1.11-verify1`、`0.1.10-qseg2`、`1.2.3-rc.1`），
不接受 SNAPSHOT、构建元数据后缀或覆写已发布版本。候选版本仍使用独立 Maven 坐标，
通过发布检查不代表已完成全部设备验收。通过当前进程环境变量提供凭据，不要写入源码或命令行：

```powershell
$publishCredential = Get-Credential -UserName release -Message 'Maven 发布凭据'
try {
    $env:ORG_GRADLE_PROJECT_xihanUsername = $publishCredential.UserName
    $env:ORG_GRADLE_PROJECT_xihanPassword = $publishCredential.GetNetworkCredential().Password
    python scripts/publish_dex2c.py --publish --clang $clang --ndk $ndk
    if ($LASTEXITCODE -ne 0) { throw 'dex2c 发布失败，请检查日志' }
} finally {
    Remove-Item Env:ORG_GRADLE_PROJECT_xihanUsername -ErrorAction SilentlyContinue
    Remove-Item Env:ORG_GRADLE_PROJECT_xihanPassword -ErrorAction SilentlyContinue
    Remove-Variable publishCredential -ErrorAction SilentlyContinue
}
```

`--publish` 在构建前、上传前检查远程 metadata 及所有预期版本文件，发现完整或部分版本就终止。
检查通过后复用 Gradle 的 Xihan 发布任务，再匿名下载逐字节比对，并确认旧版本列表仍保留；
结果写入 `published.json`。网络错误、403、缺文件或内容不一致均报错。凭据仅传给发布进程，
日志脱敏。上传不是原子操作，失败可能留下部分版本；脚本不会自动覆写、删除或修复远程文件。
请勿并行发布相同坐标，并在仓库服务端保持禁止重复部署 Release。

核验现有发布，不构建、不上传（默认读取手工 Gradle 发布的 `dex2c/build/maven-staging`）：

```powershell
python scripts/publish_dex2c.py --verify-only
# 或核验某次 --check / --publish 的独立 staging：
python scripts/publish_dex2c.py --verify-only --staging 'dex2c/build/release-0.1.3-<实际目录>/maven'
```

此模式验证当前版本的全部文件与远程一致及 metadata 包含当前版本；报告为 staging 父目录的
`verified-<版本>.json`。脚本自身的离线回归：
`python -m unittest discover -s tests/dex2c -p 'test_*.py' -v`。

## 标注与选择

```kotlin
import io.github.xihan123.dex2c.annotation.dex2c

@dex2c
object Hooks {
    fun install(loader: ClassLoader) { /* 原有 Hook DSL、反射、回调 */ }
}

class Example {
    @dex2c
    fun callback(offset: Int): (Int) -> Int = { it + offset }
}
```

`@dex2c` 为 CLASS 保留级别，支持方法和类。方法选择其编译器生成的 lambda、匿名回调和状态机；类选择有实现的方法。普通被调用函数不会沿调用链自动转换。报告记录选择原因及回调关联。

类注解排除构造器、类初始化器、abstract 和已有 native 方法。直接标记不可转换方法、Kotlin inline/reified 方法或 inline accessor、无法判断归属的生成类、自定义 invokedynamic bootstrap、未支持的字节码时明确报错。LambdaMetafactory 的对象创建部分保留在 Java 中，实际回调实现进入 native；StringConcatFactory 展开到受保护实现。

接口默认方法通过同包生成类注册桥接，因为 JVM 接口不能声明 native 方法。普通类的 native 桥接为 private static，使用无固定前缀的稳定短名；完整方法标识保留在构建报告中。

## 运行时与 R8

首次调用由模块自身 ClassLoader 加载专属 SO，按实际传入的 `Class` 注册；不会在 JNI_OnLoad 批量初始化业务类。线程独立使用当前 `JNIEnv*`，支持递归及 native → Java → native 重入。局部引用随 frame 释放，循环中复用槽位。

Java 异常检查、catch 顺序和 finally 分支在受保护函数内，无 C++ try/catch。运行时处理整数溢出、掩码移位、除零、浮点饱和转换、null、数组边界和对象身份；String 构造使用 ART 支持的 `NewObjectA` 路径。

每个保护类保留一个短名的数字索引解析方法，使用类字面量适配 LSPosed 在加载 DEX 时对 API 类型的重命名；DEX 不再重复保存明文类名比较表。精确名称到索引的映射在 native 的一段 CSE 加密数据中，不使用可能冲突的类名哈希。类型和描述符缓存按实际保护类隔离，宿主传入的 ClassLoader 和反射对象按原代码使用。

0.1.2 将运行时类、lambda 工厂及 SO 改为无固定品牌前缀的名称，并从转换后的 class 删除选择注解。`JNI_OnLoad` 只注册产物自身的运行时入口，业务类仍在第一次调用时注册。数字到 Class 的对应关系、类型签名和 native 声明仍可分析；这些改名与压缩不增加密码学强度。

生成的 R8 规则保留 native 引用的类型、成员、签名以及选中方法的包装和 Kotlin metadata。使用动态字符串查找、外部配置构造的反射名称仍需应用提供自己的 R8 规则；转换器无法静态推断任意反射目标。

## 产物与失败策略

`build/intermediates/dex2c/<variant>/generated/`：

- `selection.json`：原方法、桥接、回调关联、结构性排除项及字节码核验状态。
- `classes.jar`：供 AGP/R8 使用的转换结果；每个选中方法只留下注册和桥接调用。
- `protected.cpp`、`registration.cpp`、JNI 运行时、`keep-rules.pro`、`symbols.txt`。

`build/intermediates/dex2c/<variant>/native/`：

- `protected.raw.ll` → `protected.ll`：先 strict VMP，再优化加密 VM 的体积，最后执行 `-irobf-vmp-post`。逐方法复核 receipt、解释器入口、证书/自校验密钥折入及字节码未改变。
- `protected.o`：关闭进一步 LLVM IR pass，从上述最终已核验 IR 生成；不重新编译原 C++ 业务体。每个方法仍保留独立随机化 VM。
- `jniLibs/arm64-v8a/lib<产物短名>.so`、编译日志及 `protection.json`（IR/object/SO SHA-256、方法清单、大小）。

0.1.2 固定开启 `-irobf-cse -irobf-cse-hardened -irobf-cert-bind`，对业务、注册和 JNI 辅助代码的
字符串加密；VMP 使用 `-irobf-selfcheck -irobf-selfcheck-entry`。仅注册边界额外使用 FLA，避免
对通用数组/数值实现重复平坦化造成膨胀。A-LLVM 证书与 CSE 运行时独立编译，随插件分发。
链接启用 sections/GC、限制导出表，然后封装 → strip（删除 `.comment`）→ 验证封装与逐方法字节码。
证书定位以本 SO 为锚点，在 Xposed 宿主中绑定模块 APK；不绑定宿主证书或宿主包名。

0.1.3 要求 p11 的 `-irobf-vmp-post` 能力。它在优化后处理 VMP 入口和 `.s0` 全部函数：
展开 switch，将条件分支改为间接跳转，使用随机排列、加密的函数内相对偏移表减少动态重定位。
入口密钥和调用分发比较常量另做 CIE；不为每个 JNI 参数偏移重复生成加密表。
编译器写入 `ndkp.vmp.post` receipt，插件同时检查实际 CFG：不得残留 switch/条件 br，
间接跳转数量必须与 receipt 一致。缺少能力或校验失败即终止，不回退为仅 VMP 的产物。
`protection.json` schema 3 记录 `vmpPost` 和逐函数 `nativeIndirectBranches`。

此处理增加原生分析成本，不提供不可去虚拟化保证。公开证书参与密钥绑定但不是秘密；
掌握 VM 格式和运行时材料仍能恢复算法。构建目录内保留的 C++/IR 是诊断文件，不打入 APK。

加载/注册的普通 JNI 错误仍抛异常；错误证书、篡改或 CSE 认证失败由 A-LLVM fail-closed 终止进程，
不能由 Java Hook 的 `runCatching` 恢复。不要把错误证书产物部署到真实宿主。

编译器 strict 模式在资格检查、翻译、替换或解释器链接失败时拒绝显式选择的函数；未开启 strict 时保持兼容行为。加载或注册失败抛出异常，由应用既有 Hook 容错层处理；Release 不包含原方法体作为备用实现。

任务输入包含 class、依赖、工具链及保护配置。转换及 native 任务可恢复 Gradle 缓存；缓存保存已验证的随机化 VMP 产物。删除注解或更改库名会清理该任务拥有的旧 jniLibs，避免残留 SO。

## 验证

仓库根目录执行（PowerShell，设置本地路径）：

```powershell
$ndk = 'F:\Android\Sdk\ndk\30.0.16248370'
$clang = 'F:\Project\android\LLVM-Patch\build\bin\clang.exe'
.\dex2c\gradlew.bat -p dex2c check :gradle-plugin:validatePlugins :core:prepareDeviceFixtures "-Pdex2c.hostCompiler=$clang" "-Pdex2c.ndk=$ndk"
python tests/vmp/strict.py --clang $clang --ndk $ndk
python tests/vmp/casts.py --clang $clang --ndk $ndk --serial <adb-serial>
python tests/dex2c/device.py --sdk F:\Android\Sdk --java 'C:\Program Files\Java\jdk-21\bin\java.exe' --serial <adb-serial> --fixtures dex2c/core/build/device-fixtures --ndk $ndk --clang $clang
python tests/dex2c/gradle.py --gradle .\dex2c\gradlew.bat --sdk F:\Android\Sdk --clang $clang --work-dir work/dex2c-fresh-build-check
```

`device.py` 从临时签名 APK 加载受保护 SO，在 ART/CheckJNI 下比较 Java/Kotlin 原 DEX 和 VMP JNI，并拒绝错误签名和篡改字节码；`--ndk` 自动编译未启用 VMP 的 JNI 对照，也可通过 `--native-reference` 提供现成的对照 SO。`gradle.py` 在独立副本中验证 Debug、R8 Release、依赖回调、现有 SO 共存、16 KB ELF/APK 对齐、增量构建、缓存恢复、注解删除及缺少证书的拒绝路径。

真实 LibXposed 102 样例位于 `samples/xposed`。使用 `-Pdex2c.certificate=<debug签名的公开证书.der>` 构建 `:module:assembleRelease` 和 `:host:assembleDebug`，安装两个 APK，在 LSPosed 中仅选择测试宿主作用域后重启宿主进程。主进程和 `:worker` 均应输出 `calculate=37 exception=-99`、`isolated-loader=OK existing-native=102`；样例重复调用 install，测试独立宿主 ClassLoader、参数/结果修改、异常及既有 native 库。

启用作用域后可运行 `python tests/dex2c/xposed.py --sdk F:\Android\Sdk --serial <adb-serial> --report work/dex2c-xposed.json`，自动安装样例 APK、启动宿主并检查两个进程的结果。

CI 的 `checks` 验证 ASM/Kotlin 选择和插件；LLVM 21 工具链构建额外运行 strict/cast 及 Windows JNI/VMP 编译测试。真机与 LSPosed 验收须在显式指定的设备执行。

## 边界

类结构、构造器、初始化代码、类型解析表和 JNI 交互仍可见；VMP 保护选中的实现。高频热点和长循环有明显运行开销，按报告和业务基准选择保护范围。16 KB 对齐已做静态检查，当前验收真机为 4 KB 页面，不等同于 16 KB 真机运行验收。

可读的 `protected.cpp` 是构建目录中的诊断中间文件，不打包进 APK。交付函数只含 VM 入口逻辑，
原算法的分支/循环在加密字节码中。JNI 导入、标准库诊断及运行时解密后的明文仍可能被观察到；
该保护不承诺隐藏所有字符串或抵抗同进程任意读写。

CSE 消除静态明文，不提供离线密钥保密：公开证书、SO 代码和密钥派生材料都在交付产物中。
基于公开算法，可以仅用 APK 恢复 CSE 记录。证书/完整性绑定能够拒绝未经重新封装的换签名或篡改，
不代表主动分析者不能重新派生、修改或封装产物。VMP 提高方法逻辑恢复成本，也不作不可恢复承诺。

详细实施与实测结果见 [VALIDATION.md](VALIDATION.md)。
