# Java/Kotlin 字符串 native 保护

候选版本 `0.1.13-strings1`，插件 ID `io.github.xihan123.strings`。复用 dex2c 的 Gradle 构建、
A-LLVM 编译器验证、CSE 封装和最终 APK 验证；本候选尚未上传 Maven。

## 接入

使用已安装的 JDK 21、AGP 9（验证版本 9.4.1）、NDK r30、支持 strict/post receipt 的
A-LLVM LLVM 21；首版只生成 `arm64-v8a`，要求 minSdk 26。NDK 必须预先安装。

```kotlin
plugins {
    id("com.android.application")
    id("io.github.xihan123.strings") version "0.1.13-strings1"
}
android {
    ndkVersion = "30.0.16248370"
    defaultConfig {
        minSdk = 26
        ndk { abiFilters += "arm64-v8a" }
    }
}
stringProtection {
    includePackages.set(setOf("com.example.business"))
    excludePackages.set(setOf("com.example.business.generated"))
    certificateFile.set(file("release-cert.der"))
    verifyApkSignature.set(false)
    // clangExecutable.set(file("/path/to/patched/clang"))
    // pythonExecutable.set(file("/path/to/python3"))
    // buildTypes.set(setOf("release"))
}
```

仓库配置与 dex2c 相同，见 [接入说明](README.md#接入)。本地可使用 composite build，
插件请求不带版本。完整 Java/Kotlin Android 样例位于 `samples/strings/`，支持
`-Pprotection.mode=baseline|strings|combined|dex2c`。

`includePackages` 必填，不接受通配符；包边界匹配并包含子包，排除优先。默认只转换 Release。
最终签名者的公开 DER/PEM 证书必需，不接收私钥；轮换签名需重编译。零字符串且无 dex2c 方法时
不生成 SO，不要求证书、Python 或 NDK。配置了不存在的工具/证书文件仍属于配置错误。

## 转换与缓存

AGP `Scope.ALL / ScopedArtifact.CLASSES` 读取应用及依赖字节码，在 R8/D8 前替换选中包内
方法、构造器、初始化器、lambda 和协程生成方法的字符串 `LDC`。StringConcatFactory
拼接中的常量片段展开后同样抽取；参数求值顺序与对象到字符串的转换顺序保持不变。
普通 lambda 的创建留在 JVM。未知 bootstrap、动态常量或不支持的拼接形式明确报错。

同一产物内字符串去重，通过 UTF-16 code unit 数组无损生成 native 数据，包括 NUL、
代理对和孤立代理项。每条数组增加一个不返回给 Java 的哨兵，保证空串/全零串也可进入 CSE。
单个 native 数字索引入口通过 `NewString` 返回结果；Java `intern()` 保留常量身份语义。

生成的独立运行时使用 `AtomicReferenceArray<String>` 和 16 个初始化锁。每项首次读取完成
native 解密与 intern 后才发布；后续读取不进入 JNI。失败不发布缓存；并发首次访问只调用一次
成功的解码。缓存随生成运行时的 ClassLoader 隔离，不持有其他业务 ClassLoader 的全局注册表。
平台对同一 SO 文件的 ClassLoader 所有权限制仍适用；不支持把同一个库文件同时加载到多个
互不关联的 ClassLoader，不通过复制 SO 绕过该限制。

保留 `ConstantValue`、注解、Kotlin metadata、资源、调试属性及结构性名称。
`static final` / `const val` 被编译器内联到选中代码的位置会保护，但字段本身及包外副本可能仍含明文。
转换时重建常量池，删除失去引用的字符串；不改变字段常量和类初始化语义。R8 仍可正常删除无用代码。

## 与 dex2c 组合

两插件应用顺序无关，只有一条 variant 转换流水线、一次 native 编译和一个 SO。
dex2c 先转换选中的完整方法，字符串插件处理剩余业务方法；包装、桥接及生成运行时不重复抽取。
两个 `buildTypes` 集合按 variant 独立生效。

证书、Clang、Python 配置合并；双方配置不同文件路径时明确报错，建议只在一方设置共享项。
完整 APK 验签取双方启用值的 OR，默认关闭。dex2c 单独使用时仍使用原来的方法保护流程。
本插件不修改应用自己的 CMake/ndk-build 编译参数。

## 保护与产物

- hardened CSE：ChaCha20-Poly1305、HKDF-SHA-256、记录认证、证书绑定和本 SO 代码摘要绑定。
- CSE `derive/open` 控制入口使用 VMP、入口自校验及 post CFG；标准密码运算保留 native 边界。
- Java 缓存及 native 索引分发不虚拟化。没有新增长期派生密钥缓存。
- 完整验签可选，格式与初始化限制见 [APK_VERIFY.md](../runtime/APK_VERIFY.md)。

流程为验证 IR → 从原 IR 生成对象 → 链接 → 封装 → strip → APK 打包签名 → 最终 APK 验证。
验证器检查每条生成 UTF-16 数组的加密缓冲区和解码调用；缺记录、明文数组残留、receipt 或
实际 VMP 结构缺失均拒绝构建。最终验证核对证书、SO、转换清单、类 JAR 摘要及 R8 后的 native 解码边界。

沿用 `build/intermediates/dex2c/<variant>/` 和 `build/reports/dex2c/<variant>/`：

- `generated/string-selection.json`：唯一记录数量、出现位置/索引、排除原因及保留类别，不写明文。
- `generated/selection.json`：dex2c 方法与上述字符串清单的组合。
- `native/protection.json`：`protectedStrings`、字符串分发符号、清单与 classes.jar 摘要，以及原有 CSE/VMP/SO 证据。
- `apk-verification.json`：最终 APK 结果，包括只有字符串、没有转换方法的场景。

构建目录的 C++/IR 是诊断材料，可含原文，不打入 APK；应按应用源代码管理访问权限。

## 边界与验收

公开证书不是秘密，全部本地材料仍可离线分析。CSE 明文沿用静态存储期，Java 缓存和 intern 池
同样保留使用过的字符串；动态读取或修改解密结果仍可绕过保护。
VMP 自校验覆盖字节码，CSE 代码摘要默认首次初始化计算；热缓存命中不会重复验签或扫描代码。
初始化之后的修改不能被描述为每次读取都能检测。

已执行检查、基准、复现命令与尚缺的设备门槛见 [字符串验证记录](STRINGS_VALIDATION.md)。
未完成目标设备和真实业务应用验收前，本候选不得当作正式发布版本。
