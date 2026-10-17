# runtime/ — APK 签名证书绑定运行期 helper（`-irobf-cert-bind`）

新增的 arm64 字符串强化模式 `-irobf-cse-hardened` 使用独立运行时和链接后封装流程，见 [CSE v1 接入说明](CSE_HARDENED.md)。旧模式继续使用下述接口。

`-irobf-cert-bind` 把"运行期 APK 签名证书的 SHA-256 派生混合值"折进解密密钥（`-irobf-cse`
字符串 pepper 与 VMP 函数密钥），使产物**仅在被构建期指定证书签名时才正确运行**：错签名 /
重打包 / 缺证书 ⇒ 密钥不抵消 ⇒ 字符串与被虚拟化函数解出乱码（非分支、fail-closed，无可
patch 的 `if`）。

编译期折入由 overlay pass 自动完成；运行期读证书这一步需要 app 侧链接**一个源文件**
（证书解析是重活——本库 APK 定位 + v2/v3 签名块解析 + SHA-256——不宜以注入 IR 实现，故做成
链接式 helper）。

## 文件

| 文件 | 作用 |
|---|---|
| `ndkp_apkcert.cpp` | **要编进你的 `.so` 的唯一文件**：定义 `extern "C" void ndkp_certbind_mix(uint64_t* lo, uint64_t* hi)`，pass 注入的加载期构造器会调它。 |
| `apkcert.h` | 定位**本库所属 APK**，从其 v2/v3 签名块读取证书 DER 并 SHA-256（自 stringarmor2 移植）。刻意不走 `PackageManager.getPackageInfo`——那是 CorePatch/LSPatch/伪造签名 Xposed 模块 hook 的 API。 |
| `sha256.h` | 头文件版 FIPS 180-4 SHA-256（`apkcert.h` 依赖）。 |
| `apkcert_io.h` | 证书解析共享的 I/O 后端；旧接口默认使用 POSIX，新 CSE 模式使用 POSIX/raw syscall 双路径。 |
| `jni.cpp.reference` | stringarmor2 里"在 `JNI_OnLoad` 折证书混合值进 pepper"的**上游参考**（含 `blob.h` 等本仓库没有的依赖，**不编译**），仅示意折入设计。 |

## 集成（三步）

**1. 将 `ndkp_apkcert.cpp` 单独编译，再链接进 native 库**（C++17，POSIX，无第三方依赖）。

读取证书的代码必须不带混淆开关，并关闭 LTO。否则 `/proc/self/maps` 等路径也会被证书绑定加密，形成初始化循环。编译器会拒绝在定义 `ndkp_certbind_mix` 的翻译单元上开启 `-irobf-cert-bind`。

CMake（`externalNativeBuild`）：
```cmake
add_library(ndkp_cert_runtime OBJECT path/to/runtime/ndkp_apkcert.cpp)
target_compile_features(ndkp_cert_runtime PRIVATE cxx_std_17)
set_target_properties(ndkp_cert_runtime PROPERTIES
  POSITION_INDEPENDENT_CODE ON INTERPROCEDURAL_OPTIMIZATION OFF)
target_compile_options(ndkp_cert_runtime PRIVATE -fno-lto)
target_sources(your_lib PRIVATE $<TARGET_OBJECTS:ndkp_cert_runtime>)
# 混淆参数只加到 your_lib，不能放进全局 CMAKE_CXX_FLAGS 或 add_compile_options。
```

ndk-build（`Android.mk`）：为 helper 建独立静态库模块，随后将其添加到业务模块的 `LOCAL_STATIC_LIBRARIES`：
```make
include $(CLEAR_VARS)
LOCAL_MODULE := ndkp_cert_runtime
LOCAL_SRC_FILES := path/to/runtime/ndkp_apkcert.cpp
LOCAL_CPPFLAGS := -std=c++17 -fno-lto
include $(BUILD_STATIC_LIBRARY)
```
业务模块的混淆参数只放进该模块的 `LOCAL_CFLAGS` / `LOCAL_CPPFLAGS`，不要放进全局 `APP_CFLAGS` / `APP_CPPFLAGS`。

`ndkp_certbind_mix` 是 `extern "C"` + hidden visibility：不进你库的公开 ABI，但库内可解析；
未开 `-irobf-cert-bind` 的构建里没人引用它，`--gc-sections` 会丢掉。

**2. 导出你发版签名证书的 DER**，作为 `-irobf-cert-file` 输入：
```bash
# 从 keystore 导出（注意：不加 -rfc，得到 DER；加 -rfc 是 PEM，本 flag 也接受）
keytool -exportcert -keystore release.jks -alias release -storepass '****' -file cert.der
```
校验它与将写进 APK 的证书一致（两串 SHA-256 应相等）：
```bash
sha256sum cert.der
apksigner verify --print-certs your-signed.apk   # 看 "certificate SHA-256 digest"
```
> 绑定的是**首个签名者证书**（v2 优先，其次 v3）。用 APK 签名方案 v2/v3 签名；纯 v1
> （JAR 签名）没有签名块，运行期读取会 fail-closed。轮换签名（v3 rotation）后需用新证书
> 重新出包。

**3. 开启开关**（示例：字符串 + VMP 一起绑定）：
```
-mllvm -irobf-cse -mllvm -irobf-vmp \
-mllvm -irobf-cert-bind -mllvm -irobf-cert-file=/abs/path/cert.der
```
- 字符串绑定需要同时开 `-irobf-cse`；VMP 密钥绑定需要同时开 `-irobf-vmp`。两者可单开。
- `-irobf-cert-bind` 开但 `-irobf-cert-file` 缺失/不可读 ⇒ **构建期 fail-closed 报错**。
- 与包名绑定（`-irobf-cse-bind`）互相独立、可叠加。

## 本库来源定位（含 Xposed / LSPosed 注入）

`ndkp_certbind_mix` 将自身 hidden 函数地址传给 `certSha256ForLibrary(anchor, out)`，
以包含该地址的 `/proc/self/maps` 记录确定本库。maps 顺序不代表宿主身份；普通应用
和注入模块使用相同流程，也不要求 ART 保留 APK fd。

- **APK 内直接加载**：读取承载本库映射的 base 或 split APK；新开 fd 的设备号和
  inode 必须与该映射一致。
- **安装目录解压加载**：支持 `/data/app/<安装目录>/lib/<isa>/<库名>`（含 `~~` 随机目录）
  以及 `/mnt/expand/<卷>/app/…`。先核对磁盘 `.so` 与本库映射的设备号、inode，再仅在
  同一安装目录内枚举 APK，以精确的 `lib/<abi>/<库名>` ZIP 条目确定唯一来源。
  APK 已有映射时，额外核对其设备号、inode；条目检查与证书读取使用同一 fd。
- 零匹配、多重匹配、候选无法读取、损坏/不支持的 ZIP 均失败关闭。支持 stored/deflate，
  不支持 ZIP64、多卷格式。memfd、已删除映射、缓存中的独立 `.so`、未知安装布局不兜底
  读取其他包的证书。

定位、校验或解析失败时混合值为 `(0,0)`；读取到其他证书时使用其真实摘要派生混合值。
两种情况均无法抵消原来的构建期密钥。成功前不修改摘要输出，所有自有 fd 均会关闭。

## 设备回归

`tests/cert-bind/device_roundtrip.py` 构建临时 APK，验证 base/split 的解压与直接加载，并对 CSE、VMP、CSE+VMP+SelfCheck 分别检查正确/错误签名。需要 patched NDK、Android SDK build-tools/platform、JDK 17+、OpenSSL 和 Android 6.0+ arm64 adb 设备（build-tools 需支持 `zipalign -P 16`）：

```bash
python tests/cert-bind/device_roundtrip.py \
  --ndk "$NDK" --build-tools "$BUILD_TOOLS" --android-jar "$ANDROID_JAR" \
  --java-home "$JAVA_HOME" --serial "$SERIAL" --openssl openssl
```

每个场景还通过 `dlopen` 加载另一签名的模块 APK，核对本库与模块的真实证书 SHA-256（模块无需 ART 打开 dex）。测试使用随机包名并在结束时卸载该测试包。正确签名须返回 `OK`；错误签名须返回 `BAD` 或停留在受保护调用前的 `START` 标记（后者只说明未完成成功路径，不判定具体信号）。2026-10-15 的结果见 [验证记录](../tests/VALIDATION.md)。

VMP 解释器依赖 libc++ 异常辅助函数，即使业务输入是 C，也需用 `clang++` 链接或等效配置 C++ runtime。

原生来源与解析边界回归（Linux 使用 C++17 编译器，无需 patched Clang）：

```bash
python tests/cert-bind/test_apkcert.py
# Windows 等宿主可交叉编译并在 arm64 设备上执行同一组原生用例：
python tests/cert-bind/test_apkcert.py --ndk "$NDK" --serial "$SERIAL"
```

## 威胁模型（诚实声明）

证书绑定针对重打包、换签名后仍想恢复原绑定数据的情形。它直接读取证书，不调用
PackageManager，也**不执行 APK 整体签名验证**。ZIP 条目匹配用于确定解压库的归属，
不证明 APK 内容或解压库没有被修改。

映射存在时，设备号与 inode 校验可以发现指向不同文件的打开重定向或 bind-mount。
**解压库的 APK 没有映射证据时，不能保证发现单独替换或挂载该 APK**；同 inode 内容
改写也不属于文件身份校验的保证。任意 native hook、伪造 maps/fstat/pread 或直接修改
解密结果的动态能力不在本机制的防护范围。
