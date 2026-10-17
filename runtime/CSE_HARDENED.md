# Android arm64 CSE v1

`-mllvm -irobf-cse -mllvm -irobf-cse-hardened` 显式启用字符串强化。LLVM 20/21 均支持，其他目标报错。它使用标准 ChaCha20-Poly1305 和 HKDF-SHA-256；旧 CSE/perkey/bind 模式不自动升级。

## 接入

将 `runtime/ndkp_cse_runtime.cpp` 作为 C++17 object 单独编译，关闭混淆、LTO 和异常；与业务 `.so` 链接。保留同目录的 `cse_crypto.h`、`sha256.h`、`apkcert.h`、`apkcert_io.h`。使用 C++ 链接器并链接 libc++ 和 libdl；运行时只提供 hidden helper，不增加公开导出。

```cmake
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(NDKP_ROOT /absolute/path/to/LLVM-Patch)
add_library(ndkp_cse_runtime OBJECT ${NDKP_ROOT}/runtime/ndkp_cse_runtime.cpp)
target_compile_features(ndkp_cse_runtime PRIVATE cxx_std_17)
set_target_properties(ndkp_cse_runtime PROPERTIES
  POSITION_INDEPENDENT_CODE ON INTERPROCEDURAL_OPTIMIZATION OFF)
target_compile_options(ndkp_cse_runtime PRIVATE -fno-lto -fno-exceptions)
target_sources(your_lib PRIVATE $<TARGET_OBJECTS:ndkp_cse_runtime>)
target_link_libraries(your_lib PRIVATE dl)
target_compile_options(your_lib PRIVATE
  "SHELL:-mllvm -irobf-cse" "SHELL:-mllvm -irobf-cse-hardened")
add_custom_command(TARGET your_lib POST_BUILD
  COMMAND ${Python3_EXECUTABLE} ${NDKP_ROOT}/scripts/seal_cse.py
    --input $<TARGET_FILE:your_lib> --output $<TARGET_FILE:your_lib>.sealed
  COMMAND ${CMAKE_COMMAND} -E rename
    $<TARGET_FILE:your_lib>.sealed $<TARGET_FILE:your_lib>
  VERBATIM)
```

不要把混淆参数配置为整个工程的全局编译参数，否则也会污染运行时 TU。构建期会拒绝在定义 helper 的模块上启用混淆；运行时 object 必须始终 `-fno-lto`。

固定流程：**链接 → 封装 → strip → APK 打包、对齐、签名**。封装只修改预留的 `.ndkp.cse` 数据，不改变代码、地址、重定位或文件大小。构建中不要在链接阶段使用 `-s`/`--strip-all`；将 strip 放在封装之后。重新构建应从链接产物开始，已封装输入拒绝二次封装。输出写入临时文件并原子替换；认证失败不修改既有输出。

```bash
python scripts/seal_cse.py --input linked.so --output sealed.so
llvm-strip --strip-all sealed.so
python scripts/seal_cse.py --input sealed.so --verify
```

包名和证书绑定沿用现有开关。新模式直接完成双路径输入读取，不依赖旧 CSE 的包名/证书缓存。仅使用 hardened CSE 时无需 `ndkp_apkcert.cpp`；若同时使用旧 VMP 证书绑定，仍按旧说明链接该文件。

绑定产物的 `--verify` 还需提供期望输入（封装后暂存输入已清除）：

```bash
python scripts/seal_cse.py --input sealed.so --verify \
  --package com.example.app --cert-file release.der
```

`--package` 同运行时一样截掉首个 `:` 后缀；支持私有子进程，不支持无前导冒号的任意全局进程名。`--cert-file` 接受 DER 或常规 PEM。

## 数据与运行时行为

每个有字符串的 LLVM 模块保留一个版本化数据块。256 字节头存模块标识、seed 分片、构建 nonce、状态、记录总数及封装校验所需摘要；其后是 `[capacity:u32, nonce:12, tag:16, ciphertext:capacity]`。全部整数为小端。每条记录的真实字节长度、UTF-8/UTF-16 标记、序号和字符串内容均在密文内，容量按至少 32 字节的二次幂桶填充，最大 16 MiB。业务缓冲区同样按桶分配，解密入口仅传容量，认证后从密文元数据读取真实长度。字符标记 1 表示 8-bit 字节串（不验证其为 UTF-8），2 表示 UTF-16LE/16-bit 元素；沿用旧 CSE 对无 NUL 字节及 16-bit 常量数组的支持，不强制字符串终止符。

AAD 绑定模块标识、格式版本、绑定开关、记录序号、容量、数据块总长和记录数。96-bit nonce 为零高部与模块内唯一的 32-bit 序号。每个模块使用独立随机 seed，封装时为同一 ELF 的所有模块生成一个 256-bit build_nonce。每模块增加一条认证有效、无业务引用的假字符串记录，连同整个数据块保留到最终链接。

编译期使用暂存密钥认证加密。封装工具先认证、验证全部记录，再使用最终机器码摘要派生密钥重新加密，清除头内的期望包名 SHA-256 与证书混合值。seed 分片仍供运行时派生，不能视为攻击者不可获取的秘密。

代码摘要为 SHA-256(`NDKP-CODE-v1` 与按程序头顺序排列的每段相对虚拟地址、文件长度、段 SHA-256)。覆盖全部可执行 `PT_LOAD` 文件字节，包含非 `.text` 的代码段。为兼容 strip，唯一规范化例外为 ELF 头的 `e_shoff`、`e_shentsize`、`e_shnum`、`e_shstrndx`：计算前将这些字段归零。程序头和实际代码字节仍被绑定。拒绝可写/不可读/含非文件字节的可执行段、文本重定位及重叠映射布局。

运行时通过 `dl_iterate_phdr` 定位数据块所属 ELF，并以 volatile 读取实际映射代码计算摘要；不使用头内的期望摘要来派生密钥。每模块以原子 once 缓存实际摘要，每条字符串沿用原子 once 发布。包名及证书输入在首次解密该模块时读取并交叉验证；与实际代码摘要一起缓存这些公开输入摘要，派生密钥不缓存。验证成功后才复制到静态存储期业务缓冲区；临时明文和派生密钥清零。

Android arm64 raw I/O 使用内联 `svc` 的 openat/read/pread64/fstat/getdents64/close。包名对比 libc 与 raw 独立读取；证书解析共享边界检查，分别通过两种后端定位所属 APK，比较库映射、APK 文件身份和证书摘要，保留 base/split 及两类库加载方式。读取错误、来源歧义、不一致、未封装或认证失败均输出通用错误并以 raw `exit_group(127)` 终止进程。

## 验证与边界

```bash
python tests/cse-hardened/test_seal_cse.py
python tests/cse-hardened/device_test.py --ndk "$NDK" --serial "$SERIAL"
python tests/cert-bind/device_roundtrip.py --hardened \
  --ndk "$NDK" --build-tools "$BUILD_TOOLS" --android-jar "$ANDROID_JAR" \
  --java-home "$JAVA_HOME" --serial "$SERIAL"
```

设备测试可加 `--clang /path/to/build/bin/clang` 使用本地新构建的编译器和指定 NDK 的 sysroot。`device_test.py --work-dir` 可保留本机构建产物供检查。

本模式增加篡改、跨构建密文替换和单路径 libc 输入伪造的成本。build_nonce 公开，两种本地读取路径不是独立可信根；任意同进程修改仍可攻击解析、派生、检查或结果。代码摘要只在模块首次解密时计算，之后的修改不由该缓存检测。未访问记录的 tag 在访问时才校验；封装工具的 `--verify` 会认证全部记录。

认证有效的诱饵不能保证抵抗可读性判据，业务缓冲区和引用关系仍可能透露长度范围。明文保留静态存储期，AEAD 不阻止解密后的内存读取。设备与性能结果见 [验证记录](../tests/cse-hardened/VALIDATION.md)。
