# CSE v1 验证记录 — 2026-10-18

p7 的按需代码复验、VMP 入口复验及最新验证结果见 [增量验证记录](../anti-tamper/RECHECK_VALIDATION.md)。下文保留 p6 的原始结果。

宿主为 Windows，设备为 GM1901 / Android API 37 / arm64-v8a。Python 为本机 3.14；CI 配置使用 3.11。本记录不代表 Linux 构建或其他 Android 版本已通过。

## 编译器与基线

| LLVM | 精确 Base revision | 验证 |
| --- | --- | --- |
| 21 | `2d287f51eff2a5fbf84458a33f7fb2493cf67965` | 原始基线文件上 `git apply --check`，构建 clang / clang-resource-headers，通过 |
| 20 | `f142f8afe21bceb00fb495468aa0b5043e98c419` | 原始基线文件上 `git apply --check`，构建 clang / clang-resource-headers，通过 |

Android 交叉测试使用本地两套新编译器、NDK `30.0.16248370` 的 sysroot/库及 lld。LLVM 20 是对应 r29-beta1 Base revision 的编译器验证，未在本轮重新组装和发布完整官方 r29 NDK。

## 已通过

- Python 密码/封装回归：13 项，覆盖 RFC 8439、RFC 5869、padding 边界、绑定输入与 PEM、跨构建密文替换、头/nonce/tag/代码篡改、畸形长度、空及非 NUL 常量、原子输出、重复封装、多模块 nonce 和 strip 后校验。
- 真机 C++ RFC 密码向量及 exact-read 短读/EINTR/EOF/越界注入用例通过。
- 两 major 各自通过 O0/O2/Oz、full LTO、thin LTO 的编译 → 封装 → 真机运行 → strip → 验证 → 再运行。
- 两 major 均验证多翻译单元、GC-sections、构造器首次访问、保存指针、聚合全局引用、UTF-16、非 NUL 字节/16-bit 数组和 8 线程重复访问。检查发射 IR：解密入口传桶容量而非真实长度。
- 两 major 均验证未封装产物、可执行段字节、有效记录 tag、build_nonce、错误包名被拒绝；私有进程后缀正常；包装 libc open/read 伪造包名被 raw 路径交叉检查拒绝。失败测试要求通用错误及退出码 127。
- 两 major 各通过 **8 个 APK 场景**：base/split × 解压/直接加载 × 正确/错误签名。正确签名返回 `OK`，错误签名停在受保护调用前的 `START`；同时确认本库与独立签名模块的证书来源。APK 错签名检查不据此推断具体信号。
- 原有证书 ownership/parser 的 66 项及 runtime mix 检查通过；overlay 25 项、discovery 10 项和 locate-LLVM 1 项通过。
- 两 major 的旧 CSE 扫描、四 ABI 编链、CMake、ndk-build、证书绑定、自校验、去指纹、Windows 字符串往返/生命周期与证书混合值往返回归通过。
- 文档中的 CMake POST_BUILD 接入已实际构建、封装、`--verify`，并在设备上用独立 loader 执行成功。新增的无设备 `--compile-only` 路径已通过。

LTO 回归发现并修复了插入解密后仍残留的函数/调用副作用属性。静态 anti-tamper 回归还修复了 Windows 下 `grep -q` 提前关闭管道导致 readelf 返回 74 的误报；实际 `.init_array` 存在。

## 性能样本

下表为同一 fixture 的 **O2、无 LTO、无包名/证书绑定、静态 libc++、未 strip ELF** 单次样本。首次模块加载列包含 dlopen、构造器、代码摘要及第一次线程测试，不能解释为单串解密时间。惰性首次访问在模块初始化完成后测量；后续访问取 100000 次调用平均值。未锁频、未排除调度与热状态影响，不作为性能 SLA。

| LLVM / 模式 | ELF 字节数 | 首次模块加载及测试 | 惰性串首次访问 | 后续每次访问 |
| --- | ---: | ---: | ---: | ---: |
| 21 / 普通 | 1389776 | 2273 µs | 260 ns | 2 ns |
| 21 / hardened | 1439232 | 36441 µs | 22604 ns | 12 ns |
| 20 / 普通 | 1389760 | 1964 µs | 313 ns | 2 ns |
| 20 / hardened | 1439328 | 14712 µs | 81718 ns | 12 ns |

样本体积增加约 49 KiB，包含共享密码与 APK 来源解析运行时；比例不可直接外推到其他应用。包名/证书绑定的双路径 I/O 在每模块首次初始化时执行，其额外耗时未单独基准测试。

## 重现与未完成项

```bash
python tests/cse-hardened/test_seal_cse.py
python tests/cse-hardened/device_test.py --ndk "$NDK" --clang "$CLANG" --serial "$SERIAL"
python tests/cse-hardened/device_test.py --ndk "$NDK" --clang "$CLANG" --compile-only
python tests/cert-bind/device_roundtrip.py --hardened --ndk "$NDK" --clang "$CLANG" \
  --build-tools "$BUILD_TOOLS" --android-jar "$ANDROID_JAR" \
  --java-home "$JAVA_HOME" --serial "$SERIAL"
```

Linux 完整工具链构建/CI、其他 Android API/设备、持续压力与分配器/初始化重入场景尚未验证。未修改 VMP 密文格式或解释器，未发布 artifact。代码摘要与公开输入只在每模块首次解密时初始化，不能检测之后任意时刻的内存修改，也不能阻止认证后的明文读取。
