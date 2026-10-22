# p7 按需完整性复验 — 2026-10-18

本轮仅修改本仓库；未修改接入项目、IDA 数据库或原始 SO，未覆盖本机 SDK，未发布工具链。

## 交付行为

- `-irobf-selfcheck-entry` 在每次 VM 入口复验当前函数的字节码，并把实测 FNV-1a64 折入入口密钥；加载期校验继续存在。两种校验按已有 VMP 入口元数据定位，修复整数混淆导致常量密钥存储匹配失效的问题。
- `NDKP_CSE_RECHECK` 在指定函数入口检查本模块描述表，重算本 SO 的 RX 代码摘要和实时页权限，并以认证诱饵记录验证缓存输入。只在 hardened CSE 模式下生效；既有静态字符串缓冲区和原子 once 保持。
- 间接调用混淆保留对 `noobf` 生成函数的直接调用，避免把检查入口放入可写的函数指针表。
- 新增回归及 CI 编链步骤；patchset 从 p6 升为 p7。

使用方式见 [CSE 文档](../../runtime/CSE_HARDENED.md) 和 [VMP 回归说明](../vmp/README.md)。

## 环境和编译器

Windows x86_64、MSVC 14.51、Python 3.14；OnePlus 7 GM1901、Android API 37、arm64、4 KiB 页。
两套 Clang 均在精确基线上通过 registration.patch 检查、增量构建 clang/clang-resource-headers。
交叉验证使用 NDK `30.0.16248370` 的 sysroot、资源和 lld；LLVM 20 未重新组装官方 r29 整包。
用于旧脚本的临时 NDK 位于忽略的 `work/` 目录，系统 SDK 保持原样。

| LLVM | Base revision | 最终 Clang SHA-256 |
| --- | --- | --- |
| 21 | `2d287f51eff2a5fbf84458a33f7fb2493cf67965` | `5cc762b258d18039b93e0456d8b8396c10e4e6d19c6d7adb590ed79c6a550582` |
| 20 | `f142f8afe21bceb00fb495468aa0b5043e98c419` | `297d9e920168f2d4fad4e84c442c8fdf5317512aee22379e9bbc51410293bd9c` |

## 验证口径

`recheck_test.py` 使用独立 loader 加载一次性测试 DSO，篡改只发生在该进程的映射中。
`cold` 指 dlopen 后、首次业务调用前；VMP 文件字节修改另行验证加载期构造器。
`warm` 指检查点和字符串均调用成功之后。CSE 失败要求静默退出 127；VMP 篡改要求退出 137。
`--compile-only` 仅核实 IR、编链及封装，输出明确标注未执行设备攻击。

覆盖以下边界：

- CSE 的 O0/O2/Oz、full/thin LTO、CIE/IGV/ICall/FLA/IBr、VMP+entry，以及 VMP+entry+其他混淆组合。
- 原生函数指令、region 表、实时代码页权限、缓存摘要/输入/非法状态、五个模块描述字段、认证哨兵密文。
- 正常检查、首次在检查点初始化、并发检查、strip 后检查；初始化之后不触达检查点的旧字符串访问仍然成功，保存的明文指针仍然有效。
- 未标注的调用者调用纯函数检查点、丢弃返回值；各 CSE 配置均验证该调用仍执行检查，冷/热状态下代码篡改均退出 127。
- VMP O0/O2 和 O2 混淆组合，加载前修改字节码、首次 VM 调用前修改、成功调用后再修改；八线程、递归、VM/native/VM 回调、全局寻址及 TLS。
- 公开证书的离线解密基线仍然成功；没有把完整性复验解释成密钥保密。

## 结果

| 检查 | 结果 |
| --- | --- |
| LLVM 20/21 新增 CSE 和 VMP 入口复验矩阵 | 通过；包括全部混淆叠加后的元数据匹配回归 |
| LLVM 20/21 原生函数指令字节修改 | 首次调用前、初始化后均静默退出 127 |
| LLVM 20/21 原有 CSE 设备、描述表和 strip 回归 | 通过 |
| LLVM 20/21 hardened 证书 APK | 各 8 场景通过：base/split × extracted/direct × 正确/错误签名；正确签名还重复调用检查点 |
| LLVM 20/21 VMP 语义 | 八线程、递归、回调、全局地址和 TLS 通过，包含新增 entry 模式 |
| LLVM 20/21 既有宿主检查 | 字符串扫描/往返/生命周期、自校验、去指纹、证书绑定、四 ABI、CMake 和 ndk-build 通过 |
| Python 与解析器 | CSE 14 项、overlay 25 项、VM 生成脚本 3 项、设备 APK ownership/parser 66 项及 runtime mix 通过 |
| CI 路径和导出 | LLVM 21 的新增 `--compile-only` 路径及 actionlint 通过；两 major 的新旧 CSE helper 均无公开导出 |

CSE 状态篡改用例验证非法状态值 3；不外推为任意原子状态攻击均可检测。原生指令篡改已纳入全部 CSE 配置。
本地日志保留在 `work/recheck-*.log`（忽略目录，不随仓库分发）。

## 提交前审查

发现并修复一项 P1：`noinline` 不能阻止优化器删除纯函数的无用调用。例如：

```c
NDKP_CSE_RECHECK static int gate(int x) { return x + 1; }
int use(int x) { gate(x); return x; }
```

原实现的 LLVM 20/21 在 O2 下将 `use` 化为直接返回，后期向 `gate` 插入检查无法恢复调用。
现于 PipelineStart 插入带标记的 `llvm.sideeffect`，并用 `llvm.compiler.used` 防止参数特化；
在 VMP 处理前移除临时标记，再由 CSE 插入实际检查。最终 IR 无临时标记调用。

审查修复后，表中最终编译器重新通过两 major 的完整 `recheck_test.py` 设备矩阵，
覆盖 O0/O2/Oz、full/thin LTO、全部混淆组合及上述回归；LLVM 20 的 `--compile-only` 路径通过。
CSE Python 14 项、overlay 25 项与 `git diff --check` 也重新通过。
日志为 `work/review-recheck-21.log`、`work/review-recheck-20.log`、
`work/review-recheck-20-compile.log`、`work/review-overlay.log`。
Windows overlay 测试需显式设置 `BASH` 为 Git Bash，并设置 `PYTHONUTF8=1`。

上表其他 APK、VMP 扩展语义及既有宿主套件在此次早期调用保留修复之前通过，未在修复后全部重跑。
未发现其他阻塞提交的问题；本次审查按低频同步检查点、普通线程并发调用评估，未把信号处理器或任意并发篡改视为支持场景。

重现命令（两套 `CLANG` 分别执行）：

```bash
python tests/cse-hardened/test_seal_cse.py
python tests/cse-hardened/recheck_test.py --ndk "$NDK" --clang "$CLANG" --serial "$SERIAL"
python tests/cse-hardened/recheck_test.py --ndk "$NDK" --clang "$CLANG" --compile-only
python tests/cse-hardened/device_test.py --ndk "$NDK" --clang "$CLANG" --serial "$SERIAL"
python tests/cse-hardened/descriptor_test.py --ndk "$NDK" --clang "$CLANG" --serial "$SERIAL"
python tests/cert-bind/device_roundtrip.py --hardened --ndk "$NDK" --clang "$CLANG" \
  --build-tools "$BUILD_TOOLS" --android-jar "$ANDROID_JAR" --java-home "$JAVA_HOME" --serial "$SERIAL"
bash tests/vmp/roundtrip.sh "$STAGED_NDK" windows-x86_64 "$SERIAL"
```

## 未覆盖的保证

FNV 不是密码学认证。CSE 检查点只认证本模块哨兵记录，不重新认证全部业务记录或已解密明文，
也不覆盖所有可写全局。原子状态被伪造为合法的“初始化中”仍可能导致等待；无连续、抗并发攻击保证。
检查点之间的修改、直接绕过检查、同时修改检查器及同进程任意读写仍可能绕过。

Linux 工具链、其他 Android API、16 KiB 页设备、LSPosed 宿主及长期压力未验证。
日志中的耗时包含设备调度与测试调用，仅供发现量级异常，不是性能基准。CSE 复验同步扫描本 SO
全部 RX 文件字节，应由业务选择低频边界；VMP 复验按当前字节码长度增加入口开销。
