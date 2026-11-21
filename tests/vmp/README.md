# VMP 回归测试

## p9 调用帧与原生异常

VMP 每次调用使用独立的栈上数据帧，TLS 仅保存该函数当前帧指针；退出时恢复上一帧指针。
原生分发器不再通过整帧快照回滚内存，因此通过指针写入 caller 局部对象、别名和 `sret`
缓冲区的结果会保留。同函数递归和 VM → native → VM 重入也使用独立对象存储。

同时修复原生 C++ 异常穿过 VM 的路径：保存异常、停止当前 VM 执行、恢复控制帧和数据帧指针，
再重抛原异常。正常返回和异常返回都释放当前帧。没有增加函数内部 `try/catch` 的虚拟化支持：
带 personality 的函数仍被 eligibility 检查排除。

```bash
python tests/vmp/call_frames.py --ndk "$NDK" --serial "$SERIAL"
```

覆盖 O0/O2 × 普通/VMP/VMP+SelfCheck+Entry：局部 int 和 void**、直接 native/VM 调用、
外部缓冲区、别名与邻接字段、递归、回调重入、结构体返回、嵌套异常、异常对象释放和八线程并发。
另在预热 TLS 后注入可执行文件的 malloc 失败，验证 native 错误出参与无堆快照的 VM 递归。
IR 门禁要求真实字节码、TLS 帧指针、无分发器快照 malloc/free、入口复验，以及未被优化掉的
VM callee/递归调用。支持 `--clang` 和 `--work-dir`；不传序列号仅编链，CI 不含设备验证。
`--semantic-only` 用于演示旧编译器失败，跳过新帧结构断言。

每次入口增加与 VM 数据帧大小成正比的栈空间和清零成本，大帧及深递归需单独测量。
跨 VM 的 `longjmp`、线程取消、异步信号重入不受支持，原有向量、动态 alloca、过度对齐等
IR 支持边界也未扩展。详情见 [p9 验证记录](../../docs/vmp-call-frames-p9.md)。

## p8 定长内存操作

显式启用 `-mllvm -irobf-vmp-memops` 后，已选中的 VMP 函数内、长度不超过 64 字节的
标准 `memcmp` / `memcpy` 和非 volatile `llvm.memcpy` 在字节码生成前展开为逐字节标量操作。
比较保留首个不同的无符号字节所决定的返回值符号，复制保留返回指针；长度为零时不访问内存。
动态长度、超限长度、自定义实现、`nobuiltin`、volatile、特殊地址空间及特殊调用约定边界
（musttail、operand bundle）不在 p8 转换范围。此开关单独使用不选择函数，也不改变无 VMP 构建。
先执行 VMP eligibility 检查，被拒绝的函数不会被此开关改写。
实际展开后若无法完成 VMP 翻译（例如超过指令数上限），编译明确失败，禁止输出未保护的展开代码。

对象中的 `ndkp_vmp_memops_<函数>_cmp<N>_copy<N>` 是实际展开操作的构建收据，必须与该函数
的 `gv_code_seg_*` 同时检查；它不代表整函数无原生调用，也不提供密码学认证。分发函数仍可包含
VM 帧保存/恢复和真实外部调用。最终 strip 会移除这些本地符号。

```bash
python tests/vmp/memory_ops.py --ndk "$NDK" --serial "$SERIAL"
```

支持 `--clang` 核验另一 LLVM major 的本地编译器；不传 `--serial` 仅验证编译和 IR。
覆盖 O0/O2、无符号比较、首差优先、未对齐指针、保护页边界、零长度、返回指针与未选中路径。
CI 执行编链验证，设备结果单独记录。

p8 同时修复 VMP 将函数/别名地址错误编码为数据槽零，以及 O0 入口残留 `optnone` 与
`alwaysinline` 冲突的问题。`roundtrip.sh` 的全局地址测试包含回调地址的返回、保存和调用。

## p23 相邻二元运算融合

LLVM 21 的 VMP 在同一基本块中选择多个相邻、且有数据依赖的整数二元运算对，
为每组分配独立语义 opcode，并保留非交换运算的操作数顺序。回归同时检查四组上限、
`fence` 对保留 opcode 容量的占用、重叠候选与零候选、`i8`/`i16` 宽度、PHI 回边，
以及 protected IR、post IR 和最终 ELF 对象的完整编链。传入 `--serial` 会额外在 ARM64
设备执行独立的原生 C 参考驱动，覆盖全部样本（多组、保留码位、重叠、零候选、循环、
非交换运算、窄宽度和 `i64` 链）及边界向量；`--baseline-clang` 可比较单组基线的融合计数
和字节码长度。

```bash
python tests/vmp/fusion.py --clang "$CLANG" --ndk "$NDK"
python tests/vmp/fusion.py --clang "$CLANG" --ndk "$NDK" --serial "$SERIAL"
python tests/vmp/fusion.py --clang "$CLANG" --ndk "$NDK" \
  --baseline-clang path/to/baseline/clang
```

## 既有覆盖

测试将受保护函数与独立编译的原生实现比较，覆盖：

- 全局整数、指针和 TLS 的地址槽。
- 结构体数组、多维数组、负下标及大于 255 字节的元素。
- 八线程并发、递归和 VM → native → VM 回调。

`roundtrip.sh` 测试 plain、VMP、VMP + SelfCheck 和 VMP + SelfCheck + entry；全局变量与索引用例分别使用 O0、O2。

p7 新增 `-mllvm -irobf-selfcheck-entry`，必须同时开启 `-irobf-vmp` 和
`-irobf-selfcheck`。它在每次 VM 入口只重算当前函数的字节码哈希，将实测值折入入口密钥；
不重写共享累积值，保留递归和多线程语义。原加载期校验继续存在，不启用新开关时行为不变。
FNV-1a64 不是密码学认证，且不覆盖解释器机器码；需要覆盖本 SO 代码时在低频操作入口结合
`NDKP_CSE_RECHECK`，见 [CSE 文档](../../runtime/CSE_HARDENED.md)。

入口成本与当前函数字节码长度成正比；热路径先做性能验证。构造器之前、首次 VM 调用前及
首次调用之后的篡改回归位于 `tests/cse-hardened/recheck_test.py`，可用 `--clang` 指定本地编译器。

```bash
bash tests/vmp/roundtrip.sh "$NDK" "$HOST" "$SERIAL"
python tests/vmp/test_gen_vm_bitcode.py
python tests/fingerprint-scrub/device_check.py \
  --ndk "$NDK" --host "$HOST" --serial "$SERIAL"
```

`HOST` 为 NDK 宿主目录名，例如 `windows-x86_64`。设备测试要求 `adb` 在 PATH 中。
不传 `SERIAL` 时，`roundtrip.sh` 只编译和链接。Windows 下运行 Python 测试前，
将 `BASH` 环境变量设为 Git Bash 的 `bash.exe` 路径。

自校验测试要求正常样本退出 0、篡改样本退出 137；检测横幅只出现在 debug 输出中。

## p3 验证（2026-10-16）

Windows x86_64 上完成 Clang 构建；设备为 arm64、API 37、4 KiB 页。

| LLVM | Base revision |
|---|---|
| 20 | `f142f8afe21bceb00fb495468aa0b5043e98c419` |
| 21 | `2d287f51eff2a5fbf84458a33f7fb2493cf67965` |

两个版本的全局地址槽、GEP、TLS 和自校验设备测试通过；四 ABI、字符串加密、证书绑定静态检查、
指纹检查、CMake 和 ndk-build 测试通过。LLVM 20 使用 NDK r30 的头文件、资源库、链接器和构建脚本，
尚未验证对应官方 NDK 整包。Linux、API 26 和 16 KiB 页设备未测。

## 生成解释器 bitcode

LLVM 21 p12 的离线指令映射回归：

```bash
python tests/vmp/opcode_diversity.py --clang "$CLANG" --ndk "$NDK" --output <新的证据目录>
```

同一输入独立编译三次，`first` / `second` 每方法每次必须恰有一条 variant 与对应唯一
dispatch clone。28 项 semantic→ordinal 在转成 dict 前拒重复键和值，强制为 1..28
双射，再按 semantic 1..28 规范化为整数 tuple；CSV 换序或前导零不算新映射。
每个方法的三份 tuple 必须全不同，六份方法/构建映射也不重复。每一方法的全部 28 项
都必须让 legacy key-only decoder 失败，任一项仍可解码即拒绝；保留独立 no-flag 编译
不含 VMP 变换的检查。可选 `--output` 必须为全新目录，保留输入源码、三个 protected
IR、no-flag IR、每次编译的原始 stdout/stderr；全部通过才写 `results.json`。省略此参数
继续使用临时目录。失败保留已产生的证据，不复用旧成功报告。纯主机解析反例无需候选编译器：

```bash
python -B -m unittest discover -s tests/vmp -p 'test_opcode_diversity.py'
```

这些检查验证本次样本的逐方法差异与旧 key-only 恢复器失败，不证明不可恢复或随机性强度。
运行语义还需执行上面的
设备回归；旧恢复器失败不等于无法恢复，见 [离线加固记录](../../docs/vmp-offline-p12.md)。

```bash
bash scripts/gen_vm_bitcode.sh "$CLANG" aarch64 20
```

最后一个参数选择 `20`、`21` 或 `all`，默认 `all`。生成器拒绝用新版 LLVM 向旧版 overlay 写入
bitcode；同时更新两个版本时，使用 LLVM 20。编译器需配置 Android sysroot。不要手改 `vm.h`。
