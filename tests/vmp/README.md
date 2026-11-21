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
`--semantic-only` 用于演示旧版 LLVM 21 编译器失败，只跳过新 IR 结构断言，仍观察退休控制帧和缓存是否清零。

每次入口增加与 VM 数据帧大小成正比的栈空间和清零成本，大帧及深递归需单独测量。
跨 VM 的 `longjmp`、线程取消、异步信号重入不受支持，原有向量、动态 alloca、过度对齐等
IR 支持边界也未扩展。详情见 [p9 验证记录](../../docs/vmp-call-frames-p9.md)。

## p26 退休控制帧擦除

LLVM 21 的解释器在完整恢复调用者控制状态后，使用 volatile 字节写入擦除整个退休帧槽，
包括结构体 padding。当前 ARM64 帧为 88 字节，其中 `ip` 后有 4 字节 padding。数据帧、
返回值、`sret` 和待传播异常继续遵守既有生命周期。

脚本按实际选用 Clang 的 `-dumpversion` 识别 major，仅 LLVM 21 启用本节的观察与 post。
O0 的 `switch i64` 和 switch 前无数据帧读取断言也仅适用于 LLVM 21；LLVM 20 的分发器
使用条件链。其他 major 仍执行六模式语义编链、TLS 帧指针、无分发器快照 malloc/free、
入口复验和 callee 门禁。LLVM 20 的生成 bitcode 未在本批更新。

`call_frames.py` 在实际生成的 IR 后追加仅用于测试的隐藏访问器，取得唯一真实 TLS 控制栈、
栈顶及由结构体 GEP 计算的帧大小和 padding 边界。驱动只向空闲槽填入 `0xA5`，在 native
回调中确认栈顶前进、实际槽已保存状态且 padding 仍为 `0xA5`；正常和异常弹栈后检查完整槽
全零、相邻未使用槽未改。嵌套回调快照全部活跃前缀，再确认更深回调到达下一层，返回后活跃
帧不变、深层退休槽清零。这些检查随现有八线程用例运行，保留原生参考差分。

O2 的 VMP+SelfCheck+Entry 先执行真实 `-irobf-vmp-post`，再追加访问器；对象编译禁用后续
IR passes。`--work-dir` 保存原始 `.ll`、`.post.ll`、实际对象输入 `.observed.ll`、各模式对象
和可执行文件，以及传入 `--serial` 时的 `*.device.log`。不传设备序列号仅验证编链。

```bash
python tests/vmp/call_frames.py --clang "$CLANG" --ndk "$NDK" --serial "$SERIAL" \
  --work-dir work/m3-frame-wipe-p26/call-frames
python tests/vmp/call_frames.py --clang "$P25_CLANG" --ndk "$NDK" --serial "$SERIAL" \
  --semantic-only --work-dir work/m3-frame-wipe-p26/negative
```

第二条命令应在旧版保留退休槽内容时失败。p26 只处理退休控制帧；后续缓存批次见下节，受控敏感数据借用
仍在 [M3 路线图](../../docs/CORE_HARDENING_ROADMAP.md#m3-敏感数据借用与-vm-状态回收) 中待做。

本轮 LLVM 21 六模式设备验证全部通过，四个观察模式均确认 88 字节完整帧、4 字节 padding、
正常/原生异常/嵌套和八线程；最终记录在 `work/m3-frame-wipe-p26/final-call-frames.log`
及同名目录。冻结 p25 的 VMP/O0 和 protected/O2+post 动态负例均退出 38，见同根
`p25-negative-results.json`。实际 LLVM 20 的默认六模式编链通过，未传 `--semantic-only`，
见 `llvm20-final-call-frames.log`；此项核对共用测试兼容性，不代表 LLVM 20 已加入擦除。

## p27 解释器缓存回收

LLVM 21 在实际 native 分发前和解释器正常、原生异常退出时，清零三类可重建 TLS 缓存：
ChaCha 的元组、key/nonce、调度种子及 64 字节块，opcode key/解码表，以及调试布局 key/ID。
BB 失效时擦除完整 ChaCha 对象；材料元组错配时先擦旧对象再重建。同一材料仅切换块时，
只擦旧块及块元数据，保留仍有效的 key/nonce。冷缓存直接重建，命中路径不增加清理。
调用者数据帧、返回值、`sret` 和待传播异常沿用既有生命周期。LLVM 20 的生成 bitcode 未更新。

共用 `call_frames.py` 在真实 IR 中追加 TLS 区域访问器，区域大小由实际类型 GEP 计算，
包括结构体 padding。仅在 VM 未运行时填入 `0xA5` 哨兵；原有正常、异常和嵌套 native 回调
检查分发边界全零，返回后再次检查完整缓存全零。原生参考差分、递归、结构体返回和八线程保留。

观察器还在真实 `chacha20_byte_at` 的入口、KDF 前、块生成前和返回前插入只读回调：
材料 refill 前检查完整对象为空；block-only refill 前检查旧块和块元数据为空，key/nonce 与入口快照相同；
命中返回时检查整个对象未变。每种观察模式必须实际发生材料 refill、block-only refill 和命中，
并观察到真实 opcode 解码表已经建立。O2 protected 仍先执行真实 post，再插观察点、禁用后续 IR passes。
材料 refill 计数证明执行了 KDF 重建；正常生命周期通常已在 BB/native/退出边界清空旧材料，
因此该计数不证明走过“有效旧元组发生错配”的分支。该分支的全对象擦除仍需结合代码与产物检查。
回调会更新测试驱动的 TLS 记录，插点后的 ChaCha helper 已移除不再成立的内存访问和同步属性。

p27 统一退出 CFG 暴露了 LLVM 21 融合 continuation 对不可达 NOP 边的依赖：真实 `frame_sret`
在唯一 BB 内的融合运算后误读 BB 头，触发退出 137。同一份冻结 raw IR 只修正三条融合出口状态后，
普通及缓存观察驱动均通过。正式 pass 在替换任何融合 handler 前，从真实标量二元运算 handler 的
正常出口提取 continuation PHI；所有出口必须一致，引用的指令必须支配分发点，否则拒绝编译。
这样不依赖优化后布尔状态的类型或极性。LLVM 20 未实现该融合路径。
这些插入点用于观察失效策略。最终未插观察器的样例 raw/post、真实对象、链接库、打包库和 APK
已另外核对：152 字节完整 ChaCha 擦除含 padding，native/退出前其余缓存共 48 字节清零，
块替换精确擦除 77 字节且保留 key/nonce。三个业务 clone、两个真实 ChaCha helper 及退休帧 helper
完成全部非重定位指令的对象到链接库匹配，dex2c 函数全部字节与打包库对应，APK 内整库字节一致。

```bash
python tests/vmp/call_frames.py --clang "$CLANG" --ndk "$NDK" --serial "$SERIAL" \
  --work-dir work/m3-cache-wipe-p27/final-call-frames
python tests/vmp/call_frames.py --clang "$P26_CLANG" --ndk "$NDK" --serial "$SERIAL" \
  --semantic-only --work-dir work/m3-cache-wipe-p27/negative
```

p26 负例预期退出 50，日志中的 `bits` 可同时记录多类残留：2 为 KDF 前，4 为旧块/块元数据，
8 为有效 key/nonce 被改或未有效，16 为命中对象改变，32 为 native 边界，64 为退出后；
1 表示未观察到预期的真实缓存地址或结构大小。退出 51 表示缺少必须实际发生的命中或 refill。
脚本遇到首个设备失败即停止；四个观察模式的预编译文件可分别运行并保留负例记录。

最终六模式设备验证通过，含 O2 protected 的真实 post；四个受保护观察模式均实际发生命中、材料 refill、
block-only refill 和 opcode map 建立。使用最终观察器属性的冻结 p26 VMP/O0 与 protected/O2+post
负例均退出 50、`bits=102`，对应 KDF 前、块替换、native 和退出残留。实际 LLVM 20 的默认六模式
编链通过，但未移植本批擦除或 LLVM 21 融合路径。未改 core-hardening 样例完成两进程各 39 项、
禁用 inactive、恢复通过。证据在 `work/m3-cache-wipe-p27/` 的 `final-call-frames.log`、
`p26-final-negative-results.json`、`candidate-artifact-evidence.json`、`device-results.json`
及 `sol/machine-evidence.json`；这些本地归档不随 Git 提供。

本批仅回收这三类持久缓存。`store`、`insertvalue`、`extractvalue` 的堆内联常量由下节 p28 单独处理；
未扩展向量 eligibility，也不声称擦除所有栈临时值、寄存器或编译器 spill。

## p28 堆内联常量回收

LLVM 21 在 `store`、`insertvalue`、`extractvalue` 最后消费 owned inline 缓冲后、`free` 前，
按原 `malloc` 长度执行 volatile 字节擦除。borrowed `data_seg`、结果槽和输出保持有效。
分配失败仍消耗全部 inline payload，随后沿用零结果和正常 marker 返回。`extractvalue` 在实际源非空时才计算地址。

`memory_ops.py` 在原 p8 检查之后、仅对实际 Clang 21 执行 `inline_constants.py`，支持可选 `--work-dir`。
Clang 20 默认仍只运行原有 O0/O2 编链、拒绝与边界检查，不引入新 fixture、heap observer 或 post。
独立专项也接受相同的 `--ndk`、`--clang`、`--serial`、`--work-dir` 参数；无 `--serial` 仅编链。

```bash
python tests/vmp/memory_ops.py --clang "$CLANG" --ndk "$NDK" --serial "$SERIAL" \
  --work-dir work/m3-inline-wipe-p28/memory-ops
python tests/vmp/inline_constants.py --clang "$P27_CLANG" --ndk "$NDK" \
  --work-dir work/m3-inline-wipe-p28/p27-negative
```

`inline_constants.ll` 是保留 aggregate 指令的 `noinline optnone` 手写 IR，分别令首 opcode 真正进入
17 字节 store、24 字节 insertvalue、31 字节 extractvalue 的 malloc/read/消费/free 路径。
本批未修 emitter：部分大 `ConstantDataArray` 会 fallback 成零，`ConstantStruct` 不按所需的 inline 格式编码。
为避免旧版零常量也能通过观察，脚本冻结 pristine raw 与 O2 真 post，从实际 debug log 验证 opcode、
size/type、零 payload、function/payload/chain seeds、ChaCha key/nonce 和调度后的 keystream。
只将每函数唯一首 inline payload 的密文字节 XOR 成合法非零 pattern，前后字节完全相同；
`mutation-manifest.json` 记录原/改区间、字节、编译材料和 raw/post/观察 IR/字节码 hash。
LLVM c-string parser 支持 `\HH` 和 `\\`，长度必须与实际数组一致。
受控 VM 输入不表示 emitter 支持非零聚合初始化。

观察分支关闭 SelfCheck，在后端输入中只放宽 wrapper 会破坏的 allocator 属性，禁用后续 IR passes。
`--wrap=malloc/free` 返回真实分配内部的对象，仅初始化前后各 16 字节 guard；不向 payload 写 poison。
在实际 `free` 前读取完整原分配，要求非零残留为 0、guard 完整。
独立字节 oracle 检查 nonzero 输出与后续 marker，borrowed insert/extract 后源仍被消费，
两个 borrowed store 之后再 extract 源字段并写入额外 oracle 输出，防止错误擦除借用数据而假通过。
每路径还做一次 malloc 失败，要求尝试 1 次、free 0 次、失败输出及后续 marker 正确。
pristine VMP 和 pristine VMP+SelfCheck+Entry 独立运行正常语义，SelfCheck 不与 payload 修改混用。
`malloc(0)` 只有静态 guard/循环核对，没有动态覆盖；空 aggregate 用例不能触发这里的分配。

正式 O0/O2 真 post 的四个 pristine 和两个 observed 二进制均在设备退出 0。
`observed-O0` 与 `observed-O2-post` 各六行，覆盖三种长度的正常/失败分配：正常路径尝试 1 次、free 1 次，
完整原分配残留为 0、guard 完整、输出及 marker 正确；失败路径尝试 1 次、free 0 次，输出及 marker 正确。
冻结 p27 两个动态负例分别退出 60，正常分配的 17/24/31 字节各全部非零，业务输出和 guard 仍正确，失败分配无 free。
退出 61 表示业务 oracle 或 marker 失败。设备脚本遇到失败会停止，因此负例先不传 `--serial` 编链，再分别运行这两个文件。
正式目录 `work/m3-inline-wipe-p28/memory-ops/inline-constants/` 保存四种 pristine 与两种 observed 模式，
O2 两种 pristine 和 observed 都基于真实 post。`sol/machine-evidence.json` 核对六个 pristine clone 的
12 个 owned 分配点，从真实解码和消费沿 owned/borrowed PHI 追踪到原 malloc 长度的 volatile wipe 和 free，
同时保留 nonnull/零长度 guard。O2 IR 和后端可合并 free，汇合指针仍仅来自 owned 分配。
六组 pristine/observed 对象函数字节完全相同；两种模式合计 136,628 字节，pristine 与 observed
两组对象到实际执行二进制各匹配 31,346 条非重定位 ARM64 指令。样例四份 IR 不含 malloc/free，只作为整体回归。
样例在单台 ARM64 设备完成主/worker 各 39 项、禁用 inactive 和恢复通过；无新增性能测量。
本地证据在 `work/m3-inline-wipe-p28/`，不随 Git 提供，正式 bitcode 无测试 hook。

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

支持 `--clang` 核验另一 LLVM major 的本地编译器，`--work-dir` 保留输出；不传 `--serial` 仅验证编译和 IR。
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

## p25 handler 与操作数布局变体

LLVM 21 每融合组在编译期选择 H0 原生运算或 H1 同宽 carry/borrow；H1 只替换该组首个
add/sub。布局 L0 依次读取 target/LHS/RHS/third，L1 读取 LHS/RHS/third/target；无 add/sub
的组仅有 H0。生产编译仍使用已有 VMP 开关，无新增变体参数。

专项模式不传 `-irobf-debug`，从真实 decoder CFG/计算数据流识别变体，核对 raw/post 结构与
字节码相同。它至多编译 32 次，直到 16 个融合组的 60 种有效 H/L 组合全部出现，未齐则失败。
实际 post.s 只组装一次成 post.o，再由该对象链接 SO；设备驱动加载同一库。

```bash
python tests/vmp/fusion.py --clang "$CLANG" --ndk "$NDK" \
  --variant-coverage --baseline-clang "$P24_CLANG" \
  --serial "$SERIAL" --output <新的证据目录>
```

`--baseline-clang` 在此模式要求 p24 H0/L0 编译器；该基线不计入候选覆盖。省略 `--serial`
只验证编链与结构，不代表运行语义通过。`--output` 必须是新目录，保留每轮 IR、汇编、真实对象、
SO、结构与设备日志，完成后写 `results.json`。默认模式仍为原编译/诊断回归，不执行粗计时。

设备驱动有窄位宽、B=0、非交换次条运算、循环 PHI 和 i64 边界差分。新增两项高位可见向量
使长链 carry/borrow 的错误无法被最终 `& y` 掩掉，预期分别为 `0x8000000000000000` 和
`0x8000000000000001`。p25 原 14 候选和一个 p24 SO 另用追加 driver 做语义复验，15/15 通过且
设备 SO 哈希不变，结果为 `semantic-highbits/results.json`；五轮计时
继续使用已冻结的原 driver/hash，新增向量不计入旧计时证据。计时是每项预热 100 次、调用 2000 次
的整段 VM 粗测，无绑核或锁频，不能隔离 carry/borrow 的成本。

本地报告位于 `work/m2-variants-p25/` 的 `fusion-device/results.json`、
`timing-repeat/results.json` 与 `sol/machine-evidence.json`，不随 Git 提供。
实现边界和成本见 [M2 验收](../../docs/CORE_HARDENING_ROADMAP.md#m2-handler-与操作数布局变体)。

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
