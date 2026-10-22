# p9 VMP 调用帧修复

2026-10-19。这次改动先修复 VMP 出参和调用帧语义。
未改动接入项目生产代码、GetEnv 规避、预编译 SO 或 APK；未执行模块安装、宿主重启或设备 Hook。
共享异常桥及调用路由的本地化属于下一阶段，本修复不隐藏核心 Hook 行为。

## 原因与修复

旧 p8 使用每函数 TLS 字节数组，在间接调用或另一个 VMP 调用前复制整个 caller 数据段，
返回后恢复旧快照。被调函数通过指针写进 caller 局部对象的数据也因此被覆盖。
同函数递归要求保存调用状态，单纯删除快照仍会让递归复用同一对象存储。

现在 LLVM 20/21 均为每次 VM 调用创建独立数据帧，TLS 只发布该函数的当前帧指针。
帧在入口清零，分发器从当前帧取参数；正常和异常退出都恢复前一帧指针。
解释器已有调用栈继续保存 IP、密钥、数据/代码地址等控制状态。
删除原生分发器的 malloc/memcpy/free 整帧快照及 sret 特判；指针、别名和 sret 写入直接保留。

正式测试还暴露了独立的旧异常缺陷：桥接层捕获异常后继续执行字节码，最终 wrapper 将空的
异常地址传给 `_Unwind_Resume`。旧 p8 的单独异常探针退出 139，与局部出参修复无关。
现在从桥接层保存的 `std::exception_ptr` 重抛；在此之前停止当前 VM、恢复调用控制状态，
由 wrapper 恢复数据帧指针。重抛前清理 TLS 的异常所有权和标志，避免原生 catch 返回后污染上层 VM。

解释器源码已修改；两个 vm.h 均由 `scripts/gen_vm_bitcode.sh` 用 LLVM 20 重新生成，
未手工编辑字节数组。无 VMP 开关时不改变输入程序，未新增用户配置开关，patchset 升为 p9。

## 验证方法

正式回归 `tests/vmp/call_frames.py` 覆盖 O0/O2 × 普通、VMP、VMP+SelfCheck+Entry：

- 局部 int 和 void**、直接 native/VM 调用、外部输出缓冲区。
- 别名写入和相邻字段保留、同函数递归、VM → native → 同 VM 重入。
- 通过选中 VM callee 的结构体/sret 返回。
- 嵌套 VM 抛出后由 native catch 处理、异常逃逸到驱动、同函数重入中抛出与捕获。
- 抛出后的业务写入不得执行；异常类型和值保留，异常对象最终释放。
- 八线程重复全部用例，退出后再次检查异常对象计数。
- TLS 预热后拦截可执行文件的 malloc 并返回空：native 的错误返回和出参必须正确，
  VM 递归不得额外申请堆快照。此项不等同于全进程 OOM 或栈耗尽测试。

每个保护用例均核对真实字节码与 TLS 帧指针，分发器无快照 malloc/free，入口自校验确实存在；
IR 还要求直接 VM callee、sret 和递归调用保留，避免用被优化掉的调用“验证”调用语义。
原生 reference 独立编译。旧编译器的正式基线在首个局部 int 用例失败：应得 342，旧探针实得 307。
CI 仅运行编链和 IR 门禁，设备执行需显式提供序列号。

```powershell
python -B tests/vmp/call_frames.py --ndk <独立NDK> --clang <对应clang.exe> --serial <序列号>
python -B tests/vmp/memory_ops.py --ndk <独立NDK> --serial <序列号>
bash tests/vmp/roundtrip.sh <独立NDK> windows-x86_64 <序列号>
python -B tests/cse-hardened/recheck_test.py --ndk <独立NDK> --serial <序列号>
```

## 成本与边界

数据帧由每函数常驻 TLS 存储改为每次调用的栈存储；入口有与帧大小成正比的清零成本。
本次 13 个测试函数的 IR 数据帧：O0 为 40–192 字节，O2 为 16–160 字节，两版一致。
这不是总栈峰值，也不是接入项目的帧大小：解释器、C++ 异常设施、调用深度及编译器生成的栈帧另计。
在扩大生产 VMP 清单之前，需要用真实调用深度和大局部对象评估栈与性能。
栈帧结束不等于明文擦除；p9 未实现退出时清零，明文副本生命周期留待后续阶段处理。

p9 只验证原生 C++ 异常穿过无 personality 的 VMP 函数。函数内部 try/catch、向量、
原有 alloca 布局与对齐限制未扩展；跨 VM 的 longjmp、线程取消、异步信号重入不受支持。
独立进程测试不等同于 LSPosed 宿主兼容性；Linux 宿主、真实宿主及 16 KiB 页设备未验证。

## 本地记录

Windows x86_64；OnePlus 7 GM1901、ARM64、4 KiB 页，通过独立临时进程验证。
下表为首次完整矩阵使用的编译器。

| LLVM | Base revision | Clang SHA-256 |
| --- | --- | --- |
| 20 | f142f8afe21bceb00fb495468aa0b5043e98c419 | d9cb5b902764a0e0289f4775aabf9cbea4c2de35a695b1530deb724d78349a86 |
| 21 | 2d287f51eff2a5fbf84458a33f7fb2493cf67965 | 110999b012c10d1ea12dbefb531e8ba71e72a1d5ab51f0bc650b966b44a435f9 |

LLVM 20 使用现有独立 NDK 的头文件、资源库、链接器布局，不构成对应官方 NDK 整包认证。
两个生成头 SHA-256 相同：a2d21ccff800b78689815fb210ea632c5415a0021068a63c515de15723c6bff1。
构建和测试日志保存在 `work/call-frames*.log`，IR 与独立可执行文件在 `work/call-frames20/21`。
此次未发布二进制产物。

两版 registration.patch 在精确基线文件副本上通过正向 `git apply --check`，
在各自应用后的源码树上通过反向检查；注册补丁本身未改。
25 项 overlay 回归与 3 项 bitcode 生成脚本回归通过。
两版通过四 ABI 编链、字符串加密、证书绑定、anti-tamper、CMake 与 ndk-build 检查。
CMake 首次运行因当前 shell 缺 Ninja 失败，补齐本次进程的 PATH 后通过。

两版 CSE/VMP 完整性设备矩阵通过：冷/热篡改、缓存边界、strip、Full/Thin LTO 与混淆组合。
LLVM 20 首次运行中途因本机 ADB 连接超时中断；设备重连后完整重跑通过，
通过记录为 `work/call-frames-recheck20-retry.log`，中断日志保留，不计为成功。

两版最终调用帧设备回归的六种配置全部通过，共 12 组，包含分配失败与异常释放检查；
对应 `work/call-frames20-final.log` 和 `work/call-frames21-final.log`。
两版 `memory_ops.py` 的边界/退出条件与 O0/O2 设备语义回归通过。
两版 `roundtrip.sh` 的普通/VMP/SelfCheck/Entry、全局地址、TLS、递归与八线程设备回归通过。
临时设备程序已清理，接入项目预编译 SO 摘要保持为
`2a1eb7809d59e8c8579c2110c8b27ceaa38306f02846630a1dd4f0ec91d39892`。

## 提交前独立复核

复核发现 p8 在 eligibility 检查前展开 memops，导致带 personality/向量的函数虽被 VMP 拒绝，
仍留下原生展开代码和收据。现已将预扫描前移；实际展开后的四个翻译失败出口统一报编译错误，
不允许静默输出未保护的展开产物。没有为此增加整函数克隆/回滚机制。

新增回归核对 personality/向量拒绝时函数体与未启用 memops 的基线相同、无收据和字节码；
用 200 条定长比较触发展开后指令数超限，要求编译失败。旧 p8 在新回归的 `rejected_eh`
断言失败，修复后通过。两个 vm.h 未因本次边界修复而改变。

最终编译器 SHA-256：

- LLVM 20：31bf709ce22c36d99361e632f1da0e22178306513979b0d0fee9f7282d2e6098。
- LLVM 21：19cb3b3723029563e3ad8359a8ff03c73680d4baafbe94d63f55a8be01d513e0。

最终两版构建通过；两版调用帧 12 组设备回归及 memops 拒绝/超限、O0/O2 设备语义复测通过，
独立复核结论为 PASS。对应日志为 `work/verify-p9-fixed-frames{20,21}.log`、
`work/verify-p9-fixed-memory20.log` 与 `work/submit-p9-fixed-memory21.log`。
独立重编的解释器 bitcode 与两个生成头逐字节一致，SHA-256 为
`74af52a05b01c3d48fa82e4918e2f6b53125d495faf692ba051e81ba60453013`。
首次完整性矩阵未因仅调整 memops 拒绝边界而重复执行。
