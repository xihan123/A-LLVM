# aVMPInterpreter — VMP 解释器源码（vm.h 的生成输入）

阶段 2 VMP 的解释器。以 C++ 写成，交叉编译为目标 ABI 的 LLVM bitcode，再转成字节
数组头 `obfuscation/llvm-*/include/aVMP/vm.h`，由 `Transforms/Obfuscation/aVMP/aVMP.cpp`
在 pass 期 `#include` 并 `Linker::linkModules` 链入用户模块（入口 `vm_interpreter`）。

## 来源与许可
移植自上游 ALLVM（`github.com/abcdefgjh-li/ALLVM`，GPL-3.0，与本项目同许可）。已去品牌：
反篡改路径的 "A-Protector" 横幅已从 `aVMPInterpreter.cpp` 的 `vmp_report_and_kill` 移除。

## 本目录不参与 overlay 构建
`scripts/apply_overlay.sh` 只拷 `obfuscation/llvm-*/{Transforms/Obfuscation,include}`；本目录是
`vm.h` 的**生成输入**，不进 clang 构建，仅供审计与重新生成。

## 重新生成 vm.h（需能交叉出 bitcode 的 clang，如官方 NDK clang）
    scripts/gen_vm_bitcode.sh <ndk_clang> aarch64
产出并覆盖 `obfuscation/llvm-{20,21}/include/aVMP/vm.h`（垂直切片只需 aarch64）。

## p15 生成状态

LLVM 21 的 `vm.h` 已用 LLVM 21 重新生成（152604 字节 bitcode）：优化密码辅助函数，
缓存同一元组/64 字节块共用的调度 seed。wire 格式、轮数和每方法私有指令映射保持不变。
`tests/vmp/crypto_cache_driver.cpp` 对照 p14 黄金摘要验证随机位置、块切换和嵌套上下文，
由 CSE 设备回归编译执行；调用帧、ART、post 和篡改拒绝另行验证。
LLVM 21 的 CMake 对生成头增加显式对象依赖，避免本地增量编译漏掉 bitcode 更新。
LLVM 20 的 `vm.h` 保留 p9，未使用 LLVM 21 bitcode 覆盖旧 reader。

## p9 vm.h 生成状态（历史）
仓库提交的 `vm.h` 已用本目录解释器源码、经本地 LLVM 20 编译器
（`--target=aarch64-linux-android21 -frtti -fexceptions -O2 -fno-inline -emit-llvm`）
本地重新生成（p9，158212 字节 bitcode），同时供 LLVM 20/21 使用。
使用 LLVM 20 保证旧版 bitcode reader 兼容；生成参数和验证见
[p9 记录](../../docs/vmp-call-frames-p9.md)。"A-Protector" 横幅**不在** bitcode 内；
入口 `vm_interpreter` / `vmp_resume_unwind` 齐全，VM 状态全局（`vm_block_chain_state`
等）为 extern、由 pass 创建。仅 aarch64；其余 ABI 待 Slice 3 用 `gen_vm_bitcode.sh` 生成。

> 注：解释器自身实现 Itanium 异常模型（含 `try/catch`），**必须用 `-fexceptions`** 编译；
> `-fno-exceptions` 只针对被虚拟化的用户代码。`gen_vm_bitcode.sh` 已按此设置。
