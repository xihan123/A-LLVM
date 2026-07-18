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

## ⚠ 当前提交的 vm.h 状态（WIP）
仓库现提交的 `vm.h` 是**上游 ALLVM 的 aarch64 bitcode**（本地 Windows 无交叉 clang，未重生成）。
其反篡改 kill 路径仍内嵌上游 "A-Protector" 横幅字节（**仅篡改检测时触发** `write(2,...)+SIGKILL`，
正常执行 / roundtrip 测试不会打印，不影响 stdout/rc 语义等价）。**合入 main / 发版前必须**用本
目录去品牌后的源码经 `gen_vm_bitcode.sh` 重生成、替换该 `vm.h`。
