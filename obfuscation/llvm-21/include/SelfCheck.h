//===- SelfCheck.h - VMP 字节码完整性自校验注入 Pass ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件声明代码完整性自校验注入 Pass（-irobf-selfcheck）。
// 只校验 VMP（-irobf-vmp）产出的每函数字节码 blob（gv_code_seg_<fn>）：加载期通过 ELF
// 构造器 volatile 重算各 blob 的 FNV-1a64 与内嵌期望值比对，不符即 kill(SIGKILL) 终止
// （主响应）；并附带把哈希 XOR 累加折进 VMP 密钥全局作纵深防御——篡改即令 VMP 密钥出错、
// 解释器解出乱码而崩溃（VMProtectPreparePass 修复 VMP 绕过后真机验证生效）。详见 SelfCheck.cpp。
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_SELFCHECK_H
#define LLVM_TRANSFORMS_OBFUSCATION_SELFCHECK_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

class PassRegistry;

ModulePass *createSelfCheckPass();
void initializeSelfCheckPass(PassRegistry &Registry);

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_SELFCHECK_H
