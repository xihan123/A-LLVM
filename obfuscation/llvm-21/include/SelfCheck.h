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
// 只校验 VMP（-irobf-vmp）产出的每函数字节码 blob（gv_code_seg_<fn>），在加载期
// 通过 ELF 构造器比对其哈希，检测到篡改即终止进程。详见 SelfCheck.cpp。
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
