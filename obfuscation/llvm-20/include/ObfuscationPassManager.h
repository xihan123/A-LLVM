//===- ObfuscationPassManager.h --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef OBFUSCATION_OBFUSCATIONPASSMANAGER_H
#define OBFUSCATION_OBFUSCATIONPASSMANAGER_H

#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/Transforms/Obfuscation/Flattening.h"
#include "llvm/Transforms/Obfuscation/IndirectBranch.h"
#include "llvm/Transforms/Obfuscation/IndirectCall.h"
#include "llvm/Transforms/Obfuscation/IndirectGlobalVariable.h"
#include "llvm/Transforms/Obfuscation/ConstantIntEncryption.h"
#include "llvm/Transforms/Obfuscation/ConstantFPEncryption.h"
#include "llvm/Transforms/Obfuscation/IdaDetect.h"
#include "llvm/Transforms/Obfuscation/TimeDetect.h"
#include "llvm/Transforms/Obfuscation/RootDetect.h"
#include "llvm/Transforms/Obfuscation/VmProtectDetect.h"
#include "llvm/Transforms/Obfuscation/BanDump.h"
#include "llvm/Transforms/Obfuscation/HideMaps.h"
#include "llvm/Transforms/Obfuscation/FakeMaps.h"
#include "llvm/Transforms/Obfuscation/SelfCheck.h"
#include "llvm/Passes/PassBuilder.h"
#include <string>

namespace llvm {
class ModulePass;
class PassRegistry;

bool isIRObfuscationEnabled();
bool isIRObfuscationDebugEnabled();

// VMP（-irobf-vmp）辅助开关读取，供 aVMP pass 使用。
std::string getVMFunctionsList();
bool isForceNoInlineEnabled();

// 字符串加密强化开关读取，供 StringEncryption pass 使用。
// perkey：per-string 密钥由隐藏 pepper + 串 id 经 ChaCha8 派生，不再内联存储。
// bind：把运行期包名（/proc/self/cmdline）哈希折进 pepper（非分支、fail-closed）；
//       bind 蕴含 perkey，期望包名由 -irobf-cse-bind-package 提供。
bool isCsePerKeyEnabled();
bool isCseBindEnabled();
std::string getCseBindPackage();

ModulePass *createObfuscationPassManager();
void initializeObfuscationPassManagerPass(PassRegistry &Registry);

class ObfuscationPassManagerPass
    : public PassInfoMixin<ObfuscationPassManagerPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    ModulePass *OPM = createObfuscationPassManager();
    bool Changed = OPM->runOnModule(M);
    OPM->doFinalization(M);
    delete OPM;
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  static StringRef name() { return "ObfuscationPassManagerPass"; }
};

} // namespace llvm

#endif
