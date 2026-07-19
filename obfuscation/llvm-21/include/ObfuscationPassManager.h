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
#include "llvm/Passes/PassBuilder.h"

namespace llvm {
class ModulePass;
class PassRegistry;

bool isIRObfuscationEnabled();
bool isIRObfuscationDebugEnabled();

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
