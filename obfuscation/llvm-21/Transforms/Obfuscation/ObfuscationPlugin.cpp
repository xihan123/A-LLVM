//===- ObfuscationPlugin.cpp - Obfuscation pass plugin ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Registers the obfuscation pass manager into the new-PM pipeline. Built into
// clang via Extension.def when LLVM_OBFUSCATION_LINK_INTO_TOOLS is set.
//
//===----------------------------------------------------------------------===//

#include "llvm/Config/llvm-config.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/aVMP/aVMP.h"

using namespace llvm;

llvm::PassPluginLibraryInfo getObfuscationPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "Obfuscation", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel,
                   ThinOrFullLTOPhase) {
                  if (isIRObfuscationEnabled())
                    MPM.addPass(ObfuscationPassManagerPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "obfuscation") {
                    MPM.addPass(ObfuscationPassManagerPass());
                    return true;
                  }
                  // 纯 new-PM 的 VMProtect 入口：供 opt -passes=vmprotect 单独运行
                  // VMP（不经 legacy 适配器）。
                  if (Name == "vmprotect") {
                    MPM.addPass(VMProtectPass(true));
                    return true;
                  }
                  return false;
                });
          }};
}

#ifndef LLVM_OBFUSCATION_LINK_INTO_TOOLS
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getObfuscationPluginInfo();
}
#endif
