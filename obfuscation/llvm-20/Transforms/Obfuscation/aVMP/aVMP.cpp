//===- aVMP.cpp - Function-level VM protection (VMP) ----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 阶段 2 VMP（函数级虚拟化）。
//
// SLICE 0 占位实现：仅打通 pass 注册 / -irobf-vmp 开关 / 插件链路，尚不做任何
// 代码生成（runOnModule 返回 false）。真正的 GOVM 翻译器 / 解释器链入将在
// Slice 1 从上游 aVMP 移植进来替换本文件。此桩件保持与最终实现相同的对外接口
// （createVMProtectPass(bool) / VMProtectPass::run / is_interpreter_function /
// get_vm_function_name），使 Slice 1 的真实文件可直接替换、且下游 pass 依赖的
// 符号在链接期已存在。
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/aVMP/aVMP.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

// 桩件：合法的 ModulePass，但不改动模块。Slice 1 用真实 GOVMTranslator 替换。
struct VMProtect : public ModulePass {
  static char ID;
  bool flag;
  VMProtect() : ModulePass(ID), flag(false) {}
  VMProtect(bool flag) : ModulePass(ID), flag(flag) {}

  bool runOnModule(Module &M) override {
    // Slice 0：不做代码生成，仅证明 -irobf-vmp 能进入混淆流水线。
    return false;
  }
};

} // namespace

char VMProtect::ID = 0;
static RegisterPass<VMProtect> X("aVMP", "Enable VM Protection (VMP)", false, true);

Pass *llvm::createVMProtectPass(bool flag) { return new VMProtect(flag); }

// New PassManager 入口（占位）。
PreservedAnalyses llvm::VMProtectPass::run(Module &M, ModuleAnalysisManager &AM) {
  return PreservedAnalyses::all();
}

// 供 IndirectCall / StringEncryption 等 pass 跳过 VM 产物用。Slice 0 用命名约定
// 判定；Slice 1 会替换为对真实解释器/段全局的精确识别。
bool is_interpreter_function(llvm::Function *targetFunction) {
  return targetFunction &&
         targetFunction->getName().contains("vm_interpreter");
}

std::string get_vm_function_name(llvm::Function *targetFunction) {
  return targetFunction ? targetFunction->getName().str() : std::string();
}
