
#ifndef _OBFUSCATION_VMPROTECT_H_
#define _OBFUSCATION_VMPROTECT_H_

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO.h"
#include <string>

namespace llvm {
Pass *createVMProtectPass(bool flag = false);

struct VMProtectPass : public PassInfoMixin<VMProtectPass> {
  bool flag;
  VMProtectPass() : flag(false) {}
  VMProtectPass(bool flag) : flag(flag) {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

// 早期标记 pass（PipelineStartEP，在 inliner / IPSCCP 之前运行）。
// 给每个 VMP 目标函数打 NoInline + llvm.compiler.used，阻止它在被虚拟化前被
// 内联进调用方或被 IPSCCP 常量折叠——否则调用方用的是原生内联/折叠结果，VMP
// 桩沦为死代码、解释器永不执行、密钥/完整性绑定全失效。详见 aVMP.cpp。
struct VMProtectPreparePass : public PassInfoMixin<VMProtectPreparePass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

extern bool is_interpreter_function(llvm::Function *targetFunction);
extern std::string get_vm_function_name(llvm::Function *targetFunction);

#endif
