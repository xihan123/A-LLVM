//===- ObfuscationPassManager.cpp -----------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/aVMP/aVMP.h"

#define DEBUG_TYPE "ir-obfuscation"

using namespace llvm;

static cl::opt<bool>
EnableIRObfuscation("irobf", cl::init(false), cl::NotHidden,
                    cl::desc("Enable IR Code Obfuscation."), cl::ZeroOrMore);
static cl::opt<bool>
EnableIRObfuscationDebug("irobf-debug", cl::init(false), cl::NotHidden,
                         cl::desc("Enable debug output for obfuscation."),
                         cl::ZeroOrMore);

static cl::opt<bool>
EnableIndirectBr("irobf-indbr", cl::init(false), cl::NotHidden,
                 cl::desc("Enable IR Indirect Branch Obfuscation."),
                 cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIndirectBr("level-indbr", cl::init(0), cl::NotHidden,
                cl::desc("Set IR Indirect Branch Obfuscation Level."),
                cl::ZeroOrMore);

static cl::opt<bool>
EnableIndirectCall("irobf-icall", cl::init(false), cl::NotHidden,
                   cl::desc("Enable IR Indirect Call Obfuscation."),
                   cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIndirectCall("level-icall", cl::init(0), cl::NotHidden,
                  cl::desc("Set IR Indirect Call Obfuscation Level."),
                  cl::ZeroOrMore);

static cl::opt<bool>
EnableIndirectGV("irobf-indgv", cl::init(false), cl::NotHidden,
                 cl::desc("Enable IR Indirect Global Variable Obfuscation."),
                 cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIndirectGV("level-indgv", cl::init(0), cl::NotHidden,
                cl::desc("Set IR Indirect Global Variable Obfuscation Level."),
                cl::ZeroOrMore);

static cl::opt<bool>
EnableIRFlattening("irobf-fla", cl::init(false), cl::NotHidden,
                   cl::desc("Enable IR Control Flow Flattening Obfuscation."),
                   cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIRFlattening("level-fla", cl::init(0), cl::NotHidden,
                  cl::desc("Set IR Control Flow Flattening Obfuscation Level."),
                  cl::ZeroOrMore);

static cl::opt<bool>
EnableIRStringEncryption("irobf-cse", cl::init(false), cl::NotHidden,
                         cl::desc("Enable IR Constant String Encryption."),
                         cl::ZeroOrMore);

static cl::opt<bool>
EnableIRConstantIntEncryption("irobf-cie", cl::init(false), cl::NotHidden,
                              cl::desc("Enable IR Constant Integer Encryption."),
                              cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIRConstantIntEncryption("level-cie", cl::init(0), cl::NotHidden,
                             cl::desc("Set IR Constant Integer Encryption Level."),
                             cl::ZeroOrMore);

static cl::opt<bool>
EnableIRConstantFPEncryption("irobf-cfe", cl::init(false), cl::NotHidden,
                             cl::desc("Enable IR Constant FP Encryption."),
                             cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIRConstantFPEncryption("level-cfe", cl::init(0), cl::NotHidden,
                            cl::desc("Set IR Constant FP Encryption Level."),
                            cl::ZeroOrMore);

// 阶段 2 VMP（函数级虚拟化）。被虚拟化的函数通过注解（ndkp.vmp / "vmp"）或
// -irobf-vm_functions= 指定；VMP 要求 -frtti -fno-exceptions（见 include/ndkp.h）。
static cl::opt<std::string>
VMFunctions("irobf-vm_functions", cl::init(""), cl::NotHidden,
            cl::desc("Specify VMP protected functions, separated by semicolon "
                     "(e.g., func1;func2;func3)."),
            cl::ZeroOrMore);
static cl::opt<bool>
EnableVMProtect("irobf-vmp", cl::init(false), cl::NotHidden,
                cl::desc("Enable VMProtect (function-level virtualization)."),
                cl::ZeroOrMore);
static cl::opt<bool>
ForceNoInline("irobf-vmp-noinline", cl::init(false), cl::NotHidden,
              cl::desc("Force disable inlining for all functions in VMP."),
              cl::ZeroOrMore);

bool llvm::isIRObfuscationDebugEnabled() { return EnableIRObfuscationDebug; }

std::string llvm::getVMFunctionsList() { return VMFunctions; }
bool llvm::isForceNoInlineEnabled() { return ForceNoInline; }

bool llvm::isIRObfuscationEnabled() {
  return EnableIRObfuscation || EnableIndirectBr || EnableIndirectCall ||
         EnableIndirectGV || EnableIRFlattening || EnableIRStringEncryption ||
         EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
         EnableVMProtect;
}

namespace llvm {

struct ObfuscationPassManager : public ModulePass {
  static char ID;
  SmallVector<Pass *, 8> Passes;

  ObfuscationPassManager() : ModulePass(ID) {
    initializeObfuscationPassManagerPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "Obfuscation Pass Manager"; }

  bool doFinalization(Module &M) override {
    bool Change = false;
    for (Pass *P : Passes) {
      Change |= P->doFinalization(M);
      delete P;
    }
    Passes.clear();
    return Change;
  }

  void add(Pass *P) { Passes.push_back(P); }

  bool run(Module &M) {
    bool Change = false;
    for (Pass *P : Passes) {
      switch (P->getPassKind()) {
      case PassKind::PT_Function:
        Change |= runFunctionPass(M, (FunctionPass *)P);
        break;
      case PassKind::PT_Module:
        Change |= runModulePass(M, (ModulePass *)P);
        break;
      default:
        continue;
      }
    }
    return Change;
  }

  bool runFunctionPass(Module &M, FunctionPass *P) {
    bool Changed = false;
    Changed |= P->doInitialization(M);
    for (Function &F : M)
      Changed |= P->runOnFunction(F);
    return Changed;
  }

  bool runModulePass(Module &M, ModulePass *P) {
    return P->doInitialization(M) || P->runOnModule(M);
  }

  static std::shared_ptr<ObfuscationOptions> getOptions() {
    auto Opt = std::make_shared<ObfuscationOptions>();
    Opt->indBrOpt()->readOpt(EnableIndirectBr, LevelIndirectBr);
    Opt->iCallOpt()->readOpt(EnableIndirectCall, LevelIndirectCall);
    Opt->indGvOpt()->readOpt(EnableIndirectGV, LevelIndirectGV);
    Opt->flaOpt()->readOpt(EnableIRFlattening, LevelIRFlattening);
    Opt->cseOpt()->readOpt(EnableIRStringEncryption);
    Opt->cieOpt()->readOpt(EnableIRConstantIntEncryption,
                           LevelIRConstantIntEncryption);
    Opt->cfeOpt()->readOpt(EnableIRConstantFPEncryption,
                           LevelIRConstantFPEncryption);
    return Opt;
  }

  bool runOnModule(Module &M) override {
    bool hasObf = EnableIndirectBr || EnableIndirectCall || EnableIndirectGV ||
                  EnableIRFlattening || EnableIRStringEncryption ||
                  EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
                  EnableVMProtect;
    if (hasObf)
      EnableIRObfuscation = true;

    if (!EnableIRObfuscation)
      return run(M);

    const auto Options(getOptions());
    unsigned pointerSize = M.getDataLayout().getTypeAllocSize(
        PointerType::getUnqual(M.getContext()));

    if (isIRObfuscationDebugEnabled()) {
      errs() << "[NDKP] IR obfuscation enabled:\n";
      if (EnableVMProtect)               errs() << "  + VMProtect\n";
      if (EnableIRConstantIntEncryption) errs() << "  + ConstantIntEncryption\n";
      if (EnableIRConstantFPEncryption)  errs() << "  + ConstantFPEncryption\n";
      if (EnableIRStringEncryption)      errs() << "  + StringEncryption\n";
      if (EnableIndirectGV)              errs() << "  + IndirectGlobalVariable\n";
      if (EnableIndirectCall)            errs() << "  + IndirectCall\n";
      if (EnableIRFlattening)            errs() << "  + Flattening\n";
      if (EnableIndirectBr)              errs() << "  + IndirectBranch\n";
    }

    // VMP 最先：在常量/字符串/CFG pass 改写 IR 之前，对干净 IR 做虚拟化；其产物
    // （vm_interpreter / *_original / vm_*_seg）被后续 pass 按名跳过。
    if (EnableVMProtect)
      add(llvm::createVMProtectPass(true));

    if (EnableIRConstantIntEncryption || Options->cieOpt()->isEnabled())
      add(llvm::createConstantIntEncryptionPass(Options.get()));
    if (EnableIRConstantFPEncryption || Options->cfeOpt()->isEnabled())
      add(llvm::createConstantFPEncryptionPass(Options.get()));
    if (EnableIRStringEncryption || Options->cseOpt()->isEnabled())
      add(llvm::createStringEncryptionPass(Options.get()));
    if (EnableIndirectGV || Options->indGvOpt()->isEnabled())
      add(llvm::createIndirectGlobalVariablePass(Options.get()));
    if (EnableIndirectCall || Options->iCallOpt()->isEnabled())
      add(llvm::createIndirectCallPass(Options.get()));
    if (EnableIRFlattening || Options->flaOpt()->isEnabled())
      add(llvm::createFlatteningPass(pointerSize, Options.get()));
    if (EnableIndirectBr || Options->indBrOpt()->isEnabled())
      add(llvm::createIndirectBranchPass(Options.get()));

    return run(M);
  }
};

} // namespace llvm

char ObfuscationPassManager::ID = 0;

ModulePass *llvm::createObfuscationPassManager() {
  return new ObfuscationPassManager();
}

INITIALIZE_PASS_BEGIN(ObfuscationPassManager, "irobf", "Enable IR Obfuscation",
                      false, false)
INITIALIZE_PASS_END(ObfuscationPassManager, "irobf", "Enable IR Obfuscation",
                    false, false)
