// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "llvm/Transforms/Obfuscation/aVMP/aVMPMemoryOps.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

static cl::opt<bool> EnableVMPMemoryOps(
    "irobf-vmp-memops", cl::init(false),
    cl::desc("Lower fixed-size memcmp/memcpy (up to 64 bytes) into VMP operations"));

bool llvm::lowerVMPMemoryOps(Function &F) {
  if (!EnableVMPMemoryOps)
    return false;
  Module &M = *F.getParent();
  TargetLibraryInfoImpl Impl(Triple(M.getTargetTriple()));
  TargetLibraryInfo TLI(Impl, &F);
  SmallVector<CallInst *, 8> Calls;
  for (Instruction &I : instructions(F))
    if (auto *Call = dyn_cast<CallInst>(&I))
      Calls.push_back(Call);

  unsigned Compares = 0, Copies = 0;
  for (CallInst *Call : Calls) {
    // Operand bundles and tail-call contracts require more than byte lowering.
    if (Call->hasOperandBundles() || Call->isMustTailCall())
      continue;
    Value *Dst = nullptr, *Src = nullptr, *Length = nullptr;
    bool Compare = false;
    if (auto *Copy = dyn_cast<MemCpyInst>(Call)) {
      if (Copy->isVolatile())
        continue;
      Dst = Copy->getRawDest();
      Src = Copy->getRawSource();
      Length = Copy->getLength();
    } else {
      Function *Callee = Call->getCalledFunction();
      LibFunc Kind;
      if (!Callee || !Callee->isDeclaration() || Call->arg_size() != 3 ||
          !TLI.getLibFunc(*Call, Kind) || !TLI.has(Kind) ||
          (Kind != LibFunc_memcmp && Kind != LibFunc_memcpy))
        continue;
      Compare = Kind == LibFunc_memcmp;
      Dst = Call->getArgOperand(0);
      Src = Call->getArgOperand(1);
      Length = Call->getArgOperand(2);
    }
    auto *Count = dyn_cast<ConstantInt>(Length);
    if (!Count || Count->getValue().ugt(64) ||
        !Dst->getType()->isPointerTy() || !Src->getType()->isPointerTy() ||
        Dst->getType()->getPointerAddressSpace() != 0 ||
        Src->getType()->getPointerAddressSpace() != 0)
      continue;

    IRBuilder<> B(Call);
    B.SetCurrentDebugLocation(Call->getDebugLoc());
    Value *Result = B.getInt32(0);
    for (uint64_t I = 0; I < Count->getZExtValue(); ++I) {
      Value *Left = B.CreateGEP(B.getInt8Ty(), Dst, B.getInt64(I));
      Value *Right = B.CreateGEP(B.getInt8Ty(), Src, B.getInt64(I));
      Value *Byte = B.CreateAlignedLoad(B.getInt8Ty(), Right, Align(1));
      if (Compare) {
        Value *Other = B.CreateAlignedLoad(B.getInt8Ty(), Left, Align(1));
        Value *Diff = B.CreateSub(B.CreateZExt(Other, B.getInt32Ty()),
                                 B.CreateZExt(Byte, B.getInt32Ty()));
        // memcmp promises the sign of the first unsigned-byte difference.
        Result = B.CreateSelect(B.CreateICmpEQ(Result, B.getInt32(0)), Diff, Result);
      } else {
        B.CreateAlignedStore(Byte, Left, Align(1));
      }
    }
    if (!Call->getType()->isVoidTy())
      Call->replaceAllUsesWith(Compare ? Result : Dst);
    Call->eraseFromParent();
    Compare ? ++Compares : ++Copies;
  }
  if (!Compares && !Copies)
    return false;

  // Object-level build receipt; bytecode presence must be checked separately.
  auto *Receipt = new GlobalVariable(
      M, Type::getInt8Ty(M.getContext()), true, GlobalValue::InternalLinkage,
      ConstantInt::get(Type::getInt8Ty(M.getContext()), 0),
      "ndkp_vmp_memops_" + F.getName() + "_cmp" + Twine(Compares) +
          "_copy" + Twine(Copies));
  appendToCompilerUsed(M, {Receipt});
  return true;
}
