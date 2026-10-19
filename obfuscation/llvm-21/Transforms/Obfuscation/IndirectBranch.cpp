//===- IndirectBranch.cpp - 间接分支混淆Pass---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现间接分支混淆Pass，通过将直接分支转换为间接分支
// 来增加逆向分析的难度
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/IndirectBranch.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Module.h"

#include <random>

#define DEBUG_TYPE "indbr"

using namespace llvm;
namespace {
struct IndirectBranch : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;

  std::unordered_map<Function *, std::set<Constant *>> FunctionBBs;
  std::unordered_map<Function *, std::set<BranchInst *>> FunctionBrs;

  std::vector<Constant *> BBAddrTargets;
  std::unordered_map<Constant *, unsigned> BBIndex;
  std::unordered_map<Constant *, uint64_t> BBKeys;
  std::vector<GlobalVariable *> BBPageTable;

  CryptoUtils RandomEngine;
  bool RunOnFuncChanged = false;

  IndirectBranch(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
  }

  StringRef getPassName() const override { return {"IndirectBranch"}; }

  void NumberBasicBlock(Module &M) {
    for (auto &F : M) {
      if (!ArgsOptions->toObfuscate(ArgsOptions->indBrOpt(), &F).isEnabled())
        continue;
      // Post-VMP uses per-function relative offsets, avoiding thousands of ELF
      // dynamic relocations and duplicated page-index decoding sequences.
      if (F.getMetadata("ndkp.vmp.post.target"))
        continue;
      if (F.empty() || F.isWeakForLinker() ||
          F.getSection() == ".text.startup" ||
          F.isIntrinsic()) {
        continue;
      }
      SplitAllCriticalEdges(F, CriticalEdgeSplittingOptions(nullptr, nullptr));
      uint64_t BBKey = RandomEngine.get_uint64_t();
      for (auto &BB : F) {
        auto *Term = BB.getTerminator();
        if (!Term) continue;
        if (auto *BI = dyn_cast<BranchInst>(Term)) {
          if (BI->isConditional()) {
            FunctionBrs[&F].emplace(BI);
            unsigned N = BI->getNumSuccessors();
            for (unsigned I = 0; I < N; I++) {
              BasicBlock *Successor = BI->getSuccessor(I);
              if (!Successor) continue;
              auto BBAddr = BlockAddress::get(Successor);
              if (!BBAddr) continue;
              FunctionBBs[&F].emplace(BBAddr);
              if (BBKeys.count(BBAddr) == 0) {
                BBAddrTargets.push_back(BBAddr);
                BBKeys[BBAddr] = BBKey;
              }
            }
          }
        }
      }
    }
  }

  bool doInitialization(Module &M) override {
    BBIndex.clear();
    BBPageTable.clear();
    FunctionBBs.clear();
    FunctionBrs.clear();
    BBAddrTargets.clear();
    BBKeys.clear();

    NumberBasicBlock(M);
    if (BBAddrTargets.empty()) {
      return false;
    }

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = 1;
    createPageTableArgs.GVNamePrefix = M.getName().str() + "_IndirectBr" ;
    createPageTableArgs.RandomEngine = &RandomEngine;
    createPageTableArgs.M = &M;
    createPageTableArgs.Objects = &BBAddrTargets;
    createPageTableArgs.IndexMap = &BBIndex;
    createPageTableArgs.ObjectKeys = &BBKeys;
    createPageTableArgs.OutPageTable = &BBPageTable;

    createPageTable(createPageTableArgs);
    return false;
  }

  bool runPostOnFunction(Function &Fn) {
    SmallVector<BranchInst *, 32> Branches;
    std::vector<BasicBlock *> Targets;
    for (BasicBlock &BB : Fn) {
      auto *Br = dyn_cast<BranchInst>(BB.getTerminator());
      if (!Br || !Br->isConditional())
        continue;
      Branches.push_back(Br);
      for (BasicBlock *Target : Br->successors())
        if (llvm::find(Targets, Target) == Targets.end())
          Targets.push_back(Target);
    }
    if (Branches.empty())
      return false;
    std::mt19937_64 Engine(RandomEngine.get_uint64_t());
    std::shuffle(Targets.begin(), Targets.end(), Engine);
    auto &M = *Fn.getParent();
    auto &Ctx = M.getContext();
    auto *Int32 = Type::getInt32Ty(Ctx);
    auto *IntPtr = M.getDataLayout().getIntPtrType(Ctx);
    auto *Key = ConstantInt::get(Int32, RandomEngine.get_uint32_t());
    // Keep offsets relative to this definition even for a preemptible symbol.
    Constant *Anchor = DSOLocalEquivalent::get(&Fn);
    auto *Base = ConstantExpr::getPtrToInt(&Fn, IntPtr);
    SmallVector<Constant *, 32> Offsets;
    DenseMap<BasicBlock *, unsigned> Index;
    for (BasicBlock *Target : Targets) {
      Index[Target] = Offsets.size();
      auto *Address = ConstantExpr::getPtrToInt(BlockAddress::get(Target), IntPtr);
      auto *Offset = ConstantExpr::getTruncOrBitCast(ConstantExpr::getSub(Address, Base), Int32);
      Offsets.push_back(ConstantExpr::getAdd(Offset, Key));
    }
    auto *TableType = ArrayType::get(Int32, Offsets.size());
    auto *Table = new GlobalVariable(M, TableType, false, GlobalValue::PrivateLinkage,
        ConstantArray::get(TableType, Offsets), Fn.getName() + ".post.targets");
    Table->setSection(".AProtect.data");
    Table->setAlignment(Align(4));
    Table->setMetadata("noobf", MDNode::get(Ctx, {}));
    for (BranchInst *Br : Branches) {
      IRBuilder<> IRB(Br);
      auto *True = Br->getSuccessor(0), *False = Br->getSuccessor(1);
      Value *Slot = IRB.CreateSelect(Br->getCondition(),
          ConstantInt::get(Int32, Index[True]), ConstantInt::get(Int32, Index[False]));
      Value *Ptr = IRB.CreateGEP(TableType, Table, {ConstantInt::get(Int32, 0), Slot});
      Value *Encoded = IRB.CreateAlignedLoad(Int32, Ptr, Align(4), true);
      Value *Offset = IRB.CreateSExtOrTrunc(IRB.CreateSub(Encoded, Key), IntPtr);
      Value *Address = IRB.CreateGEP(Type::getInt8Ty(Ctx), Anchor, Offset);
      auto *Indirect = IndirectBrInst::Create(Address, 2);
      ReplaceInstWithInst(Br, Indirect);
      Indirect->addDestination(True);
      Indirect->addDestination(False);
    }
    return true;
  }

  bool runOnFunction(Function &Fn) override {
    if (isIRObfuscationDebugEnabled()) {
      errs() << "[DEBUG] IndirectBranch: Starting runOnFunction: " << Fn.getName() << "\n";
    }
    if (Fn.isDeclaration() || Fn.empty()) {
      return false;
    }

    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->indBrOpt(), &Fn);
    if (!opt.isEnabled()) {
      return false;
    }
    if (Fn.getMetadata("ndkp.vmp.post.target"))
      return runPostOnFunction(Fn);

    LLVMContext &Ctx = Fn.getContext();
    auto& M = *Fn.getParent();

    if (BBAddrTargets.empty()) {
      return false;
    }

    auto& FuncBBsSet = FunctionBBs[&Fn];
    auto& FuncBrs = FunctionBrs[&Fn];
    if (FuncBBsSet.empty() || FuncBrs.empty()) {
      return false;
    }

    std::vector<Constant *> FuncBBs;
    std::unordered_map<Constant *, uint64_t> FuncKeys;
    auto FuncKey = RandomEngine.get_uint64_t();

    for (auto bb : FuncBBsSet) {
      if (!bb) continue;
      FuncBBs.push_back(bb);
      FuncKeys[bb] = FuncKey;
    }

    if (FuncBBs.empty()) {
      return false;
    }

    std::vector<GlobalVariable *> FuncBBPageTable;
    std::unordered_map<Constant *, unsigned> FuncBBIndex;

    if (opt.level()) {
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = opt.level();
      createPageTableArgs.GVNamePrefix = M.getName().str() + Fn.getName().str() + "_IndirectBr" ;
      createPageTableArgs.RandomEngine = &RandomEngine;
      createPageTableArgs.M = &M;
      createPageTableArgs.Objects = &FuncBBs;
      createPageTableArgs.IndexMap = &BBIndex;
      createPageTableArgs.ObjectKeys = &FuncKeys;
      createPageTableArgs.OutPageTable = &FuncBBPageTable;

      enhancedPageTable(createPageTableArgs, &FuncBBIndex);
    }

    auto Int32Ty = IntegerType::getInt32Ty(Ctx);
    for (auto &BI : FuncBrs) {
      if (!BI) continue;

      if (BI->isConditional()) {
        IRBuilder<> IRB(BI);

        auto Cond = BI->getCondition();

        auto TBB = BI->getSuccessor(0);
        auto FBB = BI->getSuccessor(1);

        if (!TBB || !FBB) continue;

        auto AddrTBB = BlockAddress::get(TBB);
        auto AddrFBB = BlockAddress::get(FBB);

        if (BBIndex.find(AddrTBB) == BBIndex.end() ||
            BBIndex.find(AddrFBB) == BBIndex.end()) {
          continue;
        }

        unsigned TIdx, FIdx;
        if (opt.level()) {
          if (FuncBBIndex.find(AddrTBB) == FuncBBIndex.end() ||
              FuncBBIndex.find(AddrFBB) == FuncBBIndex.end()) {
            continue;
          }
          TIdx = FuncBBIndex[AddrTBB];
          FIdx = FuncBBIndex[AddrFBB];
        } else {
          TIdx = BBIndex[AddrTBB];
          FIdx = BBIndex[AddrFBB];
        }

        auto TIndex = ConstantInt::get(Int32Ty, TIdx);
        auto FIndex = ConstantInt::get(Int32Ty, FIdx);

        auto NextIndex = IRB.CreateSelect(Cond, TIndex, FIndex);

        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = opt.level();
        buildDecrypt.NextIndex = 0;
        buildDecrypt.NextIndexValue = NextIndex;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = BI;
        buildDecrypt.LoadTy = PointerType::getUnqual(Ctx);
        buildDecrypt.ModulePageTable = &BBPageTable;
        buildDecrypt.FuncPageTable = &FuncBBPageTable;
        buildDecrypt.ModuleKey = BBKeys[AddrTBB];
        buildDecrypt.FuncKey = FuncKeys[AddrTBB];

        auto TargetPtr = buildPageTableDecryptIR(buildDecrypt);
        IndirectBrInst *IBI = IndirectBrInst::Create(TargetPtr, 2);
        ReplaceInstWithInst(BI, IBI);
        IBI->addDestination(TBB);
        IBI->addDestination(FBB);

        RunOnFuncChanged = true;
      }
    }

    return true;
  }

  bool doFinalization(Module &M) override {
    if (!RunOnFuncChanged || BBPageTable.empty()) {
      return false;
    }
    for (auto bbPage : BBPageTable) {
      appendToCompilerUsed(M, {bbPage});
    }
    return true;
  }

};

} // namespace llvm

char IndirectBranch::ID = 0;

FunctionPass *llvm::createIndirectBranchPass(ObfuscationOptions *argsOptions) {
  return new IndirectBranch(argsOptions);
}

INITIALIZE_PASS(IndirectBranch, "indbr", "Enable IR Indirect Branch Obfuscation", false, false)
