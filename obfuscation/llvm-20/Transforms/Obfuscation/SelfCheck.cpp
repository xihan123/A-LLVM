//===- SelfCheck.cpp - VMP 字节码完整性自校验注入 Pass -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// 对 VMP 字节码常量计算 FNV-1a64，在加载期构造器中复算，不匹配时终止进程。
// 字节码不含重定位，可直接比较编译期与运行期字节；volatile 读防止校验被常量折叠。
// 各 blob 的运行期哈希还会折入 VMP 入口密钥：realkey ^ expected_acc ^ runtime_acc。
// 此检查仅覆盖字节码，不覆盖解释器或其他代码，也不提供密码学认证。
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/SelfCheck.h"
#include "llvm/Transforms/Obfuscation/DetectUtils.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <cstdint>
#include <vector>

#define DEBUG_TYPE "selfcheck"

using namespace llvm;

namespace {

// 与 createCheckOneFunc 生成的运行期 FNV-1a64 保持一致。
static uint64_t selfcheckFnv1a64(StringRef Bytes) {
  uint64_t H = 0xcbf29ce484222325ULL;
  for (unsigned char C : Bytes) {
    H ^= static_cast<uint64_t>(C);
    H *= 0x100000001b3ULL;
  }
  return H;
}

struct SelfCheck : public ModulePass {
  static char ID;

  SelfCheck() : ModulePass(ID) {
    initializeSelfCheckPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return {"SelfCheck"}; }

  bool runOnModule(Module &M) override;

private:
  // 返回运行期哈希；与 expected 不符时调用 KillFn。
  Function *createCheckOneFunc(Module &M, Function *KillFn);
};

} // namespace

char SelfCheck::ID = 0;

Function *SelfCheck::createCheckOneFunc(Module &M, Function *KillFn) {
  LLVMContext &Ctx = M.getContext();
  Type *Int8Ty = Type::getInt8Ty(Ctx);
  Type *Int64Ty = Type::getInt64Ty(Ctx);
  PointerType *PtrTy = PointerType::get(Ctx, 0);

  FunctionType *FuncTy =
      FunctionType::get(Int64Ty, {PtrTy, Int64Ty, Int64Ty}, false);
  Function *Func = Function::Create(
      FuncTy, GlobalValue::InternalLinkage,
      M.getDataLayout().getProgramAddressSpace(), "ndkp_selfcheck_one", &M);
  // NoInline + OptimizeNone：保证 FNV 循环与 volatile 读逐字节保留、不被特化/折叠。
  Func->addFnAttr(Attribute::NoInline);
  Func->addFnAttr(Attribute::OptimizeNone);

  Argument *Base = Func->getArg(0);
  Argument *Len = Func->getArg(1);
  Argument *Expected = Func->getArg(2);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
  BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
  BasicBlock *BodyBB = BasicBlock::Create(Ctx, "body", Func);
  BasicBlock *DoneBB = BasicBlock::Create(Ctx, "done", Func);
  BasicBlock *TamperBB = BasicBlock::Create(Ctx, "tamper", Func);
  BasicBlock *OkBB = BasicBlock::Create(Ctx, "ok", Func);

  IRBuilder<> B(EntryBB);
  B.CreateBr(LoopBB);

  B.SetInsertPoint(LoopBB);
  PHINode *I = B.CreatePHI(Int64Ty, 2, "i");
  PHINode *H = B.CreatePHI(Int64Ty, 2, "h");
  I->addIncoming(ConstantInt::get(Int64Ty, 0), EntryBB);
  H->addIncoming(ConstantInt::get(Int64Ty, 0xcbf29ce484222325ULL), EntryBB);
  Value *Cond = B.CreateICmpULT(I, Len);
  B.CreateCondBr(Cond, BodyBB, DoneBB);

  B.SetInsertPoint(BodyBB);
  Value *EltPtr = B.CreateGEP(Int8Ty, Base, I);
  LoadInst *Byte = B.CreateLoad(Int8Ty, EltPtr, /*isVolatile=*/true);
  Value *ByteExt = B.CreateZExt(Byte, Int64Ty);
  Value *HXor = B.CreateXor(H, ByteExt);
  Value *HMul = B.CreateMul(HXor, ConstantInt::get(Int64Ty, 0x100000001b3ULL));
  Value *INext = B.CreateAdd(I, ConstantInt::get(Int64Ty, 1));
  I->addIncoming(INext, BodyBB);
  H->addIncoming(HMul, BodyBB);
  B.CreateBr(LoopBB);

  B.SetInsertPoint(DoneBB);
  Value *Mismatch = B.CreateICmpNE(H, Expected);
  B.CreateCondBr(Mismatch, TamperBB, OkBB);

  B.SetInsertPoint(TamperBB);
  B.CreateCall(KillFn);
  B.CreateUnreachable();

  B.SetInsertPoint(OkBB);
  B.CreateRet(H);

  return Func;
}

bool SelfCheck::runOnModule(Module &M) {
  // 在 VMP 之后、段改名之前扫描字节码；排除可写的数据区。
  struct Blob {
    GlobalVariable *GV;
    uint64_t Len;
    uint64_t Expected;
  };
  std::vector<Blob> Blobs;
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.getName().starts_with("gv_code_seg_"))
      continue;
    if (!GV.isConstant() || !GV.hasInitializer())
      continue;
    if (!GV.hasSection() || GV.getSection() != ".AProtect.data")
      continue;
    auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
    if (!CDA || !CDA->getElementType()->isIntegerTy(8))
      continue;
    StringRef Bytes = CDA->getRawDataValues();
    Blobs.push_back({&GV, static_cast<uint64_t>(Bytes.size()),
                     selfcheckFnv1a64(Bytes)});
  }

  if (Blobs.empty()) {
    if (isIRObfuscationDebugEnabled())
      errs() << "[NDKP] selfcheck: no VMP bytecode blobs found (requires "
                "-irobf-vmp with virtualized functions); no-op\n";
    return false;
  }

  if (isIRObfuscationDebugEnabled())
    errs() << "[NDKP] selfcheck: protecting " << Blobs.size()
           << " VMP bytecode blob(s)\n";

  LLVMContext &Ctx = M.getContext();
  Type *VoidTy = Type::getVoidTy(Ctx);
  Type *Int64Ty = Type::getInt64Ty(Ctx);

  uint64_t ExpectedAcc = 0;
  for (const Blob &Bl : Blobs)
    ExpectedAcc ^= Bl.Expected;

  GlobalVariable *RuntimeAccGV = new GlobalVariable(
      M, Int64Ty, /*isConstant=*/false, GlobalValue::InternalLinkage,
      ConstantInt::get(Int64Ty, 0), "ndkp_selfcheck_runtime_acc");
  RuntimeAccGV->setSection(".AProtect.data");

  Function *KillFn = DetectUtils::createReportAndKillFunc(M, "SelfCheck");
  Function *CheckOne = createCheckOneFunc(M, KillFn);

  FunctionType *CtorFnTy = FunctionType::get(VoidTy, {}, false);
  Function *CtorFn = Function::Create(
      CtorFnTy, GlobalValue::InternalLinkage,
      M.getDataLayout().getProgramAddressSpace(), "ndkp_selfcheck_verify", &M);
  CtorFn->addFnAttr(Attribute::NoInline);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", CtorFn);
  IRBuilder<> B(BB);
  Value *Acc = ConstantInt::get(Int64Ty, 0);
  for (const Blob &Bl : Blobs) {
    Value *H = B.CreateCall(CheckOne, {Bl.GV, ConstantInt::get(Int64Ty, Bl.Len),
                                       ConstantInt::get(Int64Ty, Bl.Expected)});
    Acc = B.CreateXor(Acc, H);
  }
  // volatile 存：阻止 IPO/GVN 把 runtime_acc 证成常量、折掉入口桩里的 XOR。
  B.CreateStore(Acc, RuntimeAccGV)->setVolatile(true);
  B.CreateRetVoid();

  // 注册为 ELF 构造器（.init_array）。优先级 101：在应用 ctor（默认 65535）之前、
  // 加载期即校验；101 避开 0..100 的系统/ABI 保留区。
  appendToGlobalCtors(M, CtorFn, /*Priority=*/101);

  // 只修改入口桩的常量密钥存储，排除 vm_restore_call_frame 恢复的动态值。
  // 未篡改时 expected_acc 与 runtime_acc 抵消。
  if (GlobalVariable *KeyGV =
          M.getGlobalVariable("vmp_shared_vm_function_key", /*AllowInternal=*/true)) {
    Constant *ExpAccC = ConstantInt::get(Int64Ty, ExpectedAcc);
    SmallVector<StoreInst *, 8> Stores;
    for (User *U : KeyGV->users())
      if (auto *SI = dyn_cast<StoreInst>(U))
        if (SI->getPointerOperand() == KeyGV &&
            isa<ConstantInt>(SI->getValueOperand()))
          Stores.push_back(SI);
    for (StoreInst *SI : Stores) {
      IRBuilder<> IB(SI);
      LoadInst *Ld = IB.CreateLoad(Int64Ty, RuntimeAccGV);
      Ld->setVolatile(true);
      Value *Biased = IB.CreateXor(SI->getValueOperand(), ExpAccC);
      SI->setOperand(0, IB.CreateXor(Biased, Ld));
    }
    if (isIRObfuscationDebugEnabled())
      errs() << "[NDKP] selfcheck: folded integrity into " << Stores.size()
             << " VM entry-stub key store(s) (defense-in-depth)\n";
  }

  return true;
}

ModulePass *llvm::createSelfCheckPass() { return new SelfCheck(); }

INITIALIZE_PASS_BEGIN(SelfCheck, "selfcheck",
                      "Inject VMP bytecode self integrity check", false, false)
INITIALIZE_PASS_END(SelfCheck, "selfcheck",
                    "Inject VMP bytecode self integrity check", false, false)
