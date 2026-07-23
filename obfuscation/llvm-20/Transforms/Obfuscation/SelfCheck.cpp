//===- SelfCheck.cpp - VMP 字节码完整性自校验注入 Pass -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// 本文件实现代码完整性自校验（-irobf-selfcheck）。
//
// 只校验 VMP（-irobf-vmp）产出的每函数字节码 blob（gv_code_seg_<fn>）：
//   - 该 blob 是编译期已知的常量字节数组（ChaCha 加密、无指针、无重定位、段
//     .AProtect.data、isConstant=true，见 aVMP.cpp GOVMTranslator::construct_gv）；
//   - 运行期解释器只“读”它、从不写回，故其内存字节恒等于编译期密文；
//   - 因此期望哈希可在本 Pass 内直接算出并内嵌 —— 无需链接后回填工具，也无需重定位
//     归一化（数据段纯常量，文件字节 == 内存字节）。
//
// 注入一个 ELF 构造器（llvm.global_ctors，优先级 101）：加载期对每个 blob 做 FNV-1a64
// （volatile 读 —— blob 是常量，非 volatile 会被优化器对已知常量把校验折成恒真、删掉），
// 与内嵌的期望值比较。
//
// 【响应机制 = 两层】
//   ① 主：不符即调 DetectUtils 的 report/kill（getpid+kill(SIGKILL)+brk）加载期终止进程
//      （分支式响应，可被 patch，但真机验证确实生效）。
//   ② 附（纵深防御，已真机验证生效）：把各 blob 运行期哈希 XOR 累加进可写全局
//      ndkp_selfcheck_runtime_acc，并把 VMP 入口桩里 `store realkey ->
//      vmp_shared_vm_function_key` 改写为 `store (realkey^expected_acc)^load(runtime_acc)`
//      —— 未篡改时 runtime_acc==expected_acc 抵消回 realkey；篡改任一 blob 字节则
//      runtime_acc≠expected_acc → 存入的 key 错 → VMP 解释器 ChaCha 解密出乱码 opcode →
//      崩溃。**这层是真正的密码学绑定、非分支门禁**：即便 ① 的 kill 分支被 patch 掉，篡改
//      仍会经此层破坏执行（真机实测：中和 kill 后，未篡改仍正确、篡改即 rc=137）。绕过需
//      还原原始 blob 字节。前提是 VMP 目标真正经解释器执行——由 VMProtectPreparePass
//      （PipelineStartEP 早期 NoInline+compiler.used 标记）保证其不被 inline/常量折叠掉。
//
// 增量价值（相对 VMP 已有机制）：VMP 每 BB 加密由静态偏移派生密钥、无 BB 体 MAC、单
// 字节翻转不跨 BB 扩散 —— operand-level 字节翻转可静默解成合法但错误的指令并执行、无
// 任何检查触发。本全量 blob 认证（加载期哈希+kill）正好补上该缺口。范围诚实声明：只覆盖
// VMP 字节码数据，不覆盖解释器 .text 或非 VMP 代码。
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

// FNV-1a 64。编译期编码器侧；发射到运行期的 IR（见 createCheckOneFunc）逐字节等价。
// 常量与 StringEncryption.cpp 的 ndkpFnv1a64 一致（basis/prime 为标准 FNV-1a-64 值）。
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
  // 发射 i64 @ndkp_selfcheck_one(ptr base, i64 len, i64 expected)：
  //   H = FNV-1a64(volatile base[0..len))；若 H != expected 则调 KillFn 终止（主响应），
  //   否则返回 H（供 ctor XOR 累加进 runtime_acc 的纵深防御层）。
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

  // 循环头：i（0..len）、h（FNV 累加器）。
  B.SetInsertPoint(LoopBB);
  PHINode *I = B.CreatePHI(Int64Ty, 2, "i");
  PHINode *H = B.CreatePHI(Int64Ty, 2, "h");
  I->addIncoming(ConstantInt::get(Int64Ty, 0), EntryBB);
  H->addIncoming(ConstantInt::get(Int64Ty, 0xcbf29ce484222325ULL), EntryBB);
  Value *Cond = B.CreateICmpULT(I, Len);
  B.CreateCondBr(Cond, BodyBB, DoneBB);

  // 循环体：h = (h ^ zext(volatile load base[i])) * prime。
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

  // 比较：H != expected ⇒ 篡改 ⇒ kill（主响应）。
  B.SetInsertPoint(DoneBB);
  Value *Mismatch = B.CreateICmpNE(H, Expected);
  B.CreateCondBr(Mismatch, TamperBB, OkBB);

  B.SetInsertPoint(TamperBB);
  B.CreateCall(KillFn);
  B.CreateUnreachable();

  // 未篡改：返回哈希（供纵深防御层 XOR 累加）。
  B.SetInsertPoint(OkBB);
  B.CreateRet(H);

  return Func;
}

bool SelfCheck::runOnModule(Module &M) {
  // 收集 VMP 字节码 blob：gv_code_seg_<fn>（常量、.AProtect.data，见 aVMP construct_gv）。
  // 本 Pass 在流水线末尾（VMP 之后、scrubPostLinkFingerprints 段改名之前）运行，故读到的
  // 是最终字节；按全局名前缀识别（改名只动段不动名），isConstant + .AProtect.data 双重
  // 保护以排除可写的 gv_data_seg_<fn>（.AProtect.bss）。
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
    // -irobf-selfcheck 依赖 -irobf-vmp：无被虚拟化的函数即无 blob，本 Pass no-op。
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

  // expected_acc = XOR_i FNV1a64(blob_i)（编译期）。仅供纵深防御层折进密钥常量。
  uint64_t ExpectedAcc = 0;
  for (const Blob &Bl : Blobs)
    ExpectedAcc ^= Bl.Expected;

  // 运行期累加器（纵深防御层）：可写、非常量、零初值。ctor 写入 XOR_i runtime-FNV(blob_i)。
  // 非 gv_code_seg_ 名 + 非常量 => 不被上面的 blob 扫描命中；有 volatile 存/取 => 不被 DCE。
  GlobalVariable *RuntimeAccGV = new GlobalVariable(
      M, Int64Ty, /*isConstant=*/false, GlobalValue::InternalLinkage,
      ConstantInt::get(Int64Ty, 0), "ndkp_selfcheck_runtime_acc");
  RuntimeAccGV->setSection(".AProtect.data");

  // 复用 DetectUtils 的 report/kill（getpid+kill(SIGKILL)+brk），主响应。
  Function *KillFn = DetectUtils::createReportAndKillFunc(M, "SelfCheck");
  Function *CheckOne = createCheckOneFunc(M, KillFn);

  // 构造器入口：逐 blob 调 ndkp_selfcheck_one（不符即 kill；否则返回哈希），并把返回的哈希
  // XOR 累加进 runtime_acc（纵深防御层）。
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

  // 纵深防御层：把每个 VMP 函数入口桩里“store <realkey const> -> vmp_shared_vm_function_key”
  // 改写为 store (realkey ^ expected_acc) ^ load(runtime_acc)。isa<ConstantInt> 精确命中
  // aVMP.cpp 入口桩的常量存（3973 附近），排除 vm_restore_call_frame 的“存 load 出的值”。
  // 未篡改时 runtime_acc==expected_acc 抵消回 realkey；篡改任一 blob 字节则 key 错 →
  // 解释器 ChaCha 解出乱码 opcode → 崩溃。真正的密码学绑定、非分支门禁：即便上面的 kill
  // 被 patch，篡改仍经此层破坏执行（真机：中和 kill 后未篡改正确、篡改 rc=137）。前提是
  // VMP 目标真正经解释器执行——由 VMProtectPreparePass 保证不被 inline/常量折叠。
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
