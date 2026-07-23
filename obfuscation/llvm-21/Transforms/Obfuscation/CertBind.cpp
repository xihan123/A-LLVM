//===- CertBind.cpp - APK 签名证书绑定 Pass --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// 本文件实现 APK 签名证书绑定（-irobf-cert-bind）。
//
// 把"运行期 APK 签名证书 SHA-256 派生的 128-bit 混合值"折入解密密钥，使产物仅在被构建期
// 指定证书（-irobf-cert-file=<cert.der>）签名时才正确运行。折入分两处：
//   ① 字符串（在 StringEncryption.cpp）：编码期 EncLo^=certLo; EncHi^=certHi，解码期
//      PLo^=load(ndkp_cert_lo); PHi^=load(ndkp_cert_hi)。
//   ② VMP 密钥（本 Pass）：把入口桩 `store realkey -> vmp_shared_vm_function_key` 改写为
//      `store (realkey ^ (certLo^certHi)) ^ load(ndkp_cert_k64)`。
//
// 运行期证书混合值由注入的 .init_array 构造器（ndkp_certbind_init，优先级 101）在加载期、
// 原生上下文（非 VMP 帧——参 jni.cpp：证书读取的 by-ref/libc 调用在 VM 解释器桥里会破坏
// 内存，故只在此算一次并缓存）调用外部 helper：
//     void ndkp_certbind_mix(uint64_t* lo, uint64_t* hi);
// helper 由 app 侧编译 runtime/ndkp_apkcert.cpp 链入（apkcert.h 双源共识从 v2/v3 签名块
// 读证书 DER 的 SHA-256，避开可被 CorePatch/LSPatch 等 hook 的 getPackageInfo）。
// 证书不符/缺失/被重定向 ⇒ helper 返回 (0,0) ⇒ 构建期折入无法抵消 ⇒ 乱码密钥：**非分支、
// fail-closed 的密码学门禁**（无可 patch 的 if）。
//
// 【与 SelfCheck 的 VMP 密钥折入叠加】入口桩 store 在 aVMP 建时打了 !ndkp.vmpkey.entry
// 标记；本 Pass 按标记命中并包裹当前值，故与 SelfCheck 顺序无关地叠加。**本 Pass 必须排在
// SelfCheck 之后**（见 ObfuscationPassManager 流水线）：SelfCheck 用 isa<ConstantInt> 命中
// 入口桩常量存，若本 Pass 先跑把值改成非常量，SelfCheck 会静默漏掉其完整性折入。
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/CertBind.h"
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

#define DEBUG_TYPE "certbind"

using namespace llvm;

// 幂等建立运行期基座（缓存全局 + 构造器）。见 CertBind.h 说明。
NdkpCertMixGlobals llvm::getOrCreateNdkpCertMix(Module &M) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *I64 = Type::getInt64Ty(Ctx);
  PointerType *Ptr = PointerType::get(Ctx, 0);

  // 已建则按名返回（StringEncryption 与本 Pass 共用同一份）。
  NdkpCertMixGlobals G;
  G.Lo = M.getGlobalVariable("ndkp_cert_lo", /*AllowInternal=*/true);
  G.Hi = M.getGlobalVariable("ndkp_cert_hi", /*AllowInternal=*/true);
  G.K64 = M.getGlobalVariable("ndkp_cert_k64", /*AllowInternal=*/true);
  if (G.Lo && G.Hi && G.K64)
    return G;

  auto mkGlobal = [&](const char *Name) -> GlobalVariable * {
    // 可写、非常量、零初值，.AProtect.data，noobf：构造器 volatile 写入后，其余 pass
    // 不得把它证成常量（否则折入被折掉）。
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::InternalLinkage,
                                  ConstantInt::get(I64, 0), Name);
    GV->setSection(".AProtect.data");
    GV->setMetadata("noobf", MDNode::get(Ctx, {}));
    return GV;
  };
  G.Lo = mkGlobal("ndkp_cert_lo");
  G.Hi = mkGlobal("ndkp_cert_hi");
  G.K64 = mkGlobal("ndkp_cert_k64");

  // 外部 helper：void ndkp_certbind_mix(i64* lo, i64* hi)（app 侧 runtime/ndkp_apkcert.cpp）。
  FunctionCallee Mix = M.getOrInsertFunction(
      "ndkp_certbind_mix",
      FunctionType::get(Type::getVoidTy(Ctx), {Ptr, Ptr}, false));

  // 构造器：加载期原生上下文调用一次 helper，缓存 lo/hi/k64。volatile 存阻止 IPO/GVN
  // 把这些全局证成常量、折掉下游 pepper/密钥里的 XOR。
  FunctionType *CtorTy = FunctionType::get(Type::getVoidTy(Ctx), {}, false);
  Function *Ctor = Function::Create(
      CtorTy, GlobalValue::InternalLinkage,
      M.getDataLayout().getProgramAddressSpace(), "ndkp_certbind_init", &M);
  Ctor->addFnAttr(Attribute::NoInline);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Ctor);
  IRBuilder<> B(BB);
  Value *LoSlot = B.CreateAlloca(I64, nullptr, "lo");
  Value *HiSlot = B.CreateAlloca(I64, nullptr, "hi");
  B.CreateCall(Mix, {LoSlot, HiSlot});
  Value *Lo = B.CreateLoad(I64, LoSlot);
  Value *Hi = B.CreateLoad(I64, HiSlot);
  B.CreateStore(Lo, G.Lo)->setVolatile(true);
  B.CreateStore(Hi, G.Hi)->setVolatile(true);
  B.CreateStore(B.CreateXor(Lo, Hi), G.K64)->setVolatile(true);
  B.CreateRetVoid();

  // 优先级 101：与 SelfCheck 同批，加载期在应用 ctor（默认 65535）之前算好证书混合值，
  // 避开 0..100 系统/ABI 保留区。
  appendToGlobalCtors(M, Ctor, /*Priority=*/101);
  return G;
}

namespace {

struct CertBind : public ModulePass {
  static char ID;

  CertBind() : ModulePass(ID) {
    initializeCertBindPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return {"CertBind"}; }

  bool runOnModule(Module &M) override;
};

} // namespace

char CertBind::ID = 0;

bool CertBind::runOnModule(Module &M) {
  if (!isCertBindEnabled())
    return false;

  LLVMContext &Ctx = M.getContext();
  IntegerType *I64 = Type::getInt64Ty(Ctx);

  // 收集 VMP 入口桩密钥存：按 !ndkp.vmpkey.entry 标记命中（aVMP 建 store 时打，即便
  // SelfCheck 已就地改写其值仍在），ConstantInt 兜底（未打标记的旧路径 / 纯 CertBind）。
  // 命中条件同时要求指针操作数是 vmp_shared_vm_function_key，从而排除 vm_restore_call_frame
  // 那个"存 load 出的值"的存（其既无标记也非 ConstantInt）。
  GlobalVariable *KeyGV =
      M.getGlobalVariable("vmp_shared_vm_function_key", /*AllowInternal=*/true);
  SmallVector<StoreInst *, 8> Stores;
  if (KeyGV) {
    for (User *U : KeyGV->users())
      if (auto *SI = dyn_cast<StoreInst>(U))
        if (SI->getPointerOperand() == KeyGV &&
            (SI->getMetadata(NdkpVmpKeyEntryMD) ||
             isa<ConstantInt>(SI->getValueOperand())))
          Stores.push_back(SI);
  }

  // 无 VMP 密钥可折、且 StringEncryption 也未建基座（无字符串证书绑定）⇒ 无可绑定目标：
  // 不注入构造器，避免在无目标时强行要求 app 链接 ndkp_certbind_mix。
  bool ProviderExists =
      M.getGlobalVariable("ndkp_cert_lo", /*AllowInternal=*/true) != nullptr;
  if (Stores.empty() && !ProviderExists) {
    if (isIRObfuscationDebugEnabled())
      errs() << "[NDKP] certbind: no VMP entry-stub key store and no string "
                "binding; no-op\n";
    return false;
  }

  // 运行期基座（缓存全局 + 构造器）。与 StringEncryption 幂等共用。
  NdkpCertMixGlobals G = getOrCreateNdkpCertMix(M);

  if (Stores.empty())
    return true; // 仅字符串折入：基座已就绪，无 VMP 密钥需改写。

  // 构建期偏置 certLo^certHi（与构造器里 k64 = lo^hi 对齐）。未篡改证书时二者相等 → 抵消
  // 回 realkey；错证书 → k64 不同 → 存入错 key → 解释器 ChaCha 解出乱码 opcode → 崩溃。
  uint64_t CertBias = getCertBindLo() ^ getCertBindHi();
  Constant *BiasC = ConstantInt::get(I64, CertBias);
  for (StoreInst *SI : Stores) {
    IRBuilder<> IB(SI);
    LoadInst *Ld = IB.CreateLoad(I64, G.K64);
    Ld->setVolatile(true);
    Value *Biased = IB.CreateXor(SI->getValueOperand(), BiasC);
    SI->setOperand(0, IB.CreateXor(Biased, Ld));
  }
  if (isIRObfuscationDebugEnabled())
    errs() << "[NDKP] certbind: folded signing-cert into " << Stores.size()
           << " VM entry-stub key store(s)\n";
  return true;
}

ModulePass *llvm::createCertBindPass() { return new CertBind(); }

INITIALIZE_PASS_BEGIN(CertBind, "certbind",
                      "Bind decryption to APK signing certificate", false, false)
INITIALIZE_PASS_END(CertBind, "certbind",
                    "Bind decryption to APK signing certificate", false, false)
