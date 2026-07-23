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
#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/Base64.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MemoryBuffer.h"
#include <cstdint>
#include <vector>

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

// 字符串加密强化（默认关 ⇒ 与基线逐字节一致）。
// perkey：per-string 密钥由隐藏 pepper（分片存储）+ 串 id 经 ChaCha8 派生，密文表
//         不再内联密钥；消除"密钥与密文相邻可离线还原"的缺陷。
static cl::opt<bool>
EnableStrPerKey("irobf-cse-perkey", cl::init(false), cl::NotHidden,
                cl::desc("Harden -irobf-cse: derive per-string keys from a hidden "
                         "split pepper via ChaCha8 (no key stored inline)."),
                cl::ZeroOrMore);
// bind：把运行期包名（/proc/self/cmdline）哈希折进 pepper；错包名 → 解出乱码
//       （非分支、无可 patch 的 if）。bind 蕴含 perkey。
static cl::opt<bool>
EnableStrBind("irobf-cse-bind", cl::init(false), cl::NotHidden,
              cl::desc("Harden -irobf-cse: bind decryption to the running app's "
                       "package name (non-branch, fail-closed). Implies "
                       "-irobf-cse-perkey; requires -irobf-cse-bind-package."),
              cl::ZeroOrMore);
// bind 的期望包名（构建期）。bind 开但此项空 ⇒ StringEncryption 里 fail-closed 报错。
static cl::opt<std::string>
StrBindPackage("irobf-cse-bind-package", cl::init(""), cl::NotHidden,
               cl::desc("Expected Android package name to bind string decryption "
                        "to (e.g., com.example.app). Used with -irobf-cse-bind."),
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

static cl::opt<bool>
EnableIdaDetect("irobf-idadetect", cl::init(false), cl::NotHidden,
                cl::desc("Enable IR Debugger Detection Injection."),
                cl::ZeroOrMore);

static cl::opt<bool>
EnableTimeDetect("irobf-timedetect", cl::init(false), cl::NotHidden,
                 cl::desc("Enable IR Time-based Debugger Detection Injection."),
                 cl::ZeroOrMore);

static cl::opt<bool>
EnableRootDetect("irobf-rootdetect", cl::init(false), cl::NotHidden,
                 cl::desc("Enable IR Root Detection Injection."),
                 cl::ZeroOrMore);

static cl::opt<bool>
EnableVmProtectDetect("irobf-vmdetect", cl::init(false), cl::NotHidden,
                      cl::desc("Enable IR Emulator/VM Detection Injection."),
                      cl::ZeroOrMore);

static cl::opt<bool>
EnableBanDump("irobf-bandump", cl::init(false), cl::NotHidden,
              cl::desc("Enable IR Anti-Dump Injection."),
              cl::ZeroOrMore);

static cl::opt<bool>
EnableHideMaps("irobf-hidemaps", cl::init(false), cl::NotHidden,
               cl::desc("Enable IR /proc/self/maps Hiding Injection."),
               cl::ZeroOrMore);

static cl::opt<bool>
EnableFakeMaps("irobf-fakemaps", cl::init(false), cl::NotHidden,
               cl::desc("Enable IR Fake /proc maps Injection."),
               cl::ZeroOrMore);

// 代码完整性自校验：对 VMP（-irobf-vmp）产出的每函数字节码 blob（gv_code_seg_<fn>）
// 注入加载期哈希校验，检测到篡改即终止。只在有被虚拟化函数时生效，否则 no-op。
static cl::opt<bool>
EnableSelfCheck("irobf-selfcheck", cl::init(false), cl::NotHidden,
                cl::desc("Enable IR Self Integrity Check Injection "
                         "(verifies VMP bytecode blobs; requires -irobf-vmp)."),
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

// APK 签名证书绑定：把运行期 APK 签名证书 SHA-256 派生的 128-bit 混合值折进 CSE 字符串
// pepper 与 VMP 函数密钥。产物仅在被 -irobf-cert-file 指定证书签名时才正确运行（非分支、
// fail-closed）。运行期证书读取由 app 侧链接 runtime/ndkp_apkcert.cpp 提供。
static cl::opt<bool>
EnableCertBind("irobf-cert-bind", cl::init(false), cl::NotHidden,
               cl::desc("Bind decryption to the APK signing certificate (folds into "
                        "-irobf-cse strings and the VMP function key; non-branch, "
                        "fail-closed). Requires -irobf-cert-file; the app links "
                        "runtime/ndkp_apkcert.cpp."),
               cl::ZeroOrMore);
// 期望签名证书（构建期），DER 编码；其 SHA-256 在构建期折入。bind 开但此项空/不可读 ⇒
// StringEncryption/CertBind 取值时 fail-closed 报错。
static cl::opt<std::string>
CertBindFile("irobf-cert-file", cl::init(""), cl::NotHidden,
             cl::desc("Path to the expected signer certificate in DER form (PEM also "
                      "accepted); its SHA-256 is folded at build time. Used with "
                      "-irobf-cert-bind."),
             cl::ZeroOrMore);

bool llvm::isIRObfuscationDebugEnabled() { return EnableIRObfuscationDebug; }

std::string llvm::getVMFunctionsList() { return VMFunctions; }
bool llvm::isForceNoInlineEnabled() { return ForceNoInline; }
bool llvm::isVMProtectEnabled() { return EnableVMProtect; }

// bind 蕴含 perkey：开启包名绑定即启用 ChaCha8 派生密钥路径。
bool llvm::isCsePerKeyEnabled() { return EnableStrPerKey || EnableStrBind; }
bool llvm::isCseBindEnabled() { return EnableStrBind; }
std::string llvm::getCseBindPackage() { return StrBindPackage; }

// ---- APK 签名证书绑定（-irobf-cert-bind / -irobf-cert-file）构建期证书摘要 ----
// 首次取值时读文件→（PEM 则转 DER）→SHA-256→派生 128-bit 混合值并缓存。混合公式与
// 运行期 runtime/ndkp_apkcert.cpp（及 stringarmor2 jni.cpp initCertMix）逐字节一致：
//   lo = le64(sha[0:8]) ^ le64(sha[16:24]); hi = le64(sha[8:16]) ^ le64(sha[24:32])。
static bool CertMixReady = false;
static uint64_t CertMixLo = 0, CertMixHi = 0;

// 若缓冲是 PEM（含 "-----BEGIN"），抽取首个 BEGIN..END 之间的 base64 主体解码为 DER；
// 否则原样返回。令 -irobf-cert-file 既接受 keytool -exportcert 的 DER，也接受 PEM。
static std::vector<uint8_t> ndkpPemToDerIfNeeded(StringRef Bytes) {
  size_t P = Bytes.find("-----BEGIN");
  if (P == StringRef::npos)
    return std::vector<uint8_t>(Bytes.bytes_begin(), Bytes.bytes_end());
  size_t HdrEnd = Bytes.find('\n', P);
  if (HdrEnd == StringRef::npos)
    report_fatal_error("-irobf-cert-file: malformed PEM (no header newline)");
  size_t End = Bytes.find("-----END", HdrEnd);
  StringRef Body = Bytes.substr(HdrEnd + 1,
                                (End == StringRef::npos ? Bytes.size() : End) -
                                    (HdrEnd + 1));
  std::string B64;
  for (char C : Body)
    if (C != '\n' && C != '\r' && C != ' ' && C != '\t')
      B64.push_back(C);
  std::vector<char> Out;
  if (Error E = decodeBase64(B64, Out)) {
    consumeError(std::move(E));
    report_fatal_error("-irobf-cert-file: PEM base64 decode failed");
  }
  return std::vector<uint8_t>(Out.begin(), Out.end());
}

static void ensureCertMix() {
  if (CertMixReady)
    return;
  CertMixReady = true; // 只算一次（即便下面 report_fatal_error 也不会再进）。
  if (!EnableCertBind)
    return;
  // 先落到 std::string：cl::opt<std::string> 仅经用户定义转换给出 std::string，直接对其调
  // .empty() 或再隐式转 Twine/StringRef 需两次用户转换（不允许）。与本文件 BindPackage 同法。
  const std::string File = CertBindFile;
  if (File.empty())
    report_fatal_error("-irobf-cert-bind requires -irobf-cert-file=<cert.der>");
  ErrorOr<std::unique_ptr<MemoryBuffer>> Buf = MemoryBuffer::getFile(File);
  if (!Buf)
    report_fatal_error(Twine("-irobf-cert-file: cannot read '") + File + "'");
  std::vector<uint8_t> Der = ndkpPemToDerIfNeeded((*Buf)->getBuffer());
  if (Der.empty())
    report_fatal_error("-irobf-cert-file: empty certificate");
  CryptoUtils Crypto;
  unsigned char Sha[32];
  Crypto.sha256(Der.data(), static_cast<unsigned long>(Der.size()), Sha);
  auto le64 = [](const unsigned char *b) -> uint64_t {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
      v |= static_cast<uint64_t>(b[i]) << (8 * i);
    return v;
  };
  CertMixLo = le64(Sha) ^ le64(Sha + 16);
  CertMixHi = le64(Sha + 8) ^ le64(Sha + 24);
}

bool llvm::isCertBindEnabled() { return EnableCertBind; }
uint64_t llvm::getCertBindLo() {
  ensureCertMix();
  return CertMixLo;
}
uint64_t llvm::getCertBindHi() {
  ensureCertMix();
  return CertMixHi;
}

bool llvm::isIRObfuscationEnabled() {
  return EnableIRObfuscation || EnableIndirectBr || EnableIndirectCall ||
         EnableIndirectGV || EnableIRFlattening || EnableIRStringEncryption ||
         EnableStrPerKey || EnableStrBind ||
         EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
         EnableVMProtect || EnableIdaDetect || EnableTimeDetect ||
         EnableRootDetect || EnableVmProtectDetect || EnableBanDump ||
         EnableHideMaps || EnableFakeMaps || EnableSelfCheck || EnableCertBind;
}

// Release-mode（即未开 -irobf-debug）的落地成果物去指纹：在所有混淆 pass 跑完后、
// 对整模块做一次清理。必须在 run(M) 之后：Flattening.cpp:261 与 IndirectCall/VMP 内部
// 逻辑在 pass 流水线执行期间依赖 ".AProtect" 段前缀 / aproc-vmp-artifact 属性做跳过，
// 若在流水线中途改名会破坏这些 skip-gate。此处也覆盖 VMP 关闭、仅 CSE/detection 产出
// .AProtect.* 的情形。
static void scrubPostLinkFingerprints(Module &M) {
  // (1) .AProtect.{text,data,rodata,bss} -> .s0/.s1/.s2/.s3
  //     精确等值匹配（非前缀）保持四类各自独立段：函数(AX) / 可写(WA) / 只读(A) /
  //     零初始化(WA,NOBITS)。ELF 段标志由 MC 按符号种类（getKindForGlobal）推导，与段名
  //     无关，故改名后 flags/type 逐位不变，仅名字字符串改变。切勿改为前缀匹配统一改名，
  //     否则四类挤进同一段会并集出冲突标志。
  static const struct {
    const char *From;
    const char *To;
  } kSectionMap[] = {
      {".AProtect.text", ".s0"},
      {".AProtect.data", ".s1"},
      {".AProtect.rodata", ".s2"},
      {".AProtect.bss", ".s3"},
  };
  auto remap = [&](GlobalObject &GO) {
    if (!GO.hasSection())
      return;
    StringRef S = GO.getSection();
    for (const auto &E : kSectionMap)
      if (S == E.From) {
        GO.setSection(E.To);
        return;
      }
  };
  for (Function &F : M)
    remap(F);
  for (GlobalVariable &GV : M.globals())
    remap(GV);

  // (2) 去掉本模块 clang 生产者横幅（llvm.ident -> .comment）。纵深防御：NDK 的
  //     CRT/libc++/lld 目标仍会贡献 .comment，最终 .so 的彻底清零需 link 后
  //     `llvm-strip -R .comment`（见 README/DESIGN）。
  if (NamedMDNode *Ident = M.getNamedMetadata("llvm.ident"))
    Ident->eraseFromParent();
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
                  EnableStrPerKey || EnableStrBind ||
                  EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
                  EnableVMProtect || EnableIdaDetect || EnableTimeDetect ||
                  EnableRootDetect || EnableVmProtectDetect || EnableBanDump ||
                  EnableHideMaps || EnableFakeMaps || EnableSelfCheck ||
                  EnableCertBind;
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
    if (EnableIRStringEncryption || EnableStrPerKey || EnableStrBind ||
        Options->cseOpt()->isEnabled())
      add(llvm::createStringEncryptionPass(Options.get()));
    if (EnableIndirectGV || Options->indGvOpt()->isEnabled())
      add(llvm::createIndirectGlobalVariablePass(Options.get()));
    if (EnableIndirectCall || Options->iCallOpt()->isEnabled())
      add(llvm::createIndirectCallPass(Options.get()));
    if (EnableIRFlattening || Options->flaOpt()->isEnabled())
      add(llvm::createFlatteningPass(pointerSize, Options.get()));
    if (EnableIndirectBr || Options->indBrOpt()->isEnabled())
      add(llvm::createIndirectBranchPass(Options.get()));

    if (EnableIdaDetect)
      add(llvm::createIdaDetectPass());
    if (EnableTimeDetect)
      add(llvm::createTimeDetectPass());
    if (EnableRootDetect)
      add(llvm::createRootDetectPass());
    if (EnableVmProtectDetect)
      add(llvm::createVmProtectDetectPass());
    if (EnableBanDump)
      add(llvm::createBanDumpPass());
    if (EnableHideMaps)
      add(llvm::createHideMapsPass());
    if (EnableFakeMaps)
      add(llvm::createFakeMapsPass());

    // 自校验最后：读取 VMP 产出的 gv_code_seg_<fn> 最终字节，注入加载期完整性校验。
    // 必须在 VMP 之后（此处检测块 = run(M) 末尾即满足）；仍早于 run(M) 之后的段改名。
    if (EnableSelfCheck)
      add(llvm::createSelfCheckPass());

    // 证书绑定的 VMP 密钥折入必须排在 SelfCheck 之后：SelfCheck 用 isa<ConstantInt>
    // 命中入口桩密钥常量存，若 CertBind 先跑把值改成非常量会令 SelfCheck 静默漏掉。
    // CertBind 按 !ndkp.vmpkey.entry 标记命中、包裹当前值，故与 SelfCheck 顺序无关地叠加。
    if (EnableCertBind)
      add(llvm::createCertBindPass());

    bool Changed = run(M);
    // Release 模式（默认，未开 -irobf-debug）：所有 pass 跑完后统一去指纹。
    if (!isIRObfuscationDebugEnabled())
      scrubPostLinkFingerprints(M);
    return Changed;
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
