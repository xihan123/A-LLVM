//===- StringEncryption.cpp - 字符串加密Pass----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现字符串加密Pass，通过加密字符串常量来增加逆向分析的难度
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/Transforms/Obfuscation/CertBind.h"
#include "llvm/Transforms/Obfuscation/cse_crypto.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <vector>

#define DEBUG_TYPE "string-encryption"

using namespace llvm;

//===----------------------------------------------------------------------===//
// 字符串加密强化（-irobf-cse-perkey / -irobf-cse-bind）编译期原语。
//
// 这些函数是"编码器"侧：pass 在编译期用它们产出密文。解码器侧是发射到运行期的
// 等价 IR（见 buildChaChaDecodeFunc / buildPkgKeyFunc）。两侧算法必须逐字节一致，
// 否则运行期解出乱码——tests/string-enc/roundtrip.sh 是这一镜像的兜底。
//===----------------------------------------------------------------------===//
namespace {

static inline uint64_t ndkpRotl64(uint64_t v, unsigned n) {
	return (v << n) | (v >> (64 - n));
}
static inline uint32_t ndkpRotl32(uint32_t v, unsigned n) {
	return (v << n) | (v >> (32 - n));
}

// SplitMix64 单步：推进状态 z 并输出一个混合后的 64-bit 字。
static inline uint64_t ndkpSplitMixStep(uint64_t &z) {
	z += 0x9E3779B97F4A7C15ULL;
	uint64_t t = z;
	t = (t ^ (t >> 30)) * 0xBF58476D1CE4E5B9ULL;
	t = (t ^ (t >> 27)) * 0x94D049BB133111EBULL;
	return t ^ (t >> 31);
}

// 由 128-bit pepper (pLo, pHi) 经 SplitMix64 派生 256-bit ChaCha key（8×u32，LE）。
// pLo 供前 128 bit、pHi 供后 128 bit，两者各影响一半密钥。
static void ndkpChaChaKeygen(uint64_t pLo, uint64_t pHi, uint32_t key32[8]) {
	uint64_t k64[4];
	uint64_t zA = pLo;
	k64[0] = ndkpSplitMixStep(zA);
	k64[1] = ndkpSplitMixStep(zA);
	uint64_t zB = pHi;
	k64[2] = ndkpSplitMixStep(zB);
	k64[3] = ndkpSplitMixStep(zB);
	for (int i = 0; i < 4; ++i) {
		key32[2 * i] = static_cast<uint32_t>(k64[i]);
		key32[2 * i + 1] = static_cast<uint32_t>(k64[i] >> 32);
	}
}

// 标准 ChaCha 单块（这里 8 轮 = 4 双轮）。nonce = (nonce0, 0, 0)，counter = 块序号。
static void ndkpChaCha8Block(const uint32_t key[8], uint32_t counter,
                             uint32_t nonce0, uint8_t out[64]) {
	uint32_t st[16];
	st[0] = 0x61707865u;
	st[1] = 0x3320646eu;
	st[2] = 0x79622d32u;
	st[3] = 0x6b206574u;
	for (int i = 0; i < 8; ++i)
		st[4 + i] = key[i];
	st[12] = counter;
	st[13] = nonce0;
	st[14] = 0;
	st[15] = 0;

	uint32_t x[16];
	std::memcpy(x, st, sizeof(x));
	auto QR = [&](int a, int b, int c, int d) {
		x[a] += x[b]; x[d] ^= x[a]; x[d] = ndkpRotl32(x[d], 16);
		x[c] += x[d]; x[b] ^= x[c]; x[b] = ndkpRotl32(x[b], 12);
		x[a] += x[b]; x[d] ^= x[a]; x[d] = ndkpRotl32(x[d], 8);
		x[c] += x[d]; x[b] ^= x[c]; x[b] = ndkpRotl32(x[b], 7);
	};
	for (int r = 0; r < 4; ++r) {
		QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
		QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
	}
	for (int i = 0; i < 16; ++i) {
		uint32_t w = x[i] + st[i];
		out[4 * i + 0] = static_cast<uint8_t>(w);
		out[4 * i + 1] = static_cast<uint8_t>(w >> 8);
		out[4 * i + 2] = static_cast<uint8_t>(w >> 16);
		out[4 * i + 3] = static_cast<uint8_t>(w >> 24);
	}
}

// 由 pepper + 串 id 生成 len 字节 keystream。
static void ndkpChaCha8Keystream(uint64_t pLo, uint64_t pHi, uint32_t id,
                                 size_t len, std::vector<uint8_t> &ks) {
	uint32_t key[8];
	ndkpChaChaKeygen(pLo, pHi, key);
	ks.resize(len);
	uint8_t block[64];
	uint32_t ctr = 0;
	for (size_t off = 0; off < len; off += 64, ++ctr) {
		ndkpChaCha8Block(key, ctr, id, block);
		size_t n = std::min<size_t>(64, len - off);
		std::memcpy(ks.data() + off, block, n);
	}
}

// FNV-1a 64。用于把包名折进 pepper（编码器对 -irobf-cse-bind-package 字符串算，
// 解码器对 /proc/self/cmdline 首个 NUL 或 ':' 前的字节算，二者一致即匹配。
// 截到 ':' 是为兼容多进程：私有子进程 cmdline="包名:suffix"，去 suffix 得回包名）。
static uint64_t ndkpFnv1a64(const char *p, size_t n) {
	uint64_t h = 0xcbf29ce484222325ULL;
	for (size_t i = 0; i < n; ++i) {
		h ^= static_cast<uint8_t>(p[i]);
		h *= 0x100000001b3ULL;
	}
	return h;
}

static uint32_t hardenedCapacity(size_t Bytes) {
  if (Bytes > ndkp_cse::MaxCapacity - 16)
    report_fatal_error("hardened CSE constant exceeds 16 MiB capacity");
  uint32_t Capacity = 32;
  while (Capacity < Bytes + 16) Capacity *= 2;
  return Capacity;
}

// 0 = uninitialized, 1 = initializing, 2 = published. Only the winning
// thread writes the buffer; acquire/release also publishes non-atomic bytes.
static BasicBlock *emitOnceGuard(IRBuilder<> &B, GlobalVariable *State,
                                 BasicBlock *Body, BasicBlock *Done) {
  Function *F = Body->getParent();
  LLVMContext &Ctx = F->getContext();
  BasicBlock *Claim = BasicBlock::Create(Ctx, "once.claim", F);
  BasicBlock *Wait = BasicBlock::Create(Ctx, "once.wait", F);
  State->setAlignment(Align(4));
  auto *Ready = B.CreateLoad(B.getInt32Ty(), State);
  Ready->setAtomic(AtomicOrdering::Acquire);
  B.CreateCondBr(B.CreateICmpEQ(Ready, B.getInt32(2)), Done, Claim);
  B.SetInsertPoint(Claim);
  auto *Lock = B.CreateAtomicCmpXchg(State, B.getInt32(0), B.getInt32(1),
                                    MaybeAlign(4), AtomicOrdering::Acquire,
                                    AtomicOrdering::Monotonic);
  B.CreateCondBr(B.CreateExtractValue(Lock, 1), Body, Wait);
  B.SetInsertPoint(Wait);
  auto *Published = B.CreateLoad(B.getInt32Ty(), State);
  Published->setAtomic(AtomicOrdering::Acquire);
  B.CreateCondBr(B.CreateICmpEQ(Published, B.getInt32(2)), Done, Wait);
  return Claim;
}

static void emitOncePublish(IRBuilder<> &B, GlobalVariable *State) {
  auto *Store = B.CreateStore(B.getInt32(2), State);
  Store->setAtomic(AtomicOrdering::Release);
}

} // namespace

namespace {
	struct StringEncryption : public ModulePass {
		static char ID;

		// 一个字符串及其密文、解密缓冲区和初始化状态。
		struct CSPEntry {
			CSPEntry() : ID(0), Offset(0), DecGV(nullptr), DecStatus(nullptr), IsUTF16(false), DecFunc(nullptr) {}
			unsigned ID;
			unsigned Offset;
			GlobalVariable *DecGV;
			GlobalVariable *DecStatus;
			std::vector<uint8_t> Data;
			std::vector<uint8_t> EncKey;
			bool IsUTF16;
			std::vector<uint16_t> Data16;
			std::vector<uint16_t> EncKey16;
			Function *DecFunc;
		};

		// 引用字符串的聚合全局量，需要在解密后初始化。
		struct CSUser {
			CSUser(Type* ETy, GlobalVariable *User, GlobalVariable *NewGV)
				: Ty(ETy), GV(User), DecGV(NewGV), DecStatus(nullptr),
				  InitFunc(nullptr) {}
			Type *Ty;
			GlobalVariable *GV;
			GlobalVariable *DecGV;
			GlobalVariable *DecStatus;
			Function *InitFunc;
		};

		ObfuscationOptions *ArgsOptions;
		CryptoUtils RandomEngine;
		std::vector<CSPEntry *> ConstantStringPool;
		std::map<GlobalVariable *, CSPEntry *> CSPEntryMap;  ///< 全局变量到条目的映射
		std::map<GlobalVariable *, CSUser *> CSUserMap;  ///< 全局变量到用户的映射
		std::map<GlobalVariable *, CSPEntry *> DecryptedCSPEntryMap;  ///< 解密缓冲区到条目的反向映射
		std::map<GlobalVariable *, CSUser *> DecryptedCSUserMap;  ///< 解密用户缓冲区到用户的反向映射
		std::map<const CSUser *, SmallVector<CSPEntry *, 8>> UserReferencedEntries;  ///< 每个全局用户依赖的底层字符串
		std::map<GlobalVariable *, SmallVector<CSPEntry *, 8>> GlobalReferencedEntries;  ///< 任意全局变量依赖的底层字符串
		GlobalVariable *EncryptedStringTable = nullptr;
		std::set<GlobalVariable *> MaybeDeadGlobalVars;

		// ---- 字符串加密强化（-irobf-cse-perkey / -irobf-cse-bind）----
		bool UseHardened = false;
		GlobalVariable *HardenedBlob = nullptr;
		GlobalVariable *HardenedCache = nullptr;
		uint32_t HardenedSize = 0;
		void buildHardenedTable(Module &M);
		Function *buildHardenedDecrypt(Module &M, const CSPEntry *Entry);
		bool UsePerKey = false;   ///< ChaCha8 派生密钥（不内联存储密钥）
		bool UseBind = false;     ///< 把运行期包名哈希折进 pepper（蕴含 UsePerKey）
		std::string BindPackage;  ///< 期望包名（构建期，-irobf-cse-bind-package）
		uint64_t PepperLo = 0;    ///< 128-bit 隐藏 pepper 低 64 位（原始，未折包名）
		uint64_t PepperHi = 0;    ///< 128-bit 隐藏 pepper 高 64 位（原始，未折包名）
		GlobalVariable *PepperShare[4] = {nullptr, nullptr, nullptr, nullptr}; ///< pepper 分片
		Function *PkgKeyFunc = nullptr;      ///< ndkp_cse_get_pkgkey（bind 时）
		Function *SharedDecodeFunc = nullptr;///< ndkp_cse_decode（共享 ChaCha8 解码核心）

		// ---- APK 签名证书绑定（-irobf-cert-bind）----
		bool UseCertBind = false;            ///< 把运行期证书混合值折进 pepper（蕴含 UsePerKey）
		uint64_t CertLo = 0, CertHi = 0;     ///< 构建期证书混合值（-irobf-cert-file 的 DER 摘要派生）
		GlobalVariable *CertLoGV = nullptr;  ///< 运行期缓存 ndkp_cert_lo（构造器 ndkp_certbind_init 填）
		GlobalVariable *CertHiGV = nullptr;  ///< 运行期缓存 ndkp_cert_hi

		StringEncryption(ObfuscationOptions *argsOptions) : ModulePass(ID) {
			this->ArgsOptions = argsOptions;
			initializeStringEncryptionPass(*PassRegistry::getPassRegistry());
		}

		bool doFinalization(Module &) override {
			for (CSPEntry *Entry : ConstantStringPool) {
				delete (Entry);
			}
			for (auto &I : CSUserMap) {
				CSUser *User = I.second;
				delete (User);
			}
			ConstantStringPool.clear();
			CSPEntryMap.clear();
			CSUserMap.clear();
			DecryptedCSPEntryMap.clear();
			DecryptedCSUserMap.clear();
			UserReferencedEntries.clear();
			GlobalReferencedEntries.clear();
			MaybeDeadGlobalVars.clear();
			return false;
		}

		StringRef getPassName() const override {
			return {"StringEncryption"};
		}

		bool runOnModule(Module &M) override;

		static void collectConstantStringUser(GlobalVariable *CString, std::set<GlobalVariable *> &Users);

		static bool isValidToEncrypt(GlobalVariable *GV);
		static GlobalVariable *extractReferencedGlobal(Value *V);
		CSPEntry *resolveCSPEntryGlobal(GlobalVariable *GV);
		CSUser *resolveCSUserGlobal(GlobalVariable *GV);

		CSPEntry *getPointedCSPEntry(GlobalVariable *GV);

		CSUser *getPointedCSUser(GlobalVariable *GV);

		bool processConstantStringUse(Function *F);

		void deleteUnusedGlobalVariable();

		static Function *buildDecryptFunction(Module *M, const CSPEntry *Entry);

		// ---- 字符串加密强化：emitters ----
		/// 扫描模块级 llvm.global.annotations，是否存在 ndkp.str_bind（NDKP_STR_BIND）。
		static bool moduleHasStrBindAnnotation(Module &M);
		/// 生成 4 个 pepper 分片全局（.AProtect.rodata），运行期重组回 PepperLo/PepperHi。
		void createPepperGlobals(Module &M);
		/// 发射一次性 ndkp_cse_get_pkgkey()：读 /proc/self/cmdline，FNV-1a64，带缓存。
		Function *buildPkgKeyFunc(Module &M);
		/// 发射一次性 ndkp_cse_decode(out, cipher, lenBytes, id)：ChaCha8 keystream XOR。
		Function *buildChaChaDecodeFunc(Module &M);
		/// PerKey/Bind 模式下每串的薄封装解密函数（幂等守卫 + 调用 ndkp_cse_decode）。
		Function *buildDecryptFunctionChaCha(Module *M, const CSPEntry *Entry);

		Function *buildInitFunction(Module *M, const CSUser *User);

		template <typename T>
		void getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize, uint32_t MaxSize);

		void lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB, Value *Ptr, Type *Ty);

		void lowerGlobalConstantStruct(ConstantStruct *CS, IRBuilder<> &IRB, Value *Ptr, Type *Ty);

		void lowerGlobalConstantArray(ConstantArray *CA, IRBuilder<> &IRB, Value *Ptr, Type *Ty);
		void collectReferencedEntries(Constant *CV, SmallPtrSetImpl<Constant *> &Visited,
		                             SmallPtrSetImpl<CSPEntry *> &Entries);
	};
} // namespace

char StringEncryption::ID = 0;

bool StringEncryption::runOnModule(Module &M) {
	if (isIRObfuscationDebugEnabled()) {
		errs() << "[DEBUG] StringEncryption: Starting runOnModule\n";
	}
	std::set<GlobalVariable *> ConstantStringUsers;

	LLVMContext &Ctx = M.getContext();
	ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);

	// 字符串加密强化模式判定（默认全关 ⇒ 与基线逐字节一致的旧路径）。
	// bind 蕴含 perkey；bind 亦可由模块级 NDKP_STR_BIND 注解开启。
	UseHardened = isCseHardenedEnabled();
	UseBind = isCseBindEnabled() || moduleHasStrBindAnnotation(M);
	UsePerKey = isCsePerKeyEnabled() || UseBind;
	if (UseBind) {
		BindPackage = getCseBindPackage();
		// 与运行期解码对齐：包名截到首个 ':' 前，令误配 -irobf-cse-bind-package=pkg:proc
		// 自愈（纯冒号/前导冒号 → 空 → 触发下方 fail-closed 构建报错）。
		if (std::string::size_type Pos = BindPackage.find(':');
		    Pos != std::string::npos)
			BindPackage.erase(Pos);
		if (BindPackage.empty()) {
			report_fatal_error(
			    "-irobf-cse-bind requires -irobf-cse-bind-package=<package>");
		}
	}

	// APK 签名证书绑定：把运行期证书混合值折进 pepper（与包名绑定独立、可叠加）。
	// cert-bind 亦蕴含 perkey —— 需 ChaCha/pepper 路径才有可折入的密钥；故开启 cert-bind
	// 即便未显式开 -irobf-cse-perkey/-bind，字符串也走强化路径。构建期证书摘要由
	// getCertBindLo/Hi 提供（内部读 -irobf-cert-file 的 DER 并 SHA-256；缺失即 fail-closed
	// 构建报错）。运行期缓存全局 CertLoGV/CertHiGV 在下方 UsePerKey 基座里建立。
	UseCertBind = isCertBindEnabled();
	if (UseCertBind) {
		CertLo = getCertBindLo();
		CertHi = getCertBindHi();
		UsePerKey = true;
	}

	for (GlobalVariable &GV : M.globals()) {
		// 跳过没有初始化器的全局变量
		if (!GV.hasInitializer() ||
		    GV.hasDLLExportStorageClass() || GV.isDLLImportDependent()) {
			continue;
		}
		// VMP 产物不得入字符串池：gv_code_seg_* 等字节码 blob 是 SelfCheck 的校验
		// 对象（.AProtect.data 常量），入池会被加密搬进密文表并删除原常量，SelfCheck
		// 随后扫不到 blob 而静默 no-op。名单与 isValidToEncrypt 的排除保持一致。
		StringRef GVName = GV.getName();
		if (GVName.contains("gv_code_seg") || GVName.contains("gv_data_seg") ||
		    GVName.contains("vm_code_seg") || GVName.contains("vm_data_seg") ||
		    GVName.contains("scase_code_seg") || GVName.contains("scase_data_seg")) {
			continue;
		}
		Constant *Init = GV.getInitializer();
		if (Init == nullptr)
			continue;

		if (isIRObfuscationDebugEnabled()) {
			errs() << "[DEBUG] CSE: Checking global: " << GV.getName()
			       << " isConstant=" << GV.isConstant()
			       << " type=" << *GV.getType()
			       << " initType=" << *Init->getType() << "\n";

			// 打印初始化器的具体类型
			errs() << "[DEBUG] CSE:   Init->getValueID() = " << Init->getValueID() << "\n";
			errs() << "[DEBUG] CSE:   Init->getName() = " << Init->getName() << "\n";

			// 检查是否是 dso_local_equivalent
			if (auto *DSO = dyn_cast<DSOLocalEquivalent>(Init)) {
				errs() << "[DEBUG] CSE:   Init is DSOLocalEquivalent\n";
			}

			// 检查是否是 GlobalObject
			if (isa<GlobalObject>(Init)) {
				errs() << "[DEBUG] CSE:   Init is GlobalObject\n";
			}

			// 检查是否是 GlobalValue
			if (isa<GlobalValue>(Init)) {
				errs() << "[DEBUG] CSE:   Init is GlobalValue\n";
			}

			if (GlobalVariable *InnerGV = dyn_cast<GlobalVariable>(Init)) {
				errs() << "[DEBUG] CSE:   Inner GlobalVariable name: " << InnerGV->getName() << "\n";
			}
		}

		// 处理字符串常量（数组类型）
		if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
			if (CDS->isString()) {
				CSPEntry *Entry = new CSPEntry();
				Entry->IsUTF16 = false;
				StringRef Data = CDS->getRawDataValues();
				Entry->Data.reserve(Data.size());
				for (unsigned i = 0; i < Data.size(); ++i) {
					Entry->Data.push_back(static_cast<uint8_t>(Data[i]));
				}
				Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
				Type *BufferTy = CDS->getType();
				if (UseHardened)
					BufferTy = ArrayType::get(CDS->getElementType(),
					    hardenedCapacity(Entry->Data.size()) - 16);
				Constant *ZeroInit = Constant::getNullValue(BufferTy);
				GlobalVariable *DecGV = new GlobalVariable(M, BufferTy, false, GlobalValue::PrivateLinkage,
				    ZeroInit, "dec" + Twine::utohexstr(Entry->ID) + GV.getName());
				GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
				    Zero, "dec_status_" + Twine::utohexstr(Entry->ID) + GV.getName());
				DecGV->setSection(".AProtect.data");
				DecStatus->setSection(".AProtect.data");
				DecGV->setAlignment(MaybeAlign(GV.getAlignment()));
				DecGV->setMetadata("noobf", MDNode::get(Ctx, {}));
				DecStatus->setMetadata("noobf", MDNode::get(Ctx, {}));
				Entry->DecGV = DecGV;
				Entry->DecStatus = DecStatus;
				ConstantStringPool.push_back(Entry);
				CSPEntryMap[&GV] = Entry;
				DecryptedCSPEntryMap[DecGV] = Entry;
				collectConstantStringUser(&GV, ConstantStringUsers);
			} else {
				Type *EltTy = CDS->getElementType();
				if (EltTy->isIntegerTy(16)) {
					CSPEntry *Entry = new CSPEntry();
					Entry->IsUTF16 = true;
					unsigned NumElems = CDS->getNumElements();
					Entry->Data16.reserve(NumElems);
					for (unsigned i = 0; i < NumElems; ++i) {
						uint64_t v = CDS->getElementAsInteger(i);
						Entry->Data16.push_back(static_cast<uint16_t>(v));
					}
					Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
					Type *BufferTy = CDS->getType();
					if (UseHardened)
						BufferTy = ArrayType::get(EltTy,
						    (hardenedCapacity(Entry->Data16.size() * 2) - 16) / 2);
					Constant *ZeroInit = Constant::getNullValue(BufferTy);
					GlobalVariable *DecGV = new GlobalVariable(M, BufferTy, false, GlobalValue::PrivateLinkage,
					    ZeroInit, "dec" + Twine::utohexstr(Entry->ID) + GV.getName());
					GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
					    Zero, "dec_status_" + Twine::utohexstr(Entry->ID) + GV.getName());
					DecGV->setSection(".AProtect.data");
					DecStatus->setSection(".AProtect.data");
					DecGV->setAlignment(MaybeAlign(GV.getAlignment()));
					DecGV->setMetadata("noobf", MDNode::get(Ctx, {}));
					DecStatus->setMetadata("noobf", MDNode::get(Ctx, {}));
					Entry->DecGV = DecGV;
					Entry->DecStatus = DecStatus;
					ConstantStringPool.push_back(Entry);
					CSPEntryMap[&GV] = Entry;
					DecryptedCSPEntryMap[DecGV] = Entry;
					collectConstantStringUser(&GV, ConstantStringUsers);
				}
			}
		}
	}

	if (UseHardened && ConstantStringPool.empty())
		return false;

	// 强化模式下：先建 pepper 分片 + 一次性共享解码核心（bind 时含包名 key）。
	if (UseHardened && !ConstantStringPool.empty())
		buildHardenedTable(M);
	if (UsePerKey && !UseHardened) {
		PepperLo = RandomEngine.get_uint64_t();
		PepperHi = RandomEngine.get_uint64_t();
		createPepperGlobals(M);
		if (UseBind) {
			PkgKeyFunc = buildPkgKeyFunc(M);
		}
		if (UseCertBind) {
			// 建立/复用证书绑定运行期基座（缓存全局 + .init_array 构造器）。解码期读
			// CertLoGV/CertHiGV 折入 pepper；构造器加载期调 ndkp_certbind_mix 填之。
			NdkpCertMixGlobals G = getOrCreateNdkpCertMix(M);
			CertLoGV = G.Lo;
			CertHiGV = G.Hi;
		}
		SharedDecodeFunc = buildChaChaDecodeFunc(M);
	}

	// 编码期折入期望包名（bind）：pepper' = pepper ^ pkgKey（解码期用运行期包名重现）。
	uint64_t EncLo = PepperLo, EncHi = PepperHi;
	if (UseBind) {
		uint64_t PkgKey = ndkpFnv1a64(BindPackage.data(), BindPackage.size());
		EncLo ^= PkgKey;
		EncHi ^= ndkpRotl64(PkgKey, 32);
	}
	if (UseCertBind) {
		// 折入构建期证书混合值（le64 派生，见 runtime/ndkp_apkcert.cpp / jni.cpp）。解码期
		// 用运行期证书重现同一混合值抵消；错/缺证书 ⇒ 运行期 (0,0) ⇒ 不抵消 ⇒ 乱码。
		// 与包名折入独立、可叠加。
		EncLo ^= CertLo;
		EncHi ^= CertHi;
	}

	for (CSPEntry *Entry : ConstantStringPool) {
		if (UseHardened) {
			Entry->DecFunc = buildHardenedDecrypt(M, Entry);
			continue;
		}
		if (!UsePerKey) {
			// 基线：位置相关字节链式密码 + 内联密钥（不改动已验证路径）。
			if (!Entry->IsUTF16) {
				getRandomBytes(Entry->EncKey, 16, 32);
				uint8_t LastPlainChar = 0;
				for (unsigned i = 0; i < Entry->Data.size(); ++i) {
					const uint32_t KeyIndex = i % Entry->EncKey.size();
					const uint8_t CurrentKey = Entry->EncKey[KeyIndex];
					const uint8_t CurrentPlainChar = Entry->Data[i];
					uint8_t val = CurrentPlainChar;
					val ^= CurrentKey;
					if ((KeyIndex * CurrentKey) % 2 == 0) {
						val = ~val;
						val ^= CurrentKey;
						val = val - LastPlainChar;
					} else {
						val = -val;
						val ^= CurrentKey;
						val = val + LastPlainChar;
					}
					Entry->Data[i] = val;
					LastPlainChar = CurrentPlainChar;
				}
			} else {
				getRandomBytes(Entry->EncKey16, 8, 16);
				uint16_t LastPlainChar = 0;
				for (unsigned i = 0; i < Entry->Data16.size(); ++i) {
					const uint32_t KeyIndex = i % Entry->EncKey16.size();
					const uint16_t CurrentKey = Entry->EncKey16[KeyIndex];
					const uint16_t CurrentPlainChar = Entry->Data16[i];
					uint16_t val = CurrentPlainChar;
					val ^= CurrentKey;
					if (((KeyIndex * CurrentKey) % 2) == 0) {
						val = ~val;
						val ^= CurrentKey;
						val = static_cast<uint16_t>(val - LastPlainChar);
					} else {
						val = static_cast<uint16_t>(-static_cast<int16_t>(val));
						val ^= CurrentKey;
						val = static_cast<uint16_t>(val + LastPlainChar);
					}
					Entry->Data16[i] = val;
					LastPlainChar = CurrentPlainChar;
				}
			}
			Entry->DecFunc = buildDecryptFunction(&M, Entry);
		} else {
			// 强化：ChaCha8 keystream XOR，nonce=(id,0,0)，密钥由 pepper 派生（不存密钥）。
			if (!Entry->IsUTF16) {
				std::vector<uint8_t> Ks;
				ndkpChaCha8Keystream(EncLo, EncHi, Entry->ID, Entry->Data.size(), Ks);
				for (size_t i = 0; i < Entry->Data.size(); ++i) {
					Entry->Data[i] ^= Ks[i];
				}
			} else {
				std::vector<uint8_t> Ks;
				ndkpChaCha8Keystream(EncLo, EncHi, Entry->ID,
				                     Entry->Data16.size() * 2, Ks);
				for (size_t i = 0; i < Entry->Data16.size(); ++i) {
					uint16_t k =
					    static_cast<uint16_t>(Ks[2 * i] | (Ks[2 * i + 1] << 8));
					Entry->Data16[i] ^= k;
				}
			}
			Entry->DecFunc = buildDecryptFunctionChaCha(&M, Entry);
		}
	}

	for (GlobalVariable *GV : ConstantStringUsers) {
		if (isValidToEncrypt(GV)) {
			Type *EltType = GV->getValueType();
			Constant *ZeroInit = Constant::getNullValue(EltType);
			GlobalVariable *DecGV = new GlobalVariable(M, EltType, false, GlobalValue::PrivateLinkage,
			    ZeroInit, "dec_" + GV->getName());
			DecGV->setSection(".AProtect.data");
			DecGV->setAlignment(MaybeAlign(GV->getAlignment()));
			DecGV->setMetadata("noobf", MDNode::get(Ctx, {}));
			GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
			    Zero, "dec_status_" + GV->getName());
			DecStatus->setSection(".AProtect.data");
			DecStatus->setMetadata("noobf", MDNode::get(Ctx, {}));
			CSUser *User = new CSUser(EltType, GV, DecGV);
			User->DecStatus = DecStatus;
			User->InitFunc = buildInitFunction(&M, User);
			CSUserMap[GV] = User;
			DecryptedCSUserMap[DecGV] = User;
		}
	}

	for (auto &KV : CSUserMap) {
		CSUser *User = KV.second;
		if (!User || !User->GV || !User->GV->hasInitializer()) {
			continue;
		}
		SmallPtrSet<Constant *, 16> Visited;
		SmallPtrSet<CSPEntry *, 16> Entries;
		collectReferencedEntries(User->GV->getInitializer(), Visited, Entries);
		auto &Collected = UserReferencedEntries[User];
		for (CSPEntry *Entry : Entries) {
			Collected.push_back(Entry);
		}
	}

	for (GlobalVariable &GV : M.globals()) {
		if (!GV.hasInitializer()) {
			continue;
		}
		SmallPtrSet<Constant *, 16> Visited;
		SmallPtrSet<CSPEntry *, 16> Entries;
		collectReferencedEntries(GV.getInitializer(), Visited, Entries);
		if (Entries.empty()) {
			continue;
		}
		auto &Collected = GlobalReferencedEntries[&GV];
		for (CSPEntry *Entry : Entries) {
			Collected.push_back(Entry);
		}
	}

	if (UseHardened) {
		EncryptedStringTable = HardenedBlob;
	} else {
	std::vector<uint8_t> Data;
	std::vector<uint8_t> JunkBytes;

	JunkBytes.reserve(32);
	for (CSPEntry *Entry : ConstantStringPool) {
		JunkBytes.clear();
		getRandomBytes(JunkBytes, 16, 32);
		Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());

		if (Entry->IsUTF16 && (Data.size() % 2) != 0) {
			Data.push_back(0);
		}

		Entry->Offset = static_cast<unsigned>(Data.size());
		if (!Entry->IsUTF16) {
			// PerKey/Bind：不内联密钥，Offset 直接指向密文；基线保留 [key][cipher]。
			if (!UsePerKey) {
				Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
			}
			Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
		} else {
			if (!UsePerKey) {
				for (uint16_t w : Entry->EncKey16) {
					Data.push_back(static_cast<uint8_t>(w & 0xff));
					Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
				}
			}
			for (uint16_t w : Entry->Data16) {
				Data.push_back(static_cast<uint8_t>(w & 0xff));
				Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
			}
		}
	}

	Constant *CDA = ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
	EncryptedStringTable = new GlobalVariable(M, CDA->getType(), false, GlobalValue::PrivateLinkage,
	    CDA, "EncryptedStringTable");
	EncryptedStringTable->setSection(".AProtect.rodata");
	EncryptedStringTable->setMetadata("noobf", MDNode::get(Ctx, {}));

	}

	auto remapConstantRef = [&](auto &&Self, Constant *C) -> Constant * {
		if (!C) {
			return nullptr;
		}

		if (auto *StrGV = dyn_cast<GlobalVariable>(C)) {
			if (CSPEntry *Entry = resolveCSPEntryGlobal(StrGV)) {
				if (StrGV != Entry->DecGV) {
					MaybeDeadGlobalVars.insert(StrGV);
				}
				return Entry->DecGV;
			}
			if (CSUser *User = resolveCSUserGlobal(StrGV)) {
				if (StrGV != User->DecGV) {
					MaybeDeadGlobalVars.insert(StrGV);
				}
				return User->DecGV;
			}
			return C;
		}

		if (auto *CE = dyn_cast<ConstantExpr>(C)) {
			Constant *Base = cast<Constant>(CE->getOperand(0));
			Constant *NewBase = Self(Self, Base);
			if (NewBase == Base) {
				return C;
			}
			switch (CE->getOpcode()) {
			case Instruction::GetElementPtr: {
				SmallVector<Constant *, 4> Indices;
				for (unsigned i = 1; i < CE->getNumOperands(); ++i) {
					Indices.push_back(cast<Constant>(CE->getOperand(i)));
				}
				return ConstantExpr::getGetElementPtr(cast<GlobalVariable>(NewBase)->getValueType(),
				                                      NewBase, Indices);
			}
			case Instruction::BitCast:
				return ConstantExpr::getBitCast(NewBase, CE->getType());
			case Instruction::AddrSpaceCast:
				return ConstantExpr::getAddrSpaceCast(NewBase, CE->getType());
			default:
				return C;
			}
		}

		if (auto *CA = dyn_cast<ConstantArray>(C)) {
			SmallVector<Constant *, 16> NewOperands;
			bool ChangedOperands = false;
			for (unsigned i = 0; i < CA->getNumOperands(); ++i) {
				Constant *Op = CA->getOperand(i);
				Constant *NewOp = Self(Self, Op);
				NewOperands.push_back(NewOp);
				ChangedOperands |= (NewOp != Op);
			}
			if (ChangedOperands) {
				return ConstantArray::get(cast<ArrayType>(CA->getType()), NewOperands);
			}
			return C;
		}

		if (auto *CS = dyn_cast<ConstantStruct>(C)) {
			SmallVector<Constant *, 16> NewOperands;
			bool ChangedOperands = false;
			for (unsigned i = 0; i < CS->getNumOperands(); ++i) {
				Constant *Op = CS->getOperand(i);
				Constant *NewOp = Self(Self, Op);
				NewOperands.push_back(NewOp);
				ChangedOperands |= (NewOp != Op);
			}
			if (ChangedOperands) {
				return ConstantStruct::get(cast<StructType>(CS->getType()), NewOperands);
			}
			return C;
		}

		return C;
	};

	for (GlobalVariable &GV : M.globals()) {
		if (!GV.hasInitializer())
			continue;

		Constant *Init = GV.getInitializer();
		if (!Init)
			continue;

		Constant *NewInit = remapConstantRef(remapConstantRef, Init);
		if (NewInit != Init) {
			GV.setInitializer(NewInit);
		}
	}

	bool Changed = false;
	for (Function &F : M) {
		if (F.isDeclaration())
			continue;
		Changed |= processConstantStringUse(&F);
	}

	for (auto &I : CSUserMap) {
		CSUser *User = I.second;
		Changed |= processConstantStringUse(User->InitFunc);
	}

	deleteUnusedGlobalVariable();
	for (CSPEntry *Entry : ConstantStringPool) {
		if (Entry->DecFunc->use_empty()) {
			Entry->DecFunc->eraseFromParent();
		}
	}
	// 若全部薄封装被擦除，共享解码核心/包名 key 亦无用户，回收之。
	if (SharedDecodeFunc && SharedDecodeFunc->use_empty()) {
		SharedDecodeFunc->eraseFromParent();
		SharedDecodeFunc = nullptr;
	}
	if (PkgKeyFunc && PkgKeyFunc->use_empty()) {
		PkgKeyFunc->eraseFromParent();
		PkgKeyFunc = nullptr;
	}
  if (UseHardened) {
    // Decoding adds writes, synchronization and allocation. Pre-pass inferred
    // effects on callers/calls are stale and would miscompile subsequent LTO.
    const Attribute::AttrKind Effects[] = {Attribute::Memory, Attribute::NoSync,
        Attribute::NoFree, Attribute::WillReturn, Attribute::MustProgress,
        Attribute::Speculatable, Attribute::NoRecurse, Attribute::NoUnwind};
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      for (auto Kind : Effects) F.removeFnAttr(Kind);
      for (Instruction &I : instructions(F))
        if (auto *Call = dyn_cast<CallBase>(&I))
          for (auto Kind : Effects) Call->removeFnAttr(Kind);
    }
    Changed = true;
  }
	return Changed;
}

template <typename T>
void StringEncryption::getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
	uint32_t N = RandomEngine.get_uint32_t();
	uint32_t Len;

	assert(MaxSize >= MinSize);

	if (MinSize == MaxSize) {
		Len = MinSize;
	} else {
		Len = MinSize + (N % (MaxSize - MinSize));
	}

	char *Buffer = new char[Len * sizeof(T)];
	RandomEngine.get_bytes(Buffer, Len * sizeof(T));
	for (uint32_t i = 0; i < Len; ++i) {
		if constexpr (std::is_same_v<T, uint8_t>) {
			Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
		} else {
			uint8_t b0 = static_cast<uint8_t>(Buffer[i * 2]);
			uint8_t b1 = static_cast<uint8_t>(Buffer[i * 2 + 1]);
			// little-endian combine
			uint16_t w = static_cast<uint16_t>(b0 | (b1 << 8));
			Bytes.push_back(w);
		}
	}

	delete[] Buffer;
}

Function *StringEncryption::buildDecryptFunction(Module *M, const StringEncryption::CSPEntry *Entry) {
	LLVMContext &Ctx = M->getContext();
	IRBuilder<> IRB(Ctx);

	Type *PlainEltTy = Entry->IsUTF16 ? Type::getInt16Ty(Ctx) : Type::getInt8Ty(Ctx);
	PointerType *PlainPtrTy = PointerType::get(Ctx, 0);
	PointerType *DataPtrTy = PointerType::get(Ctx, 0);

	FunctionType *FuncTy = FunctionType::get(
	                           Type::getVoidTy(Ctx),
	{PlainPtrTy, DataPtrTy},
	false);
	Function *DecFunc =
	    Function::Create(FuncTy, GlobalValue::PrivateLinkage, "ndkp_decrypt_string_" + Twine::utohexstr(Entry->ID), M);

	auto ArgIt = DecFunc->arg_begin();
	Argument *PlainString = ArgIt;
	++ArgIt;
	Argument *Data = ArgIt;

	AttrBuilder NoCaptureAttrBuilder{Ctx};
	NoCaptureAttrBuilder.addAttribute(Attribute::NoCapture);

	PlainString->setName("plain_string");
	PlainString->addAttrs(NoCaptureAttrBuilder);
	Data->setName("data");
	Data->addAttrs(NoCaptureAttrBuilder);

	BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", DecFunc);
	BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", DecFunc);
	BasicBlock *LoopBr0 = BasicBlock::Create(Ctx, "LoopBr0", DecFunc);
	BasicBlock *LoopBr1 = BasicBlock::Create(Ctx, "LoopBr1", DecFunc);
	BasicBlock *LoopEnd = BasicBlock::Create(Ctx, "LoopEnd", DecFunc);
	BasicBlock *Publish = BasicBlock::Create(Ctx, "Publish", DecFunc);
	BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

	IRB.SetInsertPoint(Enter);
	ConstantInt *KeyElemSize = ConstantInt::get(Type::getInt32Ty(Ctx), Entry->IsUTF16 ? static_cast<uint32_t>(Entry->EncKey16.size()) : static_cast<uint32_t>(Entry->EncKey.size()));
	uint32_t KeySizeInBytes = Entry->IsUTF16 ? static_cast<uint32_t>(Entry->EncKey16.size() * 2) : static_cast<uint32_t>(Entry->EncKey.size());
	ConstantInt *KeySizeBytesConst = ConstantInt::get(Type::getInt32Ty(Ctx), KeySizeInBytes);

	Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeySizeBytesConst);
	BasicBlock *Claim = emitOnceGuard(IRB, Entry->DecStatus, LoopBody, Exit);

	IRB.SetInsertPoint(LoopBody);
	PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
	LoopCounter->addIncoming(IRB.getInt32(0), Claim);

	PHINode *LastDecrypted = IRB.CreatePHI(PlainEltTy, 2);
	LastDecrypted->addIncoming(Constant::getNullValue(PlainEltTy), Claim);

	Value *KeyIdx = IRB.CreateURem(LoopCounter, KeyElemSize);

	Value *KeyChar = nullptr;
	if (!Entry->IsUTF16) {
		Value *KeyCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeyIdx);
		KeyChar = IRB.CreateLoad(IRB.getInt8Ty(), KeyCharPtr);
	} else {
		Value *KeyBase = IRB.CreateBitCast(Data, PointerType::get(Ctx, 0));
		Value *KeyCharPtr = IRB.CreateInBoundsGEP(Type::getInt16Ty(Ctx), KeyBase, KeyIdx);
		KeyChar = IRB.CreateLoad(Type::getInt16Ty(Ctx), KeyCharPtr);
	}

	Value *EncChar = nullptr;
	if (!Entry->IsUTF16) {
		Value *EncCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, LoopCounter);
		EncChar = IRB.CreateLoad(IRB.getInt8Ty(), EncCharPtr, true);
	} else {
		Value *Two = IRB.getInt32(2);
		Value *IdxBytes = IRB.CreateMul(LoopCounter, Two);
		Value *EncCharBytePtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, IdxBytes);
		Value *EncChar16Ptr = IRB.CreateBitCast(EncCharBytePtr, PointerType::get(Ctx, 0));
		EncChar = IRB.CreateLoad(Type::getInt16Ty(Ctx), EncChar16Ptr, true);
	}

	Value *KeyIdxZext = IRB.CreateZExt(KeyIdx, IRB.getInt32Ty());
	Value *KeyCharZext = nullptr;
	if (!Entry->IsUTF16) {
		KeyCharZext = IRB.CreateZExt(KeyChar, IRB.getInt32Ty());
	} else {
		KeyCharZext = IRB.CreateZExt(KeyChar, IRB.getInt32Ty());
	}
	Value *Mul = IRB.CreateMul(KeyIdxZext, KeyCharZext);
	Value *BrKey = IRB.CreateAnd(Mul, IRB.getInt32(1));
	Value *BrCond = IRB.CreateICmpEQ(BrKey, IRB.getInt32(0));
	IRB.CreateCondBr(BrCond, LoopBr0, LoopBr1);

	IRB.SetInsertPoint(LoopBr0);
	Value *DecChar0 = nullptr;
	if (!Entry->IsUTF16) {
		Value *Tmp0 = IRB.CreateAdd(EncChar, LastDecrypted);
		Tmp0 = IRB.CreateXor(Tmp0, KeyChar);
		Tmp0 = IRB.CreateNot(Tmp0);
		DecChar0 = Tmp0;
	} else {
		Value *Tmp0 = IRB.CreateAdd(EncChar, LastDecrypted);
		Tmp0 = IRB.CreateXor(Tmp0, KeyChar);
		Tmp0 = IRB.CreateNot(Tmp0);
		DecChar0 = Tmp0;
	}
	IRB.CreateBr(LoopEnd);

	IRB.SetInsertPoint(LoopBr1);
	Value *DecChar1 = nullptr;
	if (!Entry->IsUTF16) {
		Value *Tmp1 = IRB.CreateSub(EncChar, LastDecrypted);
		Tmp1 = IRB.CreateXor(Tmp1, KeyChar);
		Tmp1 = IRB.CreateNeg(Tmp1);
		DecChar1 = Tmp1;
	} else {
		Value *Tmp1 = IRB.CreateSub(EncChar, LastDecrypted);
		Tmp1 = IRB.CreateXor(Tmp1, KeyChar);
		Tmp1 = IRB.CreateNeg(Tmp1);
		DecChar1 = Tmp1;
	}
	IRB.CreateBr(LoopEnd);

	IRB.SetInsertPoint(LoopEnd);
	PHINode *BrDecChar = IRB.CreatePHI(PlainEltTy, 2);
	BrDecChar->addIncoming(DecChar0, LoopBr0);
	BrDecChar->addIncoming(DecChar1, LoopBr1);
	Value *DecChar = IRB.CreateXor(BrDecChar, KeyChar);

	LastDecrypted->addIncoming(DecChar, LoopEnd);
	Value *DecCharPtr = IRB.CreateInBoundsGEP(PlainEltTy,
	                    PlainString, LoopCounter);
	IRB.CreateStore(DecChar, DecCharPtr);

	Value *NewCounter = IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
	LoopCounter->addIncoming(NewCounter, LoopEnd);

	uint32_t DataSize = Entry->IsUTF16 ? static_cast<uint32_t>(Entry->Data16.size()) : static_cast<uint32_t>(Entry->Data.size());
	Value *Cond = IRB.CreateICmpEQ(NewCounter, IRB.getInt32(static_cast<uint32_t>(DataSize)));
	IRB.CreateCondBr(Cond, Publish, LoopBody);

	IRB.SetInsertPoint(Publish);
	emitOncePublish(IRB, Entry->DecStatus);
	IRB.CreateBr(Exit);
	IRB.SetInsertPoint(Exit);
	IRB.CreateRetVoid();

	return DecFunc;
}

//===----------------------------------------------------------------------===//
// 字符串加密强化：emitters（解码器侧 IR，须与文件顶部编码器 C++ 逐字节一致）
//===----------------------------------------------------------------------===//

// 模块级扫描 NDKP_STR_BIND（ndkp.str_bind）注解。
bool StringEncryption::moduleHasStrBindAnnotation(Module &M) {
	for (Function &F : M) {
		if (F.isDeclaration())
			continue;
		for (const std::string &A : readAnnotate(&F)) {
			if (A.find("ndkp.str_bind") != std::string::npos)
				return true;
		}
	}
	return false;
}

// 生成 4 个 pepper 分片全局，运行期 pLo=sLo0^rotl(sLo1,23)、pHi=sHi0^rotl(sHi1,17)。
// 非常量（避免后续 IPO 把分片折成 pepper 字面量），private，.AProtect.rodata，noobf。
void StringEncryption::createPepperGlobals(Module &M) {
	LLVMContext &Ctx = M.getContext();
	IntegerType *I64 = Type::getInt64Ty(Ctx);
	uint64_t sLo1 = RandomEngine.get_uint64_t();
	uint64_t sLo0 = PepperLo ^ ndkpRotl64(sLo1, 23);
	uint64_t sHi1 = RandomEngine.get_uint64_t();
	uint64_t sHi0 = PepperHi ^ ndkpRotl64(sHi1, 17);
	uint64_t Vals[4] = {sLo0, sLo1, sHi0, sHi1};
	static const char *Names[4] = {"ndkp_cse_pa", "ndkp_cse_pb",
	                               "ndkp_cse_pc", "ndkp_cse_pd"};
	for (int i = 0; i < 4; ++i) {
		auto *GV = new GlobalVariable(M, I64, false, GlobalValue::PrivateLinkage,
		                              ConstantInt::get(I64, Vals[i]), Names[i]);
		GV->setSection(".AProtect.rodata");
		GV->setMetadata("noobf", MDNode::get(Ctx, {}));
		PepperShare[i] = GV;
	}
}

// i64 @ndkp_cse_get_pkgkey()：读 /proc/self/cmdline，对首 NUL 或 ':' 前字节算 FNV-1a64，
// 带 ready 缓存（每进程算一次）。截 ':' 令多进程私有子进程（cmdline="包名:suffix"）
// 也还原出包名。fopen 失败 ⇒ 返回 0（fail-closed，全串解出乱码）。
Function *StringEncryption::buildPkgKeyFunc(Module &M) {
	LLVMContext &Ctx = M.getContext();
	IntegerType *I8 = Type::getInt8Ty(Ctx);
	IntegerType *I32 = Type::getInt32Ty(Ctx);
	IntegerType *I64 = Type::getInt64Ty(Ctx);
	PointerType *Ptr = PointerType::get(Ctx, 0);
	IntegerType *SizeTy = M.getDataLayout().getIntPtrType(Ctx);

	auto mkString = [&](const std::string &S, const std::string &Name) -> Constant * {
		Constant *C = ConstantDataArray::getString(Ctx, S);
		auto *G = new GlobalVariable(M, C->getType(), true, GlobalValue::PrivateLinkage, C, Name);
		G->setSection(".AProtect.rodata");
		return ConstantExpr::getBitCast(G, Ptr);
	};

	auto *PkgKeyG = new GlobalVariable(M, I64, false, GlobalValue::PrivateLinkage,
	                                   ConstantInt::get(I64, 0), "ndkp_cse_pkg_key");
	PkgKeyG->setSection(".AProtect.data");
	PkgKeyG->setMetadata("noobf", MDNode::get(Ctx, {}));
	auto *ReadyG = new GlobalVariable(M, I32, false, GlobalValue::PrivateLinkage,
	                                  ConstantInt::get(I32, 0), "ndkp_cse_pkg_ready");
	ReadyG->setSection(".AProtect.data");
	ReadyG->setMetadata("noobf", MDNode::get(Ctx, {}));

	FunctionCallee Fopen = M.getOrInsertFunction(
	    "fopen", FunctionType::get(Ptr, {Ptr, Ptr}, false));
	FunctionCallee Fread = M.getOrInsertFunction(
	    "fread", FunctionType::get(SizeTy, {Ptr, SizeTy, SizeTy, Ptr}, false));
	FunctionCallee Fclose = M.getOrInsertFunction(
	    "fclose", FunctionType::get(I32, {Ptr}, false));

	Function *F = Function::Create(FunctionType::get(I64, {}, false),
	                               GlobalValue::PrivateLinkage, "ndkp_cse_get_pkgkey", &M);

	BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
	BasicBlock *Open = BasicBlock::Create(Ctx, "open", F);
	BasicBlock *ReadBB = BasicBlock::Create(Ctx, "read", F);
	BasicBlock *FnvHead = BasicBlock::Create(Ctx, "fnv.head", F);
	BasicBlock *FnvBody = BasicBlock::Create(Ctx, "fnv.body", F);
	BasicBlock *FnvCont = BasicBlock::Create(Ctx, "fnv.cont", F);
	BasicBlock *StoreBB = BasicBlock::Create(Ctx, "store", F);
	BasicBlock *FailBB = BasicBlock::Create(Ctx, "fail", F);
	BasicBlock *Done = BasicBlock::Create(Ctx, "done", F);

	IRBuilder<> B(Entry);
	Value *Buf = B.CreateAlloca(ArrayType::get(I8, 256), nullptr, "cmdline");
	Value *BufPtr = B.CreateBitCast(Buf, Ptr);
	emitOnceGuard(B, ReadyG, Open, Done);

	B.SetInsertPoint(Open);
	Value *Fp = B.CreateCall(Fopen, {mkString("/proc/self/cmdline", "ndkp_cse_cmdpath"),
	                                 mkString("rb", "ndkp_cse_rb")});
	B.CreateCondBr(B.CreateICmpEQ(Fp, ConstantPointerNull::get(Ptr)), FailBB, ReadBB);

	B.SetInsertPoint(ReadBB);
	Value *NRead = B.CreateCall(Fread, {BufPtr, ConstantInt::get(SizeTy, 1),
	                                    ConstantInt::get(SizeTy, 256), Fp});
	B.CreateCall(Fclose, {Fp});
	B.CreateBr(FnvHead);

	B.SetInsertPoint(FnvHead);
	PHINode *IdxPhi = B.CreatePHI(SizeTy, 2);
	PHINode *HashPhi = B.CreatePHI(I64, 2);
	IdxPhi->addIncoming(ConstantInt::get(SizeTy, 0), ReadBB);
	HashPhi->addIncoming(ConstantInt::get(I64, 0xcbf29ce484222325ULL), ReadBB);
	B.CreateCondBr(B.CreateICmpUGE(IdxPhi, NRead), StoreBB, FnvBody);

	B.SetInsertPoint(FnvBody);
	Value *CPtr = B.CreateInBoundsGEP(I8, BufPtr, IdxPhi);
	Value *CByte = B.CreateLoad(I8, CPtr);
	// 遇 NUL 或 ':' 即停。多进程私有子进程（AndroidManifest android:process=":suffix"）
	// 的 /proc/self/cmdline = "包名:suffix"，截到 ':' 前还原出包名，与编码期 FNV(包名)
	// 对齐（合法 Android/Java 包名为点分标识符，绝不含 ':'，故截断无歧义）。
	Value *IsNul = B.CreateICmpEQ(CByte, ConstantInt::get(I8, 0));
	Value *IsColon = B.CreateICmpEQ(CByte, ConstantInt::get(I8, ':'));
	B.CreateCondBr(B.CreateOr(IsNul, IsColon), StoreBB, FnvCont);

	B.SetInsertPoint(FnvCont);
	Value *HX = B.CreateXor(HashPhi, B.CreateZExt(CByte, I64));
	Value *HNext = B.CreateMul(HX, ConstantInt::get(I64, 0x100000001b3ULL));
	Value *INext = B.CreateAdd(IdxPhi, ConstantInt::get(SizeTy, 1));
	IdxPhi->addIncoming(INext, FnvCont);
	HashPhi->addIncoming(HNext, FnvCont);
	B.CreateBr(FnvHead);

	// StoreBB 的两个前驱（FnvHead 当 i>=n、FnvBody 当遇 NUL 或 ':'）都被 FnvHead 支配，
	// HashPhi 在此可直接用。
	B.SetInsertPoint(StoreBB);
	B.CreateStore(HashPhi, PkgKeyG);
	emitOncePublish(B, ReadyG);
	B.CreateBr(Done);

	B.SetInsertPoint(FailBB);
	B.CreateStore(ConstantInt::get(I64, 0), PkgKeyG);
	emitOncePublish(B, ReadyG);
	B.CreateBr(Done);

	B.SetInsertPoint(Done);
	B.CreateRet(B.CreateLoad(I64, PkgKeyG));
	return F;
}

// void @ndkp_cse_decode(ptr out, ptr cipher, i32 lenBytes, i32 id)
// pepper 重组 → (bind) ^ 包名 key → SplitMix64 扩钥 → 逐 64B 块 ChaCha8 → 逐字节 XOR。
// 全 LE 目标：块字直接 store i32（LE），与编码器 out[4i..]=LE(w) 对齐。
Function *StringEncryption::buildChaChaDecodeFunc(Module &M) {
	LLVMContext &Ctx = M.getContext();
	IntegerType *I8 = Type::getInt8Ty(Ctx);
	IntegerType *I32 = Type::getInt32Ty(Ctx);
	IntegerType *I64 = Type::getInt64Ty(Ctx);
	PointerType *Ptr = PointerType::get(Ctx, 0);
	ArrayType *BlkTy = ArrayType::get(I32, 16);

	Function *F = Function::Create(
	    FunctionType::get(Type::getVoidTy(Ctx), {Ptr, Ptr, I32, I32}, false),
	    GlobalValue::PrivateLinkage, "ndkp_cse_decode", &M);
	auto Arg = F->arg_begin();
	Argument *Out = &*Arg++;
	Argument *Cipher = &*Arg++;
	Argument *Len = &*Arg++;
	Argument *Id = &*Arg;
	Out->setName("out"); Cipher->setName("cipher"); Len->setName("len"); Id->setName("id");

	BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
	BasicBlock *BlkHead = BasicBlock::Create(Ctx, "blk.head", F);
	BasicBlock *BlkBody = BasicBlock::Create(Ctx, "blk.body", F);
	BasicBlock *XorHead = BasicBlock::Create(Ctx, "xor.head", F);
	BasicBlock *XorBody = BasicBlock::Create(Ctx, "xor.body", F);
	BasicBlock *BlkAfter = BasicBlock::Create(Ctx, "blk.after", F);
	BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", F);

	IRBuilder<> B(Entry);
	auto ROTL64 = [&](Value *V, unsigned N) {
		return B.CreateOr(B.CreateShl(V, N), B.CreateLShr(V, 64 - N));
	};
	auto ROTL32 = [&](Value *V, unsigned N) {
		return B.CreateOr(B.CreateShl(V, N), B.CreateLShr(V, 32 - N));
	};
	auto SMix = [&](Value *&Z) -> Value * {
		Z = B.CreateAdd(Z, ConstantInt::get(I64, 0x9E3779B97F4A7C15ULL));
		Value *T = Z;
		T = B.CreateMul(B.CreateXor(T, B.CreateLShr(T, 30)),
		                ConstantInt::get(I64, 0xBF58476D1CE4E5B9ULL));
		T = B.CreateMul(B.CreateXor(T, B.CreateLShr(T, 27)),
		                ConstantInt::get(I64, 0x94D049BB133111EBULL));
		return B.CreateXor(T, B.CreateLShr(T, 31));
	};

	Value *KsBlk = B.CreateAlloca(BlkTy, nullptr, "ks");
	Value *KsBlk8 = B.CreateBitCast(KsBlk, Ptr);

	// 重组 pepper
	Value *PLo = B.CreateXor(B.CreateLoad(I64, PepperShare[0]),
	                         ROTL64(B.CreateLoad(I64, PepperShare[1]), 23));
	Value *PHi = B.CreateXor(B.CreateLoad(I64, PepperShare[2]),
	                         ROTL64(B.CreateLoad(I64, PepperShare[3]), 17));
	if (UseBind && PkgKeyFunc) {
		Value *Pk = B.CreateCall(PkgKeyFunc, {});
		PLo = B.CreateXor(PLo, Pk);
		PHi = B.CreateXor(PHi, ROTL64(Pk, 32));
	}
	if (UseCertBind && CertLoGV && CertHiGV) {
		// 运行期证书混合值由 .init_array 构造器 ndkp_certbind_init 在加载期缓存到全局；
		// 与编码期 EncLo^=CertLo; EncHi^=CertHi 对称，证书匹配才抵消回原 pepper。
		PLo = B.CreateXor(PLo, B.CreateLoad(I64, CertLoGV));
		PHi = B.CreateXor(PHi, B.CreateLoad(I64, CertHiGV));
	}

	// SplitMix64 扩钥 → key[0..8)
	Value *Key[8];
	{
		Value *ZA = PLo;
		Value *K0 = SMix(ZA), *K1 = SMix(ZA);
		Value *ZB = PHi;
		Value *K2 = SMix(ZB), *K3 = SMix(ZB);
		Value *K64[4] = {K0, K1, K2, K3};
		for (int i = 0; i < 4; ++i) {
			Key[2 * i] = B.CreateTrunc(K64[i], I32);
			Key[2 * i + 1] = B.CreateTrunc(B.CreateLShr(K64[i], 32), I32);
		}
	}
	B.CreateBr(BlkHead);

	// 块循环
	B.SetInsertPoint(BlkHead);
	PHINode *Boff = B.CreatePHI(I32, 2);
	Boff->addIncoming(ConstantInt::get(I32, 0), Entry);
	B.CreateCondBr(B.CreateICmpUGE(Boff, Len), Exit, BlkBody);

	B.SetInsertPoint(BlkBody);
	Value *BlkIdx = B.CreateLShr(Boff, ConstantInt::get(I32, 6));
	Value *X[16], *Orig[16];
	X[0] = ConstantInt::get(I32, 0x61707865u);
	X[1] = ConstantInt::get(I32, 0x3320646eu);
	X[2] = ConstantInt::get(I32, 0x79622d32u);
	X[3] = ConstantInt::get(I32, 0x6b206574u);
	for (int i = 0; i < 8; ++i)
		X[4 + i] = Key[i];
	X[12] = BlkIdx;
	X[13] = Id;
	X[14] = ConstantInt::get(I32, 0);
	X[15] = ConstantInt::get(I32, 0);
	for (int i = 0; i < 16; ++i)
		Orig[i] = X[i];
	auto QR = [&](int a, int b, int c, int d) {
		X[a] = B.CreateAdd(X[a], X[b]); X[d] = B.CreateXor(X[d], X[a]); X[d] = ROTL32(X[d], 16);
		X[c] = B.CreateAdd(X[c], X[d]); X[b] = B.CreateXor(X[b], X[c]); X[b] = ROTL32(X[b], 12);
		X[a] = B.CreateAdd(X[a], X[b]); X[d] = B.CreateXor(X[d], X[a]); X[d] = ROTL32(X[d], 8);
		X[c] = B.CreateAdd(X[c], X[d]); X[b] = B.CreateXor(X[b], X[c]); X[b] = ROTL32(X[b], 7);
	};
	for (int r = 0; r < 4; ++r) {
		QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
		QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
	}
	for (int i = 0; i < 16; ++i) {
		Value *W = B.CreateAdd(X[i], Orig[i]);
		Value *Slot = B.CreateInBoundsGEP(BlkTy, KsBlk,
		                                  {ConstantInt::get(I32, 0), ConstantInt::get(I32, i)});
		B.CreateStore(W, Slot);
	}
	Value *Rem = B.CreateSub(Len, Boff);
	Value *IsLast = B.CreateICmpULT(Rem, ConstantInt::get(I32, 64));
	Value *N = B.CreateSelect(IsLast, Rem, ConstantInt::get(I32, 64));
	B.CreateBr(XorHead);

	B.SetInsertPoint(XorHead);
	PHINode *J = B.CreatePHI(I32, 2);
	J->addIncoming(ConstantInt::get(I32, 0), BlkBody);
	B.CreateCondBr(B.CreateICmpUGE(J, N), BlkAfter, XorBody);

	B.SetInsertPoint(XorBody);
	Value *KsByte = B.CreateLoad(I8, B.CreateInBoundsGEP(I8, KsBlk8, J));
	Value *Pos = B.CreateAdd(Boff, J);
	Value *CByte = B.CreateLoad(I8, B.CreateInBoundsGEP(I8, Cipher, Pos));
	B.CreateStore(B.CreateXor(KsByte, CByte), B.CreateInBoundsGEP(I8, Out, Pos));
	Value *JNext = B.CreateAdd(J, ConstantInt::get(I32, 1));
	J->addIncoming(JNext, XorBody);
	B.CreateBr(XorHead);

	B.SetInsertPoint(BlkAfter);
	Value *BoffNext = B.CreateAdd(Boff, ConstantInt::get(I32, 64));
	Boff->addIncoming(BoffNext, BlkAfter);
	B.CreateBr(BlkHead);

	B.SetInsertPoint(Exit);
	B.CreateRetVoid();
	return F;
}

// PerKey/Bind 模式下每串的薄封装：幂等守卫 + 调用共享 ndkp_cse_decode。
// 签名与基线一致 (plain, data)，data 直接指向密文（表里已无内联密钥）。
// The sealer rewrites only this retained data blob, never code or relocations.
void StringEncryption::buildHardenedTable(Module &M) {
  using namespace ndkp_cse;
  std::vector<uint8_t> Blob(HeaderSize, 0);
  std::copy(Magic, Magic + 8, Blob.begin());
  store32(Blob.data() + 16, (UseBind ? 1 : 0) | (UseCertBind ? 2 : 0));
  store32(Blob.data() + 20, uint32_t(ConstantStringPool.size() + 1));
  for (unsigned i = 24; i < 72; ++i) Blob[i] = RandomEngine.get_uint8_t();
  for (unsigned i = 184; i < 216; ++i) Blob[i] = RandomEngine.get_uint8_t();
  if (UseBind)
    stringarmor::sha2::sha256(reinterpret_cast<const uint8_t*>(BindPackage.data()),
                            BindPackage.size(), Blob.data() + 104);
  if (UseCertBind) {
    store64(Blob.data() + 136, CertLo); store64(Blob.data() + 144, CertHi);
  }
  uint8_t Key[32], Zero[32] = {};
  derive(Blob.data(), Zero, Blob.data() + 104, Key);
  auto Add = [&](uint32_t Id, uint32_t Encoding, const std::vector<uint8_t> &Bytes) {
    const uint32_t Capacity = hardenedCapacity(Bytes.size());
    if (Blob.size() + 32 + Capacity > (1u << 28))
      report_fatal_error("hardened CSE module exceeds 256 MiB");
    const uint32_t Offset = uint32_t(Blob.size());
    Blob.resize(Blob.size() + 32 + Capacity, 0);
    uint8_t *Record = Blob.data() + Offset;
    store32(Record, Capacity); store32(Record + 12, Id);
    uint8_t *Plain = Record + 32;
    store32(Plain, uint32_t(Bytes.size())); store32(Plain + 4, Encoding);
    store32(Plain + 8, Id);
    std::copy(Bytes.begin(), Bytes.end(), Plain + 16);
    for (size_t i = 16 + Bytes.size(); i < Capacity; ++i) Plain[i] = RandomEngine.get_uint8_t();
    return Offset;
  };
  for (CSPEntry *Entry : ConstantStringPool) {
    std::vector<uint8_t> Bytes = Entry->Data;
    if (Entry->IsUTF16) {
      Bytes.clear();
      for (uint16_t Word : Entry->Data16) {
        Bytes.push_back(uint8_t(Word)); Bytes.push_back(uint8_t(Word >> 8));
      }
    }
    Entry->Offset = Add(Entry->ID, Entry->IsUTF16 ? 2 : 1, Bytes);
    wipe(Bytes.data(), Bytes.size());
  }
  const char Decoy[] = "configuration loaded successfully";
  Add(uint32_t(ConstantStringPool.size()), 1,
      std::vector<uint8_t>(Decoy, Decoy + sizeof Decoy));
  HardenedSize = uint32_t(Blob.size()); store32(Blob.data() + 8, HardenedSize);
  size_t Offset = HeaderSize;
  for (uint32_t Id = 0; Id < load32(Blob.data() + 20); ++Id) {
    uint8_t *Record = Blob.data() + Offset;
    const uint32_t Capacity = load32(Record);
    uint8_t AAD[40]; aad(Blob.data(), Id, Capacity, AAD);
    seal(Key, Record + 4, AAD, sizeof AAD, Record + 32, Capacity, Record + 16);
    Offset += 32 + Capacity;
  }
  wipe(Key, sizeof Key);
  Constant *Init = ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Blob));
  HardenedBlob = new GlobalVariable(M, Init->getType(), false,
      GlobalValue::PrivateLinkage, Init, "ndkp_cse_v1_payload");
  HardenedBlob->setSection(".ndkp.cse"); HardenedBlob->setAlignment(Align(8));
  HardenedBlob->setMetadata("noobf", MDNode::get(M.getContext(), {}));
  appendToUsed(M, {HardenedBlob});
  Type *CacheTy = ArrayType::get(Type::getInt8Ty(M.getContext()), 84);
  HardenedCache = new GlobalVariable(M, CacheTy, false, GlobalValue::PrivateLinkage,
      Constant::getNullValue(CacheTy), "ndkp_cse_v1_cache");
  HardenedCache->setAlignment(Align(4));
  HardenedCache->setMetadata("noobf", MDNode::get(M.getContext(), {}));
}

Function *StringEncryption::buildHardenedDecrypt(Module &M, const CSPEntry *Entry) {
  LLVMContext &Ctx = M.getContext();
  Type *Ptr = PointerType::get(Ctx, 0), *I32 = Type::getInt32Ty(Ctx);
  Function *F = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), {Ptr, Ptr}, false),
      GlobalValue::PrivateLinkage, "ndkp_decrypt_string_" + Twine::utohexstr(Entry->ID), &M);
  FunctionCallee Decode = M.getOrInsertFunction("ndkp_cse_decode_v1",
      FunctionType::get(Type::getVoidTy(Ctx), {Ptr, I32, I32, Ptr, I32, I32, I32, Ptr}, false));
  if (auto *Helper = dyn_cast<Function>(Decode.getCallee()))
    Helper->setVisibility(GlobalValue::HiddenVisibility);
  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", F);
  BasicBlock *Body = BasicBlock::Create(Ctx, "Body", F);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", F);
  IRBuilder<> B(Enter); emitOnceGuard(B, Entry->DecStatus, Body, Exit);
  B.SetInsertPoint(Body);
  uint32_t Capacity = hardenedCapacity(Entry->IsUTF16 ? Entry->Data16.size() * 2 : Entry->Data.size()) - 16;
  B.CreateCall(Decode, {F->getArg(0), B.getInt32(Capacity), B.getInt32(Entry->IsUTF16 ? 2 : 1),
      HardenedBlob, B.getInt32(HardenedSize), B.getInt32(Entry->Offset), B.getInt32(Entry->ID), HardenedCache});
  emitOncePublish(B, Entry->DecStatus); B.CreateBr(Exit);
  B.SetInsertPoint(Exit); B.CreateRetVoid();
  return F;
}

Function *StringEncryption::buildDecryptFunctionChaCha(Module *M, const StringEncryption::CSPEntry *Entry) {
	LLVMContext &Ctx = M->getContext();
	PointerType *Ptr = PointerType::get(Ctx, 0);

	Function *DecFunc = Function::Create(
	    FunctionType::get(Type::getVoidTy(Ctx), {Ptr, Ptr}, false),
	    GlobalValue::PrivateLinkage,
	    "ndkp_decrypt_string_" + Twine::utohexstr(Entry->ID), M);
	auto Arg = DecFunc->arg_begin();
	Argument *Plain = &*Arg++;
	Argument *Data = &*Arg;
	Plain->setName("plain_string");
	Data->setName("data");

	uint32_t LenBytes = Entry->IsUTF16
	                        ? static_cast<uint32_t>(Entry->Data16.size() * 2)
	                        : static_cast<uint32_t>(Entry->Data.size());

	BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", DecFunc);
	BasicBlock *Body = BasicBlock::Create(Ctx, "Body", DecFunc);
	BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

	IRBuilder<> IRB(Enter);
	emitOnceGuard(IRB, Entry->DecStatus, Body, Exit);

	IRB.SetInsertPoint(Body);
	IRB.CreateCall(SharedDecodeFunc,
	               {Plain, Data, IRB.getInt32(LenBytes), IRB.getInt32(Entry->ID)});
	emitOncePublish(IRB, Entry->DecStatus);
	IRB.CreateBr(Exit);

	IRB.SetInsertPoint(Exit);
	IRB.CreateRetVoid();
	return DecFunc;
}

Function *StringEncryption::buildInitFunction(Module *M, const StringEncryption::CSUser *User) {
	LLVMContext &Ctx = M->getContext();
	IRBuilder<> IRB(Ctx);
	FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx), {User->DecGV->getType()}, false);
	Function *InitFunc =
	    Function::Create(FuncTy, GlobalValue::PrivateLinkage, "__global_variable_initializer_" + User->GV->getName(), M);

	auto ArgIt = InitFunc->arg_begin();
	Argument *thiz = ArgIt;


	AttrBuilder NoCaptureAttrBuilder{Ctx};
	NoCaptureAttrBuilder.addAttribute(Attribute::NoCapture);
	thiz->setName("this");
	thiz->addAttrs(NoCaptureAttrBuilder);

	BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", InitFunc);
	BasicBlock *InitBody = BasicBlock::Create(Ctx, "InitBody", InitFunc);
	BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", InitFunc);

	IRB.SetInsertPoint(Enter);
	emitOnceGuard(IRB, User->DecStatus, InitBody, Exit);

	IRB.SetInsertPoint(InitBody);
	Constant *Init = User->GV->getInitializer();
	lowerGlobalConstant(Init, IRB, User->DecGV, User->Ty);
	emitOncePublish(IRB, User->DecStatus);
	IRB.CreateBr(Exit);

	IRB.SetInsertPoint(Exit);
	IRB.CreateRetVoid();
	return InitFunc;
}

void StringEncryption::lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
	if (isa<ConstantAggregateZero>(CV)) {
		IRB.CreateStore(CV, Ptr);
		return;
	}

	std::function<Constant *(Constant *)> remapLeafConstant = [&](Constant *Leaf) -> Constant * {
		if (!Leaf) {
			return Leaf;
		}
		if (auto *GV = dyn_cast<GlobalVariable>(Leaf)) {
			if (CSPEntry *Entry = resolveCSPEntryGlobal(GV)) {
				return Entry->DecGV;
			}
			if (CSUser *User = resolveCSUserGlobal(GV)) {
				return User->DecGV;
			}
			return Leaf;
		}
		if (auto *CE = dyn_cast<ConstantExpr>(Leaf)) {
			Constant *Base = cast<Constant>(CE->getOperand(0));
			Constant *NewBase = remapLeafConstant(Base);
			if (NewBase == Base) {
				return Leaf;
			}
			switch (CE->getOpcode()) {
			case Instruction::GetElementPtr: {
				SmallVector<Constant *, 4> Indices;
				for (unsigned i = 1; i < CE->getNumOperands(); ++i) {
					Indices.push_back(cast<Constant>(CE->getOperand(i)));
				}
				if (auto *NewGV = dyn_cast<GlobalVariable>(NewBase)) {
					return ConstantExpr::getGetElementPtr(NewGV->getValueType(), NewGV, Indices);
				}
				return Leaf;
			}
			case Instruction::BitCast:
				return ConstantExpr::getBitCast(NewBase, CE->getType());
			case Instruction::AddrSpaceCast:
				return ConstantExpr::getAddrSpaceCast(NewBase, CE->getType());
			default:
				return Leaf;
			}
		}
		return Leaf;
	};

	if (ConstantArray *CA = dyn_cast<ConstantArray>(CV)) {
		lowerGlobalConstantArray(CA, IRB, Ptr, Ty);
	} else if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CV)) {
		lowerGlobalConstantStruct(CS, IRB, Ptr, Ty);
	} else {
		IRB.CreateStore(remapLeafConstant(CV), Ptr);
	}
}

void StringEncryption::lowerGlobalConstantArray(ConstantArray *CA, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
	for (unsigned i = 0, e = CA->getNumOperands(); i != e; ++i) {
		Constant *CV = CA->getOperand(i);
		Value *GEP = IRB.CreateGEP(Ty,
		                           Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
		lowerGlobalConstant(CV, IRB, GEP, CV->getType());
	}
}

void StringEncryption::lowerGlobalConstantStruct(ConstantStruct *CS, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
	for (unsigned i = 0, e = CS->getNumOperands(); i != e; ++i) {
		Constant* CV = CS->getOperand(i);
		Value *GEP = IRB.CreateGEP(Ty,
		                           Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
		lowerGlobalConstant(CV, IRB, GEP, CV->getType());
	}
}

void StringEncryption::collectReferencedEntries(Constant *CV,
                                               SmallPtrSetImpl<Constant *> &Visited,
                                               SmallPtrSetImpl<CSPEntry *> &Entries) {
	if (!CV || !Visited.insert(CV).second) {
		return;
	}

	if (auto *GV = dyn_cast<GlobalVariable>(CV)) {
		if (CSPEntry *Entry = resolveCSPEntryGlobal(GV)) {
			Entries.insert(Entry);
		}
	}

	for (unsigned i = 0; i < CV->getNumOperands(); ++i) {
		if (auto *Nested = dyn_cast<Constant>(CV->getOperand(i))) {
			collectReferencedEntries(Nested, Visited, Entries);
		}
	}
}

bool StringEncryption::processConstantStringUse(Function *F) {
	auto opt = ArgsOptions->toObfuscate(ArgsOptions->cseOpt(), F);
	if (!opt.isEnabled()) {
		return false;
	}
	LLVMContext &Ctx = F->getContext();
	LowerConstantExpr(*F);
	SmallPtrSet<GlobalVariable *, 16> LiveBuffers;
	bool Changed = false;

	auto getSafeInsertPoint = [](Instruction *Inst) -> Instruction * {
		if (!Inst) {
			return nullptr;
		}
		if (!Inst->isEHPad()) {
			return Inst;
		}
		BasicBlock *BB = Inst->getParent();
		if (!BB) {
			return Inst;
		}
		BasicBlock *PrevBB = BB->getPrevNode();
		if (!PrevBB) {
			return Inst;
		}
		return &*PrevBB->getFirstInsertionPt();
	};

	auto ensureEntryReady = [&](Instruction *InsertBefore, CSPEntry *Entry) {
		if (!InsertBefore || !Entry || LiveBuffers.count(Entry->DecGV) > 0) {
			return;
		}
		IRBuilder<> IRB(getSafeInsertPoint(InsertBefore));
		Value *OutBuf = IRB.CreateBitCast(Entry->DecGV, PointerType::get(Ctx, 0));
		Value *Data = IRB.CreateInBoundsGEP(
		                  EncryptedStringTable->getValueType(),
		                  EncryptedStringTable,
		                  {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
		fixEH(IRB.CreateCall(Entry->DecFunc, {OutBuf, Data}));
		LiveBuffers.insert(Entry->DecGV);
	};

	auto ensureUserReady = [&](Instruction *InsertBefore, CSUser *User) {
		if (!InsertBefore || !User || LiveBuffers.count(User->DecGV) > 0) {
			return;
		}
		InsertBefore = getSafeInsertPoint(InsertBefore);
		auto UserEntriesIt = UserReferencedEntries.find(User);
		if (UserEntriesIt != UserReferencedEntries.end()) {
			for (CSPEntry *Entry : UserEntriesIt->second) {
				ensureEntryReady(InsertBefore, Entry);
			}
		}
		IRBuilder<> IRB(InsertBefore);
		fixEH(IRB.CreateCall(User->InitFunc, {User->DecGV}));
		LiveBuffers.insert(User->DecGV);
	};

	auto ensureGlobalEntriesReady = [&](Instruction *InsertBefore,
	                                    GlobalVariable *GV) {
		if (!InsertBefore || !GV) {
			return;
		}
		auto It = GlobalReferencedEntries.find(GV);
		if (It == GlobalReferencedEntries.end()) {
			return;
		}
		for (CSPEntry *Entry : It->second) {
			ensureEntryReady(InsertBefore, Entry);
		}
	};

	auto rewriteResolvedGlobal = [&](Instruction &Inst, Value *Carrier, GlobalVariable *From,
	                                 GlobalVariable *To) {
		if (!From || !To || From == To) {
			return;
		}
		if (auto *GEP = dyn_cast<GetElementPtrInst>(Carrier)) {
			GEP->replaceUsesOfWith(From, To);
		} else if (auto *CE = dyn_cast<ConstantExpr>(Carrier)) {
			Constant *NewConst = nullptr;
			switch (CE->getOpcode()) {
			case Instruction::GetElementPtr: {
				SmallVector<Constant *, 4> Indices;
				for (unsigned i = 1; i < CE->getNumOperands(); ++i) {
					Indices.push_back(cast<Constant>(CE->getOperand(i)));
				}
				NewConst = ConstantExpr::getGetElementPtr(To->getValueType(), To, Indices);
				break;
			}
			case Instruction::BitCast:
				NewConst = ConstantExpr::getBitCast(To, CE->getType());
				break;
			case Instruction::AddrSpaceCast:
				NewConst = ConstantExpr::getAddrSpaceCast(To, CE->getType());
				break;
			default:
				break;
			}
			if (NewConst) {
				Inst.replaceUsesOfWith(CE, NewConst);
			}
		} else {
			Inst.replaceUsesOfWith(From, To);
		}
		MaybeDeadGlobalVars.insert(From);
	};

	auto handleResolvedOperand = [&](Instruction &Inst, Value *Carrier,
	                                 Instruction *InsertBefore) {
		GlobalVariable *GV = extractReferencedGlobal(Carrier);
		if (!GV) {
			return false;
		}

		ensureGlobalEntriesReady(InsertBefore, GV);

		if (CSUser *User = resolveCSUserGlobal(GV)) {
			if (F == User->InitFunc) {
				return false;
			}
			ensureUserReady(InsertBefore, User);
			rewriteResolvedGlobal(Inst, Carrier, GV, User->DecGV);
			return true;
		}

		if (CSPEntry *Entry = resolveCSPEntryGlobal(GV)) {
			ensureEntryReady(InsertBefore, Entry);
			rewriteResolvedGlobal(Inst, Carrier, GV, Entry->DecGV);
			return true;
		}

		if (auto *DirectGV = dyn_cast<GlobalVariable>(Carrier)) {
			if (CSPEntry *PointedEntry = getPointedCSPEntry(DirectGV)) {
				if (isIRObfuscationDebugEnabled()) {
					errs() << "[DEBUG] CSE: Found pointer to encrypted string: " << DirectGV->getName()
					       << " -> " << PointedEntry->DecGV->getName() << "\n";
				}
				ensureEntryReady(InsertBefore, PointedEntry);
				return true;
			}
			if (CSUser *PointedUser = getPointedCSUser(DirectGV)) {
				if (isIRObfuscationDebugEnabled()) {
					errs() << "[DEBUG] CSE: Found pointer to CSUser string: " << DirectGV->getName()
					       << " -> " << PointedUser->DecGV->getName() << "\n";
				}
				ensureUserReady(InsertBefore, PointedUser);
				return true;
			}
		}

		return false;
	};

	for (BasicBlock &BB : *F) {
		LiveBuffers.clear();
		Instruction *BlockInsertPoint = &*BB.getFirstInsertionPt();
		for (Instruction &Inst : BB) {
			if (PHINode *PHI = dyn_cast<PHINode>(&Inst)) {
				for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
					Changed |= handleResolvedOperand(Inst, PHI->getIncomingValue(i),
					                                 BlockInsertPoint);
				}
			} else {
				for (User::op_iterator op = Inst.op_begin(); op != Inst.op_end(); ++op) {
					Changed |= handleResolvedOperand(Inst, *op, &Inst);
				}
			}
		}
	}
	return Changed;
}

void StringEncryption::collectConstantStringUser(GlobalVariable *CString, std::set<GlobalVariable *> &Users) {
	SmallPtrSet<Value *, 16> Visited;
	SmallVector<Value *, 16> ToVisit;

	ToVisit.push_back(CString);
	while (!ToVisit.empty()) {
		Value *V = ToVisit.pop_back_val();
		if (Visited.count(V) > 0)
			continue;
		Visited.insert(V);
		for (Value *User : V->users()) {
			if (auto *GV = dyn_cast<GlobalVariable>(User)) {
				Users.insert(GV);
			} else {
				ToVisit.push_back(User);
			}
		}
	}
}

GlobalVariable *StringEncryption::extractReferencedGlobal(Value *V) {
	if (auto *GV = dyn_cast_or_null<GlobalVariable>(V)) {
		return GV;
	}

	if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
		return dyn_cast<GlobalVariable>(GEP->getPointerOperand());
	}

	if (auto *CE = dyn_cast<ConstantExpr>(V)) {
		switch (CE->getOpcode()) {
		case Instruction::GetElementPtr:
		case Instruction::BitCast:
		case Instruction::AddrSpaceCast:
			return extractReferencedGlobal(CE->getOperand(0));
		default:
			break;
		}
	}

	return nullptr;
}

StringEncryption::CSPEntry *StringEncryption::resolveCSPEntryGlobal(GlobalVariable *GV) {
	if (!GV) {
		return nullptr;
	}

	auto Iter = CSPEntryMap.find(GV);
	if (Iter != CSPEntryMap.end()) {
		return Iter->second;
	}

	auto DecIter = DecryptedCSPEntryMap.find(GV);
	if (DecIter != DecryptedCSPEntryMap.end()) {
		return DecIter->second;
	}

	return nullptr;
}

StringEncryption::CSUser *StringEncryption::resolveCSUserGlobal(GlobalVariable *GV) {
	if (!GV) {
		return nullptr;
	}

	auto Iter = CSUserMap.find(GV);
	if (Iter != CSUserMap.end()) {
		return Iter->second;
	}

	auto DecIter = DecryptedCSUserMap.find(GV);
	if (DecIter != DecryptedCSUserMap.end()) {
		return DecIter->second;
	}

	return nullptr;
}

StringEncryption::CSPEntry *StringEncryption::getPointedCSPEntry(GlobalVariable *GV) {
	if (!GV->hasInitializer())
		return nullptr;

	Constant *Init = GV->getInitializer();
	if (!Init)
		return nullptr;

	if (GlobalVariable *StrGV = extractReferencedGlobal(Init)) {
		return resolveCSPEntryGlobal(StrGV);
	}

	return nullptr;
}

StringEncryption::CSUser *StringEncryption::getPointedCSUser(GlobalVariable *GV) {
	if (!GV->hasInitializer())
		return nullptr;

	Constant *Init = GV->getInitializer();
	if (!Init)
		return nullptr;

	if (GlobalVariable *StrGV = extractReferencedGlobal(Init)) {
		return resolveCSUserGlobal(StrGV);
	}

	return nullptr;
}

bool StringEncryption::isValidToEncrypt(GlobalVariable *GV) {
	if (GV->isConstant() && GV->hasInitializer()) {
		StringRef Name = GV->getName();
		if (Name.contains("gv_code_seg") || Name.contains("gv_data_seg") ||
		    Name.contains("vm_code_seg") || Name.contains("vm_data_seg") ||
		    Name.contains("scase_code_seg") || Name.contains("scase_data_seg")) {
			return false;
		}
		return GV->getInitializer() != nullptr;
	} else {
		return false;
	}
}

void StringEncryption::deleteUnusedGlobalVariable() {
	for (GlobalVariable *GV : MaybeDeadGlobalVars) {
		if (!GV->hasLocalLinkage() && !GV->hasPrivateLinkage()) {
			continue;
		}

		GV->removeDeadConstantUsers();

		if (GV->hasInitializer()) {
			Constant *Init = GV->getInitializer();
			GV->setInitializer(nullptr);
			if (isSafeToDestroyConstant(Init))
				Init->destroyConstant();
		}

		if (GV->use_empty()) {
			GV->eraseFromParent();
		}
	}
}

ModulePass *llvm::createStringEncryptionPass(ObfuscationOptions *argsOptions) {
	return new StringEncryption(argsOptions);
}

INITIALIZE_PASS(StringEncryption, "string-encryption", "Enable IR String Encryption", false, false)
