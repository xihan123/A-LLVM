//===- CertBind.h - APK 签名证书绑定 Pass ------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// -irobf-cert-bind：把"运行期 APK 签名证书 SHA-256 派生的 128-bit 混合值"折入解密密钥
// （CSE 字符串 pepper + VMP 函数密钥），使产物仅在被 -irobf-cert-file 指定证书签名时才
// 正确运行。详见 CertBind.cpp。
//
//===----------------------------------------------------------------------===//

#ifndef OBFUSCATION_CERTBIND_H
#define OBFUSCATION_CERTBIND_H

namespace llvm {
class ModulePass;
class PassRegistry;
class Module;
class GlobalVariable;

// VMP 入口桩密钥存被打的指令元数据标记名（aVMP 建 store 时打，见 aVMP.cpp:4011 附近）。
// CertBind 按此标记命中并"包裹当前值"，从而与 SelfCheck 的密钥折入顺序无关地叠加
// （无需要求 store 的值仍是 ConstantInt）。放在头文件里以避免 aVMP/CertBind 两处字面量
// 拼写分叉导致静默失配。
inline constexpr const char *NdkpVmpKeyEntryMD = "ndkp.vmpkey.entry";

// 由注入构造器填充的运行期证书混合值全局。
struct NdkpCertMixGlobals {
  GlobalVariable *Lo = nullptr;   ///< ndkp_cert_lo  = le64(sha[0:8]) ^ le64(sha[16:24])
  GlobalVariable *Hi = nullptr;   ///< ndkp_cert_hi  = le64(sha[8:16]) ^ le64(sha[24:32])
  GlobalVariable *K64 = nullptr;  ///< ndkp_cert_k64 = Lo ^ Hi（VMP 单 u64 密钥折入用）
};

// 幂等地在模块中建立证书绑定运行期基座：三个缓存全局 + 一个 .init_array 构造器
// （优先级 101；加载期在原生上下文调用外部 helper ndkp_certbind_mix 读取当前 APK 签名
// 证书摘要并缓存到上述全局——与 jni.cpp initCertMix 同理，刻意不在 VMP 帧内跑）。首次
// 调用创建，之后按名返回既有全局。供 StringEncryption（字符串 pepper 折入）与 CertBind
// pass（VMP 密钥折入）共用同一份基座，避免重复注入构造器。
NdkpCertMixGlobals getOrCreateNdkpCertMix(Module &M);

ModulePass *createCertBindPass();
void initializeCertBindPass(PassRegistry &Registry);

} // namespace llvm

#endif
