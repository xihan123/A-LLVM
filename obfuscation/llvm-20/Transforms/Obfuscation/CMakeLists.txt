set(LLVM_OBFUSCATION_LINK_INTO_TOOLS ON CACHE BOOL
    "Statically link the obfuscation plugin into clang" FORCE)

add_llvm_pass_plugin(Obfuscation
  CryptoUtils.cpp
  Utils.cpp
  ObfuscationOptions.cpp
  ObfuscationPassManager.cpp
  ObfuscationPlugin.cpp
  StringEncryption.cpp
  Flattening.cpp
  LegacyLowerSwitch.cpp
  IndirectBranch.cpp
  IndirectCall.cpp
  IndirectGlobalVariable.cpp
  ConstantIntEncryption.cpp
  ConstantFPEncryption.cpp
  aVMP/aVMP.cpp
  aVMP/aVMPCrypto.cpp
  aVMP/aVMPDispatcher.cpp

  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  Core
  Support
  Analysis
  IPO
  TransformUtils
  BitReader
  IRReader
  BitWriter
  Linker
  )

# aVMP.cpp 的 VMProtect 实现体在 #ifdef ENABLE_VMP 内（上游约定）；仅对该源
# 文件打开此宏，其余混淆源不受影响。
set_source_files_properties(aVMP/aVMP.cpp
  PROPERTIES COMPILE_DEFINITIONS "ENABLE_VMP")
