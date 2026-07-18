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
