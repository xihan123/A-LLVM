set(LLVM_OBFUSCATION_LINK_INTO_TOOLS ON CACHE BOOL
    "Statically link the obfuscation plugin into clang" FORCE)

# 混淆源文件为 UTF-8（含中文注释/字符串）。MSVC 默认按本地代码页解析源文件，会把
# 多字节 UTF-8 序列误读为乱码，导致 "newline in constant" 等一连串解析错误；故对本
# 插件源强制 /utf-8。GCC/Clang 默认即按 UTF-8 处理，无需此项。
if(MSVC)
  add_compile_options(/utf-8)
endif()

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
  DetectUtils.cpp
  IdaDetect.cpp
  TimeDetect.cpp
  RootDetect.cpp
  VmProtectDetect.cpp
  BanDump.cpp
  HideMaps.cpp
  FakeMaps.cpp
  SelfCheck.cpp
  CertBind.cpp
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
