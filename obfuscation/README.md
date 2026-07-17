# 混淆 overlay

overlay 按 LLVM major 分目录，由 `scripts/apply_overlay.sh` 应用到 llvm-project。

```text
obfuscation/llvm-<major>/
  Transforms/Obfuscation/   -> llvm/lib/Transforms/Obfuscation/
  include/                  -> llvm/include/llvm/Transforms/Obfuscation/
  registration.patch       -> llvm-project 根目录
```

当前维护 `llvm-20` 和 `llvm-21`。构建时以 NDK 包内 `AndroidVersion.txt` 的 major 为准，不根据 NDK tag 推测。`build` 模式找不到对应目录时失败。

## 注册方式

`registration.patch` 只修改 `llvm/lib/Transforms/CMakeLists.txt`：

```cmake
add_subdirectory(Obfuscation)
```

`Transforms/Obfuscation/CMakeLists.txt` 使用 `add_llvm_pass_plugin` 构建静态插件，`ObfuscationPlugin.cpp` 通过 `registerOptimizerLastEPCallback` 注册。构建参数 `LLVM_OBFUSCATION_LINK_INTO_TOOLS=ON` 将插件链接到 clang。

一期不修改以下文件：

- Clang Driver；
- `PassBuilderPipelines.cpp`；
- `Options.td`；
- AArch64 后端。

## 目录内容

```text
Transforms/Obfuscation/
  CMakeLists.txt
  ObfuscationPlugin.cpp
  ObfuscationPassManager.cpp
  ObfuscationOptions.cpp
  CryptoUtils.cpp
  StringEncryption.cpp
  Flattening.cpp
  IndirectBranch.cpp
  IndirectCall.cpp
  IndirectGlobalVariable.cpp
  ConstantIntEncryption.cpp
  ConstantFPEncryption.cpp
  Utils.cpp
  LegacyLowerSwitch.cpp
```

各 pass 仍使用 legacy `ModulePass`，由 `ObfuscationPassManagerPass` 接入 new PM。

## 开关

所有开关通过 `-mllvm` 传入：

| 开关 | 功能 |
| --- | --- |
| `-irobf` | 总开关 |
| `-irobf-cse` | 字符串加密 |
| `-irobf-cie` | 整数常量加密 |
| `-irobf-cfe` | 浮点常量加密 |
| `-irobf-fla` | 控制流平坦化 |
| `-irobf-indbr` | 间接跳转 |
| `-irobf-icall` | 间接调用 |
| `-irobf-indgv` | 间接全局变量访问 |
| `-level-*` | 强度，范围 1 到 3 |

没有开关时不得执行 IR 变换。函数注解定义在 `include/ndkp.h`；当前注解仍需配合对应总开关。

AArch64 后端混淆和对应的 Driver 参数尚未实现。

## 适配新版本

1. 复制最近的 major 目录。
2. 在目标 NDK 的 `Base revision` 上运行 `git apply --check`。
3. 构建 clang。
4. 运行 `tests/string-enc` 和受影响的 ABI 测试。
5. 验证后再加入自动发现支持。

本目录新增代码按 GPL-3.0 分发；保留的 LLVM 和 LibTomCrypt 代码按其原始许可分发，见仓库 `LICENSES/`。
