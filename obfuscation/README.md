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
  DetectUtils.cpp            # 反分析检测公共模块（report/kill、注入 main）
  IdaDetect.cpp             # 反调试
  TimeDetect.cpp            # 时间差反调试
  RootDetect.cpp            # Root 检测
  VmProtectDetect.cpp       # 模拟器/VM 检测
  BanDump.cpp               # 反内存转储
  HideMaps.cpp              # /proc/self/maps 隐藏
  FakeMaps.cpp              # 伪造 /proc maps
  aVMP/
    aVMP.cpp                # 函数级虚拟化（VMP）：IR→字节码 + 解释器链入
    aVMPCrypto.cpp
    aVMPDispatcher.cpp
```

各 pass 仍使用 legacy `ModulePass`，由 `ObfuscationPassManagerPass` 接入 new PM。VMP（`-irobf-vmp`）在流水线最前运行，其注入的解释器（段 `.AProtect.text`）被后续 CFG pass 按段名/函数名跳过。

## 开关

所有开关通过 `-mllvm` 传入：

| 开关 | 功能 |
| --- | --- |
| `-irobf` | 总开关 |
| `-irobf-cse` | 字符串加密 |
| `-irobf-cse-perkey` | 字符串加密强化：per-string 密钥由隐藏 pepper（分片存储）+ 串 id 经 ChaCha8 派生，密文表不再内联密钥 |
| `-irobf-cse-bind` | 字符串加密强化：把运行期包名（`/proc/self/cmdline`，截到首个 `:` 前）哈希折进 pepper，`.so` 仅在目标 App 内解出正确明文（错包名→乱码，非分支）。蕴含 `-irobf-cse-perkey`；也可用 `NDKP_STR_BIND` 注解，标签 `ndkp.str_bind` |
| `-irobf-cse-bind-package=` | `-irobf-cse-bind` 的期望包名（如 `com.example.app`；若误带 `:proc` 后缀会被自动截断）；bind 开启但缺此项则构建失败（fail-closed） |

> **多进程说明**：解码器把 `/proc/self/cmdline` 截到首个 `:` 前再算哈希，因此**主进程与所有 `android:process=":suffix"` 私有子进程**都能正确解密（私有子进程 cmdline 为 `包名:suffix`，去后缀即包名；合法包名不含 `:`，截断无歧义）。**不支持**全局命名子进程（`android:process="some.other.name"`，无前导 `:`）——其进程名与包名无关，绑定串在该进程内会 fail-closed 解出乱码；请勿在此类进程放置绑定字符串。
>
> **运行期开销**：包名哈希每进程只算一次（`ready` 缓存），文件 I/O 一次性；每条串受 `dec_status` 幂等守卫，**每进程至多解密一次**（惰性、首次使用时），无逐次访问开销。派生的 ChaCha 主密钥仅依赖 pepper（+包名），每串重算而**不缓存**——刻意让主密钥不常驻 RW 内存，避免一次内存 dump 离线解出整表。
| `-irobf-cie` | 整数常量加密 |
| `-irobf-cfe` | 浮点常量加密 |
| `-irobf-fla` | 控制流平坦化 |
| `-irobf-indbr` | 间接跳转 |
| `-irobf-icall` | 间接调用 |
| `-irobf-indgv` | 间接全局变量访问 |
| `-irobf-vmp` | 函数级虚拟化（VMP） |
| `-irobf-vm_functions=` | 指定 VMP 保护的函数，分号分隔（也可用 `NDKP_VMP` 注解，标签 `ndkp.vmp`） |
| `-irobf-vmp-noinline` | VMP 下强制禁用内联 |
| `-irobf-idadetect` | 调试器检测注入 |
| `-irobf-timedetect` | 时间差反调试注入 |
| `-irobf-rootdetect` | Root 检测注入 |
| `-irobf-vmdetect` | 模拟器/VM 检测注入 |
| `-irobf-bandump` | 反内存转储注入 |
| `-irobf-hidemaps` | `/proc/self/maps` 隐藏注入 |
| `-irobf-fakemaps` | 伪造 `/proc` maps 注入 |
| `-level-*` | 强度，范围 1 到 3 |
| `-irobf-debug` | 调试模式（默认关）。关闭时（release）额外做落地去指纹，见下 |

没有开关时不得执行 IR 变换。函数注解定义在 `include/ndkp.h`；当前注解仍需配合对应总开关。（`NDKP_STR_BIND` 会在模块级开启 bind 模式，但仍需 `-irobf-cse` 基础开关与 `-irobf-cse-bind-package=<包名>`。）

### Release 去指纹（`-irobf-debug` 关闭时，默认）

未开 `-irobf-debug` 时，所有混淆 pass 跑完后对整模块做一次去指纹，消除易被分析者用来识别工具链/定位 VM 的特征：

- **自曝段名改名**：`.AProtect.text/.data/.rodata/.bss` → `.s0/.s1/.s2/.s3`。ELF 段标志（AX/WA/A/NOBITS）由符号种类推导、与段名无关，故仅名字改变、布局与标志逐位不变。改名在流水线**最后**统一进行，不影响 Flattening/IndirectCall/VMP 在流水线中途按 `.AProtect` 前缀或 `aproc-vmp-artifact` 属性做的跳过。
- **VMP 调试串清除**：删除解释器中 3 个运行期门控的调试串 helper（`vm_debug_log_*`）及其落在 `.rodata` 的 `[vm-debug]…` 格式串与 `vm-entry`/`get-byte-after-chacha`/`vm-new-bb…` 等 stage 令牌。开 `-irobf-debug` 时保留这些串以便诊断。
- **clang 生产者横幅**：剥除本模块 `llvm.ident`（→ `.comment`）。

> **关于 `.comment` 的彻底清零**：编译期只能去掉**本模块**的贡献。最终 `.so` 的 `.comment` 还来自官方 NDK 的 CRT/libc++/compiler-rt 目标与 lld，工具链把链接后的 `.so` 直接交给用户、没有 link 后处理入口，故无法在 clang 内清零。需要时在 link 后自行执行 `llvm-strip -R .comment <输出.so>`（该工具已随 NDK 提供）。注意本项目的 clang 版本串与官方 NDK clang 相同，`.comment` **并非**混淆工具链的唯一指纹，此项为纵深防御。

VMP 已实现并本地验证（IR + clang codegen → 原生 aarch64 `.so`），设备语义等价验证前不发布（见 `DESIGN.md`）。检测类 pass（`-irobf-{idadetect,timedetect,rootdetect,vmdetect,bandump,hidemaps,fakemaps}`）注入到 `main`；构建为可执行文件时生效，构建为 `.so`（无 `main`）时自动跳过。

AArch64 后端混淆和对应的 Driver 参数尚未实现。

## 适配新版本

1. 复制最近的 major 目录。
2. 在目标 NDK 的 `Base revision` 上运行 `git apply --check`。
3. 构建 clang。
4. 运行 `tests/string-enc` 和受影响的 ABI 测试。
5. 验证后再加入自动发现支持。

本目录新增代码按 GPL-3.0 分发；保留的 LLVM 和 LibTomCrypt 代码按其原始许可分发，见仓库 `LICENSES/`。
