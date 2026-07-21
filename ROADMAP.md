# 路线图

`[x]` 已完成，`[~]` 已实现但未完成端到端验证，`[ ]` 未开始。

## 阶段 0 — 骨架

- [x] 仓库结构、`config/`（`channels.json` / `patchset.env`）
- [x] 版本发现 `discover_ndk.py`（分通道、按 Host 出构建矩阵、按 tag 出聚合发布矩阵、资产完整性去重）
- [x] 上游基线定位 `locate_llvm.py`（读 `clang_source_info.md` 的 Base revision，取不到即失败；不宣称包含 Android 下游补丁）
- [x] 元数据 `make_release_meta.py`（`Ndkp.*` + build/patch JSON + `LICENSES/`）
- [x] 覆盖脚本 `apply_overlay.sh` / `overlay_ndk.sh`
- [x] 工作流 `discover.yml` / `build.yml` / `patch-check.yml`
- [x] 测试 `tests/package-layout`、`tests/abi-smoke`、`tests/string-enc`、`tests/build-system-smoke`、`tests/discover`
- [x] 用户注解宏 `include/ndkp.h`（`NDKP_STR_ENCRYPT` / `NDKP_FLATTEN` / `NDKP_VMP`）

## 阶段 1a — 无修改重打包

- [x] `mode=repack`：下载官方 NDK、写元数据、打包、发不可变 Release
- [x] 包结构与追溯元数据测试接入 `build.yml`
- [x] 多 Host artifact 聚合后生成单一 `SHA256SUMS` 并发布一次

## 阶段 1b — 自建 clang（无混淆）

- [x] 浅克隆 `llvm-project@base_commit`
- [x] cmake + ninja 编 `clang;lld`（Linux：free-disk-space）
- [x] `overlay_ndk.sh` 白名单覆盖官方 NDK 的 `bin/` + resource include
- [x] 四 ABI、CMake toolchain、ndk-build 冒烟接入 `build.yml`
- [x] `mode=build` 缺少对应 LLVM major overlay 时 fail closed
- [ ] 在 CI 端到端跑通一次并归档产物（`mode=build` 尚未在 Actions 实跑）

## 阶段 1c — 混淆一期

- [x] overlay `obfuscation/llvm-20/` 与 `llvm-21/`（各 50 文件，逐字节相同）
- [x] `registration.patch`（静态 pass-plugin，仅追加一行 `add_subdirectory(Obfuscation)`）
- [x] new-PM 插件注册 `ObfuscationPlugin.cpp` + legacy 适配器
- [x] 命令行开关：`-irobf` / `-irobf-cse` / `-irobf-cie` / `-irobf-cfe` / `-irobf-fla` / `-irobf-indbr` / `-irobf-icall` / `-irobf-indgv` + `level-*`
- [x] `apply_overlay.sh` 用 `git apply --check` 门控 registration.patch
- [x] Pass 实现（字符串加密 / 平坦化 / 间接化 / 常量加密），本地验证：WSL/clang-20 编译 13 个 pass 0 错误；真实 r29 NDK 的 aarch64-android21 上 `tests/string-enc` rc=0
- [~] 读 `llvm.global.annotations`：`readAnnotate` 把 `ndkp.string_encrypt`→`+cse`、`ndkp.fla`→`+fla` 折叠；但注解无法独立开启混淆（见「已知缺陷」#3）

## 阶段 2 — VMP（函数级虚拟化）

- [x] `-irobf-vmp` / `NDKP_VMP` pass（移植 aVMP：IR→字节码 + aarch64 解释器 `Linker::linkModules` 链入）
- [x] translator eligibility 校验（拒绝向量/token/异常处理函数，fail-safe 跳过）
- [x] 本地 IR + clang codegen 验证（trivial/scalar-loop/全 flag 同开；产出原生 aarch64 `.so`）
- [x] 修复 `vmp_debug_id` 链接（解释器该符号漏了 `extern "C"`→C++ 修饰名，pass 的 `getFunction` 找不到→undefined symbol；曾阻塞任何 VMP 二进制链接）。真机 arm64-v8a 语义验证：单函数（compute 循环 / 返回字符串）+ 与 perkey/bind/fla 组合 + 纯 VMP+fla 均正确
- [~] 多函数规模化：真机 arm64-v8a 三函数嵌套虚拟化（`top→mid→leaf` 互调 + `main` 调用三者，各自独立 `gv_code_seg_*`）plain==VMP 输出一致；性能/体积实测——compute 循环 **~1.0× 运行时**（块体以原生 handler 存于解释器、仅控制流虚拟化，已核 `ror #51`/FNV 素数为原生），体积 **+~1.8MB 固定解释器/模块**、每增一函数 ~数十 KB。剩：各 ABI 解释器扩展（arm/x86/x86_64，当前仅 aarch64 解释器 bitcode）；控制流密集函数的开销刻画

## 阶段 1d / 2b — 编译期扩展保护

- [x] 反分析检测注入 `-irobf-{idadetect,timedetect,rootdetect,vmdetect,bandump,hidemaps,fakemaps}`
- [x] 代码完整性自校验 `-irobf-selfcheck` / `NDKP_SELFCHECK`（VMP 字节码内部校验：编译期对每函数字节码 blob `gv_code_seg_<fn>` 算 FNV-1a64 内嵌、注入 ELF 构造器加载期 volatile 重算比对、篡改即 kill；无需链接后回填工具/重定位归一化。真机 arm64-v8a：happy-path 正确、篡改即 SIGKILL、VMP-only 同篡改静默放过。待 CI patch-check）
- [x] 字符串加密强化 `-irobf-cse-perkey` / `-irobf-cse-bind` / `NDKP_STR_BIND`
- [ ] 函数级 SO 自加密 `-irobf-pack` / `NDKP_PACK` + `tools/ndkp-postlink` + `runtime/ndkp_rt.c`
- [ ] `include/ndkp.h` 增加扩展宏；新增 `tests/anti-tamper`、`tests/pack-roundtrip`

## 阶段 3 — 后端扩展 / macOS

- [ ] AArch64 后端机器码混淆（`-aarch64-obfuscate-*`，独立补丁 hunk）
- [ ] macOS host（`darwin-x86_64`，dmg 解包 + macOS runner + 签名/公证）
- [ ] 历史版本回填、性能/体积基准

## 多 Host 支持

发现与构建层当前只接受两个已接线 Host；darwin 在阶段 3 接入后再开放：

- [x] `linux-x86_64`：完整流水线（repack 可用；build 本地验证）
- [X] `windows-x86_64`：完整流水线（repack 可用；build 本地验证）
- [ ] `darwin-x86_64`：见阶段 3

## 已知缺陷

按优先级排列：

1. `registration.patch` 锚定 `add_subdirectory(HipStdPar)`。LLVM 20/21 已通过本地 `git apply --check`，仍需在 NDK 实际 Base revision 上跑 CI。
2. LLVM 21 不支持 `Utils.cpp:493` 使用的 Mul `ConstantExpr`。问题只在 `-irobf-cie`/`-irobf-cfe` 且 `level >= 2` 时触发，应改为 IRBuilder 指令或禁用该分支。
3. 注解不能单独启用 pass；仍需同时传入对应的 `-irobf-*` 开关。
4. 个别 namespace 注释不准确，部分 `#include <iostream>` 未使用。

## 发版前必做

- [x] 跑一次 `patch-check.yml`（`mode=build` / AArch64+ARM+X86），验证 overlay、四 ABI、构建系统与字符串测试全绿
- [x] Linux `mode=build` 全量（四 ABI）端到端跑通一次
- [x] Windows host 在 `windows-latest` 上跑通一次（先验证 repack，再验证 build）
- [x] `LICENSE` 换成完整 GPL-3.0 文本
