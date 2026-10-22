# 路线图

`[x]` 已完成，`[~]` 已实现但未完成端到端验证，`[ ]` 未开始。

状态核对：2026-10-15。稳定性修复的环境、结果及未覆盖项见 [验证记录](./tests/VALIDATION.md)；历史 CI 成功不代表当前工作区修复已通过 CI。

## 阶段 0 — 骨架

- [x] 仓库结构、`config/`（`channels.json` / `patchset.env`）
- [x] 版本发现 `discover_ndk.py`（分通道、按 Host 出构建矩阵、按 tag 出聚合发布矩阵、资产完整性去重）
- [x] 上游基线定位 `locate_llvm.py`（读 `clang_source_info.md` 的 Base revision，取不到即失败；不包含 Android 下游补丁）
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
- [x] cmake + ninja 编 `clang` 和 `clang-resource-headers`（Linux：free-disk-space）；lld/strip/objcopy 保留官方版本
- [x] `overlay_ndk.sh` 白名单覆盖官方 NDK 的 `bin/` + resource include
- [x] 四 ABI、CMake toolchain、ndk-build 冒烟接入 `build.yml`
- [x] `mode=build` 缺少对应 LLVM major overlay 时 fail closed
- [x] Linux/Windows `mode=build` 端到端构建并发布（[2026-09-09 Actions](https://github.com/xihan123/A-LLVM/actions/runs/34327396203)，[r30 产物](https://github.com/xihan123/A-LLVM/releases/tag/r30-30.0.16248370)）

## 阶段 1c — 混淆一期

- [x] overlay `obfuscation/llvm-20/` 与 `llvm-21/`（各 54 文件，逐字节相同）
- [x] `registration.patch`（静态 pass-plugin，仅追加一行 `add_subdirectory(Obfuscation)`）
- [x] new-PM 插件注册 `ObfuscationPlugin.cpp` + legacy 适配器
- [x] 命令行开关：`-irobf` / `-irobf-cse` / `-irobf-cie` / `-irobf-cfe` / `-irobf-fla` / `-irobf-indbr` / `-irobf-icall` / `-irobf-indgv` + `level-*`
- [x] `apply_overlay.sh` 用 `git apply --check` 门控 registration.patch
- [x] Pass 实现（字符串加密 / 平坦化 / 间接化 / 常量加密），本地验证：WSL/clang-20 编译 13 个 pass 0 错误；真实 r29 NDK 的 aarch64-android21 上 `tests/string-enc` rc=0
- [x] 读 `llvm.global.annotations`：`readAnnotate` 把 `ndkp.string_encrypt`→`+cse`、`ndkp.fla`→`+fla` 折叠；需配合功能开关，CSE/FLA 正向注解不构成白名单。保持现有行为，已更正文档
- [x] CSE 解密缓冲区保留静态存储期；解密、聚合初始化及包名缓存采用原子一次性发布，修复逃逸指针失效与并发读取。Windows 16 线程及 Android arm64 回归通过
- [x] 常量加密改用 APInt 计算常量乘积，兼容不支持 Mul ConstantExpr 的较新 LLVM 21 基线；Windows LLVM 21 的 O0/O2/Oz × level 1–3 整数/浮点往返通过

## 阶段 2 — VMP（函数级虚拟化）

- [x] `-irobf-vmp` / `NDKP_VMP` pass（移植 aVMP：IR→字节码 + aarch64 解释器 `Linker::linkModules` 链入）
- [x] translator eligibility 校验（拒绝向量/token/异常处理函数，fail-safe 跳过）
- [x] 本地 IR + clang codegen 验证（trivial/scalar-loop/全 flag 同开；产出原生 aarch64 `.so`）
- [x] 修复 `vmp_debug_id` 链接（解释器该符号漏了 `extern "C"`→C++ 修饰名，pass 的 `getFunction` 找不到→undefined symbol；曾阻塞任何 VMP 二进制链接）。真机 arm64-v8a 语义验证：单函数（compute 循环 / 返回字符串）+ 与 perkey/bind/fla 组合 + 纯 VMP+fla 均正确
- [x] 多函数规模化 + **真正经解释器执行**：关键修复 `VMProtectPreparePass`（`PipelineStartEP` 早期给 VMP 目标打 `NoInline`+`llvm.compiler.used`，令 IPSCCP 停止参数追踪→调用点不被折叠）——此前"~1.0× 原生"实为函数被 inline/常量折叠掉、VM 桩死代码、根本没走 VM。同时修复 translator 循环/PHI 前向引用 bug（`basicblock_map` operator[] 污染致分支全跳 BB0 死循环；PHI 回边值未分配槽；PHI bb_id 未回填）。真机 arm64-v8a：直线/循环(LCG,FNV)/递归(fib)/内存(alloca,load,store,gep)/switch/VM→native/float 全 == 原生；旧"compute 挂死"已修。性能：真解释后 hot 循环 ~10000× 原生（故仅虚拟化小型/关键函数）；向量指令拒绝→安全回退原生。体积 +~1.8MB；剩：各 ABI 解释器扩展（当前仅 aarch64 bitcode）

- [x] VMP 稳定性（2026-10-15）：执行状态、每函数数据区、解释器缓存及调用栈改为 TLS，并统一按注解/名称列表判断递归调用。Android 17 arm64 的 8 线程、递归、VM→native→VM 回调及 VMP+SelfCheck 语义回归通过

## 阶段 1d / 2b — 编译期扩展保护

- [x] 反分析检测注入 `-irobf-{idadetect,timedetect,rootdetect,vmdetect,bandump,hidemaps,fakemaps}`
- [x] 代码完整性自校验 `-irobf-selfcheck` / `NDKP_SELFCHECK`（VMP 字节码内部校验：编译期对每函数字节码 blob `gv_code_seg_<fn>` 算 FNV-1a64 内嵌、注入 ELF 构造器加载期 volatile 重算比对、不符即 kill(SIGKILL)（主响应）；纵深防御层把哈希折进 VMP 密钥全局 `store (realkey^expected_acc)^runtime_acc`——**`VMProtectPreparePass` 修复 VMP 绕过后本层真机验证生效**：篡改→key 错→解释器解出乱码→崩溃，真正的密码学绑定非分支门禁（中和 kill 后未篡改仍正确、篡改即 rc=137）。真机 arm64-v8a：happy-path 正确、篡改即 SIGKILL。
- [x] 字符串加密强化 `-irobf-cse-perkey` / `-irobf-cse-bind` / `NDKP_STR_BIND`
- [x] APK 签名证书绑定 `-irobf-cert-bind` / `-irobf-cert-file=`（把运行期 APK 签名证书 SHA-256 派生的 128-bit 混合值折进 CSE 字符串 pepper 与 VMP 函数密钥——与包名绑定同范式的非分支、fail-closed 门禁；证书从磁盘 APK v2/v3 签名块双源共识读取，避开 `getPackageInfo`。字符串需 `-irobf-cse`、VMP 密钥需 `-irobf-vmp`；VMP 密钥折入按 `!ndkp.vmpkey.entry` 标记命中入口桩密钥存，排在 SelfCheck 之后以与其完整性折入叠加。运行期读证书由 app 侧链接 `runtime/ndkp_apkcert.cpp` 提供，其余 IR 自动注入。helper 已改为不带混淆、关闭 LTO 的独立目标，并增加误配置诊断；静态测试与真实 APK 的 CSE / VMP / CSE+VMP+SelfCheck 正确、错误签名回归均在 Android 17 arm64 通过）
- [ ] 函数级 SO 自加密 `-irobf-pack` / `NDKP_PACK` + `tools/ndkp-postlink` + `runtime/ndkp_rt.c`
- [x] `include/ndkp.h` 已有 `NDKP_STR_BIND` / `NDKP_SELFCHECK`；`tests/anti-tamper` 已接入构建
- [ ] 自加密配套 `NDKP_PACK` 宏与 `tests/pack-roundtrip`

## 阶段 3 — 后端扩展 / macOS

- [ ] AArch64 后端机器码混淆（`-aarch64-obfuscate-*`，独立补丁 hunk）
- [ ] macOS host（`darwin-x86_64`，dmg 解包 + macOS runner + 签名/公证）
- [ ] 历史版本回填、性能/体积基准

## 多 Host 支持

发现与构建层当前只接受两个已接线 Host；darwin 在阶段 3 接入后再开放：

- [x] `linux-x86_64`：完整流水线（repack/build 已有 CI 产物）
- [x] `windows-x86_64`：完整流水线（repack/build 已有 CI 产物）
- [ ] `darwin-x86_64`：见阶段 3

## 当前优先事项

按优先级排列：

1. 等待并检查当前 p1 的 Linux/Windows Actions 结果：r30 LLVM 21 两组构建已启动，链接见 [验证记录](./tests/VALIDATION.md)。本地 Windows r29 LLVM 21 构建及设备回归已通过。
2. LLVM 20 对应 r29-beta1（`20.0.0 / r547379`），实际 Base revision 为 `f142f8afe21bceb00fb495468aa0b5043e98c419`。补丁检查已通过，Linux/Windows 完整构建与回归已启动。双目录内容一致不等于双版本都已验证。
3. 新增宿主字符串生命周期、常量/证书往返，以及 VMP 样本编链已接入 `build.yml`；Android 设备测试仍需显式运行，发布前按 [验证记录](./tests/VALIDATION.md) 复测。
4. 注解独立开启 pass / annotation-only 模式暂缓；保持现有 opt-in 开关行为。完成稳定性门槛后再推进性能/体积基准、其他 ABI 解释器及后端扩展。
5. 构建加速按 [预构建复用计划](./BUILD_ACCELERATION_PLAN.md) 推进：先实现增量 overlay 同步，再验证 Linux/Windows 快照恢复；准备检查已完成，流水线尚未修改。

## 发版前必做

以下完成项记录历史流水线；p1 仍需完成上述当前优先事项 1–3。

- [x] 跑一次 `patch-check.yml`（`mode=build` / AArch64+ARM+X86），验证 overlay、四 ABI、构建系统与字符串测试全绿
- [x] Linux `mode=build` 全量（四 ABI）端到端跑通一次
- [x] Windows host 在 `windows-latest` 上跑通一次（先验证 repack，再验证 build）
- [x] `LICENSE` 换成完整 GPL-3.0 文本
