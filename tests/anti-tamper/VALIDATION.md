# 裸 syscall 与 CSE region 验证（2026-10-18）

实现分支：`feat/raw-syscall-cse`，基于 `f2ac7ef`，patchset `p6`。
LLVM-Patch 原工作区的 CSE v2 改动未带入；QDReaderHook 在现有目录接入。

## 构建环境

- Windows x86_64 / MSVC 14.51；完整重编两套 overlay 的 26 个编译单元，再与不变的缓存 LLVM 库重链接 Clang，输出位于本工作树 `work/build-20`、`work/build-21`。
- LLVM 20：`f142f8afe21bceb00fb495468aa0b5043e98c419`；LLVM 21：NDK r30 Base revision `2d287f51eff2a5fbf84458a33f7fb2493cf67965`。两套 registration.patch 均在对应提交的原始文件上通过 `git apply --check`。
- Android 编链使用 NDK `30.0.16248370` 的 sysroot/runtime；LLVM 20 是兼容性测试构建，未另外装配 LLVM 20 NDK 发行包。
- `vm.h` 使用 NDK Clang 19 经 `gen_vm_bitcode.sh` 重生成，以保证 LLVM 20/21 均能读取。
- 设备：OnePlus 7 / GM1901 / arm64，ADB `192.168.43.102:5555`。

## 已通过

- 两套 Clang：四 Android ABI 的 O0/O2 原生 syscall helper、DetectUtils IR 和目标文件编译；含 PIC、帧指针及 debug 输出路径。IR 中响应函数无 libc getpid/kill/syscall/write/abort/exit 调用。
- 两套 Clang：宿主 string-enc roundtrip、lifetime、cert-bind roundtrip。
- 两套 Clang：CSE 的 O0/O2/Oz、full/thin LTO 编链与设备语义、strip、未封装拒绝、代码/tag 篡改、包名与私有进程、libc 输入伪造；各配置 IR 均为三指针 region ABI。
- CSE region：正常 8/16-bit 输出、完整记录交换、capacity/ordinal/tag 篡改、错误 region 位置、输出容量和编码失配、无效 offset/count/null region、认证有效但长度为奇数的 UTF-16。失败退出 127、stderr 为空、共享输出缓冲区未写入。
- 描述表审查修复：原先只修改 module/region 数据即可将认证有效的 37 字节记录写进 16 字节输出区。现在 region 表进入 RX 摘要范围，模块入口核对字段并传递快照；两套 Clang 在 Android API 29 默认布局下，O0/O2/Oz、full/thin LTO、CIE/IGV/ICall/FLA/IBr 组合均通过 `tests/cse-hardened/descriptor_test.py`。每种配置验证模块重定向、联动记录交换、未使用 region 篡改、blob/cache/total/count 改写及非 RX 表布局，均静默退出 127。
- 两套 Clang：自校验 release/debug × 正常/篡改 × 允许/拒绝 kill syscall。替换 libc getpid/kill/syscall/write 后正常样本退出 0，篡改退出 137，kill 被 seccomp 拒绝时退出 127；debug 裸 write 仍能输出诊断。
- 原生裸终止：替换 libc getpid/kill/tgkill/raise/syscall 后 SIGKILL 仍生效，seccomp 拒绝 kill 时 exit_group 兜底生效。
- LLVM 21：string-enc、anti-tamper、fingerprint-scrub、四 ABI、CMake/ndk-build、cert-bind 冒烟；VMP 并发、递归、回调、全局地址和 TLS 的设备语义。
- LLVM 21：hardened 证书绑定，base/split × extracted/direct × 正确/错误证书，8 种设备组合。
- QDReaderHook：O0/O2 和 CSE+VMP+selfcheck 原生自检；自身两个信号过滤、其他进程/进程组透传、无效信号/线程、缺失原函数及 errno；过滤生效后裸终止仍能结束子进程。
- Python：LLVM CSE 13 项、overlay 25 项；QDReaderHook 构建来源/封装 33 项。Windows overlay 测试显式指定 Git Bash，构建系统测试使用本机 Ninja。

## 应用产物

本机 NDK 已按工具白名单更新为修复版 LLVM 21，并写入本地 p6 元数据。替换前的三个编译器及 source.properties 保存在本工作树 `work/sdk-before-raw-response`。

通过临时 Gradle init 使用全新 native 构建目录运行 `:native:updatePrebuilt`，更新预编译 SO、来源记录和绑定证书。随后通过全记录认证、来源一致性检查及 `:app:assembleDebug`；APK 内 SO 与预编译 SO 的 SHA-256 相同。

- dev 合并后重编的 SO 大小：969,544 字节。
- SHA-256：`750547e4cb2845057676ae8e243ccc85ecb37a86a4db8afb9c95b8b07348634d`。
- 导出保持 JNI/NativeGuard/native_init；CSE helper 未公开导出，固定校验失败字符串已移除。

合入 dev 后使用缓存 LLVM 库再次重链接 LLVM 20/21，更新本机 LLVM 21，并在新的 native 构建目录重新编译。新产物通过完整 CSE 记录认证、源码与编译器来源核对、Debug APK 签名证书核对、SO 一致性及 ZIP/ELF 16 KiB 对齐检查。上文设备回归针对相同源码的上一轮构建，本轮随机化产物未重复执行设备回归。

未安装或重启真实宿主应用，未完成 LSPosed 宿主及 16 KiB 页设备验收，未发布 Release。裸 syscall 不抵抗直接修改响应指令或内核层拦截。
