# p8 VMP 内存操作验证

目标是减少原生调用分发函数泄露定长比较/复制的语义，不改变无开关构建。
实现与边界见 [VMP 回归说明](../tests/vmp/README.md)。

## 实现

`-irobf-vmp-memops` 默认关闭，仅处理已经选中且交给 VMP 的函数。长度上限为 64 字节；
标准 `memcmp` 保留无符号字节的首差符号，标准 `memcpy` 保留返回地址，零长度不访问内存。
保留动态/大块操作、用户定义函数、`nobuiltin`、volatile、特殊地址空间、musttail 和 operand bundle。
展开发生在常规优化之后、字节码生成之前，后续原生优化无法重新把这些字节码折回 libc 调用。
提交前的 p9 复核补齐拒绝边界：先执行 VMP eligibility 检查，拒绝时不展开；
实际展开后若翻译失败则报编译错误，避免留下原生展开代码和孤立收据。

函数/别名地址现在与全局变量共用真实地址槽，由入口写入运行时地址；修复返回回调时错误引用零槽。
O0 重建入口时移除 `optnone`，避免与入口的 `alwaysinline` 属性冲突。
本轮未改动解释器源或生成的 `vm.h`。

## 本地验证

Windows x86_64，设备 OnePlus 7 GM1901、arm64、4 KiB 页：

| LLVM | Base revision | 结果 |
| --- | --- | --- |
| 20 | `f142f8afe21bceb00fb495468aa0b5043e98c419` | 构建、内存操作 O0/O2、回调指针/并发/递归/TLS、完整性复验通过 |
| 21 | `2d287f51eff2a5fbf84458a33f7fb2493cf67965` | 同上；接入项目生产接入通过独立设备自检 |

两版本 registration.patch 在精确基线文件副本上通过 `git apply --check`，
在对应已应用源码树上通过完整反向检查；注册补丁本身未修改。
25 项 overlay Python 回归通过。两版本通过字符串加密、四 ABI、CMake/ndk-build、
证书绑定静态检查及 anti-tamper 编链；冷/热状态、缓存边界、strip、LTO 与混淆组合的设备复验通过。
CI 增加内存操作编链检查，设备测试仍需显式提供序列号。

```powershell
python -B tests/vmp/memory_ops.py --ndk <独立NDK> --serial <序列号>
bash tests/vmp/roundtrip.sh <独立NDK> windows-x86_64 <序列号>
python -B tests/cse-hardened/recheck_test.py --ndk <独立NDK> --serial <序列号>
```

本地日志保存在 `work/memops-*.log` 和 `work/memops20-*.log`。
接入项目实际对象记录了 11 次比较、1 次复制，共六个业务函数；另外新增三个初始化/安装 VMP 目标。
发布门禁同时要求字节码、转换计数和新编译参数。完整性仍不保证行为不可观察。

未验证 Linux 宿主构建、真实 LSPosed 或 16 KiB 页设备；LLVM 20 沿用已有验证 NDK 布局，
不等同于官方 LLVM 20 NDK 整包认证。未执行发布，也未覆盖系统 SDK。
