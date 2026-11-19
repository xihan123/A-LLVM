# main-only TU 诊断回归

覆盖 LLVM 20/21 中七种 main-only 检测的普通跳过与 strict 契约。
使用相应源码构建的 Clang 和独立候选 NDK；不覆盖已安装 SDK。

```powershell
python -B tests/main-entry/check.py --clang <候选clang.exe> --ndk <候选NDK目录> --work-dir work/main-entry-21
```

每个 major 使用不同 `--work-dir`。脚本持久保存命令、逐命令日志、IR、object、共享库及
`report.json`。资源目录由实际候选 Clang 的 `--print-resource-dir` 查询，要求位于所传 NDK
的 `lib/clang` 下且包含 `include`；查询命令及输出也写入日志和报告，不按目录名大小选头文件。
因此 `--clang` 应指向已装入该候选 NDK 的编译器。检查：

- O0/O2 下 no-option 与 strict-alone 的 IR 完全一致；仅跳过检测也保持无 main IR。
- 七开关逐项及组合，在无 main、仅声明 main 时输出带源模块标识的逐项 warning；strict 失败。
- 有 main 时 strict 允许注入，并逐项确认 main 调用了对应检测 helper；这些产物只静态检查。
- 同一 Clang 命令编译 main 与辅助 TU 时，仅辅助 TU 警告；另一 TU 的 main 不满足 strict。
- 无 main 的 object 和真实 arm64 SO，在普通、strict-alone、七项跳过三种模式下逐字节一致，
  因此用户已有的 `JNI_OnLoad` 和构造器没有被此批修改。

可加 `--serial <adb序列号>`，用不带检测开关编译的 loader 加载**无 main**的共享库，
核对既有构造器、普通函数和显式 `JNI_OnLoad` 的返回值。设备端仅运行这份安全 fixture；
含 main 的七种旧检测从不在设备运行。未传 serial 的报告明确记录设备验证未完成。

该测试只证明当前 TU 的诊断和跳过语义，不声明整个最终 SO/进程没有其他保护，
也不代表七种旧检测已经完成运行期有效性或兼容性验收。
