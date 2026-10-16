# VMP 回归测试

测试将受保护函数与独立编译的原生实现比较，覆盖：

- 全局整数、指针和 TLS 的地址槽。
- 结构体数组、多维数组、负下标及大于 255 字节的元素。
- 八线程并发、递归和 VM → native → VM 回调。

`roundtrip.sh` 测试 plain、VMP 和 VMP + SelfCheck；全局变量与索引用例分别使用 O0、O2。

```bash
bash tests/vmp/roundtrip.sh "$NDK" "$HOST" "$SERIAL"
python tests/vmp/test_gen_vm_bitcode.py
python tests/fingerprint-scrub/device_check.py \
  --ndk "$NDK" --host "$HOST" --serial "$SERIAL"
```

`HOST` 为 NDK 宿主目录名，例如 `windows-x86_64`。设备测试要求 `adb` 在 PATH 中。
不传 `SERIAL` 时，`roundtrip.sh` 只编译和链接。Windows 下运行 Python 测试前，
将 `BASH` 环境变量设为 Git Bash 的 `bash.exe` 路径。

自校验测试要求正常样本退出 0、篡改样本退出 137；检测横幅只出现在 debug 输出中。

## p3 验证（2026-10-16）

Windows x86_64 上完成 Clang 构建；设备为 arm64、API 37、4 KiB 页。

| LLVM | Base revision |
|---|---|
| 20 | `f142f8afe21bceb00fb495468aa0b5043e98c419` |
| 21 | `2d287f51eff2a5fbf84458a33f7fb2493cf67965` |

两个版本的全局地址槽、GEP、TLS 和自校验设备测试通过；四 ABI、字符串加密、证书绑定静态检查、
指纹检查、CMake 和 ndk-build 测试通过。LLVM 20 使用 NDK r30 的头文件、资源库、链接器和构建脚本，
尚未验证对应官方 NDK 整包。Linux、API 26 和 16 KiB 页设备未测。

## 生成解释器 bitcode

```bash
bash scripts/gen_vm_bitcode.sh "$CLANG" aarch64 20
```

最后一个参数选择 `20`、`21` 或 `all`，默认 `all`。生成器拒绝用新版 LLVM 向旧版 overlay 写入
bitcode；同时更新两个版本时，使用 LLVM 20。编译器需配置 Android sysroot。不要手改 `vm.h`。
