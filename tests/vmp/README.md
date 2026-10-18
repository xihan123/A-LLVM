# VMP 回归测试

测试将受保护函数与独立编译的原生实现比较，覆盖：

- 全局整数、指针和 TLS 的地址槽。
- 结构体数组、多维数组、负下标及大于 255 字节的元素。
- 八线程并发、递归和 VM → native → VM 回调。

`roundtrip.sh` 测试 plain、VMP、VMP + SelfCheck 和 VMP + SelfCheck + entry；全局变量与索引用例分别使用 O0、O2。

p7 新增 `-mllvm -irobf-selfcheck-entry`，必须同时开启 `-irobf-vmp` 和
`-irobf-selfcheck`。它在每次 VM 入口只重算当前函数的字节码哈希，将实测值折入入口密钥；
不重写共享累积值，保留递归和多线程语义。原加载期校验继续存在，不启用新开关时行为不变。
FNV-1a64 不是密码学认证，且不覆盖解释器机器码；需要覆盖本 SO 代码时在低频操作入口结合
`NDKP_CSE_RECHECK`，见 [CSE 文档](../../runtime/CSE_HARDENED.md)。

入口成本与当前函数字节码长度成正比；热路径先做性能验证。构造器之前、首次 VM 调用前及
首次调用之后的篡改回归位于 `tests/cse-hardened/recheck_test.py`，可用 `--clang` 指定本地编译器。

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
