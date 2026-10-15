# 稳定性修复验证记录（2026-10-15）

本记录对应 p1 修复及后续代码清理；CI 验证版本为 `5634b305effd549161211d36f6e7bf91235d46e9`。

## CI 构建（已启动，结果待定）

| NDK / LLVM | Linux | Windows |
| --- | --- | --- |
| r30 / LLVM 21 | [38742852164](https://github.com/xihan123/A-LLVM/actions/runs/38742852164) | [38742858923](https://github.com/xihan123/A-LLVM/actions/runs/38742858923) |
| r29-beta1 / LLVM 20 | [38743051472](https://github.com/xihan123/A-LLVM/actions/runs/38743051472) | [38743058073](https://github.com/xihan123/A-LLVM/actions/runs/38743058073) |

四组均使用 `mode=build`、`patchset=p1`、`AArch64;ARM;X86`，只生成验证产物。该提交的 [checks](https://github.com/xihan123/A-LLVM/actions/runs/38742592937) 已通过。

LLVM 20 基线已从官方 r29-beta1 Linux 安装包确认：`AndroidVersion.txt` 为 `20.0.0 / r547379`，`clang_source_info.md` 的 Base revision 为 `f142f8afe21bceb00fb495468aa0b5043e98c419`。`registration.patch` 已在该提交的 `llvm/lib/Transforms/CMakeLists.txt` 上通过 `git apply --check`；完整编译和语义回归以 CI 结果为准。

## 环境

- Host：Windows x86_64，MSVC + Ninja，Git Bash。
- 基座：官方 Windows NDK r29；LLVM 21 精确 Base revision `386af4a5c64ab75eaee2448dc38f2e34a40bfed0`。
- 构建：将 LLVM 21 overlay 应用到上述源码，构建 `clang` / `clang-resource-headers`，按白名单组装隔离的测试 NDK。
- 设备：Android 17 / API 37，arm64-v8a。
- APK 工具：build-tools 36.1.0、android-35/android.jar、JDK 21、OpenSSL。

## 修复与结果

| 项目 | 验证结果 |
| --- | --- |
| CSE 静态生命周期、原子初始化 | Windows：plain/CSE/perkey × O0/O2/Oz，每组合独立运行 3 次，16 线程；逃逸指针、分支、聚合表、4608 字节共享串及线程退出后访问全部通过 |
| CSE Android 行为 | 同一生命周期测试样本交叉编译后在 arm64 设备运行，CSE/perkey × O0/O2/Oz 全部通过 |
| 常量加密 APInt 乘积 | Windows：整数/浮点 × O0/O2/Oz × level 1–3，与独立未混淆调用方的期望结果一致 |
| 证书 helper 独立编译 | 宿主正确证书解出明文、错误证书不解出明文；helper 定义与 cert-bind 同编译单元的误配置被明确拒绝 |
| VMP TLS 与名称选择递归 | arm64 设备：plain/VMP/VMP+SelfCheck，8 线程、递归、VM→native→VM 回调，与独立原生参考实现一致 |
| 实际 APK 证书绑定 | CSE、VMP、CSE+VMP+SelfCheck 三组：正确签名全部 `OK`；错误签名分别为 `BAD`、`START`、`START` |
| NDK 集成 | 四 ABI 编链、字符串扫描、证书静态检查、anti-tamper 静态检查、fingerprint-scrub、CMake 与 ndk-build 冒烟、包结构/元数据检查均通过 |
| 基础脚本 | discovery 10 项、locate-llvm 1 项及 build-system-smoke runner 测试通过 |
| 补丁 | 两份相同 registration.patch 在干净 r29 LLVM 21 基线上 `git apply --check` 通过；不作为 LLVM 20 基线验证 |
| 源码一致性 | 两套 overlay 各 54 文件逐字节一致；Python 和逐文件 Bash 语法检查、`git diff --check` 通过；生成的 vm.h 与 registration.patch 未修改 |

APK 测试先写入 `START`，受保护调用完成后才写 `OK` 或 `BAD`。错误签名停留在 `START` 只证明观察窗口内未完成成功路径，不证明具体崩溃信号。每组先验证正确签名；临时 APK 使用随机包名并在结束时卸载。

## 重跑命令

在仓库根目录的 Bash/Git Bash 中执行。`CLANG` 指向本机可运行的自建编译器；`NDK` 指向组装后的 NDK。设备测试需要 `adb` 在 PATH 中，并显式设置 `SERIAL`。

```bash
# Windows 宿主；Linux 改为 x86_64-unknown-linux-gnu。
TARGET=x86_64-pc-windows-msvc
bash tests/string-enc/roundtrip.sh "$CLANG" --target="$TARGET"
bash tests/string-enc/lifetime.sh "$CLANG" --target="$TARGET"
bash tests/constant-enc/roundtrip.sh "$CLANG" --target="$TARGET"
bash tests/cert-bind/roundtrip.sh "$CLANG" --target="$TARGET"

# HOST 为 windows-x86_64 或 linux-x86_64。
bash tests/abi-smoke/run.sh "$NDK" "$HOST"
bash tests/string-enc/check.sh "$NDK" "$HOST"
bash tests/cert-bind/run.sh "$NDK" "$HOST"
bash tests/anti-tamper/run.sh "$NDK" "$HOST"
bash tests/fingerprint-scrub/run.sh "$NDK" "$HOST"
bash tests/build-system-smoke/run.sh "$NDK" "$HOST"
bash tests/package-layout/check_layout.sh "$NDK" "$HOST"

# 无 SERIAL 参数时 VMP 脚本只编链，不运行设备样本。
bash tests/vmp/roundtrip.sh "$NDK" "$HOST" "$SERIAL"
python tests/cert-bind/device_roundtrip.py \
  --ndk "$NDK" --build-tools "$BUILD_TOOLS" --android-jar "$ANDROID_JAR" \
  --java-home "$JAVA_HOME" --serial "$SERIAL" --openssl openssl
```

`build-system-smoke` 要求 CMake/Ninja 在 PATH 中；包结构检查要求先运行 `scripts/make_release_meta.py`。宿主往返测试调用原生可执行文件，不能用 Android target 替代宿主 target。

设备 CSE 验证使用 `tests/string-enc/lifetime.c` 与 `lifetime_driver.c`：driver 独立以 O2、无混淆编译；fixture 以 O0/O2/Oz 和 CSE/perkey 编译，链接成 arm64 可执行文件后通过 adb 执行。本轮该矩阵为手动执行；自动设备脚本目前覆盖 VMP 和 APK 证书绑定。

## 行为边界与剩余验证

- 解密后的字符串保留静态存储期，明文会在首次使用后驻留内存；不再在基本块结束时清零，以维持原始字符串字面量的指针语义。
- 证书 helper 必须单独编译、不带混淆并关闭 LTO；集成示例见 [runtime/README.md](../runtime/README.md)。
- VMP 解释器仍仅支持 arm64，C 输入也需链接 libc++；本轮未验证信号处理器重入或异常传播。
- CSE/FLA 正向注解不是函数白名单；所有功能仍需要开关。此次未引入 annotation-only 模式。
- Linux、LLVM 20 与 r30 较新 LLVM 21 基线的完整构建已启动，尚无最终结果。两套 overlay 字节一致不代替各自基线测试。
- CI 新增宿主语义测试与 Android VMP 编链；CI 不自动执行 adb 设备测试。
- anti-tamper 本轮做了静态检查及未篡改的组合语义回归，未重跑篡改后终止的设备矩阵。

下一步检查四组 CI 的构建与回归结果；通过后再推进 [路线图](../ROADMAP.md) 中的性能/体积基准及功能扩展。
