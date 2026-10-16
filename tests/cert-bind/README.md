# 证书绑定回归

`test_apkcert.py` 编译并运行原生断言用例。它只替换 maps 内容与测试安装目录的路径，
fd、文件身份检查、ZIP 和签名块解析均使用真实实现。签名块夹具是合成数据，测试的是
证书提取及来源判断，不是 APK 整体签名验证。

```bash
# Linux，C++17；可通过 CXX 指定编译器。已接入 checks 工作流。
python tests/cert-bind/test_apkcert.py
# Windows 等宿主也可使用 NDK 编译，在 arm64 设备执行相同用例。
python tests/cert-bind/test_apkcert.py --ndk "$NDK" --serial "$SERIAL"

bash tests/cert-bind/run.sh "$NDK" "$HOST"
bash tests/cert-bind/roundtrip.sh "$CLANG" --target=x86_64-pc-windows-msvc
python tests/cert-bind/device_roundtrip.py \
  --ndk "$NDK" --build-tools "$BUILD_TOOLS" --android-jar "$ANDROID_JAR" \
  --java-home "$JAVA_HOME" --serial "$SERIAL" --openssl openssl
```

设备脚本需要 Android 6.0+ arm64、patched Clang、JDK 17+、OpenSSL，以及支持
`zipalign -P 16` 的 build-tools。它创建随机包名，退出时卸载测试包。模块 APK 位于
测试包自己的文件目录中，通过 `dlopen` 加载，不需要 Xposed 或 ART 打开模块 dex。

## 2026-10-16 本库 APK 定位验证

环境：Windows x86_64、patched NDK r30 / Clang 21、build-tools 36.0.0、
android-35/android.jar、JDK 21；设备为 Android API 37 / arm64-v8a。

| 检查 | 结果 |
| --- | --- |
| 原生来源与解析回归 | 66 项通过，另验证真实 `ndkp_certbind_mix` 公式及失败归零；每个来源用例均检查 fd 数量和失败时摘要不变 |
| 四 ABI 编译链接 | arm64、armv7、x86、x86_64，API 21，`-Wall -Wextra -Werror`、`--no-undefined` 通过 |
| 证书静态冒烟 | 构造器、符号门控、明文隐藏、缺证书构建失败均通过 |
| Windows MSVC roundtrip | 正确证书解密、错/缺证书失败、错误 helper 编译方式被拒绝，均通过 |
| 字符串加密扫描 | O0/O2/Oz 的 CSE、perkey、包名绑定均通过 |
| 真实 APK | base/split × 解压/直接加载 × CSE/VMP/组合 × 正确/错误签名，共 24 组通过 |
| 同进程两个库 | 每组均核对本库与独立签名模块的 SHA-256；模块也检查自己的 runtime 混合值 |

正确签名均返回 `OK`；错误签名的 CSE 返回 `BAD`，VMP 与组合模式停留在 `START`。
`START` 仅表示观察窗口内未完成受保护调用，不判定具体信号。

运行时使用显式 POSIX fd 清理，避免析构器引入的异常辅助符号与当前 VMP 产物发生
COMDAT 冲突。静态冒烟改为消费完整工具输出，避免 `grep -q` 在 `pipefail` 下导致
SIGPIPE 假失败。

本轮未在 Linux 主机执行新增用例（本机 WSL 无 C++ 编译器），已接入 Linux CI；
未重建 LLVM 20/21，未修改 overlay、NDK 产物或 patchset。32 位 ABI 仅做编译链接检查。
来源定位的安全边界见 [runtime 文档](../../runtime/README.md)。

## 提交前审查修复

发现并修复了官方 `zipalign` 的兼容性问题：它会给 ZIP 本地头附加不足 4 字节的
原始零填充，原实现将这种合法填充误判为损坏，导致包含已对齐 stored 资源的解压加载
APK 无法读取证书。已用 build-tools 30.0.3 与 36.0.0 实际生成并确认该格式。

解析器现在仅允许本地头尾部的零填充，中央目录的残缺字段、非零残片和 ZIP64 仍拒绝。
新增 1/2/3/5 字节填充与非零反例，修复前首个正例失败、修复后全部通过；设备矩阵另加
stored 资源，覆盖真实 `zipalign` 输出。四 ABI 编译链接及 Clang 静态分析通过。
