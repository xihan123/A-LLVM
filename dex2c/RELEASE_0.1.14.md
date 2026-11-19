# dex2c / strings 0.1.14 发布准备记录

日期：2026-11-19。已更新共同正式版本号并完成 Windows 本地构建和 Maven staging，**尚未上传**到远端。
六个 Maven 坐标的 `0.1.13` 均已发布；匿名下载确认其 90 个版本文件与既有 `published.json` 记录逐字节一致。
发布脚本检查六项坐标与 90 条文件路径，确认 `0.1.14` 当前未占用。上传必须保持版本不可覆写。

本次的两个修复和两个插件入口配置变更应通过新版本共同发布：

- 最终 APK 验证读取 UTF-8 清单时使用原始字节，修复 Windows 默认 ANSI 代码页无法解码含中文类名清单的问题。
- 空保护回执只有在方法与字符串选择均为空时才跳过 APK 检查；Java 与 Python 验证器以及回归测试保持相同规则。
- 两插件共享 Python 路径时，只将双方显式配置视为配置冲突；任一插件单独指定 Python 可由两者共同使用。
- 同步主插件、运行时依赖和 Java/Kotlin 样例到 `0.1.14`。两个插件仍使用同一共享插件包。

本次在 Windows、JDK 21、Gradle 9.9.1、NDK `30.0.16248370` 和本地 LLVM 21 上完成构建。
44 项 Gradle 检查、25 项 dex2c Python 检查、29 项 overlay 脚本检查、发现及工具定位测试通过。
字符串样例从本地 staging 解析插件，不使用 composite build；R8 Release、字符串模式、组合加载顺序、
构建缓存、零命中、错误配置和 APK 验证检查通过。生成 staging 时未连接设备；后续真机回归见下文。
staging、构建日志和 SHA-256 manifest 位于 `build/release-0.1.14-*/`。

### 真机回归（2026-11-19）

OnePlus 7（GM1901，API 37，arm64-v8a，4 KiB 页面）从 `release-0.1.14-z_j4gckw/maven` 安装消费者依赖，
R8 Release 下的字符串单独、dex2c 单独、两种组合插件顺序及最终 APK 验证均在 ART CheckJNI 下返回预期值 `87`。
dex2c 的 Java 与 Kotlin fixture 在 ART CheckJNI 下分别得到与基线相同的结果；错误签名和篡改 VM 均被拒绝。
最终 APK 验证器 15 项测试通过，4 项因当前 fixture 不包含相应可选场景而跳过。
设备记录位于 `core/build/device-fixtures/device-results.json`，字符串样例记录位于 `work/release-0.1.14-device-strings/results.json`。

此设备不是 16 KiB 页面设备，也没有覆盖 API 26、LSPosed 目标应用或 Linux 消费者；这些门槛仍待验收。

发布坐标为 `io.github.xihan123.dex2c:annotations|runtime|core|gradle-plugin:0.1.14`，
以及 `io.github.xihan123.dex2c` 和 `io.github.xihan123.strings` 的 Gradle plugin marker。
总计 90 个 Maven 文件。发布前应在本机环境重新运行：

```powershell
python scripts/publish_dex2c.py --check --clang $clang --ndk $ndk
```

只有待发布 staging 和本次源码一致、远端版本检查通过且授权凭据可用时，再使用已记录的
`--publish` 流程。发布成功须以生成的 `published.json` 和匿名逐字节远端核验结果为准。

本次 Maven 构建不能替代 API 26、真实 16 KiB 页设备、Linux 消费者、设备运行和目标应用业务门槛验收。
该 Maven 包不包含 Clang；启用 QSEG 等新编译器能力的接入项目须配套与源码匹配的 LLVM 21 / p18 工具链，
当前 NDK 的官方远端发布状态应单独确认。
