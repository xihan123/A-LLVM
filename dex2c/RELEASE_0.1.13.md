# dex2c / strings 0.1.13 发布记录

日期：2026-10-22。按维护者要求将两款插件统一设为正式版本号 `0.1.13`。
当前尚未上传远端 Maven；上次源码提交为 `0d4c04f`，候选验证见
[字符串验证报告](STRINGS_VALIDATION.md)。旧候选记录保留原始版本与证据标识。

## 发布内容

发布 `io.github.xihan123.dex2c` 与 `io.github.xihan123.strings` 两个 plugin marker，
以及 `io.github.xihan123.dex2c` 下的 annotations、runtime、core、gradle-plugin。
六项 publication 共 90 个版本文件，上传后必须匿名下载逐字节核验。
仓库为 `https://mirrors.xihan.website/repository/maven-releases/`。

字符串插件支持指定包中的方法体常量、拼接片段与 UTF-16 边界；保留字段 ConstantValue、
注解、metadata 和资源。两个插件共用转换、证书/工具链配置、CSE/VMP 保护与一个 SO。
配置冲突拒绝构建，最终 APK 验签任一插件启用即生效，Debug 默认保留 ART 原实现。

本次不修改 LLVM pass 或工具链参数，不递增 patchset。仓库现有工具链版本为
`p18-candidate1`；其历史 QSEG 性能门禁状态不因插件正式版本号而改变。

## 下游接入与验收边界

消费项目 的 app、fanqie、qqreader 统一移除 lsparanoid，分别选择各自业务包和
`com.example.shared`。dex2c 先处理完整方法，字符串插件覆盖剩余方法，不叠加旧字符串混淆。
使用已有公开证书与同一 `dex2c.clang` 配置，保持现有 QSEG 与完整验签开关。

正式坐标重新执行发布检查：42 项 Gradle、22 项 Python 测试通过，90 个 staging 文件完整，
本机证据为 `dex2c/build/release-0.1.13-t0062486/manifest.json`；匿名检查确认版本尚不存在。
历史候选另完成 4 KiB 设备检查。API 26、真实 16 KiB 设备、Linux 消费者及真实业务完整启动/内存
验收仍有缺项；正式版本号不能用于声称这些验证已完成，也不解除下游既有发布门禁。
运行时明文与 Java 缓存可读取，公开证书不是秘密。

三个实际消费者从正式 staging 构建 Release 与最终分发 APK，R8、签名、证书、DEX、SO、
QSEG 和字符串保护核验通过。app/fanqie/qqreader 分别抽取 1829/549/513 条去重字符串，
2920/1136/1070 处引用；99 项应用单元测试及 56 项下游脚本测试通过。
本次未安装或运行新的 Hook APK；下游接入与原始证据位置见其 `docs/STRING_PROTECTION.md`。
