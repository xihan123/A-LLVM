# p18-candidate1 / dex2c 0.1.13-hardening1

当前为本地候选，不覆盖 p17 或 0.1.12，不向远端发布。
与接入项目的分阶段验收实施记录对应，细节在接入项目侧维护。

## 阶段3：认证与产物绑定

- QSEG 封装拒绝重复资源身份、非法种类/长度与错误 ELF ABI，防止同域材料被复用。
- 最终 APK 校验拒绝错误 SO ABI、额外 QSEG、重复方法/符号、未知策略及自洽但过期的段回执。
- 对 QSEG 的本地 ZIP 头、中央目录、标志、CRC、长度与边界使用运行时相同约束。
- 保留 ChaCha20-Poly1305 / HKDF / 先认证后解析解压；未修改算法。

2026-10-22 主机验证：QSEG 15项、最终签名APK验证14项通过；
覆盖认证后畸形压缩流、超长恢复、尾随数据、错误身份、三构建材料差异和域分离。
最终 APK 测试使用既有签名 fixture，不能当作新候选 runtime 的设备验收。

## 阶段4：生命周期候选

已实现隐藏 acquire/release/stats v1、引用计数、1MiB 空闲 LRU、清零解除映射。
旧裸指针接口永久固定驻留；未知原生异常展开的 VM 同样固定，并逐函数写入回执。
编译器、dex2c 和最终 APK 校验器联合核对生命周期；不改 QSEG 二进制格式或密码算法。

独立候选 NDK：`build/hardening-candidate/ndk`，本地插件仓库：
`dex2c/build/hardening-candidate-maven`。稳定 SDK SHA256 未变化，详见候选 manifest。
LLVM21 overlay 精确基线应用检查、候选 Clang 构建、现有字符串/ABI/证书/自检主机检查通过。
真实编译器测试 `tests/qseg/compiler_lifetime.py` 确认 noexcept 借用、未知展开固定驻留。
OnePlus7 4KiB：独立 runtime O0/O2 并发/嵌套/异常API/旧接口/清零拦截测试通过；
实际签名 fixture Java/Kotlin 语义和篡改拒绝通过；真实隐藏接口九次借用释放后 active=0、
idle=32768、pinned=0，只读写入退出139。真实签名探针未覆盖跨64KiB块，不能扩大此结论。

验证日志及 JSON 位于 `build/hardening-candidate/` 和 `build/hardening-lifetime-tests/`。
复测命令见 `runtime/QSEG.md` 和各 Python CLI 的 `--help`；测试时必须配套候选编译器、
签名 APK 和其未剥离 linked.so，不混用稳定版本。

## 阶段5—6

三份相同业务类/证书的fixture中，55个VM的资源标识、密文摘要、函数密钥摘要和分派顺序均有三向差异，
Java/Kotlin实机语义相同；验证脚本 `tests/qseg/build_diversity.py`。
三个接入模块的最终签名APK已通过DEX包装、SO/QSEG/签名/回执一致性及认证恢复审计；
指定关键入口及继承Hook覆盖门禁通过。三个宿主各三次启动冒烟通过，测试后恢复原模块。

冻结源码46ed166与稳定p17编译器重新构建基线fixture：30组热路径交替配对比值中位数0.986412，
bootstrap95%区间[0.961741,1.013423]，通过<=1.03；只涵盖该预热VM工作负载。
接入模块独立Trace诊断APK，计入install/lateInit并合并嵌套：命中/未命中各30次，
未命中P95=1027.9ms未通过1秒门禁；命中P95=618.2ms、中位数595.9ms，未达500ms争取目标。
默认无Trace源码与候选产物已恢复，不能据诊断数据声称默认产物已通过。

API26 / 真实16KiB / 完整业务回归 / 真实启用停用的完整启动差值仍未验证。
包管理器禁用探测仍存在注入事件，其am start差值作废。
当前只保留候选，不发布正式版本。完整证据、逐产物哈希与剩余门禁在接入项目侧记录
（`docs/security/evidence/top-tier-step6.json` 和 `top-tier-release-gate.json`），不在本仓库保留。
