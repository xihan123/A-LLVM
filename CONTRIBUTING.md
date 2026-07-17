# 贡献指南

## 当前状态

- LLVM 20/21 overlay 已实现并通过本地编译测试。
- `tests/string-enc` 已在本机 NDK 上通过。
- GitHub Actions 完整构建和 Windows CI 尚未跑通。
- 阶段状态和已知问题见 [ROADMAP.md](./ROADMAP.md)。

## 开发环境

Python 脚本只使用标准库。Shell 脚本要求 Bash；Windows 可使用 Git Bash。

常用命令：

```bash
python scripts/discover_ndk.py --dry-run --channels stable,beta,rc
python tests/discover/test_discover.py

bash tests/package-layout/check_layout.sh <ndk_dir> <host>
bash tests/abi-smoke/run.sh <ndk_dir> <host>
bash tests/build-system-smoke/run.sh <ndk_dir> <host>
bash tests/string-enc/check.sh <ndk_dir> <host>
```

构建工作流可从 Actions 手动触发：

- `discover`：发现版本并构建全部选择的 Host；
- `build`：构建单个版本和 Host；
- `patch-check`：应用 overlay、构建工具链并运行测试，不发布。

## 代码路径

```text
scripts/discover_ndk.py       版本发现和 Release 去重
scripts/locate_llvm.py        读取 LLVM major 和上游 Base revision
scripts/apply_overlay.sh      将 overlay 应用到 llvm-project
scripts/overlay_ndk.sh        覆盖官方 NDK 工具
scripts/make_release_meta.py  写入构建和许可元数据
obfuscation/llvm-*/           LLVM major 对应的 pass 实现
tests/                        发布前检查
```

## 必须保持的约束

- `build` 模式缺少对应 LLVM major overlay 时失败。
- `Base revision` 缺失时失败，不回退到近似 LLVM 版本。
- 没有混淆开关时，overlay 不执行 IR 变换。
- 只覆盖白名单工具和 clang resource headers。
- 已有 Release 不覆盖；构建或参数变化时递增 `config/patchset.env`。
- 自动发布必须等待全部 Host artifact 完成，并生成一份总 `SHA256SUMS`。
- Python 脚本不增加第三方依赖。

## 修改 overlay

每个 LLVM major 使用独立目录：

```text
obfuscation/llvm-<major>/
  Transforms/Obfuscation/
  include/
  registration.patch
```

修改后至少执行：

1. `git apply --check`；
2. 最小 clang 构建；
3. `tests/string-enc`；
4. 受影响的 ABI 和构建系统测试。

同一实现复制到多个 major 前，应分别在对应的 NDK `Base revision` 上验证。

## 发布

`config/patchset.env` 是发布版本的一部分。以下变化需要递增 patchset：

- overlay 或 pass 行为变化；
- 编译参数变化；
- 工具覆盖白名单变化；
- 测试或打包规则导致产物变化。

自动发布由 `discover.yml` 聚合，不要让多个 Host job 直接写同一 Release。
