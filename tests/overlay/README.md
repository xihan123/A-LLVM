# 增量 overlay 回归

在仓库根目录运行，需要 Python 3、Git 和 Bash，不下载或编译 LLVM：

```bash
python -m unittest discover -s tests/overlay -p 'test_*.py' -v
```

从 Windows PowerShell 运行时，若 PATH 中的 `bash` 是 WSL 启动器，先指定 Git Bash：

```powershell
$env:BASH = 'C:/Program Files/Git/bin/bash.exe'
python -m unittest discover -s tests/overlay -p 'test_*.py' -v
```

测试使用临时目录，覆盖字节内容和 mtime 保持、过期源文件和可选头文件删除、重命名（含仅大小写变化）、中断后重试、越界清单、软链接、Windows junction、硬链接，以及 LLVM 20/21 注册补丁的首次应用、重复应用和异常状态。系统不允许创建软链接时，相应测试会明确跳过；junction 测试只在 Windows 运行。

同步器只管理 `llvm/lib/Transforms/Obfuscation/` 和 `llvm/include/llvm/Transforms/Obfuscation/`。每个目录用 `.ndkp-overlay-files.json` 记录相对文件路径，只有清单中已不存在于当前 overlay 的文件才会删除。首次接管旧的 `cp -a` 目录时，未知文件会保留；不能据此清除历史残留，快照应从有清单的干净构建生成。空目录会保留，文件与目录类型冲突会报错。

`apply_overlay.sh` 要求对应 major 的源文件目录和非空 `registration.patch`，缺少时失败。它先检查补丁是否可以正向应用或已完整应用，再同步文件；冲突或部分应用状态失败，不以冷构建重试掩盖错误。重复运行仍会同步当前提交的 overlay。

这些临时目录测试不代替各精确 LLVM 基线上的补丁验证、Clang 构建、NDK 回归或设备语义测试。
