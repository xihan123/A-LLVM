# 双 Host 构建快照与 10 分钟验收

`build.yml`、`discover.yml` 和 `patch-check.yml` 的 `use_snapshot` 开关暂默认为 `false`，支持 Linux 和 Windows 的 `mode=build`；repack 自动跳过。四组热构建通过验收后才默认启用，显式 false 始终保留冷构建入口。

手动运行 `dev` 上的 `build`，勾选 `use_snapshot` 即开始试点。首次无缓存时冷构建；所有现有测试、打包和 NDK artifact 上传成功后，`dev` 或仓库默认分支才可保存快照。PR 不保存快照，不使用模糊恢复键，也不会发布 Release。

```bash
python -m unittest discover -s tests/build-snapshot -p 'test_*.py' -v
```

测试不下载或构建 LLVM。两种宿主都用 GNU tar 的 `--posix` 格式验证时间戳及只读文件归档往返。Windows 本地需设置 `SNAPSHOT_TAR=C:\Program Files\Git\usr\bin\tar.exe`；不要将整个 Git usr/bin 提到 MSVC 的 PATH 前面。脚本仍仅依赖 Python 3.11+ 标准库。

`patch-check` 默认验证 r29-beta1 / LLVM 20 与 r30 / LLVM 21 的双 Host。填写 `ndk_tag` 和 `internal` 可改为指定 NDK 的双 Host；两者须同时填写。

`snapshot_probe` 默认 `none`；`strings` 修改 StringEncryption.cpp，`vmp` 修改 aVMP.cpp，`multi` 同时修改这两个文件及 SelfCheck.cpp、Utils.cpp。样本仅向工作区源文件追加唯一注释，不改变语义；必须启用快照，不写缓存。每个样本都经过正常编译、完整测试、ZIP 解压验证与上传，不能将样本耗时替代无修改恢复耗时。

## 快照边界

- 缓存仅包含 `llvm-project/`、`build/`、`.llvm-build-snapshot.json`。官方 NDK 和发布 ZIP 每次重新组装。
- v2 精确键包含绝对工作路径、Base revision、major、host/架构、runner 镜像、Linux 系统包版本、编译器/链接器/CMake/Ninja/Python/GNU tar 的路径、版本和二进制摘要、有效 CMake 参数、注册补丁、overlay CMake 文件及构建辅助脚本摘要。Windows 另记录 MSVC、SDK、UCRT 及 INCLUDE/LIB/LIBPATH 环境。CMake 使用被记录的 Python 绝对路径。
- Pass 文件、仓库提交和 patchset 不进入键；来源提交与完整 overlay 摘要写入快照来源记录。恢复后仍同步当前提交的 overlay。
- 清单检查所有文件的 SHA-256、大小、mtime 和权限，以及目录、符号链接目标；另检查 LLVM HEAD、实际 CMakeCache 和关键生成文件。时间戳恢复丢失精度也会拒绝复用。
- 缺失、不完整或不兼容快照只清除工作区内两个固定构建目录，再走冷构建。当前提交的补丁、配置、编译和测试错误不会触发冷构建重试。
- 缓存键不可覆盖。若一个精确键的缓存内容损坏，后续运行仍可冷构建，但需要手动清除该缓存后才会重新保存；不能把无效缓存当作命中。

## 如何比较效果

1. 同一基线、host、targets，开启快照运行一次，确认冷构建通过全部测试并成功保存缓存。
2. 使用相同代码再运行一次，确认 `state.json` 中 `hit=true` 且 Ninja `compile_edges=0`。
3. 分别选择 strings、vmp、multi 样本重跑相同输入，确认缓存键不变、重编范围符合实际依赖、全部回归通过。每组三个样本 job 各小于 600 秒才达标。

每次构建上传 `build-metrics-<tag>-<host>` artifact，包含配置、样本名、命中原因、快照来源、计时及 Ninja 编译/链接输出列表。计时覆盖下载、解压、克隆、配置、同步、编译、NDK 组装、各测试、打包、包内工具验证、恢复校验和保存。`compile_work_seconds` / `link_work_seconds` 是 Ninja 任务耗时之和，不能当作并行构建的墙钟时间；总耗时以 Actions API 的 job started_at/completed_at 为准，另报告缓存未命中比例。

未压缩快照体积写入 `state.json`。压缩体积、下载/保存详情见 Actions Cache 步骤日志及仓库 Cache 页面；需要连同 runner 镜像和命中结果记录后再比较。只改变工具链、镜像或配置后发生的冷构建不算热构建样本。

包内 `NDKP-build-info.json` 记录当前仓库提交和快照来源，避免把基础快照的提交误当作当前产物版本。当前阶段使用 `p4`；达到计划中的真实 CI 验收标准前，保持默认关闭。
