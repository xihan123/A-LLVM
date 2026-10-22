# QSEG v1 分段数据

仅支持 LLVM 21 / Android arm64 / API 26 及以上。发布版本为 dex2c `0.1.12` / A-LLVM `p17`。
`segmentedData` 的插件默认值保持关闭，由接入方显式开启。历史 `0.1.9` 保留为对照，
发布步骤和未完成设备验收见 [发布记录](../dex2c/RELEASE_0.1.12.md)。
不恢复联网授权，不处理机器码、整个 DEX 或预编译兼容层。

## 使用

Gradle dex2c 配置：

```kotlin
dex2c {
    segmentedData.set(true)
}
```

插件注册生成的 assets 目录，并为 `qseg` 后缀设置 STORED。每个业务翻译单元显式传入
`-mllvm -irobf-segmented-data -mllvm -irobf-segmented-output=<独立暂存目录>`，同时要求
hardened CSE 与证书绑定。LLVM 20 对新开关明确报不支持。

暂存目录仅用于构建，包含原始数据，不能打包。CSE runtime 的 derive/open VM 是引导区，
编译时只定义 `NDKP_QSEG`，不启用分段、CSE 或证书绑定。加载器独立编译，不使用 LTO。
链接 `-lz -Wl,--rosegment`，保证摘要槽在非执行只读区，引用描述在受代码摘要覆盖的 RX 区。

顺序：生成描述和暂存数据 → 链接 → `seal_qseg.py` 封装 → strip → 从最终 SO 与容器逐段
认证恢复并核对暂存内容 → 生成保护回执 → 打包、16 KiB 对齐、签名。

## 格式

SO 保留 512 字节只读 image，整数均为 little-endian：

| 偏移 | 内容 |
|---:|---|
| 0 | `NDKPQSG1` |
| 8 / 12 / 16 / 20 | 容器长度 / sealed=1 / cert flags=2 / chunk 数 |
| 24 | 16 字节随机模块及构建标识 |
| 40 / 72 | 32 字节 seed / salt |
| 104 | 48 字节构建输入占位；封装后清零 |
| 152 / 184 | 32 字节最终 RX 摘要 / seed mask |
| 216 / 220 | 目录长度 / ABI=ELF EM_AARCH64(183) |
| 224 | 32 字节保留零 |
| 256 | 128 字节 NUL 结尾 APK 内路径 |
| 384 | 32 字节容器 SHA-256 |
| 416 | 96 字节保留零 |

容器为 `QSEGDAT1` + u32 version=1 + u32 directory length，随后是加密目录、16 字节 tag、
按目录顺序连续存放的密文块。上限 256 MiB、16384 块；单资源上限 16 MiB。
目录条目为 64 字节：id[16]，kind、chunk、offset、stored length、restored length、
resource length、codec、ordinal 各 u32，tag[16]。kind 1 为 VM，2 为字符串块。

字符串按 LLVM 模块合并，目标块大小 32 KiB，超限单条独占；入口直接持块引用、偏移、长度和
编码，不再为每串放置幂次填充密文槽。VM 每函数分段，每块最多 64 KiB，第一次进入时恢复
整个函数为连续缓冲区。保留原内层 VM 编码、轮数、私有 opcode 和每次入口自校验。
调度比较稳定 token，调用帧保存该标识，与恢复后的字节码地址分别传递。

## 密钥、认证与加载

根密钥由原 VMP derive 入口结合实时 RX 摘要、公开签名证书和 image 派生。
HKDF-SHA-256 的 salt 使用 image salt；索引 info 为 `NDKP-QSEG-index-v1 || moduleID`，
块 info 为 `NDKP-QSEG-v1 || resourceID || kind:u32 || chunk:u32`。
每个域使用独立密钥与零 nonce；一次构建内 ID 不重复，构建 seed、salt 和模块标识随机。
索引 AAD 为容器前缀和 moduleID；块 AAD 为 moduleID 和目录条目前 48 字节。
派生密钥使用后擦除，不缓存。

先 raw DEFLATE level 6，至少节省 16 字节且节省比例达到 5% 才压缩，再使用
ChaCha20-Poly1305。目录先认证再解释；块先认证再解压，严格核对输入和输出长度。
VM 内层密文一般不能压缩，收益主要来自字符串合并与取消重复封装。

通过本 SO 映射定位所属 APK，复用证书、inode 和路径验证；不依赖宿主 AssetManager。
容器只能是该 APK 内唯一、中央及本地头一致的 STORED entry。初始化认证整个密文容器与
目录，不提前恢复所有业务块。首次访问在锁内恢复，全部成功后 mprotect 只读并发布；
旧 get 接口后续访问返回同一地址，固定驻留到进程结束，不写明文文件。失败终止，不回退。

p18 的 v1 生命周期接口 `ndkp_qseg_acquire_v1/release_v1` 使用 RX 描述符作为资源句柄，
锁内维护引用计数。活跃资源不回收；零引用资源按页计费，获取/释放触发 LRU，空闲预算 1MiB。
淘汰时映射改为可写、volatile 清零整个映射再 munmap；不新增后台线程。
旧 get 与借用混用时永久固定该资源。隐藏 `ndkp_qseg_stats_v1` 统计互斥的活跃、空闲、
固定驻留字节及驻留峰值、淘汰次数；统计范围仅为恢复资源映射，不是全部进程内存。

编译器仅对原函数具有 nounwind 契约的 VM 生成主借用，在解释器返回后、Java 异常分支前释放。
未知原生异常展开路径使用 `pinned-unproven-unwind`，不构成任意 C++ EH 的回收支持。
SelfCheck 临时借用成对释放；字符串复制在借用期间完成，交付给业务的副本保持原生命周期。
段回执记录 `lease-v1/copy-v1/pinned-unproven-unwind/pinned-legacy`，保护回执记录 ABI、预算及
逐 VM 策略；最终 APK 验证拒绝未知 ABI、缺失策略、分段与保护回执不一致的回收声明。

`ndkp_qseg_get/copy/verify/recheck` 为隐藏接口，原 CSE v1 ABI 保留。schema 5 保护回执
绑定最终 SO、容器、段收据、原函数及块摘要；schema 4 继续支持。最终校验工具：

```powershell
python tests/qseg/audit_apk.py --apk <apk> --protection <protection.json> `
  --segments <segments.json> --certificate <公开证书.der>
```

## 验证边界

离线 APK、公开证书和实现仍足以恢复内容。本设计增加跨文件认证、目录解析、分段恢复和
VM 分析步骤，不提供 APK-only 保密保证。MT 对 360 文件仅确认加载器/载荷分离，未还原其企业版算法。

`runtime-cache` 仅复用 variant 内的稳定 runtime 编译产物，键覆盖编译器内容、NDK 元数据、
编译参数、证书、全部捆绑源码及头文件、sysroot 和 resource headers；复用前核对内容摘要。
业务编译、链接、封装、strip 后验证和保护回执仍执行。干净构建删除此缓存。

必须区分回调累计、系统 am start 时间与完整启用/禁用启动增量。30 次回调测量不能替代
完整注入开销或 API 26 / 16 KiB 真机兼容验证。三个最终 APK 均缩小、性能无明显退步及
完整设备验收仍有缺项。p18 按维护者要求采用正式版本号，QSEG 继续默认关闭；
正式版本号不代表上述验收已完成。
