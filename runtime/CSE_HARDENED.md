# Android arm64 CSE v1

`-mllvm -irobf-cse -mllvm -irobf-cse-hardened` 显式启用字符串强化。LLVM 20/21 均支持，其他目标报错。它使用标准 ChaCha20-Poly1305 和 HKDF-SHA-256；旧 CSE/perkey/bind 模式不自动升级。

## 接入

将 `runtime/ndkp_cse_runtime.cpp` 作为 C++17 object 单独编译，关闭混淆、LTO 和异常；与业务 `.so` 链接。保留同目录的 `cse_crypto.h`、`cse_region.h`、`sha256.h`、`apkcert.h`、`apkcert_io.h`。使用 C++ 链接器并链接 libc++ 和 libdl；运行时只提供 hidden helper，不增加公开导出。

```cmake
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(NDKP_ROOT /absolute/path/to/LLVM-Patch)
add_library(ndkp_cse_runtime OBJECT ${NDKP_ROOT}/runtime/ndkp_cse_runtime.cpp)
target_compile_features(ndkp_cse_runtime PRIVATE cxx_std_17)
set_target_properties(ndkp_cse_runtime PROPERTIES
  POSITION_INDEPENDENT_CODE ON INTERPROCEDURAL_OPTIMIZATION OFF)
target_compile_options(ndkp_cse_runtime PRIVATE -fno-lto -fno-exceptions)
target_sources(your_lib PRIVATE $<TARGET_OBJECTS:ndkp_cse_runtime>)
target_link_libraries(your_lib PRIVATE dl)
target_link_options(your_lib PRIVATE "-Wl,--no-rosegment")
target_compile_options(your_lib PRIVATE
  "SHELL:-mllvm -irobf-cse" "SHELL:-mllvm -irobf-cse-hardened")
add_custom_command(TARGET your_lib POST_BUILD
  COMMAND ${Python3_EXECUTABLE} ${NDKP_ROOT}/scripts/seal_cse.py
    --input $<TARGET_FILE:your_lib> --output $<TARGET_FILE:your_lib>.sealed
  COMMAND ${CMAKE_COMMAND} -E rename
    $<TARGET_FILE:your_lib>.sealed $<TARGET_FILE:your_lib>
  VERBATIM)
```

不要把混淆参数配置为整个工程的全局编译参数，否则也会污染运行时 TU。构建期会拒绝在定义 helper 的模块上启用 CSE/证书绑定；可选的密码入口 VMP 见下文。运行时 object 必须始终 `-fno-lto`。

这里显式使用 `--no-rosegment`：Android 29 的默认独立只读 `PT_LOAD` 会把运行时真实使用的
8 字节格式 Magic 放在非执行段，严格封装扫描将其识别为尺寸无效的 CSE 块。该链接选项使只读
常量位于 R-X `PT_LOAD`，与已通过的 Android 26 样例布局相同；常量纳入代码摘要认证，真正的
`.ndkp.cse` 封装块仍在 R-W 段。p30 独立 fixture 显式采用此布局，封装工具和生产常量未修改。

固定流程：**链接 → 封装 → strip → APK 打包、对齐、签名**。封装只修改预留的 `.ndkp.cse` 数据，不改变代码、地址、重定位或文件大小。构建中不要在链接阶段使用 `-s`/`--strip-all`；将 strip 放在封装之后。重新构建应从链接产物开始，已封装输入拒绝二次封装。输出写入临时文件并原子替换；认证失败不修改既有输出。

```bash
python scripts/seal_cse.py --input linked.so --output sealed.so
llvm-strip --strip-all sealed.so
python scripts/seal_cse.py --input sealed.so --verify
```

包名和证书绑定沿用现有开关。新模式直接完成双路径输入读取，不依赖旧 CSE 的包名/证书缓存。仅使用 hardened CSE 时无需 `ndkp_apkcert.cpp`；若同时使用旧 VMP 证书绑定，仍按旧说明链接该文件。

绑定产物的 `--verify` 还需提供期望输入（封装后暂存输入已清除）：

```bash
python scripts/seal_cse.py --input sealed.so --verify \
  --package com.example.app --cert-file release.der
```

`--package` 同运行时一样截掉首个 `:` 后缀；支持私有子进程，不支持无前导冒号的任意全局进程名。`--cert-file` 接受 DER 或常规 PEM。

## 解密关键路径 VMP（p13，p15/p16 优化）

LLVM 21 的 dex2c 从 0.1.6 起默认将独立 CSE runtime 的 `derive`（密钥派生）和 `open`
（认证及解密控制）虚拟化，并检查真实字节码、入口自校验及 post CFG。业务模块的
CSE、证书绑定、VMP 和校验保持原有配置；运行时密码线格式及封装算法不变。

手动集成时，只在 `ndkp_cse_runtime.cpp` 的独立目标上定义 `NDKP_CSE_VMP`，使用
`-O1 -frtti -fno-exceptions -fno-lto -fno-vectorize -fno-slp-vectorize -fno-unroll-loops`
及 `-mllvm -irobf-vmp -mllvm -irobf-vmp-strict -mllvm -irobf-vmp-memops`
`-mllvm -irobf-selfcheck -mllvm -irobf-selfcheck-entry`。运行时仍禁止 CSE、包名绑定
和证书绑定混淆参数，以免读取自身字符串或证书时形成初始化循环；业务上的绑定不受影响。
普通客户端不定义该宏时沿用原生运行时。

需要二次 CFG 保护时，先生成 raw IR，再以 `-Oz -mllvm -irobf-vmp-post -S -emit-llvm`
输出最终 IR，验证后以 `-Oz -Xclang -disable-llvm-passes -c` 生成对象。
不要在同一次调用混用 `-irobf-vmp` 和 `-irobf-vmp-post`。

标准 SHA、HMAC、ChaCha20、Poly1305 和清零函数保留原生调用边界，避免批量算术与
内存循环进入 VM。密码函数放在独立内部命名空间，防止其他翻译单元的原生 inline
定义通过 COMDAT 选择替换保护实现。此配置增加首次解密成本，已解密字符串仍沿用
默认的 once 缓存；下文 scoped 调用每次重新认证自身记录，没有新增持久化派生密钥缓存。

p15 / dex2c 0.1.8 将密钥材料的字节拼装放到与 HKDF 相同的原生 helper 边界，
`derive` 仍在 VM 中组织材料准备、HKDF 调用与清零；`open` 的认证/解密控制仍在 VM 中。
这会减少 VM 内部可观察到的低层字节操作，并非新增一层加固；保护计数仍是两个入口。
测试样本的 derive 字节码从 12,330 降至 143 bytes，输出与原生及历史格式一致。
解释器的 ChaCha/调度辅助函数允许优化后再执行 post，64 字节块的调度 seed 与既有密钥流一起缓存。
不改变加密轮数、wire ordinal、私有映射或封装格式，也不新增 CSE 派生密钥缓存。

p16 / dex2c 0.1.9 将恒时标签比较放到原生密码原语边界，避免 16 字节 XOR/OR
循环在每条字符串的 VM 中解释。open 仍在 VM 中决定认证失败和解密；测试样本的
open 字节码由 728 降至 172 bytes，derive 保持 143 bytes。每个标签字节的破坏均拒绝，
且失败时不修改输出。此项属于低层比较离开 VM 的保护范围取舍。
Android arm64 的 SHA-256 通过 getauxval(AT_HWCAP) 检查 SHA2，在独立 target("sha2")
函数中执行硬件压缩；无扩展时使用原软件实现，非 Android/arm64 也保留软件路径。
两条路径通过标准向量、0..257 字节/8 种地址偏移与大输入差分，格式和摘要不变。

VMP 只能提高分析成本；SO 和公开证书仍包含全部本地解密材料，APK-only 离线恢复缺口未修复。
设备语义、差分及性能回归：

```bash
python tests/cse-hardened/device_test.py --ndk "$NDK" --clang "$CLANG" \
  --serial "$SERIAL" --runtime-vmp --work-dir build/cse-vmp-device
```

## 数据与运行时行为

每个有字符串的 LLVM 模块保留一个版本化数据块。256 字节头存模块标识、seed 分片、构建 nonce、状态、记录总数及封装校验所需摘要；其后是 `[capacity:u32, nonce:12, tag:16, ciphertext:capacity]`。全部整数为小端。每条记录的真实字节长度、UTF-8/UTF-16 标记、序号和字符串内容均在密文内，容量按至少 32 字节的二次幂桶填充，最大 16 MiB。业务缓冲区同样按桶分配，解密入口只传输出、模块描述和 region 三个指针；模块描述保存 blob/cache/region 表及总长和记录数，region 保存偏移、独立输出容量和编码。记录序号由 region 在表中的位置校验，不再作为包装函数参数传递。认证后从密文元数据读取真实长度。字符标记 1 表示 8-bit 字节串（不验证其为 UTF-8），2 表示 UTF-16LE/16-bit 元素；沿用旧 CSE 对无 NUL 字节及 16-bit 常量数组的支持，不强制字符串终止符。

AAD 绑定模块标识、格式版本、绑定开关、记录序号、容量、数据块总长和记录数。96-bit nonce 为零高部与模块内唯一的 32-bit 序号。每个模块使用独立随机 seed，封装时为同一 ELF 的所有模块生成一个 256-bit build_nonce。每模块增加一条认证有效、无业务引用的假字符串记录，连同整个数据块保留到最终链接。

编译期使用暂存密钥认证加密。封装工具先认证、验证全部记录，再使用最终机器码摘要派生密钥重新加密，清除头内的期望包名 SHA-256 与证书混合值。seed 分片仍供运行时派生，对攻击者并非秘密。

代码摘要为 SHA-256(`NDKP-CODE-v1` 与按程序头顺序排列的每段相对虚拟地址、文件长度、段 SHA-256)。覆盖全部可执行 `PT_LOAD` 文件字节，包含非 `.text` 的代码段。为兼容 strip，唯一规范化例外为 ELF 头的 `e_shoff`、`e_shentsize`、`e_shnum`、`e_shstrndx`：计算前将这些字段归零。程序头和实际代码字节仍被绑定。拒绝可写/不可读/含非文件字节的可执行段、文本重定位及重叠映射布局。

运行时通过 `dl_iterate_phdr` 定位数据块所属 ELF，并以 volatile 读取实际映射代码计算摘要；不使用头内的期望摘要来派生密钥。每模块以原子 once 缓存实际摘要，默认每条字符串沿用原子 once 发布。包名及证书输入在首次解密该模块时读取并交叉验证；与实际代码摘要一起缓存这些公开输入摘要，派生密钥不缓存。默认路径验证成功后才复制到静态存储期业务缓冲区；临时明文和派生密钥清零。scoped 路径复用模块公开输入缓存，但每次调用独立映射并重新认证所需记录。

region 表不含重定位，放入 `.text.ndkp.cse.regions`，由上述代码摘要认证；运行时拒绝表未完整落入本库可执行文件字节的布局。含绝对指针的模块表保留在数据段，每模块生成一个共享入口，用 volatile 读取并与代码中的 blob/cache/regions 引用、总长和记录数核对，再传递已核对字段的局部快照。这样既防止模块基址重定向，也避免核对后再次读取被改写的描述表。每串包装函数仍只传指针，不传容量或序号整数。

Android arm64 raw I/O 使用内联 `svc` 的 openat/read/pread64/fstat/getdents64/close。包名对比 libc 与 raw 独立读取；证书解析共享边界检查，分别通过两种后端定位所属 APK，比较库映射、APK 文件身份和证书摘要，保留 base/split 及两类库加载方式。读取错误、来源歧义、不一致、未封装或认证失败均静默以 raw `exit_group(127)` 终止进程，不生成固定诊断字符串。

## 函数作用域明文（p30，LLVM 21，可选）

同时启用 `-mllvm -irobf-cse -mllvm -irobf-cse-hardened -mllvm -irobf-cse-scoped`，并在
选定业务函数上使用 `NDKP_CSE_SCOPED`。scoped 开关默认关闭；CSE/hardened 已启用时，注解与
scoped 开关缺一即保留普通 CSE 行为。启用 scoped 而缺少 CSE/hardened 前置开关则编译拒绝。
当前只支持 Android arm64、RegionV1/ModuleV1 和普通函数返回，不支持
`segmentedData`。LLVM 20 只同步内部 ABI 头，未移植 scoped 编译器变换。

```cpp
#include "ndkp.h"
#include <cstddef>

extern "C" unsigned hash8(const char* __attribute__((noescape)), std::size_t) noexcept;

NDKP_CSE_SCOPED unsigned sensitive_hash() noexcept {
  return hash8("sensitive", sizeof("sensitive"));
}
```

函数必须已有原始 `nounwind` 合同；C++ 可用 `noexcept`，所有调用也必须直接、不可抛出且正常
返回。编译器先检查原始证明，再移除因新增映射副作用而过期的效果属性，保留真实调用和普通
返回前的清理；`const`/`pure` 包装和未使用的返回值不能让 scoped 调用被优化删除。
`nounwind` 只约束异常展开，不能证明外部代码没有隐藏的 `longjmp`、取消、信号或其他非局部
退出。业务接入必须满足该合同；当前拒绝已知 EH、间接调用、inline asm、operand bundle、
`musttail`、`returns_twice`、不返回调用和其他非普通出口。

只接受本函数直接引用的不可变字节或 UTF-16 常量，返回值限于标量或 void。scoped 衍生指针
可读取或传给直接 `nounwind`、`captures(none)` 的消费函数；上例的 `noescape` 声明要求实现
确实不保留、不写入该指针。保存到局部指针槽也被拒绝，不能返回指针、转为整数或经全局指针、
聚合间接取得字符串。所有 scoped 衍生 GEP 都必须 `inbounds`；literal、load、调用点和
callee 参数所要求的对齐最多为 4096 字节。调用方仍须满足实际读取范围和消费函数合同。
该业务函数不能同时选中 VMP/post；独立密码运行时仍可使用前述两个 strict VMP
入口、memops、entry SelfCheck 和真实 post。

每次调用为其所用 region 创建新的页取整映射，完成认证解密并真正 `mprotect` 为只读后才
发布指针。生成的共享 guard 仍 volatile 核对五个 ModuleV1 字段，传递核对后的局部快照，
region 表仍要求属于本库已认证的 RX 文件字节。每个普通返回按 acquire 的反序 release：
恢复 RW，用 volatile 字节写擦除全部映射长度（含页 padding），真实 `munmap`，再擦除
compiler-private lease 并设为 retired。ARM64 lease 为 24 字节，state 位于偏移 16；状态为
fresh(0) → active(1) → retired(2)。退休后 data、mapped 和 padding 为零，state 保留 2，
不能称为整个 lease 全零。重入和并发各自持有独立 lease，地址在释放后可能被系统重用。

未注解函数继续使用静态 DecGV 和 once 发布，即使与 scoped 函数共用同一 literal；scoped
调用不会借用或擦除该静态存储。模块代码摘要及包名/证书公开输入仍 once 缓存，scoped 每次
重新认证自身记录不等于每次重新读取全部代码或 APK。保证只覆盖独立映射和 lease；消费函数
副本、Java 字符串、寄存器、栈、spill、缓存及其他 crypto 临时值由其所有者处理。同进程读取
和 APK-only 离线恢复的边界不变。每次映射、认证和释放增加成本，适合低频敏感函数；p30
没有新增性能测量或性能收益结论。

独立回归可分别保留编链与设备结果。签名模式需要 SDK build-tools 37.0.0、Platform 37
和有相邻 `keytool` 的 JDK；`--work-dir` 必须是新目录，设备阶段复用同一目录：

```bash
python tests/cse-hardened/scoped_test.py --ndk "$NDK" \
  --work-dir build/cse-scoped --compile-only --signed --sdk "$SDK" --java "$JAVA"
python tests/cse-hardened/scoped_test.py --work-dir build/cse-scoped \
  --device-only --serial "$SERIAL" --adb "$ADB"
```

p30 正式结果位于 `work/m3-cse-scoped-p30/scoped-fixture-3/build.json` 和 `results.json`，
逐命令保存 argv、cwd、rc、原始 stdout/stderr 和哈希。O0/O2 原生及 bound IR、独立 runtime
的两个 strict crypto 入口和真实 post、24 个 IR 编译拒绝例、实际 C++ 65536 对齐拒绝例与
两个 return block 的反序释放均通过。OnePlus 7 / GM1901 / API 37 / ARM64 / 4 KiB 上 22
例全部符合预期：七个 native 正例/默认关闭控制退出 0，四个原生 guard/tag 攻击退出 127，
四个遗漏全页擦除、真实 unmap、RO 或 release 的 observer 控制退出 90；签名 O0/O2 主进程和
O2 `:worker` 三例退出 0，错证书、错包名、tag 和 guard 四例退出 127，无明文发布或业务继续。
观察器转发真实生产调用，只把页 padding 填成 `0xa7`，用真实 fork/write 检查只读权限，
在 unmap 前扫描整个映射为零，并要求实际 unmap 后 `mincore` 返回 ENOMEM。正常 scoped
每轮有 13 次映射/发布/退休，覆盖 byte/UTF-16、多 region/分支、递归、两线程、const/pure
包装及同 literal 的静态 getter。

五个 APK 均实际对齐、合法签名并通过主机 apksigner 验证，最终 native ZIP entry 与 stripped
库全字节一致，运行时仍使用自身双路径读取包名及证书。`NDKP_APK_VERIFY` 未定义，不能将
主机签名验证写成设备完整 APK 验签。正式生产源码为 compiler-freeze-3，fixture 为
fixture-freeze-4；compiler-freeze-2 只有源码快照，不能作为编译执行证据。失败的
`scoped-fixture-1`（observer noescape 声明）和 `scoped-fixture-2`（独立只读段 Magic）及
诊断日志仍保留。独立 [样例接入](../dex2c/samples/core-hardening/README.md#p30-scoped-cse-probe)
另有真实启用/禁用/恢复记录；API 26/29 真机、物理 16 KiB 页、Linux 和完整业务未扩大覆盖。

## 按需复验（p7，可选）

在低频、敏感操作入口加 `include/ndkp.h` 中的 `NDKP_CSE_RECHECK`，并保留
`-mllvm -irobf-cse -mllvm -irobf-cse-hardened`：

```c
#include "ndkp.h"

NDKP_CSE_RECHECK
int sensitive_operation(int value) {
  return value + 1;
}
```

注解阻止该函数被内联。hardened CSE 在优化前额外保留检查点的副作用，避免纯函数
返回值未使用时整个调用被删除；随后移除临时标记并在入口插入实际检查。没有混淆开关时不注入检查。
编译器在入口核对本模块描述表的五个字段，传递局部快照。复验重新读取本 SO 的
全部可执行 `PT_LOAD` 字节及实时页权限，比较封装摘要和缓存摘要，并解密认证本模块
最后一条诱饵记录，以验证缓存的包名/证书输入、seed 与记录元数据。临时输出随即清零。
首次调用检查点可以完成模块初始化；之后不重读 APK 或包名，不修改 once 缓存。
支持与 VMP、自校验、LTO 组合。间接调用混淆保留指向生成的 `noobf` 检查入口的直接调用，
避免将其改成可写表中的函数指针。

此检查是同步的，成本随本 SO 可执行段大小增长，适合初始化阶段转换、配置提交等低频边界。
不要放在每帧、逐字节处理、信号处理器或持有关键锁的热路径。它不会检查其他 SO，因此
不会把对外部模块的合法修改算作本库代码篡改；但检查点之前对本 SO 的 inline Hook 或
可写代码映射会被拒绝，部署时必须核实应用的兼容要求。

检查点只认证一个哨兵记录，并非重解密所有业务记录；其他记录仍在首次访问时认证。
每个检查点只核对所属 LLVM 模块的描述表和缓存，代码摘要覆盖整个 SO。它不校验业务明文、
全部可写全局或任意函数指针，也不消除检查与使用之间的竞态。绕过检查调用、同时改写检查器
或同进程任意读写仍在威胁模型内。静态存储期明文和公开证书离线恢复的边界不变。

```bash
python tests/cse-hardened/recheck_test.py --ndk "$NDK" --clang "$CLANG" --serial "$SERIAL"
python tests/cse-hardened/recheck_test.py --ndk "$NDK" --clang "$CLANG" --compile-only
```

设备回归同时验证旧默认模式在初始化后的盲区、检查点前后的篡改、指针存活、并发和 strip。
`--compile-only` 只验证编链、IR 和封装，不含篡改测试。
新注解使用额外的 hidden 入口 `ndkp_cse_recheck_module_v1`，需同步 p7 运行时并重新编译。
CSE v1 格式、原解密 ABI 和默认明文生命周期保持不变。

## 验证与边界

```bash
python tests/cse-hardened/test_seal_cse.py
python tests/cse-hardened/device_test.py --ndk "$NDK" --serial "$SERIAL"
python tests/cse-hardened/descriptor_test.py --ndk "$NDK" --serial "$SERIAL"
python tests/cert-bind/device_roundtrip.py --hardened \
  --ndk "$NDK" --build-tools "$BUILD_TOOLS" --android-jar "$ANDROID_JAR" \
  --java-home "$JAVA_HOME" --serial "$SERIAL"
```

设备测试可加 `--clang /path/to/build/bin/clang` 使用本地新构建的编译器和指定 NDK 的 sysroot。`device_test.py --work-dir` 可保留本机构建产物供检查。

本模式增加篡改、跨构建密文替换和单路径 libc 输入伪造的成本。build_nonce 公开，两种本地读取路径不是独立可信根；任意同进程修改仍可攻击解析、派生、检查或结果。默认代码摘要只在模块首次解密时计算；未执行显式检查点时，之后的修改不由该缓存检测。未访问记录的 tag 在访问时才校验；封装工具的 `--verify` 会认证全部记录。

认证有效的诱饵不能保证抵抗可读性判据，业务缓冲区和引用关系仍可能透露长度范围。默认明文保留静态存储期；scoped 的清理范围见上文，AEAD 不阻止解密后的内存读取。设备与性能结果见 [验证记录](../tests/cse-hardened/VALIDATION.md)。

## 内部 ABI 更新

`ndkp_cse_decode_region_v1` 替代旧八参数 `ndkp_cse_decode_v1`。更新编译器时必须同步运行时，并重新编译业务对象；新旧对象错误混用会在链接阶段失败。CSE v1 文件格式和封装算法保持不变。此入口只供编译器生成的模块检查入口调用；手写调用者不能把未经核对的模块表作为可信输入。模块字段检查、region 表的代码摘要绑定和认证后元数据检查共同约束输出容量与记录身份。默认代码摘要仍只在首次解密模块时计算；p7 的显式检查点边界见上文。

p30 增加 hidden `ndkp_cse_acquire_region_v1` / `ndkp_cse_release_region_v1` 和
compiler-private `ScopedRegionV1`，同样要求同步 runtime/header 并重新编译。acquire 只接收
生成 guard 核对后的 ModuleV1 快照和已认证 RX region；这些入口不是公开手写借用 API。
原 decode ABI、CSE v1 封装格式、RegionV1/ModuleV1 和默认生命周期保持原有行为。
