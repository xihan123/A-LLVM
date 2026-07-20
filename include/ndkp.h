/*
 * ndkp.h — 函数级注解宏
 *
 * 每个宏展开为 Clang 的 __attribute__((annotate(...)))，把一个 ndkp.* 标签写入
 * llvm.global.annotations。obfuscation overlay 的各 Pass 在运行时读取该标签，决定
 * 对哪些函数施加变换。
 *
 * 用法：用 patched clang 编译，并在编译参数里打开总开关 -mllvm -irobf 以及对应的
 * 功能开关（见各宏说明）。注解只负责圈定作用函数，不替代开关。非 patched clang
 * 下 annotate 属性被忽略，源码可用普通 NDK 正常编译。
 */
#ifndef NDKP_H
#define NDKP_H

#if defined(__clang__)
#  define NDKP_ANNOTATE(x) __attribute__((annotate(x)))
#else
#  define NDKP_ANNOTATE(x)
#endif

/* 字符串常量加密。标签 ndkp.string_encrypt 折叠为 +cse，需配合 -mllvm -irobf-cse。 */
#define NDKP_STR_ENCRYPT NDKP_ANNOTATE("ndkp.string_encrypt")

/* 字符串加密的包名绑定（强化）。标签 ndkp.str_bind：模块内任一函数带此注解即
 * 等效开启 bind 模式——把运行期 /proc/self/cmdline 的哈希折进 pepper，使 .so 仅在
 * 目标 App 内解出正确明文（错包名 → 乱码，非分支、无可 patch 的检查）。bind 蕴含
 * per-string 密钥派生（ChaCha8，密钥不内联存储）。
 * 需配合 -mllvm -irobf-cse -mllvm -irobf-cse-bind-package=<包名>；缺包名则构建失败。
 * 亦可直接用命令行开关 -mllvm -irobf-cse-bind 而不加注解。 */
#define NDKP_STR_BIND NDKP_ANNOTATE("ndkp.str_bind")

/* 控制流平坦化。标签 ndkp.fla 折叠为 +fla，需配合 -mllvm -irobf-fla。 */
#define NDKP_FLATTEN NDKP_ANNOTATE("ndkp.fla")

/* 函数级虚拟化（VMP）：将函数编译为字节码，运行时由链入的解释器执行。
 * 需配合 -mllvm -irobf-vmp，且该翻译单元须以 -frtti -fno-exceptions 编译。
 * 等价于用 -mllvm -irobf-vm_functions=<name;name> 按函数名指定。 */
#define NDKP_VMP NDKP_ANNOTATE("ndkp.vmp")

#endif /* NDKP_H */
