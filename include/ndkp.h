/*
 * ndkp.h — 用户注解 API（Android NDK 混淆工具链）
 *
 * 这些宏映射到 obfuscation overlay 中各 Pass 约定的 annotate 字符串。
 * 编译时用 patched clang，并在 flags 里打开对应总开关（如 -mllvm -irobf-cse），
 * 被注解的函数即进入该功能的作用名单。未使用 patched clang 时这些宏为空，
 * 源码可照常用普通 NDK 编译。
 *
 * 一期已接入：字符串加密 / 控制流平坦化。
 * 二期接入：VMP 指定函数虚拟化。
 */
#ifndef NDKP_H
#define NDKP_H

#if defined(__clang__)
#  define NDKP_ANNOTATE(x) __attribute__((annotate(x)))
#else
#  define NDKP_ANNOTATE(x)
#endif

/* 对该函数内的字符串常量启用加密（配合 -mllvm -irobf-cse） */
#define NDKP_STR_ENCRYPT NDKP_ANNOTATE("ndkp.string_encrypt")

/* 对该函数启用控制流平坦化（配合 -mllvm -irobf-fla） */
#define NDKP_FLATTEN NDKP_ANNOTATE("ndkp.fla")

/* 二期：对该函数启用 VMP 虚拟化（配合 -mllvm -irobf-vmp）。
 * 注意：VMP 要求 -frtti -fno-exceptions。 */
#define NDKP_VMP NDKP_ANNOTATE("ndkp.vmp")

#endif /* NDKP_H */
