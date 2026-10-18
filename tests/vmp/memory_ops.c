// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <string.h>

#ifdef REFERENCE
#define compare_block reference_compare_block
#define copy_block reference_copy_block
#define compare_lengths reference_compare_lengths
#define copy_lengths reference_copy_lengths
#endif

__attribute__((noinline)) int compare_block(const void *a, const void *b) {
  return memcmp(a, b, 16);
}

__attribute__((noinline)) void *copy_block(void *a, const void *b) {
  return memcpy(a, b, 16);
}

#define LENGTH_CASE(N, OP) case N: return OP(a, b, N)
__attribute__((noinline)) int compare_lengths(const void *a, const void *b, size_t n) {
  switch (n) {
    LENGTH_CASE(0, memcmp);
    LENGTH_CASE(1, memcmp);
    LENGTH_CASE(7, memcmp);
    LENGTH_CASE(64, memcmp);
    LENGTH_CASE(65, memcmp);
    default: return memcmp(a, b, n);
  }
}

__attribute__((noinline)) void *copy_lengths(void *a, const void *b, size_t n) {
  switch (n) {
    LENGTH_CASE(0, memcpy);
    LENGTH_CASE(1, memcpy);
    LENGTH_CASE(7, memcpy);
    LENGTH_CASE(64, memcpy);
    LENGTH_CASE(65, memcpy);
    default: return memcpy(a, b, n);
  }
}
