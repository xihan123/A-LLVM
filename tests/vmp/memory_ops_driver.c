// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int compare_block(const void *, const void *);
int reference_compare_block(const void *, const void *);
void *copy_block(void *, const void *);
void *reference_copy_block(void *, const void *);
int compare_lengths(const void *, const void *, size_t);
int reference_compare_lengths(const void *, const void *, size_t);
void *copy_lengths(void *, const void *, size_t);
void *reference_copy_lengths(void *, const void *, size_t);
static int sign(int n) { return (n > 0) - (n < 0); }

int main(void) {
  unsigned char a[96], b[96], dst[96], expected[96];
  for (unsigned offset = 0; offset < 8; ++offset) {
    for (unsigned changed = 0; changed <= 16; ++changed) {
      for (unsigned i = 0; i < sizeof a; ++i) a[i] = b[i] = (i * 73 + 129) & 255;
      if (changed < 16) b[offset + changed] ^= 0x80;
      assert(sign(compare_block(a + offset, b + offset)) ==
             sign(reference_compare_block(a + offset, b + offset)));
      assert(sign(compare_block(b + offset, a + offset)) ==
             sign(reference_compare_block(b + offset, a + offset)));
      memset(dst, 0xA5, sizeof dst);
      memcpy(expected, dst, sizeof dst);
      assert(copy_block(dst + offset, a + offset) == dst + offset);
      assert(reference_copy_block(expected + offset, a + offset) == expected + offset);
      assert(!memcmp(dst, expected, sizeof dst));
    }
  }
  const size_t sizes[] = {0, 1, 7, 16, 64, 65, 80};
  for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; ++i) {
    size_t n = sizes[i];
    memset(a, 0x80, sizeof a); memset(b, 0x7F, sizeof b);
    assert(sign(compare_lengths(a, b, n)) == sign(reference_compare_lengths(a, b, n)));
    memset(dst, 0xA5, sizeof dst); memcpy(expected, dst, sizeof dst);
    assert(copy_lengths(dst + 1, a + 1, n) == dst + 1);
    assert(reference_copy_lengths(expected + 1, a + 1, n) == expected + 1);
    assert(!memcmp(dst, expected, sizeof dst));
  }
  // First difference wins even when a later difference has the opposite sign.
  memset(a, 0, sizeof a); memset(b, 0, sizeof b);
  a[0] = 0x80; b[15] = 0xFF;
  assert(compare_block(a, b) > 0);
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char *region = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(region != MAP_FAILED && !mprotect(region + page, page, PROT_NONE));
  memset(region + page - 16, 0x80, 16);
  memset(a, 0x80, sizeof a);
  assert(compare_block(region + page - 16, a) == 0);
  assert(copy_block(dst, region + page - 16) == dst);
  assert(copy_block(region + page - 16, a) == region + page - 16);
  // Zero length must not dereference either pointer.
  assert(compare_lengths(region + page, region + page, 0) == 0);
  assert(copy_lengths(region + page, region + page, 0) == region + page);
  assert(!munmap(region, 2 * page));
  puts("VMP memory operations OK");
}
