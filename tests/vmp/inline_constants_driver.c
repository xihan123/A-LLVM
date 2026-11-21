#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t (*operation)(void *, uint64_t);
uint64_t inline_store(void *, uint64_t);
uint64_t inline_insert(void *, uint64_t);
uint64_t inline_extract(void *, uint64_t);
uint64_t reference_inline_store(void *, uint64_t);
uint64_t reference_inline_insert(void *, uint64_t);
uint64_t reference_inline_extract(void *, uint64_t);

static const operation operations[] = {inline_store, inline_insert, inline_extract};
static const operation references[] = {
    reference_inline_store, reference_inline_insert, reference_inline_extract};
static const char *names[] = {"store", "insert", "extract"};
static const size_t sizes[] = {17, 24, 31};
static const uint64_t increments[] = {37, 19, 29};

static void write_u64(unsigned char *out, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) out[i] = (unsigned char)(value >> (i * 8));
}

static unsigned char pattern(unsigned tag, size_t index) {
  return (unsigned char)(0x31 + tag * 11 + index * 5);
}

static void expected(unsigned char *out, unsigned index, uint64_t marker, int mutated) {
  unsigned char aggregate[31] = {0};
  if (mutated)
    for (size_t i = 0; i < sizes[index]; ++i) aggregate[i] = pattern(index + 1, i);
  if (index == 0) {
    memcpy(out, aggregate, 17);
  } else if (index == 1) {
    write_u64(aggregate + 8, marker);
    memcpy(out, aggregate, 24);
    write_u64(aggregate, UINT64_C(0x1122334455667788));
    memcpy(out + 24, aggregate, 24);
    memcpy(out + 48, aggregate + 16, 8);
    write_u64(out + 56, marker);
    write_u64(out + 64, UINT64_C(0x1122334455667788));
  } else {
    out[0] = aggregate[30];
  }
}

#ifdef NDKP_OBSERVE_INLINE
static int active, fail_allocation;
static size_t expected_size, attempts, frees, residual, damaged_guards;
static unsigned char *allocation, *base;
static int allocation_error;
void *__real_malloc(size_t);
void __real_free(void *);

void *__wrap_malloc(size_t size) {
  if (!active || size != expected_size) return __real_malloc(size);
  ++attempts;
  if (fail_allocation) return NULL;
  if (allocation) { allocation_error = 1; return NULL; }
  base = (unsigned char *)__real_malloc(size + 32);
  if (!base) { allocation_error = 1; return NULL; }
  allocation = base + 16;
  memset(base, 0xd3, 16);
  memset(allocation + size, 0xd3, 16);
  return allocation;
}

void __wrap_free(void *pointer) {
  if (pointer && pointer == allocation) {
    const volatile unsigned char *bytes = allocation;
    for (size_t i = 0; i < expected_size; ++i) residual += bytes[i] != 0;
    for (size_t i = 0; i < 16; ++i)
      damaged_guards += base[i] != 0xd3 || allocation[expected_size + i] != 0xd3;
    ++frees;
    allocation = NULL;
    __real_free(base);
    base = NULL;
  } else {
    __real_free(pointer);
  }
}
#endif

int main(void) {
  const uint64_t marker = UINT64_C(0x8877665544332211);
  int semantic_error = 0, observation_error = 0;
  for (unsigned index = 0; index < 3; ++index) {
    unsigned char actual[96], oracle[96], reference[96];
    memset(actual, 0xa5, sizeof(actual));
    memset(oracle, 0xa5, sizeof(oracle));
    memset(reference, 0xa5, sizeof(reference));
    expected(oracle + 8, index, marker, 0);
    uint64_t result = references[index](reference + 8, marker);
    semantic_error |= result != marker + increments[index] || memcmp(reference, oracle, sizeof(oracle));
#ifndef NDKP_OBSERVE_INLINE
    result = operations[index](actual + 8, marker);
    semantic_error |= result != marker + increments[index] || memcmp(actual, oracle, sizeof(oracle));
#else
    for (int failure = 0; failure < 2; ++failure) {
      memset(actual, 0xa5, sizeof(actual));
      memset(oracle, 0xa5, sizeof(oracle));
      expected(oracle + 8, index, marker, !failure);
      expected_size = sizes[index];
      attempts = frees = residual = damaged_guards = 0;
      allocation_error = 0;
      fail_allocation = failure;
      active = 1;
      result = operations[index](actual + 8, marker);
      active = 0;
      int outputs_match = result == marker + increments[index] && !memcmp(actual, oracle, sizeof(oracle));
      semantic_error |= !outputs_match;
      observation_error |= attempts != 1 || frees != (size_t)!failure || residual || damaged_guards || allocation_error;
      printf("INLINE case=%s size=%zu failed=%d attempts=%zu frees=%zu residual=%zu guard=%zu output=%s\n",
             names[index], sizes[index], failure, attempts, frees, residual, damaged_guards,
             outputs_match ? "ok" : "bad");
      if (allocation) {
        __real_free(base);
        allocation = base = NULL;
      }
    }
#endif
  }
  if (semantic_error) return 61;
  if (observation_error) return 60;
  puts("VMP inline constants OK");
  return 0;
}
