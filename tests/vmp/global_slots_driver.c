#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include "global_slots.h"

uint32_t global_roundtrip(uint32_t *, uint32_t);
uint32_t reference_global_roundtrip(uint32_t *, uint32_t);
uint64_t global_tls(uint32_t *, uint32_t *, uint32_t);
uint64_t reference_global_tls(uint32_t *, uint32_t *, uint32_t);
static atomic_int start;
static int failures[8];

static void *worker(void *arg) {
  int index = *(int *)arg;
  while (!atomic_load_explicit(&start, memory_order_acquire)) {}
  for (uint32_t i = 0; i < 100; ++i) {
    uint32_t a = 0, b = 0, ref_a = 0, ref_b = 0;
    uint32_t x = (uint32_t)index * 0x1020304u + i;
    uint64_t expected = reference_global_tls(&ref_a, &ref_b, x);
    if (global_tls(&a, &b, x) != expected || a != ref_a || b != ref_b)
      failures[index] = 1;
  }
  return NULL;
}

int main(void) {
  uint32_t values[3] = {7, 23, 41};
  struct Record records[3] = {0};
  for (int i = 0; i < 3; ++i) {
    records[i].value = 100 + i;
    records[i].pointer = &values[i];
    for (int j = 0; j < 3; ++j) records[i].grid[1][j] = i * 16 + j;
  }
  for (int i = -1; i <= 1; ++i)
    for (int j = 0; j < 3; ++j)
      if (indexed_records(&records[1], i, j) != reference_indexed_records(&records[1], i, j)) return 4;
  for (uint32_t i = 1; i < 100; ++i) {
    uint32_t word = 0, reference = 0;
    if (global_roundtrip(&word, i) != reference_global_roundtrip(&reference, i)
        || word != reference || word != i) return 1;
  }
  pthread_t threads[8];
  int indices[8];
  for (int i = 0; i < 8; ++i) {
    indices[i] = i;
    if (pthread_create(&threads[i], NULL, worker, &indices[i])) return 2;
  }
  atomic_store_explicit(&start, 1, memory_order_release);
  int failed = 0;
  for (int i = 0; i < 8; ++i) {
    if (pthread_join(threads[i], NULL)) return 3;
    failed |= failures[i];
  }
  puts(failed ? "global slots FAIL" : "global slots OK");
  return failed;
}
