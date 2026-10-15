#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

uint32_t compute(uint32_t);
uint32_t reference_compute(uint32_t);
uint32_t recurse(uint32_t);
uint32_t reference_recurse(uint32_t);
uint32_t callback_roundtrip(uint32_t);
uint32_t native_callback(uint32_t x) { return compute(x + 2); }

static atomic_int start;
static int failures[8];
static void *worker(void *arg) {
  int index = *(int *)arg;
  while (!atomic_load_explicit(&start, memory_order_acquire)) {}
  for (uint32_t i = 0; i < 20; ++i) {
    uint32_t x = index * 31 + i;
    if (compute(x) != reference_compute(x)) failures[index] = 1;
    if (recurse(i % 7) != reference_recurse(i % 7)) failures[index] |= 2;
    if (callback_roundtrip(x) != (reference_compute(x + 2) ^ reference_compute(x + 1)))
      failures[index] |= 4;
  }
  return NULL;
}

int main(void) {
  pthread_t threads[8];
  int indices[8];
  for (int i = 0; i < 8; ++i) {
    indices[i] = i;
    if (pthread_create(&threads[i], NULL, worker, &indices[i])) return 2;
  }
  atomic_store_explicit(&start, 1, memory_order_release);
  int failed = 0;
  for (int i = 0; i < 8; ++i) {
    pthread_join(threads[i], NULL);
    failed |= failures[i];
    if (failures[i]) printf("thread %d: failed cases=%d (compute=1 recurse=2 callback=4)\n", i, failures[i]);
  }
  puts(failed ? "FAIL" : "OK");
  return failed;
}
