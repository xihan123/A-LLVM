#include "call_frames.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <pthread.h>
#include <stdexcept>
extern "C" {
int reference_frame_local(int (*)(int *));
int reference_frame_direct();
int reference_frame_vm();
int reference_frame_external(int (*)(int *), int *);
int reference_frame_pointer(int (*)(void **), void *);
int reference_frame_alias(void (*)(int *, int *));
int reference_frame_recursive(int, int *);
int reference_frame_reentrant(int, int *, int (*)(int, int *));
uint64_t reference_frame_sret(uint64_t);
int reference_frame_catch(int (*)(int *, int), int);
int reference_frame_escape(int (*)(int *, int), int *, int);
}
static int token;
static bool fail_malloc;
static int rejected_allocations;
extern "C" void *__real_malloc(size_t);
extern "C" void *__wrap_malloc(size_t size) {
  if (fail_malloc) { ++rejected_allocations; return nullptr; }
  return __real_malloc(size);
}
static int allocating_write(int *out) {
  void *allocation = std::malloc(16);
  int result = allocation ? 3 : 2;
  *out = allocation ? 42 : 19;
  std::free(allocation);
  return result;
}
int native_frame_write(int *out) { *out = 42; return 3; }
static int write_pointer(void **out) { *out = &token; return 3; }
static void write_alias(int *a, int *b) { *a = 42; *b += 1; }
static int write_throw(int *out, int code) {
  *out = 42;
  if (code) throw code;
  return 3;
}
static int catch_write(int *out, int code) {
  try { return frame_escape(write_throw, out, code); }
  catch (int) { return 10; }
}
static int reference_catch_write(int *out, int code) {
  try { return reference_frame_escape(write_throw, out, code); }
  catch (int) { return 10; }
}
static int bounce(int depth, int *parent) {
  return frame_reentrant(depth, parent, bounce);
}
static int reference_bounce(int depth, int *parent) {
  return reference_frame_reentrant(depth, parent, reference_bounce);
}
static int bounce_catch(int depth, int *parent) {
  if (!depth) { *parent = 42; throw 9; }
  try { return frame_reentrant(depth, parent, bounce_catch); }
  catch (int) { return 30; }
}
static int reference_bounce_catch(int depth, int *parent) {
  if (!depth) { *parent = 42; throw 9; }
  try { return reference_frame_reentrant(depth, parent, reference_bounce_catch); }
  catch (int) { return 30; }
}
static std::atomic<int> live_exceptions{0};
struct TrackedError : std::runtime_error {
  TrackedError() : std::runtime_error("frame unwind") { ++live_exceptions; }
  TrackedError(const TrackedError &other) : std::runtime_error(other) { ++live_exceptions; }
  ~TrackedError() override { --live_exceptions; }
};
static int throw_tracked(int *out, int) { *out = 42; throw TrackedError(); }
#ifdef NDKP_OBSERVE_FRAMES
extern "C" {
unsigned char *ndkp_test_frame_stack();
unsigned ndkp_test_frame_top();
size_t ndkp_test_frame_stride();
size_t ndkp_test_frame_padding_end();
unsigned char *ndkp_test_cache_region(unsigned, size_t *);
}
static thread_local int observation_error;
static thread_local unsigned observed_callbacks;
static bool bytes_are(const volatile unsigned char *bytes, size_t size, unsigned char value) {
  for (size_t i = 0; i < size; ++i)
    if (bytes[i] != value) return false;
  return true;
}
enum { Cache, OpcodeKey, OpcodeMap, LayoutKey, TraceLayout, FaultLayout, DebugLayout,
       BlockIndex, ScheduleSeed, BlockValid, Block, MaterialValid, KeyWords, NonceWords };
static thread_local unsigned cache_errors;
static thread_local unsigned cache_hits, material_refills, block_refills;
static thread_local unsigned cache_refilled;
static thread_local bool saw_opcode_map;
static thread_local unsigned char cache_snapshot[256];
static bool caches_are_zero() {
  for (unsigned part = Cache; part <= DebugLayout; ++part) {
    size_t size;
    const volatile unsigned char *bytes = ndkp_test_cache_region(part, &size);
    if (!bytes_are(bytes, size, 0)) return false;
  }
  return true;
}
extern "C" void ndkp_test_cache_event(unsigned phase, const volatile unsigned char *cache) {
  size_t size;
  unsigned char *actual = ndkp_test_cache_region(Cache, &size);
  if (cache != actual || size > sizeof(cache_snapshot)) { cache_errors |= 1; return; }
  if (phase == 0) {
    cache_refilled = 0;
    for (size_t i = 0; i < size; ++i) cache_snapshot[i] = cache[i];
    size_t map_size;
    const volatile unsigned char *map = ndkp_test_cache_region(OpcodeMap, &map_size);
    if (map_size > 1 && map[0] == 0 && map[1] && map[1] < map_size) saw_opcode_map = true;
  } else if (phase == 1) {
    if (!bytes_are(cache, size, 0)) cache_errors |= 2;
    ++material_refills;
    cache_refilled = 1;
  } else if (phase == 2) {
    for (unsigned part = BlockIndex; part <= Block; ++part) {
      size_t count;
      const volatile unsigned char *bytes = ndkp_test_cache_region(part, &count);
      if (!bytes_are(bytes, count, 0)) cache_errors |= 4;
    }
    if (!cache_refilled) {
      ++block_refills;
      for (unsigned part : {KeyWords, NonceWords}) {
        size_t count;
        const volatile unsigned char *bytes = ndkp_test_cache_region(part, &count);
        size_t offset = bytes - cache;
        for (size_t i = 0; i < count; ++i)
          if (bytes[i] != cache_snapshot[offset + i]) cache_errors |= 8;
      }
    }
    size_t valid_size;
    const volatile unsigned char *valid = ndkp_test_cache_region(MaterialValid, &valid_size);
    if (*valid != 1) cache_errors |= 8;
    cache_refilled |= 2;
  } else if (phase == 3 && !cache_refilled) {
    ++cache_hits;
    for (size_t i = 0; i < size; ++i)
      if (cache[i] != cache_snapshot[i]) cache_errors |= 16;
  }
}
static bool observe_active(unsigned expected_top) {
  ++observed_callbacks;
  if (!caches_are_zero()) cache_errors |= 32;
  if (ndkp_test_frame_top() != expected_top) return false;
  size_t stride = ndkp_test_frame_stride();
  size_t padding_end = ndkp_test_frame_padding_end();
  volatile unsigned char *frame = ndkp_test_frame_stack() + (expected_top - 1) * stride;
  bool written = false;
  for (size_t i = 0; i < stride; ++i) {
    if (i >= sizeof(int) && i < padding_end) {
      if (frame[i] != 0xa5) return false;
    } else if (frame[i] != 0xa5) {
      written = true;
    }
  }
  return written;
}
static int observing_write(int *out) {
  if (!observe_active(1)) observation_error = 1;
  return native_frame_write(out);
}
static int observing_throw(int *out, int code) {
  if (!observe_active(1)) observation_error = 2;
  return write_throw(out, code);
}
static int observing_deeper(int *out) {
  if (!observe_active(2)) observation_error = 3;
  return native_frame_write(out);
}
static int observing_nested(int *out) {
  unsigned top = ndkp_test_frame_top();
  size_t stride = ndkp_test_frame_stride();
  volatile unsigned char *stack = ndkp_test_frame_stack();
  unsigned char active[512];
  size_t active_size = top * stride;
  if (!observe_active(1) || active_size > sizeof(active)) {
    observation_error = 4;
    return native_frame_write(out);
  }
  for (size_t i = 0; i < active_size; ++i) active[i] = stack[i];
  unsigned before = observed_callbacks;
  int result = frame_local(observing_deeper);
  if (!caches_are_zero()) cache_errors |= 64;
  if (result != 342 || observed_callbacks != before + 1 || ndkp_test_frame_top() != top ||
      !bytes_are(stack + active_size, stride, 0) ||
      !bytes_are(stack + active_size + stride, stride, 0xa5)) observation_error = 5;
  for (size_t i = 0; i < active_size; ++i)
    if (stack[i] != active[i]) observation_error = 6;
  return native_frame_write(out);
}
static int check_retired_frames() {
  size_t stride = ndkp_test_frame_stride();
  size_t padding_end = ndkp_test_frame_padding_end();
  if (stride > 128 || padding_end >= stride || padding_end <= sizeof(int)) return 30;
  volatile unsigned char *stack = ndkp_test_frame_stack();
  if (ndkp_test_frame_top() != 0) return 31;
  for (int phase = 0; phase < 3; ++phase) {
    // Prime only inactive slots, including padding that member stores leave alone.
    for (size_t i = 0; i < 3 * stride; ++i) stack[i] = 0xa5;
    for (unsigned part = Cache; part <= DebugLayout; ++part) {
      size_t size;
      volatile unsigned char *bytes = ndkp_test_cache_region(part, &size);
      for (size_t i = 0; i < size; ++i) bytes[i] = 0xa5;
    }
    observation_error = 0;
    observed_callbacks = 0;
    if (phase == 0) {
      if (frame_local(observing_write) != 342) return 32;
    } else if (phase == 1) {
      int out = 7;
      try { frame_escape(observing_throw, &out, 9); return 33; }
      catch (int code) { if (code != 9 || out != 42) return 34; }
    } else if (frame_local(observing_nested) != 342) {
      return 35;
    }
    if (!caches_are_zero()) cache_errors |= 64;
    if (observation_error) return 40 + observation_error;
    if (observed_callbacks != (phase == 2 ? 2u : 1u)) return 36;
    if (ndkp_test_frame_top() != 0) return 37;
    if (!bytes_are(stack, stride, 0)) return 38;
    if (!bytes_are(stack + stride, stride, phase == 2 ? 0 : 0xa5) ||
        !bytes_are(stack + 2 * stride, stride, 0xa5)) return 39;
  }
  return 0;
}
#endif
static int check() {
  if (frame_local(native_frame_write) != reference_frame_local(native_frame_write)) return 1;
  if (frame_direct() != reference_frame_direct()) return 2;
  if (frame_vm() != reference_frame_vm()) return 3;
  int out = 7, expected = 7;
  if (frame_external(native_frame_write, &out) != reference_frame_external(native_frame_write, &expected)
      || out != expected) return 4;
  if (frame_pointer(write_pointer, &token) != reference_frame_pointer(write_pointer, &token)) return 5;
  if (frame_alias(write_alias) != reference_frame_alias(write_alias)) return 6;
  for (int depth = 0; depth <= 6; ++depth) {
    out = expected = 7;
    if (frame_recursive(depth, &out) != reference_frame_recursive(depth, &expected) || out != expected) return 7;
    out = expected = 7;
    if (bounce(depth, &out) != reference_bounce(depth, &expected) || out != expected) return 8;
  }
  for (uint64_t seed = 0; seed < 7; ++seed)
    if (frame_sret(seed) != reference_frame_sret(seed)) return 9;
  for (int code : {0, 9})
    if (frame_catch(catch_write, code) != reference_frame_catch(reference_catch_write, code)) return 10;
  out = 7;
  try { frame_escape(write_throw, &out, 9); return 11; }
  catch (int code) { if (code != 9 || out != 42) return 12; }
  // A fresh call after unwinding must not inherit a pointer into the retired frame.
  if (frame_escape(write_throw, &out, 0) != 3 || frame_local(native_frame_write) != 342) return 13;
  out = expected = 7;
  if (bounce_catch(4, &out) != reference_bounce_catch(4, &expected) || out != expected) return 14;
  out = 7;
  try { frame_escape(throw_tracked, &out, 0); return 15; }
  catch (const TrackedError &error) {
    if (out != 42 || error.what()[0] != 'f') return 16;
  }
#ifdef NDKP_OBSERVE_FRAMES
  if (!caches_are_zero()) cache_errors |= 64;
  int frames = check_retired_frames();
  if (frames) return frames;
  if (cache_errors) return 50;
  if (!cache_hits || !material_refills || !block_refills || !saw_opcode_map) return 51;
  return 0;
#else
  return 0;
#endif
}
static std::atomic<int> start{0};
static int failures[8];
static void *worker(void *arg) {
  int index = *static_cast<int *>(arg);
  while (!start.load(std::memory_order_acquire)) {}
  for (int i = 0; i < 3 && !failures[index]; ++i) failures[index] = check();
  return nullptr;
}
int main() {
  int first = check();
  if (first) {
#ifdef NDKP_OBSERVE_FRAMES
    std::printf("VMP caches FAIL: bits=%u hit=%u material=%u block-only=%u opcode=%u\n",
                cache_errors, cache_hits, material_refills, block_refills, unsigned(saw_opcode_map));
#endif
    std::printf("call frames FAIL case %d\n", first);
    return first;
  }
  if (live_exceptions.load() != 0) return 17;
  // Warm TLS first, then fail executable malloc calls. A failed native allocation
  // must preserve its out-parameter, and VM recursion must need no heap snapshot.
  fail_malloc = true;
  int allocation_result = frame_local(allocating_write);
  int recursive_result = frame_recursive(4, nullptr);
  fail_malloc = false;
  if (allocation_result != 219 || rejected_allocations != 1 ||
      recursive_result != reference_frame_recursive(4, nullptr)) return 19;
  pthread_t threads[8];
  int indices[8];
  for (int i = 0; i < 8; ++i) {
    indices[i] = i;
    if (pthread_create(&threads[i], nullptr, worker, &indices[i])) return 20;
  }
  start.store(1, std::memory_order_release);
  int failed = 0;
  for (int i = 0; i < 8; ++i) {
    if (pthread_join(threads[i], nullptr)) return 21;
    if (failures[i]) failed = failures[i];
  }
  if (live_exceptions.load() != 0) return 18;
  if (failed) {
    std::printf("call frames FAIL case %d\n", failed);
    return failed;
  }
#ifdef NDKP_OBSERVE_FRAMES
  std::printf("VMP retired frames OK: stride=%zu padding=%zu normal/unwind/nested, 8 threads\n",
              ndkp_test_frame_stride(), ndkp_test_frame_padding_end() - sizeof(int));
  size_t cache_size;
  ndkp_test_cache_region(Cache, &cache_size);
  std::printf("VMP caches OK: bytes=%zu hit=%u material=%u block-only=%u native/exit/nested, 8 threads\n",
              cache_size, cache_hits, material_refills, block_refills);
#endif
  std::puts("VMP call frames OK");
  return failed;
}
