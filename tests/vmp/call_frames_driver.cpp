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
}
static thread_local int observation_error;
static thread_local unsigned observed_callbacks;
static bool bytes_are(const volatile unsigned char *bytes, size_t size, unsigned char value) {
  for (size_t i = 0; i < size; ++i)
    if (bytes[i] != value) return false;
  return true;
}
static bool observe_active(unsigned expected_top) {
  ++observed_callbacks;
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
  return check_retired_frames();
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
  if (first) { std::printf("call frames FAIL case %d\n", first); return first; }
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
#endif
  std::puts("VMP call frames OK");
  return failed;
}
