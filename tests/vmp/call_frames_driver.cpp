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
  return 0;
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
  std::puts(failed ? "call frames FAIL" : "VMP call frames OK");
  return failed;
}
