#include "call_frames.h"
int frame_write(int *out) { *out = 42; return 3; }
int frame_local(int (*fn)(int *)) {
  int value = 7;
  int result = fn(&value);
  return result * 100 + value;
}
int frame_direct() {
  int value = 7;
  int result = native_frame_write(&value);
  return result * 100 + value;
}
int frame_vm() {
  int value = 7;
  int result = frame_write(&value);
  return result * 100 + value;
}
int frame_external(int (*fn)(int *), int *out) {
  int result = fn(out);
  return result * 100 + *out;
}
int frame_pointer(int (*fn)(void **), void *expected) {
  void *out = nullptr;
  int result = fn(&out);
  return result * 100 + (out == expected);
}
int frame_alias(void (*fn)(int *, int *)) {
  struct { int before, value, after; } values = {11, 7, 19};
  fn(&values.value, &values.value);
  return values.before * 10000 + values.value * 100 + values.after;
}
int frame_recursive(int depth, int *parent) {
  int value = depth + 10;
  if (parent) *parent += 3;
  int child = depth ? frame_recursive(depth - 1, &value) : 0;
  return value + child;
}
int frame_reentrant(int depth, int *parent, int (*bounce)(int, int *)) {
  int value = depth + 10;
  if (parent) *parent += 3;
  int child = depth ? bounce(depth - 1, &value) : 0;
  return value + child;
}
FrameWords frame_make(uint64_t seed) {
  FrameWords result;
  // Keep scalar stores at O2: vector instructions are outside VMP eligibility.
  volatile FrameWords *out = &result;
  out->a = seed + 1;
  out->b = seed + 2;
  out->c = seed + 3;
  out->d = seed + 4;
  return result;
}
uint64_t frame_sret(uint64_t seed) {
  FrameWords words = frame_make(seed);
  return words.a + words.b * 3 + words.c * 5 + words.d * 7;
}
int frame_catch(int (*fn)(int *, int), int code) {
  int value = 7;
  int result = fn(&value, code);
  return result * 100 + value;
}
int frame_escape(int (*fn)(int *, int), int *out, int code) {
  int result = fn(out, code);
  *out += 1; // Must not run after the native call throws.
  return result;
}
