#include <stdint.h>

#ifdef REFERENCE
#define compute reference_compute
#define recurse reference_recurse
#endif

uint32_t compute(uint32_t x) {
  for (int i = 0; i < 12; ++i) x = x * 1664525u + 1013904223u;
  return x;
}

uint32_t recurse(uint32_t x) {
  if (x < 2) return x;
  return recurse(x - 1) + recurse(x - 2);
}

// The native callback calls compute again while the outer VM frame is suspended.
extern uint32_t native_callback(uint32_t x);
#ifndef REFERENCE
uint32_t callback_roundtrip(uint32_t x) {
  return native_callback(x) ^ compute(x + 1);
}
#endif
