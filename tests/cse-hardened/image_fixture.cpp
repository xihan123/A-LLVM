#include "ndkp.h"

// This translation unit has no data constants, including annotation-only metadata.
extern "C" NDKP_CSE_RECHECK int checkpoint(int value) {
  return value * 3 + 7;
}

extern "C" NDKP_CSE_RECHECK __attribute__((const, noinline)) int image_unused_gate(int value) noexcept {
  return value + 1;
}
extern "C" __attribute__((const, noinline)) int image_relay_inner(int value) noexcept {
  return image_unused_gate(value);
}
extern "C" __attribute__((pure, noinline)) int image_relay_outer(int value) noexcept {
  return image_relay_inner(value);
}
extern "C" int image_unchecked_caller(int value) {
  image_relay_outer(value);
  return value * 3 + 7;
}
