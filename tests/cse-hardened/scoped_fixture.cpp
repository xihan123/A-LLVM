#include "ndkp.h"
#include "scoped_fixture.h"

#ifdef NDKP_SCOPED_NO_ANNOTATION
#define TEST_SCOPED
#else
#define TEST_SCOPED NDKP_CSE_SCOPED
#endif

extern "C" const char* scoped_static_value() noexcept {
  return "NDKP_CORE_SCOPED_p30_9b6d";
}

extern "C" TEST_SCOPED int scoped_multi(int branch) noexcept {
  uint32_t bytes = scoped_observe8("NDKP_CORE_SCOPED_p30_9b6d", ScopedBytes, 0, 0);
  if (branch < 0) return bytes == ScopedByteHash ? 0 : 1;
  uint32_t words = scoped_observe16(u"scope \u4e2d\u6587", ScopedWords);
  if (branch == 0) return bytes == ScopedByteHash && words == ScopedWordHash ? 0 : 2;
  return (bytes ^ words) == (ScopedByteHash ^ ScopedWordHash) ? 0 : 3;
}

extern "C" TEST_SCOPED int scoped_recursive(unsigned depth) noexcept {
  uint32_t before = scoped_observe8("NDKP_CORE_SCOPED_p30_9b6d", ScopedBytes, 2, depth);
  if (!depth) return before == ScopedByteHash ? 0 : 4;
  int nested = scoped_recursive(depth - 1);
  uint32_t after = scoped_observe8("NDKP_CORE_SCOPED_p30_9b6d", ScopedBytes, 3, depth);
  return !nested && before == ScopedByteHash && after == before ? 0 : 5;
}

extern "C" TEST_SCOPED int scoped_thread(unsigned worker) noexcept {
  uint32_t before = scoped_observe8("NDKP_CORE_SCOPED_p30_9b6d", ScopedBytes, 4, worker);
  int waited = scoped_thread_barrier(worker);
  uint32_t after = scoped_observe8("NDKP_CORE_SCOPED_p30_9b6d", ScopedBytes, 5, worker);
  return !waited && before == ScopedByteHash && after == before ? 0 : 6;
}

// The original constant load satisfies const; scoped lowering adds the effects.
extern "C" TEST_SCOPED __attribute__((const, noinline)) int scoped_unused_gate(unsigned index) noexcept {
  return static_cast<unsigned char>("NDKP_CORE_SCOPED_p30_9b6d"[index % (ScopedBytes - 1)]);
}
extern "C" __attribute__((const, noinline)) int scoped_relay_inner(unsigned index) noexcept {
  return scoped_unused_gate(index);
}
extern "C" __attribute__((pure, noinline)) int scoped_relay_outer(unsigned index) noexcept {
  return scoped_relay_inner(index);
}
extern "C" int scoped_unused_driver(unsigned index) noexcept {
  int used = scoped_relay_outer(index);
  (void)scoped_relay_outer(index);
  return used;
}
