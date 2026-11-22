#ifndef NDKP_SCOPED_FIXTURE_H
#define NDKP_SCOPED_FIXTURE_H
#include <cstddef>
#include <cstdint>

constexpr size_t ScopedBytes = 26;
constexpr size_t ScopedWords = 9;
constexpr uint32_t ScopedByteHash = 0x1cb3380bu;
constexpr uint32_t ScopedWordHash = 0x34574550u;

extern "C" {
uint32_t scoped_observe8(const char* __attribute__((noescape)), size_t, unsigned, unsigned) noexcept;
uint32_t scoped_observe16(const char16_t* __attribute__((noescape)), size_t) noexcept;
int scoped_thread_barrier(unsigned) noexcept;
const char* scoped_static_value() noexcept;
__attribute__((visibility("default"))) int scoped_multi(int) noexcept;
int scoped_recursive(unsigned) noexcept;
int scoped_thread(unsigned) noexcept;
int scoped_unused_driver(unsigned) noexcept;
__attribute__((visibility("default"))) int run_scoped(int) noexcept;
}
#endif
