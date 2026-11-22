#ifndef CORE_CSE_SCOPED_CONSUMER_H
#define CORE_CSE_SCOPED_CONSUMER_H
#include <cstddef>
#include <cstdint>

extern "C" uint32_t core_cse_hash8(const char* __attribute__((noescape)), size_t) noexcept;
extern "C" uint32_t core_cse_hash16(const char16_t* __attribute__((noescape)), size_t) noexcept;
extern "C" int core_cse_scoped_probe() noexcept;
#endif
