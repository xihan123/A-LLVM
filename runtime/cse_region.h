// SPDX-License-Identifier: Apache-2.0
#ifndef NDKP_CSE_REGION_H
#define NDKP_CSE_REGION_H
#include <cstddef>
#include <cstdint>

namespace ndkp_cse {
struct RegionV1 {
  uint32_t offset, out_capacity, encoding;
};
struct ModuleV1 {
  const uint8_t* blob;
  uint8_t* cache;
  const RegionV1* regions;
  uint32_t total, count;
};
struct ScopedRegionV1 {
  uint8_t* data;
  size_t mapped;
  uint32_t state;
};
static_assert(sizeof(RegionV1) == 12, "CSE region ABI");
#if INTPTR_MAX == INT64_MAX
static_assert(sizeof(ModuleV1) == 32 && offsetof(ModuleV1, total) == 24, "CSE module ABI");
static_assert(sizeof(ScopedRegionV1) == 24 && offsetof(ScopedRegionV1, state) == 16,
              "CSE scoped region ABI");
#endif
}
// Compiler-internal entry: module is a checked snapshot from the generated module
// guard; regions must reside in the owning image's authenticated executable bytes.
extern "C" __attribute__((visibility("hidden"))) void ndkp_cse_decode_region_v1(
    uint8_t*, const ndkp_cse::ModuleV1*, const ndkp_cse::RegionV1*);
extern "C" __attribute__((visibility("hidden"))) void ndkp_cse_recheck_module_v1(
    const ndkp_cse::ModuleV1*);
// A compiler-private, zero-initialized lease is used once: fresh(0), active(1), retired(2).
extern "C" __attribute__((visibility("hidden"))) uint8_t* ndkp_cse_acquire_region_v1(
    const ndkp_cse::ModuleV1*, const ndkp_cse::RegionV1*, ndkp_cse::ScopedRegionV1*);
extern "C" __attribute__((visibility("hidden"))) void ndkp_cse_release_region_v1(
    ndkp_cse::ScopedRegionV1*);
#endif
