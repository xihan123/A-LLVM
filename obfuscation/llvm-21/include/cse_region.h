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
static_assert(sizeof(RegionV1) == 12, "CSE region ABI");
#if INTPTR_MAX == INT64_MAX
static_assert(sizeof(ModuleV1) == 32 && offsetof(ModuleV1, total) == 24, "CSE module ABI");
#endif
}
// Compiler-internal entry: module is a checked snapshot from the generated module
// guard; regions must reside in the owning image's authenticated executable bytes.
extern "C" __attribute__((visibility("hidden"))) void ndkp_cse_decode_region_v1(
    uint8_t*, const ndkp_cse::ModuleV1*, const ndkp_cse::RegionV1*);
#endif
