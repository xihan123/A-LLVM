// SPDX-License-Identifier: Apache-2.0
#ifndef NDKP_QSEG_H
#define NDKP_QSEG_H
#include <cstddef>
#include <cstdint>
extern "C" {
extern __attribute__((visibility("hidden"))) const uint8_t ndkp_qseg_image[512];
struct ndkp_qseg_cache_stats_v1 {
  uint64_t active_bytes, idle_bytes, pinned_bytes, peak_resident_bytes, evictions;
};
// ref 是只读描述符句柄；每次成功 acquire 必须且只能配对一次 release。
__attribute__((visibility("hidden"))) const uint8_t* ndkp_qseg_acquire_v1(const uint8_t* ref);
__attribute__((visibility("hidden"))) void ndkp_qseg_release_v1(const uint8_t* ref);
__attribute__((visibility("hidden"), retain)) void ndkp_qseg_stats_v1(ndkp_qseg_cache_stats_v1* out);
__attribute__((visibility("hidden"))) const uint8_t* ndkp_qseg_get(const uint8_t* ref);
__attribute__((visibility("hidden"))) void ndkp_qseg_copy(uint8_t*, const uint8_t*, uint32_t, uint32_t, uint32_t);
__attribute__((visibility("hidden"))) void ndkp_qseg_verify();
__attribute__((visibility("hidden"))) void ndkp_qseg_recheck();
// These wrappers call the existing embedded derive/open VM entries.
__attribute__((visibility("hidden"))) void ndkp_qseg_measure(uint8_t[32], uint8_t[48]);
__attribute__((visibility("hidden"))) void ndkp_qseg_derive(const uint8_t[32], const uint8_t[48], uint8_t[32]);
__attribute__((visibility("hidden"))) bool ndkp_qseg_open(const uint8_t[32], const uint8_t*, size_t, uint8_t*, size_t, const uint8_t[16]);
}
#endif
