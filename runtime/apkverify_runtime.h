// SPDX-License-Identifier: Apache-2.0
#ifndef NDKP_APKVERIFY_RUNTIME_H
#define NDKP_APKVERIFY_RUNTIME_H
#include <cstdint>
#include <sys/stat.h>
// Borrowed fd: owned by this DSO until unload. Failure terminates the process.
extern "C" __attribute__((visibility("hidden"))) int ndkp_verified_apk(
    uint8_t certificate[32], struct stat* identity);
#endif
