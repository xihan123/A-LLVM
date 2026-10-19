// SPDX-License-Identifier: Apache-2.0
#ifndef NDKP_APKVERIFY_H
#define NDKP_APKVERIFY_H
#include <cstddef>
#include <cstdint>

namespace ndkp_apkverify {
// The caller owns a stable, read-only file descriptor and checks its identity.
using ReadAt = bool (*)(void*, uint64_t, void*, size_t);
enum class Error { None, Io, Zip, SigningBlock, Unsupported, Signer, Certificate,
                   Algorithm, Signature, Content, Attributes, Sdk };
struct Result { uint8_t certificate[32]; uint32_t schemes; };
bool verify(ReadAt read, void* context, uint64_t size, const uint8_t expected[32],
            unsigned api, Result& result, Error& error);
const char* errorName(Error error);
}
#endif
