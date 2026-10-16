#include "apkcert.h"

extern "C" __attribute__((visibility("hidden"))) void ndkp_certbind_mix(uint64_t*, uint64_t*);
extern "C" __attribute__((visibility("default"))) bool module_cert_probe(uint8_t out[32]) {
    if (!stringarmor::apkcert::certSha256ForLibrary(
            reinterpret_cast<const void*>(&ndkp_certbind_mix), out)) return false;
    uint64_t lo, hi;
    ndkp_certbind_mix(&lo, &hi);
    using stringarmor::apkcert::le64;
    return lo == (le64(out) ^ le64(out + 16)) && hi == (le64(out + 8) ^ le64(out + 24));
}
