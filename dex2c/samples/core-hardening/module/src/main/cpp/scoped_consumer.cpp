#include "scoped_consumer.h"

extern "C" uint32_t core_cse_hash8(const char* __attribute__((noescape)) data, size_t count) noexcept {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < count; ++i) hash = (hash ^ static_cast<uint8_t>(data[i])) * 16777619u;
    return hash;
}

extern "C" uint32_t core_cse_hash16(const char16_t* __attribute__((noescape)) data, size_t count) noexcept {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < count; ++i) {
        uint16_t word = static_cast<uint16_t>(data[i]);
        hash = (hash ^ static_cast<uint8_t>(word)) * 16777619u;
        hash = (hash ^ static_cast<uint8_t>(word >> 8)) * 16777619u;
    }
    return hash;
}
