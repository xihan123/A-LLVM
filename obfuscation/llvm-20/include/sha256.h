/*
 * Copyright 2026 StringArmor
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal FIPS 180-4 SHA-256, header-only. Used by the optional signing-cert binding
 * (STRINGARMOR_CERT_BIND) to hash the app's signing certificate at runtime so the digest
 * can be folded into the payload pepper. Computing the digest natively (from the raw cert
 * DER bytes) rather than in Java keeps the only hookable surface the raw-cert JNI calls —
 * faking a whole certificate that hashes to the build-time value is infeasible.
 *
 * One-shot; processes the message in 64-byte blocks so no large buffer is needed (a signing
 * cert is ~1 KB). Verified against the standard vector SHA256("abc") in the host self-test.
 */
#ifndef STRINGARMOR_SHA256_H
#define STRINGARMOR_SHA256_H

#include <cstddef>
#include <cstdint>

namespace stringarmor {
namespace sha2 {

inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// Writes the 32-byte big-endian SHA-256 digest of msg[0..len) into out.
inline void sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
    static const uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

    auto processBlock = [&](const uint8_t* p) {
        uint32_t w[64];
        for (int t = 0; t < 16; ++t) {
            w[t] = (static_cast<uint32_t>(p[t * 4]) << 24) | (static_cast<uint32_t>(p[t * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(p[t * 4 + 2]) << 8) | static_cast<uint32_t>(p[t * 4 + 3]);
        }
        for (int t = 16; t < 64; ++t) {
            const uint32_t s0 = ror(w[t - 15], 7) ^ ror(w[t - 15], 18) ^ (w[t - 15] >> 3);
            const uint32_t s1 = ror(w[t - 2], 17) ^ ror(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int t = 0; t < 64; ++t) {
            const uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t t1 = hh + S1 + ch + K[t] + w[t];
            const uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    };

    size_t i = 0;
    for (; i + 64 <= len; i += 64) processBlock(msg + i);

    uint8_t block[64] = {0};
    const size_t rem = len - i;
    for (size_t j = 0; j < rem; ++j) block[j] = msg[i + j];
    block[rem] = 0x80;
    const uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    if (rem >= 56) {
        processBlock(block);
        for (int j = 0; j < 64; ++j) block[j] = 0;
    }
    for (int j = 0; j < 8; ++j) block[56 + j] = static_cast<uint8_t>(bitlen >> (56 - 8 * j));
    processBlock(block);

    for (int j = 0; j < 8; ++j) {
        out[j * 4]     = static_cast<uint8_t>(h[j] >> 24);
        out[j * 4 + 1] = static_cast<uint8_t>(h[j] >> 16);
        out[j * 4 + 2] = static_cast<uint8_t>(h[j] >> 8);
        out[j * 4 + 3] = static_cast<uint8_t>(h[j]);
    }
}

}  // namespace sha2
}  // namespace stringarmor

#endif  // STRINGARMOR_SHA256_H
