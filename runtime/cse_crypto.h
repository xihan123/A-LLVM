// SPDX-License-Identifier: Apache-2.0
// Shared byte-exact CSE v1 primitives. Keep overlay copies identical (tested).
#ifndef NDKP_CSE_CRYPTO_H
#define NDKP_CSE_CRYPTO_H
#include "sha256.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

// Only the separately compiled runtime opts in. Business CSE constants and the
// sealer's host-side primitives must not acquire VMP annotations implicitly.
#if defined(NDKP_CSE_VMP)
#define NDKP_CSE_CORE __attribute__((annotate("ndkp.vmp"), noinline))
#define NDKP_CSE_PRIMITIVE __attribute__((noinline))
#else
#define NDKP_CSE_CORE
#define NDKP_CSE_PRIMITIVE
#endif

namespace ndkp_cse {
#if defined(NDKP_CSE_VMP)
// Do not let a native inline definition from another TU win COMDAT selection
// over a protected crypto implementation (or collide with its promoted linkage).
namespace vmp {
#endif
NDKP_CSE_PRIMITIVE inline void wipe(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}
inline uint32_t load32(const uint8_t* p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint64_t load64(const uint8_t* p) {
  return load32(p) | uint64_t(load32(p + 4)) << 32;
}
inline void store32(uint8_t* p, uint32_t x) {
  for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(x >> (i * 8));
}
inline void store64(uint8_t* p, uint64_t x) {
  for (unsigned i = 0; i < 8; ++i) p[i] = uint8_t(x >> (i * 8));
}
NDKP_CSE_PRIMITIVE inline bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
  uint32_t diff = 0;
  for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
  return diff == 0;
}
inline uint32_t rotl(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
inline void qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
  a += b; d = rotl(d ^ a, 16); c += d; b = rotl(b ^ c, 12);
  a += b; d = rotl(d ^ a, 8); c += d; b = rotl(b ^ c, 7);
}
NDKP_CSE_PRIMITIVE inline void block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                  uint8_t out[64]) {
  uint32_t s[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
  for (unsigned i = 0; i < 8; ++i) s[4 + i] = load32(key + 4 * i);
  s[12] = counter;
  for (unsigned i = 0; i < 3; ++i) s[13 + i] = load32(nonce + 4 * i);
  uint32_t x[16]; std::memcpy(x, s, sizeof x);
  for (unsigned i = 0; i < 10; ++i) {
    qr(x[0], x[4], x[8], x[12]); qr(x[1], x[5], x[9], x[13]);
    qr(x[2], x[6], x[10], x[14]); qr(x[3], x[7], x[11], x[15]);
    qr(x[0], x[5], x[10], x[15]); qr(x[1], x[6], x[11], x[12]);
    qr(x[2], x[7], x[8], x[13]); qr(x[3], x[4], x[9], x[14]);
  }
  for (unsigned i = 0; i < 16; ++i) store32(out + 4 * i, x[i] + s[i]);
  wipe(x, sizeof x); wipe(s, sizeof s);
}
NDKP_CSE_PRIMITIVE inline void crypt(const uint8_t key[32], const uint8_t nonce[12], uint8_t* p, size_t n) {
  uint8_t ks[64]; uint32_t counter = 1;
  while (n) {
    block(key, nonce, counter++, ks);
    const size_t take = n < 64 ? n : 64;
    for (size_t i = 0; i < take; ++i) p[i] ^= ks[i];
    n -= take; p += take;
  }
  wipe(ks, sizeof ks);
}
// 26-bit-limb Poly1305; all arithmetic has fixed iteration counts.
NDKP_CSE_PRIMITIVE inline void poly1305(const uint8_t key[32], const uint8_t* msg, size_t n, uint8_t tag[16]) {
  const uint32_t r0 = load32(key) & 0x3ffffff;
  const uint32_t r1 = (load32(key + 3) >> 2) & 0x3ffff03;
  const uint32_t r2 = (load32(key + 6) >> 4) & 0x3ffc0ff;
  const uint32_t r3 = (load32(key + 9) >> 6) & 0x3f03fff;
  const uint32_t r4 = (load32(key + 12) >> 8) & 0x00fffff;
  uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
  while (n) {
    uint8_t b[17] = {};
    const size_t take = n < 16 ? n : 16;
    std::memcpy(b, msg, take); b[take] = 1;
    h0 += load32(b) & 0x3ffffff;
    h1 += (load32(b + 3) >> 2) & 0x3ffffff;
    h2 += (load32(b + 6) >> 4) & 0x3ffffff;
    h3 += (load32(b + 9) >> 6) & 0x3ffffff;
    h4 += (load32(b + 12) >> 8) | uint32_t(b[16]) << 24;
    uint64_t d0 = uint64_t(h0)*r0 + uint64_t(h1)*r4*5 + uint64_t(h2)*r3*5 + uint64_t(h3)*r2*5 + uint64_t(h4)*r1*5;
    uint64_t d1 = uint64_t(h0)*r1 + uint64_t(h1)*r0 + uint64_t(h2)*r4*5 + uint64_t(h3)*r3*5 + uint64_t(h4)*r2*5;
    uint64_t d2 = uint64_t(h0)*r2 + uint64_t(h1)*r1 + uint64_t(h2)*r0 + uint64_t(h3)*r4*5 + uint64_t(h4)*r3*5;
    uint64_t d3 = uint64_t(h0)*r3 + uint64_t(h1)*r2 + uint64_t(h2)*r1 + uint64_t(h3)*r0 + uint64_t(h4)*r4*5;
    uint64_t d4 = uint64_t(h0)*r4 + uint64_t(h1)*r3 + uint64_t(h2)*r2 + uint64_t(h3)*r1 + uint64_t(h4)*r0;
    uint32_t c;
    c = uint32_t(d0 >> 26); h0 = uint32_t(d0) & 0x3ffffff; d1 += c;
    c = uint32_t(d1 >> 26); h1 = uint32_t(d1) & 0x3ffffff; d2 += c;
    c = uint32_t(d2 >> 26); h2 = uint32_t(d2) & 0x3ffffff; d3 += c;
    c = uint32_t(d3 >> 26); h3 = uint32_t(d3) & 0x3ffffff; d4 += c;
    c = uint32_t(d4 >> 26); h4 = uint32_t(d4) & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    msg += take; n -= take; wipe(b, sizeof b);
  }
  uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
  c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
  c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
  c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
  c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
  uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
  uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
  uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
  uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
  uint32_t g4 = h4 + c - (1u << 26);
  uint32_t mask = (g4 >> 31) - 1;
  h0 = (h0 & ~mask) | (g0 & mask); h1 = (h1 & ~mask) | (g1 & mask);
  h2 = (h2 & ~mask) | (g2 & mask); h3 = (h3 & ~mask) | (g3 & mask);
  h4 = (h4 & ~mask) | (g4 & mask);
  uint64_t f = uint64_t(uint32_t(h0 | h1 << 26)) + load32(key + 16);
  store32(tag, uint32_t(f));
  f = uint64_t(uint32_t(h1 >> 6 | h2 << 20)) + load32(key + 20) + (f >> 32);
  store32(tag + 4, uint32_t(f));
  f = uint64_t(uint32_t(h2 >> 12 | h3 << 14)) + load32(key + 24) + (f >> 32);
  store32(tag + 8, uint32_t(f));
  f = uint64_t(uint32_t(h3 >> 18 | h4 << 8)) + load32(key + 28) + (f >> 32);
  store32(tag + 12, uint32_t(f));
}
NDKP_CSE_PRIMITIVE inline void auth(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t* aad, size_t an, const uint8_t* data, size_t n, uint8_t tag[16]) {
  std::vector<uint8_t> mac((an + 15) / 16 * 16 + (n + 15) / 16 * 16 + 16, 0);
  if (an) std::memcpy(mac.data(), aad, an);
  const size_t offset = (an + 15) / 16 * 16;
  if (n) std::memcpy(mac.data() + offset, data, n);
  store64(mac.data() + mac.size() - 16, an); store64(mac.data() + mac.size() - 8, n);
  uint8_t first[64]; block(key, nonce, 0, first);
  poly1305(first, mac.data(), mac.size(), tag);
  wipe(first, sizeof first); wipe(mac.data(), mac.size());
}
inline void seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad,
                 size_t an, uint8_t* data, size_t n, uint8_t tag[16]) {
  crypt(key, nonce, data, n); auth(key, nonce, aad, an, data, n, tag);
}
NDKP_CSE_CORE inline bool open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad,
                 size_t an, uint8_t* data, size_t n, const uint8_t tag[16]) {
  uint8_t computed[16]; auth(key, nonce, aad, an, data, n, computed);
  const bool ok = equal(computed, tag, 16); wipe(computed, sizeof computed);
  if (ok) crypt(key, nonce, data, n);
  return ok;
}
NDKP_CSE_PRIMITIVE inline void hmac(const uint8_t* key, size_t kn, const uint8_t* msg, size_t n, uint8_t out[32]) {
  uint8_t k[64] = {}, outer[96];
  if (kn > 64) stringarmor::sha2::sha256(key, kn, k);
  else if (kn) std::memcpy(k, key, kn);
  std::vector<uint8_t> inner(64 + n);
  for (unsigned i = 0; i < 64; ++i) { inner[i] = k[i] ^ 0x36; outer[i] = k[i] ^ 0x5c; }
  if (n) std::memcpy(inner.data() + 64, msg, n);
  stringarmor::sha2::sha256(inner.data(), inner.size(), outer + 64);
  stringarmor::sha2::sha256(outer, sizeof outer, out);
  wipe(k, sizeof k); wipe(outer, sizeof outer); wipe(inner.data(), inner.size());
}
NDKP_CSE_PRIMITIVE inline void hkdf(const uint8_t* ikm, size_t n, const uint8_t salt[32],
                 const uint8_t* info, size_t in, uint8_t out[32]) {
  uint8_t prk[32]; hmac(salt, 32, ikm, n, prk);
  std::vector<uint8_t> expanded(info, info + in); expanded.push_back(1);
  hmac(prk, 32, expanded.data(), expanded.size(), out);
  wipe(prk, sizeof prk); wipe(expanded.data(), expanded.size());
}
// Wire layout: fixed 256-byte module header, then [capacity:u32, nonce:12,
// tag:16, ciphertext:capacity]. All integers little-endian; no native structs.
constexpr size_t HeaderSize = 256;
constexpr uint32_t MaxCapacity = 1u << 24;
constexpr uint8_t Magic[8] = {'N','D','K','P','C','S','E',1};
// Header: size@8, state@12, flags@16, count@20, module-id@24, seed@40,
// nonce@72, expected-inputs@104 (48 staging bytes), code-hash@152,
// seed-mask@184..215, reserved@216..255. Expected inputs are erased after sealing.
// Material assembly is a primitive, like HKDF; keep byte loops outside VM control.
NDKP_CSE_PRIMITIVE inline void key_material(const uint8_t* h, const uint8_t code[32],
                                           const uint8_t inputs[48], uint8_t ikm[80], uint8_t info[64]) {
  for (unsigned i = 0; i < 32; ++i) ikm[i] = h[40 + i] ^ h[184 + i];
  std::memcpy(ikm + 32, inputs, 48);
  std::memset(info, 0, 64);
  std::memcpy(info, "NDKP-CSE-v1", 11); std::memcpy(info + 16, h + 24, 16);
  std::memcpy(info + 32, code, 32);
}
NDKP_CSE_CORE inline void derive(const uint8_t* h, const uint8_t code[32], const uint8_t inputs[48], uint8_t key[32]) {
  uint8_t ikm[80], info[64];
  key_material(h, code, inputs, ikm, info);
  hkdf(ikm, sizeof ikm, h + 72, info, sizeof info, key); wipe(ikm, sizeof ikm);
}
inline void aad(const uint8_t* h, uint32_t ordinal, uint32_t cap, uint8_t out[40]) {
  std::memcpy(out, h + 24, 16); store32(out + 16, 1);
  store32(out + 20, load32(h + 16)); store32(out + 24, ordinal); store32(out + 28, cap);
  store32(out + 32, load32(h + 8)); store32(out + 36, load32(h + 20));
}
#if defined(NDKP_CSE_VMP)
} // namespace vmp
using namespace vmp;
#endif
} // namespace ndkp_cse
#undef NDKP_CSE_CORE
#undef NDKP_CSE_PRIMITIVE
#endif
