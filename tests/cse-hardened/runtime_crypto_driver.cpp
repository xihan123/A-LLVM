// Compare the separately linked protected runtime against native primitives.
#include "cse_crypto.h"
#include <cstdio>
namespace ndkp_cse::vmp {
void derive(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t*);
void hmac(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*);
bool open(const uint8_t*, const uint8_t*, const uint8_t*, size_t, uint8_t*, size_t, const uint8_t*);
}
int main() {
  using namespace ndkp_cse;
  uint8_t header[256] = {}, code[32] = {}, inputs[48] = {}, key[32], protectedKey[32];
  for (unsigned i = 0; i < 256; ++i) header[i] = uint8_t(i);
  derive(header, code, inputs, key);
  vmp::derive(header, code, inputs, protectedKey);
  if (!equal(key, protectedKey, 32)) {
    std::puts("derive mismatch");
    for (auto x : key) std::printf("%02x", x);
    std::puts("");
    for (auto x : protectedKey) std::printf("%02x", x);
    std::puts("");
    return 1;
  }
  for (unsigned trial = 0; trial < 8; ++trial) {
    for (unsigned i = 0; i < sizeof header; ++i) header[i] ^= uint8_t(i + trial * 17);
    for (unsigned i = 0; i < sizeof code; ++i) code[i] = uint8_t(i * 31 + trial);
    for (unsigned i = 0; i < sizeof inputs; ++i) inputs[i] = uint8_t(i + trial * 43);
    derive(header, code, inputs, key);
    vmp::derive(header, code, inputs, protectedKey);
    if (!equal(key, protectedKey, 32)) return 2;
  }
  uint8_t native[64], vm[64], nonce[12] = {}, associated[40] = {};
  for (size_t n : {size_t(0), size_t(1), size_t(15), size_t(16), size_t(17), size_t(63), size_t(64), size_t(65), size_t(1024)}) {
    std::vector<uint8_t> a(n, 0x5a), b = a;
    hmac(key, 32, a.data(), a.size(), native); vmp::hmac(key, 32, b.data(), b.size(), vm);
    if (!equal(native, vm, 32)) { std::puts("hmac mismatch"); return 3; }
    uint8_t tag[16]; seal(key, nonce, associated, 40, a.data(), a.size(), tag); b = a;
    if (!open(key, nonce, associated, 40, a.data(), a.size(), tag) ||
        !vmp::open(key, nonce, associated, 40, b.data(), b.size(), tag) || a != b) {
      std::puts("open mismatch"); return 6;
    }
    // Each trial must authenticate the original ciphertext with just one bad tag byte.
    seal(key, nonce, associated, 40, b.data(), b.size(), tag);
    const auto ciphertext = b;
    for (unsigned byte = 0; byte < sizeof tag; ++byte) {
      tag[byte] ^= 1;
      b = ciphertext;
      if (vmp::open(key, nonce, associated, 40, b.data(), b.size(), tag) || b != ciphertext) return 7;
      tag[byte] ^= 1;
    }
  }
  std::puts("CSE native/VMP differential passed");
}
