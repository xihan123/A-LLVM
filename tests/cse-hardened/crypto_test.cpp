// RFC 8439 / RFC 5869 vectors, run with native or Android C++17 compiler.
#include "cse_crypto.h"
#include <cassert>
#include <string>
#include <cstdio>
using namespace ndkp_cse;
static std::vector<uint8_t> hex(const char* s) {
  std::vector<uint8_t> out;
  while (*s) { unsigned x; assert(std::sscanf(s, "%2x", &x) == 1); out.push_back(uint8_t(x)); s += 2; }
  return out;
}
int main() {
  uint8_t key[32]; for (unsigned i = 0; i < 32; ++i) key[i] = uint8_t(0x80 + i);
  auto nonce = hex("070000004041424344454647");
  auto associated = hex("50515253c0c1c2c3c4c5c6c7");
  const std::string message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  std::vector<uint8_t> plain(message.begin(), message.end());
  uint8_t tag[16]; seal(key, nonce.data(), associated.data(), associated.size(), plain.data(), plain.size(), tag);
  auto expectedTag = hex("1ae10b594f09e26a7e902ecbd0600691");
  auto expectedCipher = hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
  assert(plain == expectedCipher && equal(tag, expectedTag.data(), 16));
  tag[0] ^= 1;
  assert(!open(key, nonce.data(), associated.data(), associated.size(), plain.data(), plain.size(), tag));
  assert(plain == expectedCipher); tag[0] ^= 1;
  assert(open(key, nonce.data(), associated.data(), associated.size(), plain.data(), plain.size(), tag));
  assert(std::string(plain.begin(), plain.end()) == message);
  auto ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  uint8_t salt[32] = {}, info[10], derived[32];
  // RFC salt is 13 bytes, so use extract/expand explicitly for this vector.
  for (unsigned i = 0; i < 13; ++i) salt[i] = uint8_t(i);
  for (unsigned i = 0; i < 10; ++i) info[i] = uint8_t(0xf0 + i);
  uint8_t prk[32]; hmac(salt, 13, ikm.data(), ikm.size(), prk);
  uint8_t expansion[11]; std::memcpy(expansion, info, 10); expansion[10] = 1;
  hmac(prk, 32, expansion, sizeof expansion, derived);
  auto expected = hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
  assert(equal(derived, expected.data(), 32));
  // Exercise all padding boundaries, empty messages and multiple blocks.
  for (size_t n : {size_t(0), size_t(1), size_t(15), size_t(16), size_t(17), size_t(63), size_t(64), size_t(65), size_t(1024)}) {
    std::vector<uint8_t> bytes(n, 0x5a), original = bytes;
    seal(key, nonce.data(), info, sizeof info, bytes.data(), bytes.size(), tag);
    assert(open(key, nonce.data(), info, sizeof info, bytes.data(), bytes.size(), tag));
    assert(bytes == original);
  }
  std::puts("CSE crypto vectors passed");
}
