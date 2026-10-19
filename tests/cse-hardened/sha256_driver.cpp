#include "sha256.h"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
  using namespace stringarmor::sha2;
  const uint8_t abc[3] = {'a', 'b', 'c'};
  const uint8_t expected[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
  };
  uint8_t actual[32], portable[32];
  sha256(abc, sizeof abc, actual);
  if (std::memcmp(actual, expected, sizeof actual)) return 1;
  std::vector<uint8_t> data(4 * 1024 * 1024 + 8);
  for (size_t i = 0; i < data.size(); ++i) data[i] = uint8_t(i * 71 + (i >> 8));
  for (unsigned offset = 0; offset < 8; ++offset) {
    for (size_t length = 0; length <= 257; ++length) {
      sha256(data.data() + offset, length, actual);
      detail::sha256_impl(data.data() + offset, length, portable, false);
      if (std::memcmp(actual, portable, sizeof actual)) return 2;
    }
  }
  const auto start = std::chrono::steady_clock::now();
  sha256(data.data() + 1, data.size() - 8, actual);
  const auto middle = std::chrono::steady_clock::now();
  detail::sha256_impl(data.data() + 1, data.size() - 8, portable, false);
  const auto end = std::chrono::steady_clock::now();
  if (std::memcmp(actual, portable, sizeof actual)) return 3;
  std::printf("SHA256 hardware=%d selected_us=%lld portable_us=%lld: vectors/alignment/padding OK\n",
      int(sha256_acceleration_available()),
      (long long)std::chrono::duration_cast<std::chrono::microseconds>(middle - start).count(),
      (long long)std::chrono::duration_cast<std::chrono::microseconds>(end - middle).count());
}
