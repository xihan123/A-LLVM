// SPDX-License-Identifier: Apache-2.0
#include "apkverify.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
static bool readAt(void* context, uint64_t offset, void* output, size_t count) {
  FILE* f = static_cast<FILE*>(context);
#ifdef _WIN32
  if (_fseeki64(f, offset, SEEK_SET)) return false;
#else
  if (fseeko(f, offset, SEEK_SET)) return false;
#endif
  return std::fread(output, 1, count, f) == count;
}
int main(int argc, char** argv) {
  if (argc != 4 || std::strlen(argv[2]) != 64) return 2;
  uint8_t expected[32];
  for (unsigned i = 0; i < 32; ++i) {
    char s[3]{argv[2][i * 2], argv[2][i * 2 + 1], 0}; char* end;
    expected[i] = uint8_t(std::strtoul(s, &end, 16)); if (*end) return 2;
  }
  FILE* f = std::fopen(argv[1], "rb"); if (!f) return 2;
#ifdef _WIN32
  _fseeki64(f, 0, SEEK_END); auto size = _ftelli64(f);
#else
  fseeko(f, 0, SEEK_END); auto size = ftello(f);
#endif
  ndkp_apkverify::Result result; std::memset(&result, 0xa5, sizeof result);
  ndkp_apkverify::Error error;
  bool ok = ndkp_apkverify::verify(readAt, f, uint64_t(size), expected, unsigned(std::atoi(argv[3])), result, error);
  std::fclose(f);
  if (!ok) {
    ndkp_apkverify::Result original; std::memset(&original, 0xa5, sizeof original);
    if (std::memcmp(&original, &result, sizeof result)) return 3;
  }
  std::printf("%s\n", ndkp_apkverify::errorName(error)); return ok ? 0 : 1;
}
