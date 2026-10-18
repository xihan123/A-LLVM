// Exercise exact-read boundaries and errors without relying on libc interposition.
#include "apkcert.h"
#include <cassert>
#include <climits>
#include <cstdio>
struct FaultIO {
  inline static unsigned calls = 0;
  inline static bool truncate = false;
  static ssize_t pread(int, void* out, size_t n, off64_t offset) {
    if (++calls == 1) { errno = EINTR; return -1; }
    if (truncate && offset >= 3) return 0;
    if (n == 0) return 0;
    *static_cast<unsigned char*>(out) = static_cast<unsigned char>(offset);
    return 1; // Successful short reads must be accumulated, not treated as EOF.
  }
};
int main() {
  unsigned char bytes[8] = {};
  using stringarmor::apkcert::readAt;
  assert(readAt<FaultIO>(0, 0, bytes, sizeof bytes));
  for (unsigned i = 0; i < 8; ++i) assert(bytes[i] == i);
  assert(FaultIO::calls == 9);
  FaultIO::calls = 0; FaultIO::truncate = true;
  assert(!readAt<FaultIO>(0, 0, bytes, sizeof bytes));
  FaultIO::calls = 0;
  assert(!readAt<FaultIO>(0, UINT64_MAX, bytes, 1));
  assert(!readAt<FaultIO>(0, INT64_MAX, bytes, 1));
  assert(FaultIO::calls == 0);
  std::puts("CSE exact-read fault tests passed");
}
