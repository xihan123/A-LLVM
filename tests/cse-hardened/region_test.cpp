// Descriptor/record identity and output bounds, including authenticated bad metadata.
#include "cse_region.h"
#include "cse_crypto.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ndkp_cse;

int main() {
  // The fixture injects already-cached public inputs to isolate record validation.
  alignas(4) uint8_t cache[84] = {2};
  uint8_t blob[HeaderSize + 3 * 64] = {};
  std::memcpy(blob, Magic, 8);
  store32(blob + 8, sizeof blob); store32(blob + 12, 1); store32(blob + 20, 3);
  RegionV1 regions[] = {{256, 16, 1}, {320, 16, 2}, {384, 16, 1}};
  ModuleV1 module{blob, cache, regions, sizeof blob, 3};
  uint8_t key[32]; derive(blob, cache + 4, cache + 36, key);
  for (unsigned i = 0; i < 3; ++i) {
    uint8_t* record = blob + regions[i].offset;
    store32(record, 32); store32(record + 12, i);
    store32(record + 32, 6); store32(record + 36, regions[i].encoding);
    store32(record + 40, i);
    std::memcpy(record + 48, "hello!", 6);
    uint8_t associated[40]; aad(blob, i, 32, associated);
    seal(key, record + 4, associated, sizeof associated, record + 32, 32, record + 16);
  }
  auto* output = static_cast<uint8_t*>(mmap(nullptr, 32, PROT_READ | PROT_WRITE,
                                         MAP_SHARED | MAP_ANONYMOUS, -1, 0));
  assert(output != MAP_FAILED);
  for (unsigned i = 0; i < 3; ++i) {
    std::memset(output, 0xcc, 32);
    ndkp_cse_decode_region_v1(output + 1, &module, regions + i);
    assert(output[0] == 0xcc && !std::memcmp(output + 1, "hello!", 6));
    for (unsigned j = 7; j < 32; ++j) assert(output[j] == 0xcc);
  }
  for (unsigned test = 0; test < 12; ++test) {
    std::memset(output, 0xcc, 32);
    int errors[2]; assert(pipe(errors) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
      close(errors[0]); assert(dup2(errors[1], STDERR_FILENO) == STDERR_FILENO); close(errors[1]);
      alarm(10);
      const RegionV1* selected = regions;
      switch (test) {
      case 0: std::swap_ranges(blob + 256, blob + 320, blob + 320); break;
      case 1: store32(blob + 256, 64); break;
      case 2: store32(blob + 268, 1); break;
      case 3: selected = reinterpret_cast<const RegionV1*>(reinterpret_cast<uintptr_t>(regions) + 1); break;
      case 4: selected = regions + 3; break;
      case 5: regions[0].out_capacity = 15; break;
      case 6: regions[0].offset = sizeof blob - 1; break;
      case 7: regions[0].encoding = 2; break;
      case 8: module.count = 2; break;
      case 9: selected = nullptr; break;
      case 10: blob[256 + 16] ^= 1; break;
      case 11: {
        // A valid tag must not allow an odd UTF-16 byte length.
        selected = regions + 1;
        uint8_t* record = blob + 320;
        uint8_t associated[40]; aad(blob, 1, 32, associated);
        assert(open(key, record + 4, associated, sizeof associated, record + 32, 32, record + 16));
        store32(record + 32, 3);
        seal(key, record + 4, associated, sizeof associated, record + 32, 32, record + 16);
        break;
      }
      }
      ndkp_cse_decode_region_v1(output + 1, &module, selected);
      _exit(99);
    }
    close(errors[1]);
    int status; assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 127);
    char diagnostic; assert(read(errors[0], &diagnostic, 1) == 0); close(errors[0]);
    for (unsigned j = 0; j < 32; ++j) assert(output[j] == 0xcc);
  }
  assert(munmap(output, 32) == 0);
  puts("CSE regions: identity, bounds, UTF-16 and silent rejection OK");
}
