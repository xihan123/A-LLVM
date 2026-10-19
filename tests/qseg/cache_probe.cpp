// Test-only offsets come from the unstripped matching fixture, never production exports.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <thread>
#include <vector>
#include <atomic>
int main(int argc, char** argv) {
  assert(argc == 5);
  void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) { std::fprintf(stderr, "%s\n", dlerror()); return 2; }
  Dl_info info{}; assert(dladdr(dlsym(library, "JNI_OnLoad"), &info));
  const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
  auto get = reinterpret_cast<const uint8_t* (*)(const uint8_t*)>(base + std::strtoull(argv[2], nullptr, 16));
  auto* ref = reinterpret_cast<const uint8_t*>(base + std::strtoull(argv[3], nullptr, 16));
  std::atomic<bool> go{false}; const uint8_t* results[8]{};
  std::vector<std::thread> threads;
  for (unsigned i = 0; i < 8; ++i) threads.emplace_back([&, i] { while (!go.load()) {} results[i] = get(ref); });
  go.store(true); for (auto& thread : threads) thread.join();
  for (auto* p : results) assert(p && p == results[0]);
  assert(get(ref) == results[0]);
  FILE* maps = std::fopen("/proc/self/maps", "r"); assert(maps);
  char line[4096]; bool readonly = false;
  while (std::fgets(line, sizeof line, maps)) {
    unsigned long begin, end; char perms[5]{};
    if (std::sscanf(line, "%lx-%lx %4s", &begin, &end, perms) == 3 &&
        reinterpret_cast<uintptr_t>(results[0]) >= begin && reinterpret_cast<uintptr_t>(results[0]) < end)
      readonly = !std::strcmp(perms, "r--p");
  }
  std::fclose(maps); assert(readonly);
  if (!std::strcmp(argv[4], "write")) *const_cast<volatile uint8_t*>(results[0]) ^= 1;
  std::puts("cache=stable concurrent=ok readonly=ok");
  return 0;
}
