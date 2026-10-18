#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

// Mutations are confined to this disposable loader's own test DSO.
int main(int argc, char** argv) {
  if (argc != 6) return 2;
  void* library = dlopen(argv[1], RTLD_NOW);
  if (!library) { std::puts(dlerror()); return 3; }
  auto value = reinterpret_cast<const char* (*)()>(dlsym(library, "short_value"));
  const bool throughCaller = std::strstr(argv[2], "-caller") != nullptr;
  auto checkpoint = reinterpret_cast<int (*)(int)>(dlsym(library,
      throughCaller ? "unchecked_caller" : "checkpoint"));
  Dl_info info{};
  if (!value || !checkpoint || !dladdr(reinterpret_cast<void*>(value), &info)) return 4;
  const bool clean = !std::strcmp(argv[2], "clean");
  const bool cached = !std::strcmp(argv[2], "cached");
  const char* saved = nullptr;
  if (clean || cached || !std::strncmp(argv[2], "warm", 4)) {
    // Exercise checkpoint before the first string initialization as well.
    if (checkpoint(5) != 22) return 5;
    saved = value();
    if (std::strcmp(saved, "ok")) return 6;
  }
  if (!clean) {
    auto* address = static_cast<unsigned char*>(info.dli_fbase) + std::strtoull(argv[3], nullptr, 16);
    const size_t pageSize = size_t(sysconf(_SC_PAGESIZE));
    void* page = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) & ~(pageSize - 1));
    const int protection = std::atoi(argv[4]);
    if (mprotect(page, pageSize, PROT_READ | PROT_WRITE | (protection & PROT_EXEC))) return 7;
    if (std::strcmp(argv[5], "permissions")) {
      if (!std::strcmp(argv[5], "state")) *reinterpret_cast<volatile uint32_t*>(address) = 3;
      else *reinterpret_cast<volatile unsigned char*>(address) ^= 1;
      __builtin___clear_cache(reinterpret_cast<char*>(page), reinterpret_cast<char*>(page) + pageSize);
      if (mprotect(page, pageSize, protection)) return 8;
    }
  }
  if (cached) {
    // Baseline: once-decoded pointers remain usable without reaching a checkpoint.
    return saved == value() && !std::strcmp(saved, "ok") ? 0 : 9;
  }
  const auto before = std::chrono::steady_clock::now();
  if (checkpoint(5) != 22 || std::strcmp(value(), "ok")) return 10;
  if (clean) {
    const auto elapsed = std::chrono::steady_clock::now() - before;
    std::thread workers[4];
    for (auto& worker : workers) worker = std::thread([&] {
      for (int i = 0; i < 4; ++i)
        if (checkpoint(i) != i * 3 + 7 || value() != saved || std::strcmp(saved, "ok")) std::abort();
    });
    for (auto& worker : workers) worker.join();
    std::printf("recheck_us=%lld resident=ok threads=ok\n",
        static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count()));
  }
  return 0;
}
