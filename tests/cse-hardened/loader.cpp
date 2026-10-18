#include <cstdio>
#include <dlfcn.h>
#include <chrono>
#include <cstring>
int main(int argc, char** argv) {
  if (argc != 2) return 2;
  const auto before = std::chrono::steady_clock::now();
  void* library = dlopen(argv[1], RTLD_NOW);
  if (!library) { std::puts(dlerror()); return 3; }
  auto run = reinterpret_cast<int (*)()>(dlsym(library, "run"));
  if (!run) return 4;
  auto secret = reinterpret_cast<const char* (*)()>(dlsym(library, "get_secret"));
  auto wide = reinterpret_cast<const char16_t* (*)()>(dlsym(library, "get_wide"));
  if (!secret || !wide || std::strcmp(secret(), "NDKP_HARDENED_secret_19a7") ||
      wide()[5] != u'\u4e2d' || wide()[6] != u'\u6587' || wide()[7] != 0) return 5;
  auto binary = reinterpret_cast<const unsigned char* (*)()>(dlsym(library, "get_binary"));
  auto words = reinterpret_cast<const char16_t* (*)()>(dlsym(library, "get_words"));
  if (!binary || !words || binary()[0] != 0xfe || binary()[1] != 0xff || binary()[2] != 1 ||
      words()[0] != 0x1234 || words()[1] != 0xabcd) return 8;
  int result = run();
  const auto first = std::chrono::steady_clock::now();
  if (!result) result = run();
  const auto second = std::chrono::steady_clock::now();
  auto lazy = reinterpret_cast<const char* (*)()>(dlsym(library, "get_lazy_secret"));
  if (!lazy) return 6;
  const auto lazyBefore = std::chrono::steady_clock::now();
  const char* volatile sink = lazy();
  const auto lazyFirst = std::chrono::steady_clock::now();
  if (std::strcmp(sink, "NDKP_LAZY_SECRET_7731")) return 7;
  for (unsigned i = 0; i < 100000; ++i) sink = lazy();
  const auto lazyRepeated = std::chrono::steady_clock::now();
  std::printf("result=%d first_us=%lld repeat_us=%lld lazy_first_ns=%lld lazy_repeat_ns=%lld\n", result,
      static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(first-before).count()),
      static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(second-first).count()),
      static_cast<long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(lazyFirst-lazyBefore).count()),
      static_cast<long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(lazyRepeated-lazyFirst).count() / 100000));
  return result;
}
