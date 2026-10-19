#include <dlfcn.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <thread>
#include <unistd.h>
#include <vector>
int main(int argc, char** argv) {
  if (argc < 2) return 2;
  void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) { fprintf(stderr, "%s\n", dlerror()); return 3; }
  auto check = reinterpret_cast<bool(*)()>(dlsym(library, "check_verified"));
  if (!check || !check()) return 4;
  if (argc > 2 && std::strcmp(argv[2], "replace") == 0) {
    if (argc != 5 || rename(argv[3], argv[4])) return 5;
  } else if (argc > 2 && std::strcmp(argv[2], "change") == 0) {
    int fd = open(argv[3], O_RDWR); unsigned char byte;
    off_t end = fd < 0 ? -1 : lseek(fd, -1, SEEK_END);
    if (end < 0 || pread(fd, &byte, 1, end) != 1) return 6;
    byte ^= 1;
    if (pwrite(fd, &byte, 1, end) != 1 || fsync(fd)) return 7;
    close(fd);
  } else if (argc > 2 && std::strcmp(argv[2], "host") == 0) {
    void* host = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
    auto other = host ? reinterpret_cast<bool(*)()>(dlsym(host, "check_verified")) : nullptr;
    if (!other || !other()) return 8;
  } else if (argc > 2 && std::strcmp(argv[2], "add") == 0) {
    if (link(argv[3], argv[4])) return 10;
  }
  std::atomic<bool> ok{true}; std::vector<std::thread> threads;
  for (unsigned i = 0; i < 16; ++i) threads.emplace_back([&] {
    for (unsigned j = 0; j < 16; ++j) if (!check()) ok = false;
  });
  for (auto& thread : threads) thread.join();
  if (!ok || !check()) return 9;
  dlclose(library); puts("verified"); return 0;
}
