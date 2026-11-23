#include <cstdio>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

static int (*constructorCheckpoint)(int);
static pthread_barrier_t start;
extern "C" __attribute__((visibility("default"))) int image_constructor_checkpoint(int value) {
  return constructorCheckpoint(value);
}
static void* recheck_thread(void*) {
  pthread_barrier_wait(&start);
  for (unsigned i = 0; i < 128; ++i)
    if (constructorCheckpoint(5) != 22) return reinterpret_cast<void*>(uintptr_t(1));
  return nullptr;
}

int main(int argc, char** argv) {
  if (argc != 4) return 2;
  void* first = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!first) return 3;
  auto checkpoint = reinterpret_cast<int (*)(int)>(dlsym(first, "checkpoint"));
  if (!checkpoint || checkpoint(5) != 22) return 4;
  if (!std::strcmp(argv[3], "constructor-concurrency")) {
    constructorCheckpoint = checkpoint;
    pthread_t thread;
    if (pthread_barrier_init(&start, nullptr, 2) || pthread_create(&thread, nullptr, recheck_thread, nullptr)) return 9;
    pthread_barrier_wait(&start);
    for (unsigned i = 0; i < 16; ++i) {
      // dlopen holds the Android loader lock while this DSO's ctor calls back.
      void* callback = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
      if (!callback) { std::fprintf(stderr, "%s\n", dlerror()); return 10; }
      if (dlclose(callback)) return 10;
    }
    void* result = nullptr;
    if (pthread_join(thread, &result) || result || pthread_barrier_destroy(&start)) return 11;
    return 0;
  }
  void* second = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
  if (!second) return 3;
  auto other = reinterpret_cast<int (*)(int)>(dlsym(second, "checkpoint"));
  auto identity = reinterpret_cast<void (*)(const void*)>(dlsym(first, "image_identity_check"));
  if (!checkpoint || !other || !identity || checkpoint(5) != 22 || other(5) != 22) return 4;
  if (!std::strcmp(argv[3], "foreign")) identity(reinterpret_cast<void*>(other));
  if (!std::strcmp(argv[3], "foreign-mutation")) {
    const size_t page = size_t(sysconf(_SC_PAGESIZE));
    void* address = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(other) & ~(page - 1));
    if (mprotect(address, page, PROT_READ | PROT_WRITE | PROT_EXEC)) return 5;
    // The checkpoint only measures its own DSO; this unrelated RWX page is allowed.
    if (checkpoint(5) != 22) return 6;
  }
  if (std::strcmp(argv[3], "foreign-mutation") && other(6) != 25) return 7;
  if (checkpoint(6) != 25) return 8;
  return 0;
}
