#include "scoped_fixture.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

int main(int argc, char** argv) {
  if (argc != 3) return 2;
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  void* library = dlopen(argv[1], RTLD_NOW);
  if (!library) { std::puts(dlerror()); return 3; }
  if (!std::strcmp(argv[2], "attack")) {
    auto call = reinterpret_cast<int (*)(int)>(dlsym(library, "scoped_multi"));
    if (!call) return 4;
    int result = call(-1);
    std::printf("attack-continued result=%d\n", result);
    return 80;
  }
  auto run = reinterpret_cast<int (*)(int)>(dlsym(library, "run_scoped"));
  if (!run) return 5;
  int result = run(std::atoi(argv[2]));
  std::printf("scoped-result=%d\n", result);
  return result;
}
