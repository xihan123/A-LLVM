#include <cstring>
#include <dlfcn.h>
int main(int argc, char** argv) {
  if (argc != 2) return 2;
  void* library = dlopen(argv[1], RTLD_NOW);
  if (!library) return 3;
  auto get = reinterpret_cast<const char* (*)()>(dlsym(library, "short_value"));
  return !get || std::strcmp(get(), "ok") ? 4 : 0;
}
