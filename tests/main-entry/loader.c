#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 2)
    return 1;
  void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) {
    puts(dlerror());
    return 2;
  }
  int (*load)(void *, void *) = (int (*)(void *, void *))dlsym(library, "JNI_OnLoad");
  int (*probe)(int) = (int (*)(int))dlsym(library, "main_entry_probe");
  if (!load || !probe || probe(5) != 33 || load(NULL, NULL) != 0x00010006 || probe(5) != 33)
    return 3;
  if (dlclose(library))
    return 4;
  puts("main-entry no-main SO semantics OK");
  return 0;
}
