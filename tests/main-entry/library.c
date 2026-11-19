static int initialized;

__attribute__((constructor)) static void fixture_init(void) {
  initialized = 11;
}

int JNI_OnLoad(void *vm, void *reserved) {
  (void)vm;
  (void)reserved;
  return 0x00010006;
}

int main_entry_probe(int value) {
  return value * 3 + 7 + initialized;
}
