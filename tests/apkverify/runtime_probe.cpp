// Test-only ABI for the exact production bootstrap and borrowed descriptor.
#ifdef TEST_REENTER
extern "C" __attribute__((visibility("protected"))) int __system_property_get(const char*, char*);
#endif
#include "apkverify_runtime.h"
#include <unistd.h>
extern "C" __attribute__((visibility("default"))) bool check_verified() {
  uint8_t cert[32], magic[4]; struct stat st{};
  int fd = ndkp_verified_apk(cert, &st);
  return st.st_size > 0 && pread(fd, magic, 4, 0) == 4 && magic[0] == 'P' && magic[1] == 'K';
}
#ifdef TEST_REENTER
extern "C" int __system_property_get(const char*, char*) {
  uint8_t certificate[32]; ndkp_verified_apk(certificate, nullptr); return 26;
}
#endif
