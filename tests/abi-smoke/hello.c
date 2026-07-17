#include <string.h>

/* 供 string-enc 测试用的敏感明文（开启 -irobf-cse 后不应出现在 ELF 里）。 */
static const char SECRET[] = "NDKP_SECRET_STRING_do_not_leak";

__attribute__((visibility("default")))
int ndkp_secret_len(void) {
    return (int)strlen(SECRET);
}

__attribute__((visibility("default")))
const char *ndkp_secret(void) {
    return SECRET;
}
