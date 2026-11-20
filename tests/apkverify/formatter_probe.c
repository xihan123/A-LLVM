/* SPDX-License-Identifier: Apache-2.0 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/platform.h>

static int call_mbedtls_vsnprintf(char *dst, size_t n, const char *format, ...)
{
    va_list args;
    int result;

    va_start(args, format);
    result = mbedtls_vsnprintf(dst, n, format, args);
    va_end(args);
    return result;
}

static int check_bytes(const char *actual, const char *expected, size_t length)
{
    return memcmp(actual, expected, length) == 0;
}

int main(void)
{
    int checks = 0;
    int failures = 0;
    char buffer[16];
    char *null_buffer = NULL;
    const char *normal_format = "value=%d";
    const char *short_format = "abcdef";
    int result;

#define CHECK(name, condition) do { \
        ++checks; \
        if (!(condition)) { \
            printf("FAIL %s\n", name); \
            ++failures; \
        } else { \
            printf("PASS %s\n", name); \
        } \
    } while (0)

    memset(buffer, 'X', sizeof(buffer));
    result = mbedtls_snprintf(buffer, sizeof(buffer), normal_format, 42);
    CHECK("snprintf.normal.return", result == 8);
    CHECK("snprintf.normal.bytes", check_bytes(buffer, "value=42\0", 9));

    memset(buffer, 'X', sizeof(buffer));
    result = mbedtls_snprintf(buffer, 7, short_format);
    CHECK("snprintf.exact.return", result == 6);
    CHECK("snprintf.exact.bytes", check_bytes(buffer, "abcdef\0", 7));
    CHECK("snprintf.exact.sentinel", buffer[7] == 'X');

    memset(buffer, 'X', sizeof(buffer));
    result = mbedtls_snprintf(buffer, 5, short_format);
    CHECK("snprintf.truncation.return", result == 6);
    CHECK("snprintf.truncation.bytes", check_bytes(buffer, "abcd\0", 5));
    CHECK("snprintf.truncation.sentinel", buffer[5] == 'X');

    memset(buffer, 'X', sizeof(buffer));
    result = mbedtls_snprintf(buffer, 0, short_format);
    CHECK("snprintf.zero.return", result == 6);
    CHECK("snprintf.zero.untouched", check_bytes(buffer, "XXXXXXXXXXXXXXXX", sizeof(buffer)));

    result = mbedtls_snprintf(null_buffer, 0, short_format);
    CHECK("snprintf.null.zero.return", result == 6);

    memset(buffer, 'X', sizeof(buffer));
    result = mbedtls_snprintf(buffer, 1, short_format);
    CHECK("snprintf.one.return", result == 6);
    CHECK("snprintf.one.terminator", buffer[0] == '\0');
    CHECK("snprintf.one.sentinel", buffer[1] == 'X');

    memset(buffer, 'X', sizeof(buffer));
    result = call_mbedtls_vsnprintf(buffer, sizeof(buffer), normal_format, 42);
    CHECK("vsnprintf.normal.return", result == 8);
    CHECK("vsnprintf.normal.bytes", check_bytes(buffer, "value=42\0", 9));

    memset(buffer, 'X', sizeof(buffer));
    result = call_mbedtls_vsnprintf(buffer, 5, short_format);
    CHECK("vsnprintf.truncation.return", result == 6);
    CHECK("vsnprintf.truncation.bytes", check_bytes(buffer, "abcd\0", 5));
    CHECK("vsnprintf.truncation.sentinel", buffer[5] == 'X');

    memset(buffer, 'X', sizeof(buffer));
    result = call_mbedtls_vsnprintf(buffer, 0, short_format);
    CHECK("vsnprintf.zero.return", result == 6);
    CHECK("vsnprintf.zero.untouched", check_bytes(buffer, "XXXXXXXXXXXXXXXX", sizeof(buffer)));

    result = call_mbedtls_vsnprintf(null_buffer, 0, short_format);
    CHECK("vsnprintf.null.zero.return", result == 6);

    memset(buffer, 'X', sizeof(buffer));
    result = call_mbedtls_vsnprintf(buffer, 1, short_format);
    CHECK("vsnprintf.one.return", result == 6);
    CHECK("vsnprintf.one.terminator", buffer[0] == '\0');
    CHECK("vsnprintf.one.sentinel", buffer[1] == 'X');

    printf("SUMMARY checks=%d failures=%d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
