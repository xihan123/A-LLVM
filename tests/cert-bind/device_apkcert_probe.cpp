// device_apkcert_probe.cpp — 真机验证 runtime/apkcert.h 的核心：APK v2/v3 签名块解析 +
// 签名者证书 DER 的 SHA-256。用官方 NDK 交叉编译到 arm64-v8a，push 到设备对任意 APK 跑，
// 其输出应逐位 == apksigner 报告的 "certificate SHA-256 digest"。
//
// 这验证 -irobf-cert-bind 运行期证书读取的核心解析器在真机 / 目标 Android 版本上正确。
// 注意：完整入口 certSha256ForLibrary 需要本库地址及可定位的 APK 映射或安装目录。
// 本探针只测解析+哈希（parseSignerCertSha256Fd）；完整来源与绑定验证由
// device_roundtrip.py 在真实 APK 进程内覆盖，maps/ZIP 边界由 test_apkcert.py 覆盖。
//
// 用法：device_apkcert_probe <apk-path>
#include <cstdint>
#include <cstdio>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "apkcert.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <apk-path>\n", argv[0]);
        return 2;
    }
    const int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        std::perror("open");
        return 3;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        std::perror("fstat");
        close(fd);
        return 4;
    }
    uint8_t sha[32];
    const bool ok = stringarmor::apkcert::parseSignerCertSha256Fd(
        fd, static_cast<uint64_t>(st.st_size), sha);
    close(fd);
    if (!ok) {
        std::fprintf(stderr, "parse failed (v1-only, unsigned, or not an APK?)\n");
        return 1;
    }
    for (int i = 0; i < 32; ++i)
        std::printf("%02x", sha[i]);
    std::printf("\n");
    return 0;
}
