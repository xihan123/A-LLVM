// device_apkcert_probe.cpp — 真机验证 runtime/apkcert.h 的核心：APK v2/v3 签名块解析 +
// 签名者证书 DER 的 SHA-256。用官方 NDK 交叉编译到 arm64-v8a，push 到设备对任意 APK 跑，
// 其输出应逐位 == apksigner 报告的 "certificate SHA-256 digest"。
//
// 这验证 -irobf-cert-bind 运行期证书读取的核心解析器在真机 / 目标 Android 版本上正确。
// 注意：apkcert.h 的完整入口 certSha256Consensus 依赖 /proc/self 里映射的 /data/app/…/
// base.apk（双源发现 + 同 inode 校验 + 一致性），只能在**已安装 APK 的进程内**测；本探针
// 只测与之无关、但密码学关键的解析+哈希部分（parseSignerCertSha256Fd）。完整 E2E（编译期
// 折入 + 运行期抵消）需先构建 overlay clang。
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
