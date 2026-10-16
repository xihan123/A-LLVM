// Real fds and ZIP parsing; only maps contents and the fixture installation root are replaced.
#include "apkcert.h"
#include <cassert>
#include <cstdarg>
#include <string>

using namespace stringarmor::apkcert;
extern "C" void ndkp_certbind_mix(uint64_t*, uint64_t*);
static std::string fixture, maps;
static unsigned checks;
static const char* virtualRoot = "/data/app/ndkp-test";

extern "C" int __real_open(const char*, int, ...);
extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" int __wrap_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    const std::string value(path), prefix(virtualRoot);
    if (value == prefix || value.compare(0, prefix.size() + 1, prefix + "/") == 0) {
        return __real_open((fixture + "/install" + value.substr(prefix.size())).c_str(), flags, mode);
    }
    return __real_open(path, flags, mode);
}
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
    if (std::strcmp(path, "/proc/self/maps") != 0) return __real_fopen(path, mode);
    FILE* f = tmpfile();
    assert(f && fwrite(maps.data(), 1, maps.size(), f) == maps.size());
    rewind(f);
    return f;
}

static std::string file(const char* name) { return fixture + "/" + name; }
static void copy(const std::string& from, const std::string& to) {
    FILE* src = fopen(from.c_str(), "rb"); FILE* dst = fopen(to.c_str(), "wb");
    assert(src && dst);
    char data[4096]; size_t n;
    while ((n = fread(data, 1, sizeof data, src))) assert(fwrite(data, 1, n, dst) == n);
    assert(!ferror(src)); fclose(src); fclose(dst);
}
static std::string row(const std::string& real, const std::string& path,
                       uintptr_t address = 0x1000, int mismatch = 0) {
    struct stat st{}; assert(stat(real.c_str(), &st) == 0);
    char fields[256];
    std::snprintf(fields, sizeof fields, "%llx-%llx r-xp 00000000 %x:%x %llu ",
                  static_cast<unsigned long long>(address),
                  static_cast<unsigned long long>(address + 0x1000),
                  static_cast<unsigned>(major(st.st_dev)) + (mismatch == 1),
                  static_cast<unsigned>(minor(st.st_dev)),
                  static_cast<unsigned long long>(st.st_ino) + (mismatch == 2));
    return fields + path + "\n";
}
static unsigned fdCount() {
    DIR* d = opendir("/proc/self/fd"); assert(d);
    unsigned n = 0; while (readdir(d)) ++n;
    closedir(d); return n;
}
static void expect(const char* name, bool success, const char* digest = "a.sha",
                   uintptr_t anchor = 0x1234) {
    uint8_t out[32], expected[32]; std::memset(out, 0xa5, sizeof out);
    const unsigned before = fdCount();
    const bool actual = certSha256ForLibrary(reinterpret_cast<const void*>(anchor), out);
    if (actual != success) std::fprintf(stderr, "unexpected result: %s = %d\n", name, actual);
    assert(actual == success && fdCount() == before);
    if (success) {
        FILE* f = fopen(file(digest).c_str(), "rb"); assert(f);
        assert(fread(expected, 1, sizeof expected, f) == sizeof expected); fclose(f);
    } else std::memset(expected, 0xa5, sizeof expected);
    assert(std::memcmp(out, expected, sizeof out) == 0);
    std::printf("[ok] %s\n", name); ++checks;
}

int main(int argc, char** argv) {
    assert(argc == 2); fixture = argv[1];
    const std::string own = row(file("owner.apk"), file("owner.apk"));
    const std::string host = row(file("host.apk"), file("host.apk"), 0x5000);
    maps = host + own; expect("host first, no retained APK fd", true);
    maps = own + host; expect("module first, no retained APK fd", true);
    expect("second library has its own signer", true, "b.sha", 0x5234);
    maps = own; expect("anchor outside any mapping", false, "a.sha", 0x3000);
    expect("null anchor", false, "a.sha", 0);
    maps = own + own; expect("ambiguous anchor range", false);
    maps = own.substr(0, own.size() - 1); expect("truncated maps", false);
    maps = own + std::string(PATH_MAX + 300, 'x') + "\n"; expect("overlong maps", false);
    maps = "broken maps record\n"; expect("malformed maps", false);
    for (int mismatch : {1, 2}) {
        maps = row(file("owner.apk"), file("owner.apk"), 0x1000, mismatch);
        expect(mismatch == 1 ? "device mismatch" : "inode mismatch", false);
    }
    maps = row(file("owner.apk"), file("owner.apk") + " (deleted)"); expect("deleted APK", false);
    maps = "1000-2000 r-xp 0 00:00 0 [anon:module]\n"; expect("anonymous mapping", false);
    maps = row(file("owner.apk"), "/memfd:module (deleted)"); expect("memfd", false);
    maps = row(file("owner.apk"), file("missing-file.apk")); expect("open failure", false);
    for (const char* name : {"owner.apk", "v3.apk", "prefer-v2.apk", "deflated.apk", "comment.apk", "extra.apk"}) {
        maps = row(file(name), file(name));
        expect(name, true, std::strcmp(name, "v3.apk") == 0 ? "b.sha" : "a.sha");
    }
    for (const char* name : {"unsigned.apk", "truncated.apk", "empty.apk", "zip64.apk", "multidisk.apk"}) {
        maps = row(file(name), file(name)); expect(name, false);
    }
    // The actual runtime ABI uses its own hidden function address, including failure defaults.
    maps = row(file("owner.apk"), file("owner.apk"), reinterpret_cast<uintptr_t>(&ndkp_certbind_mix));
    uint64_t lo = 0, hi = 0; ndkp_certbind_mix(&lo, &hi);
    uint8_t hash[32]; FILE* sha = fopen(file("a.sha").c_str(), "rb"); assert(sha);
    assert(fread(hash, 1, 32, sha) == 32); fclose(sha);
    assert(lo == (le64(hash) ^ le64(hash + 16)) && hi == (le64(hash + 8) ^ le64(hash + 24)));
    maps.clear(); ndkp_certbind_mix(&lo, &hi); assert(lo == 0 && hi == 0);
#if defined(__aarch64__)
    const char* isa = "arm64";
#elif defined(__arm__)
    const char* isa = "arm";
#elif defined(__x86_64__)
    const char* isa = "x86_64";
#else
    const char* isa = "x86";
#endif
    const std::string install = file("install"), libs = install + "/lib", arch = libs + "/" + isa;
    assert(mkdir(install.c_str(), 0700) == 0 && mkdir(libs.c_str(), 0700) == 0 && mkdir(arch.c_str(), 0700) == 0);
    const std::string library = arch + "/libowner.so";
    copy(file("owner.apk"), library);
    const std::string libPath = std::string(virtualRoot) + "/lib/" + isa + "/libowner.so";
    const std::string libMap = row(library, libPath);
    copy(file("owner.apk"), install + "/base.apk"); maps = host + libMap;
    expect("extracted base without APK mapping or fd", true);
    assert(rename((install + "/base.apk").c_str(), (install + "/split_config.apk").c_str()) == 0);
    copy(file("missing.apk"), install + "/base.apk");
    expect("extracted split with unrelated base", true);
    maps += row(install + "/split_config.apk", std::string(virtualRoot) + "/split_config.apk", 0x9000);
    expect("extracted split with matching APK mapping", true);
    maps = libMap + row(install + "/split_config.apk", std::string(virtualRoot) + "/split_config.apk", 0x9000, 1);
    expect("extracted APK mapping device mismatch", false);
    maps = libMap + row(install + "/split_config.apk", std::string(virtualRoot) + "/split_config.apk", 0x9000, 2);
    expect("extracted APK mapping inode mismatch", false);
    maps = row(library, libPath, 0x1000, 2); expect("extracted library inode mismatch", false);
    maps = row(library, libPath, 0x1000, 1); expect("extracted library device mismatch", false);
    maps = row(library, std::string(virtualRoot) + "-other/lib/" + isa + "/libowner.so");
    expect("installation prefix confusion", false);
    maps = row(library, library); expect("standalone cached so", false);
    maps = row(library, std::string(virtualRoot) + "/lib/other/libowner.so"); expect("wrong ISA", false);
    maps = libMap;
    copy(file("host.apk"), install + "/base.apk"); expect("multiple APK matches", false);
    copy(file("missing.apk"), install + "/base.apk");
    for (const char* name : {"owner.apk", "deflated.apk", "comment.apk", "extra.apk", "duplicate.apk", "wrong-abi.apk", "missing.apk",
                             "unsigned.apk", "truncated.apk", "zip64.apk", "multidisk.apk", "bad-local.apk",
                             "bad-name.apk", "bad-extra.apk", "zip64-extra.apk", "bad-local-size.apk", "bad-count.apk", "bad-record.apk", "bad-offset.apk", "bad-method.apk", "bad-size.apk"}) {
        copy(file(name), install + "/split_config.apk");
        expect(name, std::strcmp(name, "owner.apk") == 0 || std::strcmp(name, "deflated.apk") == 0 ||
                     std::strcmp(name, "comment.apk") == 0 || std::strcmp(name, "extra.apk") == 0);
    }
    for (const char* name : {"padding-1.apk", "padding-2.apk", "padding-3.apk", "padding-5.apk", "bad-local-extra.apk"}) {
        copy(file(name), install + "/split_config.apk");
        expect(name, std::strcmp(name, "bad-local-extra.apk") != 0);
    }
    copy(file("owner.apk"), install + "/split_config.apk");
    assert(symlink("/missing", (install + "/unreadable.apk").c_str()) == 0);
    expect("unreadable candidate even with a valid match", false);
    assert(unlink((install + "/unreadable.apk").c_str()) == 0);
    virtualRoot = "/mnt/expand/volume/app/ndkp-test";
    maps = row(library, std::string(virtualRoot) + "/lib/" + isa + "/libowner.so");
    expect("adopted storage", true);
    virtualRoot = "/data/app/~~slot/ndkp-test";
    maps = row(library, std::string(virtualRoot) + "/lib/" + isa + "/libowner.so");
    expect("randomized installation slot", true);
    std::printf("%u ownership/parser checks and runtime mix checks passed\n", checks);
}
