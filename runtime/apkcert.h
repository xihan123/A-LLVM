/*
 * Copyright 2026 StringArmor
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native signing-certificate acquisition for the optional cert binding
 * (STRINGARMOR_CERT_BIND). Instead of asking the framework
 * (PackageManager.getPackageInfo -> SigningInfo.getApkContentsSigners), which is the exact
 * API every "signature-verification bypass" tool hooks (CorePatch / LSPatch / fake-signature
 * Xposed modules), this reads the signer certificate straight out of the on-disk APK's
 * APK Signature Scheme v2/v3 block and SHA-256s its DER. The digest is byte-identical to the
 * build-time value (keystore cert.getEncoded() == the DER apksigner embeds == what
 * Signature.toByteArray() returns), so no encoder-side change is needed.
 *
 * certSha256ForLibrary anchors discovery to an address inside the protected library.
 * In-APK mappings identify the APK directly; extracted libraries identify their installation
 * directory, where exactly one APK must contain lib/<abi>/<name>. Fresh fds are checked
 * against mapped device/inode identities. Neither maps order nor an ART-owned fd identifies
 * the host or the library's owner. Unknown or ambiguous origins fail closed.
 * For extracted libraries without an APK mapping, directory/ZIP membership establishes
 * ownership but cannot detect replacement or a bind-mount of that APK alone. This reads
 * certificate bytes, not an APK-wide cryptographic signature verification, and does not
 * defend against arbitrary native hooks.
 *
 * Pure C++/POSIX, no JNI, no third-party deps: /proc/self is always readable by its own
 * process, so this needs neither root nor any hookable framework API.
 */
#ifndef STRINGARMOR_APKCERT_H
#define STRINGARMOR_APKCERT_H

#include <dirent.h>
#include <cerrno>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "sha256.h"
#include "apkcert_io.h"

namespace stringarmor {
namespace apkcert {

// Read exactly n bytes without changing the fd's file offset.
template <class IO = apkio::Posix>
inline bool readAt(int fd, uint64_t off, void* buf, size_t n) {
    if (off > INT64_MAX || n > static_cast<uint64_t>(INT64_MAX) - off) return false;
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
        const ssize_t r = IO::pread(fd, p + got, n - got, static_cast<off64_t>(off + got));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            return false;
        }
        got += static_cast<size_t>(r);
    }
    return true;
}

inline uint16_t le16(const uint8_t* b) {
    return static_cast<uint16_t>(b[0]) | (static_cast<uint16_t>(b[1]) << 8);
}
inline uint32_t le32(const uint8_t* b) {
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
}
inline uint64_t le64(const uint8_t* b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(b[i]) << (8 * i);
    return v;
}

// A bounded forward cursor over [pos, end) of the file, reading little-endian length prefixes.
// Every read is range-checked; once ok flips false all subsequent reads are no-ops.
struct Cursor {
    int fd;
    uint64_t pos;
    uint64_t end;
    bool ok;
};

template <class IO = apkio::Posix>
inline uint32_t nextU32(Cursor& c) {
    if (!c.ok || c.pos + 4 > c.end) {
        c.ok = false;
        return 0;
    }
    uint8_t b[4];
    if (!readAt<IO>(c.fd, c.pos, b, 4)) {
        c.ok = false;
        return 0;
    }
    c.pos += 4;
    return le32(b);
}

// Open a sub-cursor spanning the next `len` bytes of `c` and advance `c` past them.
inline Cursor subCursor(Cursor& c, uint32_t len) {
    Cursor s{c.fd, c.pos, 0, false};
    if (c.ok && c.pos + len <= c.end) {
        s.end = c.pos + len;
        s.ok = true;
        c.pos += len;
    } else {
        c.ok = false;
    }
    return s;
}

// APK Sig Block magic "APK Sig Block 42" as two little-endian u64s, so the 16-byte literal
// never lands contiguously in .rodata. bytes: 41 50 4B 20 53 69 67 20 | 42 6C 6F 63 6B 20 34 32.
constexpr uint64_t kMagicLo = 0x20676953204B5041ULL;
constexpr uint64_t kMagicHi = 0x3234206B636F6C42ULL;

// APK Signature Scheme block IDs.
constexpr uint32_t kV2BlockId = 0x7109871au;
constexpr uint32_t kV3BlockId = 0xf05368c0u;

constexpr uint32_t kMaxCertDer = 1u << 20;  // 1 MiB: generous ceiling for one X.509 cert.

// Parse the signer certificate out of one v2/v3 ID-value block and SHA-256 its DER.
// Layout (all inner length prefixes u32 LE): signers -> signer[0] -> signed-data ->
// digests(skip) -> certificates -> cert[0] DER. v2 and v3 share this prefix, so one parser
// covers both (we stop after the first cert). Returns false on any bounds violation.
template <class IO = apkio::Posix>
inline bool hashFirstSignerCert(int fd, uint64_t valStart, uint64_t valEnd, uint8_t out[32]) {
    Cursor val{fd, valStart, valEnd, true};
    const uint32_t signersLen = nextU32<IO>(val);
    Cursor signers = subCursor(val, signersLen);

    const uint32_t signerLen = nextU32<IO>(signers);
    Cursor signer = subCursor(signers, signerLen);

    const uint32_t signedDataLen = nextU32<IO>(signer);
    Cursor sd = subCursor(signer, signedDataLen);

    const uint32_t digestsLen = nextU32<IO>(sd);
    (void)subCursor(sd, digestsLen);  // skip digests sequence

    const uint32_t certsLen = nextU32<IO>(sd);
    Cursor certs = subCursor(sd, certsLen);

    const uint32_t certLen = nextU32<IO>(certs);
    if (!certs.ok || certLen == 0 || certLen > kMaxCertDer || certs.pos + certLen > certs.end) {
        return false;
    }
    uint8_t* der = static_cast<uint8_t*>(std::malloc(certLen));
    if (der == nullptr) {
        return false;
    }
    const bool read = readAt<IO>(fd, certs.pos, der, certLen);
    if (read) {
        stringarmor::sha2::sha256(der, certLen, out);
    }
    std::free(der);
    return read;
}

struct ZipDirectory {
    uint64_t offset;
    uint64_t size;
    uint16_t entries;
};

// Classic single-disk ZIP only. The comment must end at EOF; reject ZIP64 sentinels.
template <class IO = apkio::Posix>
inline bool zipDirectory(int fd, uint64_t fileSize, ZipDirectory& cd) {
    if (fileSize < 22) {
        return false;
    }
    const uint64_t kMaxEocd = 22 + 0xFFFFu;  // 22-byte record + max ZIP comment
    const uint64_t tailLen = fileSize < kMaxEocd ? fileSize : kMaxEocd;
    uint8_t* tail = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(tailLen)));
    if (tail == nullptr) {
        return false;
    }
    const uint64_t tailStart = fileSize - tailLen;
    bool haveEocd = false;
    if (readAt<IO>(fd, tailStart, tail, static_cast<size_t>(tailLen))) {
        for (uint64_t i = tailLen - 22 + 1; i-- > 0;) {
            const uint8_t* e = tail + i;
            if (le32(e) != 0x06054b50 || i + 22 + le16(e + 20) != tailLen) continue;
            cd = {le32(e + 16), le32(e + 12), le16(e + 10)};
            haveEocd = le16(e + 4) == 0 && le16(e + 6) == 0 &&
                       le16(e + 8) == cd.entries && cd.entries != 0xffff &&
                       cd.offset != 0xffffffffu && cd.size != 0xffffffffu &&
                       cd.offset + cd.size == tailStart + i;
            break;
        }
    }
    std::free(tail);
    return haveEocd;
}

// Locate the APK Signing Block, preferring v2 to v3, and hash the first signer cert.
template <class IO = apkio::Posix>
inline bool parseSignerCertSha256Fd(int fd, uint64_t fileSize, uint8_t out[32]) {
    ZipDirectory cd{};
    if (!zipDirectory<IO>(fd, fileSize, cd) || cd.offset < 24) {
        return false;
    }
    const uint64_t cdOffset = cd.offset;

    // --- Signing Block footer sits in the 24 bytes just before the central directory:
    //     u64 sizeOfBlock | "APK Sig Block 42" (16 bytes). The same u64 size leads the block.
    uint8_t footer[24];
    if (!readAt<IO>(fd, cdOffset - 24, footer, 24)) {
        return false;
    }
    if (le64(footer + 8) != kMagicLo || le64(footer + 16) != kMagicHi) {
        return false;  // no APK Signing Block (e.g. v1-only) -> fail-closed
    }
    const uint64_t blockSize = le64(footer);
    if (blockSize < 24 || blockSize > cdOffset - 8) {  // subtraction form: cdOffset >= 24, no wrap
        return false;
    }
    const uint64_t blockStart = cdOffset - blockSize - 8;
    uint8_t hdr[8];
    if (!readAt<IO>(fd, blockStart, hdr, 8) || le64(hdr) != blockSize) {
        return false;
    }

    // --- Iterate ID-value pairs: u64 pairLen | u32 id | value(pairLen-4). Prefer v2, else v3.
    const uint64_t pairsStart = blockStart + 8;
    const uint64_t pairsEnd = cdOffset - 24;
    uint64_t v3Start = 0, v3End = 0;
    bool haveV3 = false;
    uint64_t pos = pairsStart;
    for (int guard = 0; guard < 4096 && pos + 12 <= pairsEnd; ++guard) {
        uint8_t hp[12];
        if (!readAt<IO>(fd, pos, hp, 12)) {
            return false;
        }
        const uint64_t pairLen = le64(hp);
        // Subtraction form avoids u64 wrap on a garbage/huge pairLen (pos+12 <= pairsEnd here).
        if (pairLen < 4 || pairLen > pairsEnd - pos - 8) {
            return false;
        }
        const uint32_t id = le32(hp + 8);
        const uint64_t valStart = pos + 12;              // after u64 len + u32 id
        const uint64_t valEnd = pos + 8 + pairLen;
        if (id == kV2BlockId) {
            return hashFirstSignerCert<IO>(fd, valStart, valEnd, out);  // v2 preferred
        }
        if (id == kV3BlockId && !haveV3) {
            v3Start = valStart;
            v3End = valEnd;
            haveV3 = true;
        }
        pos += 8 + pairLen;
    }
    if (haveV3) {
        return hashFirstSignerCert<IO>(fd, v3Start, v3End, out);
    }
    return false;
}

// Check central and local record boundaries without inflating file contents.
struct ZipLibrary { uint64_t offset, compressed, size; uint16_t method; };
template <class IO = apkio::Posix>
inline bool zipHasLibrary(int fd, uint64_t size, const char* entry, bool& found,
                          ZipLibrary* library = nullptr) {
    ZipDirectory cd{};
    if (!zipDirectory<IO>(fd, size, cd)) return false;
    uint64_t pos = cd.offset;
    const uint64_t end = pos + cd.size;
    const size_t wanted = std::strlen(entry);
    found = false;
    for (unsigned i = 0; i < cd.entries; ++i) {
        uint8_t h[46], local[30];
        if (end - pos < sizeof h || !readAt<IO>(fd, pos, h, sizeof h) ||
            le32(h) != 0x02014b50) return false;
        const uint16_t nameLen = le16(h + 28), extraLen = le16(h + 30);
        const uint64_t recordSize = sizeof h + nameLen + extraLen + le16(h + 32);
        const uint64_t localPos = le32(h + 42), compressed = le32(h + 20);
        const uint16_t method = le16(h + 10);
        if (recordSize > end - pos || nameLen == 0 || le16(h + 34) != 0 ||
            compressed == 0xffffffffu || le32(h + 24) == 0xffffffffu ||
            localPos == 0xffffffffu || (le16(h + 8) & 0x41) ||
            (method != 0 && method != 8) || localPos > cd.offset ||
            cd.offset - localPos < sizeof local ||
            !readAt<IO>(fd, localPos, local, sizeof local) || le32(local) != 0x04034b50 ||
            le16(local + 26) != nameLen || le16(local + 8) != method ||
            le16(local + 6) != le16(h + 8) ||
            (!(le16(h + 8) & 8) && std::memcmp(local + 14, h + 16, 12) != 0) ||
            (method == 0 && compressed != le32(h + 24))) return false;
        const uint64_t data = localPos + sizeof local + nameLen + le16(local + 28);
        if (data > cd.offset || compressed > cd.offset - data) return false;
        // Reject malformed extra fields and ZIP64 in either header.
        const uint64_t extraStarts[] = {pos + sizeof h + nameLen,
                                        localPos + sizeof local + nameLen};
        const uint16_t extraSizes[] = {extraLen, le16(local + 28)};
        for (unsigned j = 0; j < 2; ++j) {
            uint64_t extra = extraStarts[j], extraEnd = extra + extraSizes[j];
            while (extra < extraEnd) {
                if (extraEnd - extra < 4) {
                    // zipalign pads local extra fields with raw zeros, not another TLV.
                    uint8_t padding[3]{};
                    if (j != 1 || !readAt<IO>(fd, extra, padding, static_cast<size_t>(extraEnd - extra)) ||
                        padding[0] != 0 || padding[1] != 0 || padding[2] != 0) return false;
                    break;
                }
                uint8_t tag[4];
                if (!readAt<IO>(fd, extra, tag, 4) ||
                    le16(tag) == 1 || le16(tag + 2) > extraEnd - extra - 4) return false;
                extra += 4 + le16(tag + 2);
            }
        }
        bool match = nameLen == wanted;
        for (size_t n = 0; n < nameLen;) {
            uint8_t a[256], b[256];
            const size_t count = nameLen - n < sizeof a ? nameLen - n : sizeof a;
            if (!readAt<IO>(fd, pos + sizeof h + n, a, count) ||
                !readAt<IO>(fd, localPos + sizeof local + n, b, count) ||
                std::memcmp(a, b, count) != 0) return false;
            if (match && std::memcmp(a, entry + n, count) != 0) match = false;
            n += count;
        }
        if (match) {
            if (found || le32(h + 24) == 0) return false;
            found = true;
            if (library) *library = {data, compressed, le32(h + 24), method};
        }
        pos += recordSize;
    }
    return pos == end;
}

struct Mapping {
    unsigned long long start, end, inode;
    unsigned devMajor, devMinor;
    char path[PATH_MAX];
};

inline bool mappedIdentity(const Mapping& m, const struct stat& st) {
    return m.inode != 0 && m.inode == static_cast<unsigned long long>(st.st_ino) &&
           m.devMajor == major(st.st_dev) && m.devMinor == minor(st.st_dev);
}

// Either locate the anchor, or check all existing mappings of one APK (absence is allowed).
template <class IO = apkio::Posix>
inline bool inspectMaps(uintptr_t anchor, Mapping* owner,
                        const char* apk = nullptr, const struct stat* expected = nullptr) {
    auto* maps = IO::stream("/proc/self/maps");
    if (!maps) return false;
    char line[PATH_MAX + 256];
    bool ok = true, found = false;
    while (IO::gets(line, sizeof line, maps)) {
        const size_t len = std::strlen(line);
        if (len == 0 || line[len - 1] != '\n') { ok = false; break; }
        line[len - 1] = '\0';
        Mapping m{};
        unsigned long long offset;
        char perms[5];
        int pathStart = 0;
        if (std::sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n",
                        &m.start, &m.end, perms, &offset, &m.devMajor, &m.devMinor,
                        &m.inode, &pathStart) != 7 || pathStart == 0 || m.start >= m.end ||
            std::strlen(line + pathStart) >= sizeof m.path) { ok = false; break; }
        std::strcpy(m.path, line + pathStart);
        if (owner && anchor >= m.start && anchor < m.end) {
            if (found) { ok = false; break; }
            *owner = m;
            found = true;
        }
        if (apk && std::strcmp(apk, m.path) == 0 && !mappedIdentity(m, *expected)) {
            ok = false;
            break;
        }
    }
    ok = ok && !IO::error(maps) && (!owner || found);
    IO::finish(maps);
    return ok;
}

inline bool endsWith(const char* path, const char* suffix) {
    const size_t n = std::strlen(path), len = std::strlen(suffix);
    return n >= len && std::memcmp(path + n - len, suffix, len) == 0;
}

inline bool cleanAbsolutePath(const char* path) {
    return path[0] == '/' && !std::strchr(path, '\\') &&
           !std::strstr(path, " (deleted)") && !std::strstr(path, "/../") &&
           !std::strstr(path, "/./") && !std::strstr(path, "//");
}

// Android's installed lib/<instruction-set>/<name> layout, including adopted storage.
inline bool extractedLibraryPaths(const char* path, char root[PATH_MAX],
                                  char entry[PATH_MAX], const char*& relative) {
#if defined(__aarch64__)
    const char* isa = "arm64"; const char* abi = "arm64-v8a";
#elif defined(__arm__)
    const char* isa = "arm"; const char* abi = "armeabi-v7a";
#elif defined(__x86_64__)
    const char* isa = "x86_64"; const char* abi = "x86_64";
#elif defined(__i386__)
    const char* isa = "x86"; const char* abi = "x86";
#else
    const char* isa = ""; const char* abi = "";
    return false;
#endif
    const char* install = nullptr;
    if (std::strncmp(path, "/data/app/", 10) == 0) install = path + 10;
    else if (std::strncmp(path, "/mnt/expand/", 12) == 0) {
        const char* volumeEnd = std::strchr(path + 12, '/');
        if (volumeEnd && volumeEnd != path + 12 &&
            std::strncmp(volumeEnd, "/app/", 5) == 0) install = volumeEnd + 5;
    }
    if (!install || !cleanAbsolutePath(path) || !endsWith(path, ".so")) return false;
    const char* lib = std::strstr(install, "/lib/");
    if (!lib || lib == install) return false;
    const char* slotEnd = std::strchr(install, '/');
    if (slotEnd != lib && (std::strncmp(install, "~~", 2) != 0 ||
                          std::strchr(slotEnd + 1, '/') != lib || slotEnd + 1 == lib)) return false;
    const char* name = lib + 5;
    const size_t isaLen = std::strlen(isa);
    if (std::strncmp(name, isa, isaLen) != 0 || name[isaLen] != '/') return false;
    name += isaLen + 1;
    if (!*name || std::strchr(name, '/')) return false;
    const size_t rootLen = lib - path;
    std::memcpy(root, path, rootLen);
    root[rootLen] = '\0';
    relative = lib + 1;
    const int n = std::snprintf(entry, PATH_MAX, "lib/%s/%s", abi, name);
    return n > 0 && n < PATH_MAX;
}

// Retain the sole matching APK fd so discovery and certificate parsing use the same file.
// Explicit POSIX cleanup avoids introducing C++ exception-unwinding helpers into this runtime.
template <class IO = apkio::Posix>
inline int openExtractedLibraryApk(const Mapping& owner) {
    char root[PATH_MAX], entry[PATH_MAX];
    const char* relative = nullptr;
    if (!extractedLibraryPaths(owner.path, root, entry, relative)) return -1;
    const int directory = IO::open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return -1;
    const int library = IO::openat(directory, relative, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat libStat{};
    const bool validLibrary = library >= 0 && IO::stat(library, &libStat) == 0 &&
        S_ISREG(libStat.st_mode) && libStat.st_size > 0 && mappedIdentity(owner, libStat);
    if (library >= 0) IO::close(library);
    if (!validLibrary) { IO::close(directory); return -1; }
    auto* dir = IO::directory(directory);
    if (!dir) { IO::close(directory); return -1; }
    int selected = -1;
    char selectedPath[PATH_MAX]{};
    struct stat selectedStat{};
    bool ok = true;
    for (;;) {
        errno = 0;
        const dirent* e = IO::next(dir);
        if (!e) { ok = errno == 0; break; }
        if (!endsWith(e->d_name, ".apk")) continue;
        const int candidate = IO::openat(directory, e->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat st{};
        bool match = false;
        if (candidate < 0 || IO::stat(candidate, &st) != 0 ||
            !S_ISREG(st.st_mode) || st.st_size <= 0 ||
            !zipHasLibrary<IO>(candidate, static_cast<uint64_t>(st.st_size), entry, match)) {
            if (candidate >= 0) IO::close(candidate);
            ok = false; break;
        }
        if (!match) { IO::close(candidate); continue; }
        const int n = std::snprintf(selectedPath, sizeof selectedPath, "%s/%s", root, e->d_name);
        if (selected >= 0 || n < 0 || static_cast<size_t>(n) >= sizeof selectedPath) {
            IO::close(candidate);
            ok = false; break;
        }
        selected = candidate;
        selectedStat = st;
    }
    IO::finish(dir); // Also closes the installation directory fd.
    if (!ok || selected < 0 || !inspectMaps<IO>(0, nullptr, selectedPath, &selectedStat)) {
        if (selected >= 0) IO::close(selected);
        return -1;
    }
    return selected;
}

// The anchor must be local/hidden in the protected DSO. Never infer its owner from maps order.
template <class IO = apkio::Posix>
inline bool certSha256ForLibrary(const void* anchor, uint8_t out[32], struct stat* identity = nullptr) {
    Mapping owner{};
    if (!anchor || !inspectMaps<IO>(reinterpret_cast<uintptr_t>(anchor), &owner) ||
        owner.inode == 0 || !cleanAbsolutePath(owner.path)) return false;
    const bool direct = endsWith(owner.path, ".apk");
    const int apk = direct ? IO::open(owner.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
                           : openExtractedLibraryApk<IO>(owner);
    if (apk < 0) return false;
    struct stat st{};
    uint8_t hash[32];
    const bool ok = IO::stat(apk, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
        (!direct || mappedIdentity(owner, st)) &&
        parseSignerCertSha256Fd<IO>(apk, static_cast<uint64_t>(st.st_size), hash);
    IO::close(apk);
    if (!ok) return false;
    if (identity) *identity = st;
    std::memcpy(out, hash, sizeof hash);
    return true;
}

}  // namespace apkcert
}  // namespace stringarmor

#endif  // STRINGARMOR_APKCERT_H
