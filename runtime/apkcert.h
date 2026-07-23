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
 * Anti-redirect: the certificate is fetched over TWO independent native paths and only the
 * consensus is trusted (see certSha256Consensus):
 *   Source A  base.apk path discovered from /proc/self/maps, then a fresh open()+pread.
 *   Source B  the fd the ART runtime already holds open on base.apk, discovered by scanning
 *             /proc/self/fd (readlinkat), read in place with pread (never closed).
 * Both parses must succeed, both fds/paths must resolve to the same inode (fstat/stat), and
 * both digests must be equal — else fail-closed (garbage decrypt). A single-vector bypass
 * (framework hook, open() redirect, or bind-mount over the path) perturbs exactly one source
 * and is caught. Defeating it requires a consistent inline hook of pread + a forged fstat,
 * i.e. the same root/dynamic capability that could just hook decrypt()'s return value — a
 * threat cert binding never claimed to stop (see the project threat model).
 *
 * Pure C++/POSIX, no JNI, no third-party deps: /proc/self is always readable by its own
 * process, so this needs neither root nor any hookable framework API.
 */
#ifndef STRINGARMOR_APKCERT_H
#define STRINGARMOR_APKCERT_H

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "sha256.h"

namespace stringarmor {
namespace apkcert {

// Read exactly n bytes at absolute offset off. pread64 does not move the fd's file offset,
// so it is safe to use on the ART runtime's own base.apk fd (Source B). Any short read or
// error -> false.
inline bool readAt(int fd, uint64_t off, void* buf, size_t n) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
        const ssize_t r = pread64(fd, p + got, n - got, static_cast<off64_t>(off + got));
        if (r <= 0) {
            return false;
        }
        got += static_cast<size_t>(r);
    }
    return true;
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

inline uint32_t nextU32(Cursor& c) {
    if (!c.ok || c.pos + 4 > c.end) {
        c.ok = false;
        return 0;
    }
    uint8_t b[4];
    if (!readAt(c.fd, c.pos, b, 4)) {
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
inline bool hashFirstSignerCert(int fd, uint64_t valStart, uint64_t valEnd, uint8_t out[32]) {
    Cursor val{fd, valStart, valEnd, true};
    const uint32_t signersLen = nextU32(val);
    Cursor signers = subCursor(val, signersLen);

    const uint32_t signerLen = nextU32(signers);
    Cursor signer = subCursor(signers, signerLen);

    const uint32_t signedDataLen = nextU32(signer);
    Cursor sd = subCursor(signer, signedDataLen);

    const uint32_t digestsLen = nextU32(sd);
    (void)subCursor(sd, digestsLen);  // skip digests sequence

    const uint32_t certsLen = nextU32(sd);
    Cursor certs = subCursor(sd, certsLen);

    const uint32_t certLen = nextU32(certs);
    if (!certs.ok || certLen == 0 || certLen > kMaxCertDer || certs.pos + certLen > certs.end) {
        return false;
    }
    uint8_t* der = static_cast<uint8_t*>(std::malloc(certLen));
    if (der == nullptr) {
        return false;
    }
    const bool read = readAt(fd, certs.pos, der, certLen);
    if (read) {
        stringarmor::sha2::sha256(der, certLen, out);
    }
    std::free(der);
    return read;
}

// Locate the APK Signing Block, find the preferred (v2, else v3) ID-value pair, and hash its
// signer cert. Reads only what it needs via pread (no whole-file buffering). fail-closed.
inline bool parseSignerCertSha256Fd(int fd, uint64_t fileSize, uint8_t out[32]) {
    if (fileSize < 22) {
        return false;
    }
    // --- End Of Central Directory: scan the tail for signature 0x06054b50, take the last one.
    const uint64_t kMaxEocd = 22 + 0xFFFFu;  // 22-byte record + max ZIP comment
    const uint64_t tailLen = fileSize < kMaxEocd ? fileSize : kMaxEocd;
    uint8_t* tail = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(tailLen)));
    if (tail == nullptr) {
        return false;
    }
    const uint64_t tailStart = fileSize - tailLen;
    uint64_t cdOffset = 0;
    bool haveEocd = false;
    if (readAt(fd, tailStart, tail, static_cast<size_t>(tailLen))) {
        for (uint64_t i = tailLen - 22 + 1; i-- > 0;) {
            if (tail[i] == 0x50 && tail[i + 1] == 0x4b && tail[i + 2] == 0x05 &&
                tail[i + 3] == 0x06) {
                cdOffset = le32(tail + i + 16);
                if (cdOffset >= 24 && cdOffset <= fileSize) {
                    haveEocd = true;
                    break;
                }
            }
        }
    }
    std::free(tail);
    if (!haveEocd) {
        return false;
    }

    // --- Signing Block footer sits in the 24 bytes just before the central directory:
    //     u64 sizeOfBlock | "APK Sig Block 42" (16 bytes). The same u64 size leads the block.
    uint8_t footer[24];
    if (!readAt(fd, cdOffset - 24, footer, 24)) {
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
    if (!readAt(fd, blockStart, hdr, 8) || le64(hdr) != blockSize) {
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
        if (!readAt(fd, pos, hp, 12)) {
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
            return hashFirstSignerCert(fd, valStart, valEnd, out);  // v2 preferred
        }
        if (id == kV3BlockId && !haveV3) {
            v3Start = valStart;
            v3End = valEnd;
            haveV3 = true;
        }
        pos += 8 + pairLen;
    }
    if (haveV3) {
        return hashFirstSignerCert(fd, v3Start, v3End, out);
    }
    return false;
}

// --- self-APK discovery (two independent oracles) ------------------------------------------

inline bool endsWithBaseApk(const char* s) {
    const size_t n = std::strlen(s);
    const char suffix[] = "/base.apk";
    const size_t m = sizeof(suffix) - 1;
    return n >= m && std::strncmp(s + n - m, suffix, m) == 0 &&
           std::strstr(s, "/data/app/") != nullptr;
}

// Source A path: first /data/app/.../base.apk mapped into this process (/proc/self/maps).
inline bool selfApkPathFromMaps(char* out, size_t cap) {
    const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    char buf[4096];
    char line[1024];
    size_t lineLen = 0;
    bool found = false;
    ssize_t r;
    while (!found && (r = read(fd, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < r; ++i) {
            const char ch = buf[i];
            if (ch == '\n' || lineLen + 1 >= sizeof line) {
                line[lineLen] = '\0';
                const char* path = std::strchr(line, '/');
                if (path != nullptr && endsWithBaseApk(path) && std::strlen(path) < cap) {
                    std::strcpy(out, path);
                    found = true;
                    break;
                }
                lineLen = 0;
            } else {
                line[lineLen++] = ch;
            }
        }
    }
    close(fd);
    return found;
}

// Source B: the ART runtime's already-open base.apk fd, found by readlink over /proc/self/fd.
// Returns the fd (do NOT close it — it belongs to the runtime) and its resolved path.
inline int selfApkOpenFd(char* pathOut, size_t cap) {
    DIR* d = opendir("/proc/self/fd");
    if (d == nullptr) {
        return -1;
    }
    const int dfd = dirfd(d);
    int result = -1;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') {
            continue;
        }
        char target[1024];
        const ssize_t n = readlinkat(dfd, e->d_name, target, sizeof target - 1);
        if (n <= 0) {
            continue;
        }
        target[n] = '\0';
        if (endsWithBaseApk(target) && static_cast<size_t>(n) < cap) {
            std::strcpy(pathOut, target);
            result = static_cast<int>(strtol(e->d_name, nullptr, 10));
            break;
        }
    }
    closedir(d);
    return result;
}

inline bool sameInode(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

// Fetch SHA-256(signer cert) via the two independent paths and trust only their consensus.
// Returns true and fills out[32] iff both parse, both resolve to the same inode, and both
// digests match; otherwise false (caller fails closed).
inline bool certSha256Consensus(uint8_t out[32]) {
    char pathMaps[1024];
    char pathFd[1024];
    if (!selfApkPathFromMaps(pathMaps, sizeof pathMaps)) {
        return false;
    }
    const int runtimeFd = selfApkOpenFd(pathFd, sizeof pathFd);
    if (runtimeFd < 0) {
        return false;
    }

    // Same-inode check across: runtime fd, the maps path, and the fd's own readlink path.
    // Catches open() redirection and post-open bind-mounts (readlink shows base.apk but a
    // fresh stat resolves through the overlay to a different inode than the live fd).
    struct stat stRt, stMaps, stFd;
    if (fstat(runtimeFd, &stRt) != 0 || stat(pathMaps, &stMaps) != 0 ||
        stat(pathFd, &stFd) != 0) {
        return false;
    }
    if (!sameInode(stRt, stMaps) || !sameInode(stRt, stFd)) {
        return false;
    }

    // Source A: fresh open() of the maps-discovered path.
    const int freshFd = open(pathMaps, O_RDONLY | O_CLOEXEC);
    if (freshFd < 0) {
        return false;
    }
    struct stat stFresh;
    uint8_t hashA[32];
    const bool okA = fstat(freshFd, &stFresh) == 0 && sameInode(stRt, stFresh) &&
                     parseSignerCertSha256Fd(freshFd, static_cast<uint64_t>(stFresh.st_size), hashA);
    close(freshFd);
    if (!okA) {
        return false;
    }

    // Source B: the runtime's live fd, read in place (never closed).
    uint8_t hashB[32];
    if (!parseSignerCertSha256Fd(runtimeFd, static_cast<uint64_t>(stRt.st_size), hashB)) {
        return false;
    }

    if (std::memcmp(hashA, hashB, 32) != 0) {
        return false;  // the two read paths disagree -> a redirect/hook is in play
    }
    std::memcpy(out, hashA, 32);
    return true;
}

}  // namespace apkcert
}  // namespace stringarmor

#endif  // STRINGARMOR_APKCERT_H
