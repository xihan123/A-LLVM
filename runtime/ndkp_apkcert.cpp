/*
 * ndkp_apkcert.cpp — runtime signing-certificate reader for -irobf-cert-bind (A-LLVM / NDKP).
 *
 * The app author compiles this ONE file into the protected .so. The obfuscator injects a
 * load-time constructor that calls ndkp_certbind_mix() exactly once (in native context, never
 * inside a VMP-virtualized frame) and caches the returned 128-bit mix; the -irobf-cse string
 * decoder and the VMProtect function-key store then XOR that mix back into their keys. The
 * build folded the SHA-256 of the *build-time* signer cert into the same keys, so the two only
 * cancel when the running APK is signed by that certificate — otherwise the keystream is wrong
 * and both strings and virtualized functions decode to garbage (non-branching, fail-closed).
 *
 * The certificate is read straight from the on-disk APK's v2/v3 signing block over two
 * independent, cross-checked native paths (apkcert.h) — never PackageManager.getPackageInfo,
 * the API every signature-bypass tool (CorePatch / LSPatch / fake-signature Xposed) hooks. A
 * wrong/absent/redirected cert yields (0,0): fail-closed.
 *
 * Pure C++/POSIX, no JNI, no root, no third-party deps. See runtime/README.md for how to build
 * and how to produce the matching -irobf-cert-file=<cert.der> input.
 */
#include <cstdint>

#include "apkcert.h"  // stringarmor::apkcert::certSha256Consensus (pulls in sha256.h)

namespace {
// Little-endian u64 from 8 bytes — byte-identical to apkcert.h/jni.cpp so the runtime mix
// matches the digest the pass folded at build time.
inline uint64_t le64(const uint8_t* b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(b[i]) << (8 * i);
    return v;
}
}  // namespace

// Called once from the obfuscator's injected .init_array constructor. extern "C" gives a stable,
// unmangled symbol the pass emits a plain declaration for; hidden visibility keeps it out of the
// .so's public ABI while staying resolvable within it (--gc-sections drops it in builds that
// never enable -irobf-cert-bind, since nothing references it there).
extern "C" __attribute__((visibility("hidden"))) void ndkp_certbind_mix(uint64_t* out_lo,
                                                                        uint64_t* out_hi) {
    uint8_t sha[32];
    uint64_t lo = 0, hi = 0;  // fail-closed default: (0,0) unless the two sources reach consensus.
    if (stringarmor::apkcert::certSha256Consensus(sha)) {
        lo = le64(sha) ^ le64(sha + 16);
        hi = le64(sha + 8) ^ le64(sha + 24);
    }
    *out_lo = lo;
    *out_hi = hi;
}
