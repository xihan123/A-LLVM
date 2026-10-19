// SPDX-License-Identifier: Apache-2.0
// APK v2/v3 signed-data and 1 MiB content digests; see Android ApkSigningBlockUtils.
#include "apkverify.h"
#include <algorithm>
#include <cstring>
#include <vector>
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"

namespace ndkp_apkverify {
namespace {
constexpr uint32_t V2 = 0x7109871a, V3 = 0xf05368c0, V31 = 0x1b93ad61;
constexpr size_t Chunk = 1u << 20, MaxBlock = 16u << 20;
uint32_t le32(const uint8_t* p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
uint64_t le64(const uint8_t* p) { return le32(p) | uint64_t(le32(p + 4)) << 32; }
void put32(uint8_t* p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(v >> (8 * i)); }
bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
  unsigned diff = 0; for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i]; return diff == 0;
}
struct View {
  const uint8_t* p = nullptr; size_t n = 0; bool ok = true;
  View take(size_t size) {
    if (!ok || size > n) { ok = false; return {nullptr, 0, false}; }
    View result{p, size}; if (size) p += size; n -= size; return result;
  }
  uint32_t u32() { auto v = take(4); return v.ok ? le32(v.p) : 0; }
  View lp() { uint32_t size = u32(); return take(size); }
  bool end() const { return ok && n == 0; }
};
struct Hash {
  mbedtls_md_context_t ctx;
  bool ok;
  explicit Hash(mbedtls_md_type_t type) {
    mbedtls_md_init(&ctx);
    ok = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(type), 0) == 0 && mbedtls_md_starts(&ctx) == 0;
  }
  ~Hash() { mbedtls_md_free(&ctx); }
  void add(const void* p, size_t n) { if (ok && n) ok = mbedtls_md_update(&ctx, static_cast<const uint8_t*>(p), n) == 0; }
  bool finish(uint8_t* out) { return ok && mbedtls_md_finish(&ctx, out) == 0; }
};
struct Algorithm { uint32_t id; mbedtls_md_type_t md; mbedtls_pk_type_t pk; size_t length; bool pss; };
bool algorithm(uint32_t id, Algorithm& a) {
  switch (id) {
    case 0x0101: a = {id, MBEDTLS_MD_SHA256, MBEDTLS_PK_RSASSA_PSS, 32, true}; break;
    case 0x0102: a = {id, MBEDTLS_MD_SHA512, MBEDTLS_PK_RSASSA_PSS, 64, true}; break;
    case 0x0103: a = {id, MBEDTLS_MD_SHA256, MBEDTLS_PK_RSA, 32, false}; break;
    case 0x0104: a = {id, MBEDTLS_MD_SHA512, MBEDTLS_PK_RSA, 64, false}; break;
    case 0x0201: a = {id, MBEDTLS_MD_SHA256, MBEDTLS_PK_ECDSA, 32, false}; break;
    case 0x0202: a = {id, MBEDTLS_MD_SHA512, MBEDTLS_PK_ECDSA, 64, false}; break;
    default: return false;
  }
  return true;
}
struct Record { uint32_t id; View bytes; };
bool records(View input, std::vector<Record>& out) {
  while (input.ok && input.n) {
    View record = input.lp(); uint32_t id = record.u32(); View bytes = record.lp();
    if (!record.end() || !bytes.ok || !bytes.n || out.size() >= 16 ||
        std::any_of(out.begin(), out.end(), [id](const Record& r) { return r.id == id; })) return false;
    out.push_back({id, bytes});
  }
  return input.end() && !out.empty();
}
struct File {
  ReadAt read; void* context; uint64_t size, start = 0, cd = 0, eocd = 0;
  std::vector<uint8_t> tail, block;
  View v2, v3;
  bool at(uint64_t offset, void* p, size_t n) const {
    return offset <= size && n <= size - offset && read(context, offset, p, n);
  }
  bool locate(Error& error) {
    error = Error::Zip;
    if (size < 22 || size >= UINT32_MAX) return false; // ZIP64 is deliberately unsupported.
    tail.resize(size_t(std::min<uint64_t>(size, 65557)));
    if (!at(size - tail.size(), tail.data(), tail.size())) { error = Error::Io; return false; }
    bool found = false;
    for (size_t pos = tail.size() - 22;; --pos) {
      const uint8_t* p = tail.data() + pos;
      if (le32(p) == 0x06054b50 && size_t(p[20] | unsigned(p[21]) << 8) == tail.size() - pos - 22) {
        eocd = size - tail.size() + pos;
        if (le32(p + 4) || (p[8] != p[10] || p[9] != p[11]) ||
            (p[10] == 255 && p[11] == 255) || le32(p + 12) == UINT32_MAX || le32(p + 16) == UINT32_MAX) return false;
        cd = le32(p + 16);
        if (cd + uint64_t(le32(p + 12)) != eocd || cd < 32) return false;
        tail.erase(tail.begin(), tail.begin() + pos); found = true; break;
      }
      if (pos == 0) break;
    }
    if (!found) return false;
    error = Error::SigningBlock;
    uint8_t footer[24];
    if (!at(cd - 24, footer, sizeof footer)) { error = Error::Io; return false; }
    uint64_t length = le64(footer);
    if (std::memcmp(footer + 8, "APK Sig Block 42", 16) || length < 24 || length > MaxBlock || length > cd - 8) return false;
    start = cd - length - 8; block.resize(size_t(length + 8));
    if (!at(start, block.data(), block.size())) { error = Error::Io; return false; }
    if (le64(block.data()) != length) return false;
    View pairs{block.data() + 8, block.size() - 32};
    bool has2 = false, has3 = false;
    while (pairs.ok && pairs.n) {
      View prefix = pairs.take(8);
      if (!prefix.ok) return false;
      uint64_t span = le64(prefix.p);
      if (span < 4 || span > pairs.n) return false;
      View value = pairs.take(size_t(span)); uint32_t id = value.u32();
      if (id == V31) { error = Error::Unsupported; return false; }
      if (id == V2) { if (has2) return false; has2 = true; v2 = value; }
      if (id == V3) { if (has3) return false; has3 = true; v3 = value; }
    }
    if (!pairs.end() || (!has2 && !has3) || (has2 && !v2.n) || (has3 && !v3.n)) return false;
    put32(tail.data() + 16, uint32_t(start));
    return true;
  }
};
bool content(const File& f, mbedtls_md_type_t md, uint8_t* out) {
  const size_t length = md == MBEDTLS_MD_SHA256 ? 32 : 64;
  const uint64_t sizes[]{f.start, f.eocd - f.cd, f.tail.size()};
  const uint64_t offsets[]{0, f.cd, 0};
  uint32_t count = 0; for (uint64_t size : sizes) count += uint32_t((size + Chunk - 1) / Chunk);
  uint8_t prefix[5]{0x5a}; put32(prefix + 1, count);
  Hash total(md); total.add(prefix, sizeof prefix);
  std::vector<uint8_t> buffer(Chunk);
  for (unsigned section = 0; section < 3; ++section) {
    for (uint64_t offset = 0; offset < sizes[section];) {
      size_t n = size_t(std::min<uint64_t>(Chunk, sizes[section] - offset));
      if (section < 2 && !f.at(offsets[section] + offset, buffer.data(), n)) return false;
      prefix[0] = 0xa5; put32(prefix + 1, uint32_t(n));
      Hash chunk(md); chunk.add(prefix, sizeof prefix);
      chunk.add(section == 2 ? f.tail.data() + offset : buffer.data(), n);
      uint8_t digest[64]; if (!chunk.finish(digest)) return false;
      total.add(digest, length); offset += n;
    }
  }
  return total.finish(out);
}
bool attributes(View attrs, bool v3, bool hasV3) {
  std::vector<uint32_t> ids;
  while (attrs.ok && attrs.n) {
    View attr = attrs.lp(); uint32_t id = attr.u32();
    if (!attr.ok || std::find(ids.begin(), ids.end(), id) != ids.end() || ids.size() >= 128) return false;
    ids.push_back(id);
    if (id == 0x3ba06f8c || id == 0x559f8b02 || id == 0xc2a6b3ba) return false; // Rotation is not supported.
    if (id == 0xbeeff00d) {
      uint32_t version = attr.u32();
      if (v3 || !attr.end() || version != 3 || !hasV3) return false;
    }
  }
  return attrs.end();
}
struct Certificate {
  mbedtls_pk_context pk;
  Certificate() { mbedtls_pk_init(&pk); }
  ~Certificate() { mbedtls_pk_free(&pk); }
};
// Only SPKI is used. Certificate identity is pinned by its complete DER hash;
// its issuer, dates and self-signature algorithm are not an APK trust decision.
bool publicKeyFromCertificate(View der, View& spki) {
  auto* p = const_cast<uint8_t*>(der.p); const uint8_t* end = p + der.n; size_t length;
  constexpr int sequence = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
  if (mbedtls_asn1_get_tag(&p, end, &length, sequence) || length != size_t(end - p)) return false;
  if (mbedtls_asn1_get_tag(&p, end, &length, sequence)) return false;
  end = p + length;
  if (p < end && *p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) {
    if (mbedtls_asn1_get_tag(&p, end, &length, *p)) return false;
    p += length;
  }
  for (int tag : {MBEDTLS_ASN1_INTEGER, sequence, sequence, sequence, sequence}) {
    if (mbedtls_asn1_get_tag(&p, end, &length, tag)) return false;
    p += length;
  }
  const uint8_t* start = p;
  if (mbedtls_asn1_get_tag(&p, end, &length, sequence)) return false;
  spki = {start, size_t(p - start) + length}; return true;
}
bool signer(const File& f, View input, bool v3, const uint8_t expected[32], unsigned api,
            uint8_t computed[2][64], bool ready[2], Error& error) {
  error = Error::Signer;
  View signers = input.lp(); if (!input.end()) return false;
  View one = signers.lp(); if (!signers.end()) return false;
  View signedBytes = one.lp(), signedData = signedBytes;
  uint32_t min = 0, max = 0;
  if (v3) { min = one.u32(); max = one.u32(); }
  View signatures = one.lp(), publicKey = one.lp();
  if (!one.end() || !signedData.ok || !publicKey.n) return false;
  View digests = signedData.lp(), certificates = signedData.lp();
  if (v3) {
    uint32_t signedMin = signedData.u32(), signedMax = signedData.u32();
    error = Error::Sdk;
    if (min != signedMin || max != signedMax || min > max || max > INT32_MAX ||
        (api >= 28 && (api < min || api > max))) return false;
  }
  View attrs = signedData.lp();
  // Android ignores extensions after attributes; these bytes remain covered by the signature.
  if (!signedData.ok) return false;
  error = Error::Attributes;
  if (!attributes(attrs, v3, f.v3.n != 0)) return false;
  error = Error::Certificate;
  View first = certificates.lp();
  if (!certificates.ok || !first.ok || !first.n) return false;
  Hash certHash(MBEDTLS_MD_SHA256); uint8_t certDigest[32]; certHash.add(first.p, first.n);
  if (!certHash.finish(certDigest) || !equal(certDigest, expected, 32)) return false;
  Certificate cert;
  View spki;
  if (!publicKeyFromCertificate(first, spki) || spki.n != publicKey.n || !equal(spki.p, publicKey.p, publicKey.n) ||
      mbedtls_pk_parse_public_key(&cert.pk, spki.p, spki.n)) return false;
  unsigned certCount = 1;
  while (certificates.ok && certificates.n) {
    View der = certificates.lp(), key;
    if (++certCount > 16 || !der.ok || !der.n || !publicKeyFromCertificate(der, key)) return false;
  }
  if (!certificates.end()) return false;
  std::vector<Record> sigs, sums;
  error = Error::Algorithm;
  if (!records(signatures, sigs) || !records(digests, sums) || sigs.size() != sums.size()) return false;
  for (size_t i = 0; i < sigs.size(); ++i) {
    Algorithm a;
    if (sigs[i].id != sums[i].id || !algorithm(sigs[i].id, a) || sums[i].bytes.n != a.length) return false;
    uint8_t digest[64]; Hash signedHash(a.md); signedHash.add(signedBytes.p, signedBytes.n);
    error = Error::Signature;
    mbedtls_pk_rsassa_pss_options pss{a.md, int(a.length)};
    if (!signedHash.finish(digest) || mbedtls_pk_verify_ext(a.pk, a.pss ? &pss : nullptr,
        &cert.pk, a.md, digest, a.length, sigs[i].bytes.p, sigs[i].bytes.n)) return false;
    unsigned which = a.length == 32 ? 0 : 1;
    error = Error::Content;
    if (!ready[which]) { if (!content(f, a.md, computed[which])) return false; ready[which] = true; }
    if (!equal(computed[which], sums[i].bytes.p, a.length)) return false;
  }
  return true;
}
}
bool verify(ReadAt read, void* context, uint64_t size, const uint8_t expected[32],
            unsigned api, Result& result, Error& error) {
  if (!read || !expected || api < 26) { error = Error::Unsupported; return false; }
  File f{read, context, size};
  if (!f.locate(error)) return false;
  if (!f.v2.n && api < 28) { error = Error::Sdk; return false; }
  uint8_t computed[2][64]{}; bool ready[2]{};
  if (f.v3.n && !signer(f, f.v3, true, expected, api, computed, ready, error)) return false;
  if (f.v2.n && !signer(f, f.v2, false, expected, api, computed, ready, error)) return false;
  Result output{}; std::memcpy(output.certificate, expected, 32);
  output.schemes = (f.v2.n ? 2u : 0u) | (f.v3.n ? 4u : 0u);
  result = output; error = Error::None; return true;
}
const char* errorName(Error error) {
  static const char* names[]{"ok", "io", "zip", "signing-block", "unsupported", "signer", "certificate",
                             "algorithm", "signature", "content", "attributes", "sdk"};
  return names[static_cast<unsigned>(error)];
}
}
