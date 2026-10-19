// SPDX-License-Identifier: Apache-2.0
// Bootstrap TU: no obfuscation/LTO. Crypto entry wrappers live in the CSE VM TU.
#include "qseg.h"
#include "cse_crypto.h"
#include "apkcert.h"
#if defined(NDKP_APK_VERIFY)
#include "apkverify_runtime.h"
#endif
#include <array>
#include <map>
#include <mutex>
#include <sys/mman.h>
#include <zlib.h>
#include <link.h>

namespace {
using namespace ndkp_cse;
using namespace stringarmor::apkcert;
using Raw = stringarmor::apkio::Raw;
constexpr size_t EntrySize = 64, MaxSize = 1u << 28;
using ID = std::array<uint8_t, 16>;
[[noreturn]] void fail() { for (;;) Raw::call(__NR_exit_group, 127); }
struct Chunk { uint32_t ordinal, offset, stored, plain, codec; std::array<uint8_t, 64> entry; };
struct Resource { uint32_t kind = 0, size = 0; std::vector<Chunk> chunks; const uint8_t* data = nullptr; };
struct State {
  std::mutex mutex;
  bool ready = false;
  int fd = -1;
  uint64_t offset = 0;
  uint32_t size = 0;
  uint8_t code[32]{}, inputs[48]{};
  std::vector<std::pair<uintptr_t, uintptr_t>> executable;
  std::map<ID, Resource> resources;
};
State& state() { static State value; return value; }
void* allocate(size_t size) {
  void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) fail();
  return p;
}
void publish(void* p, size_t size) { if (mprotect(p, size, PROT_READ)) fail(); }
void read(int fd, uint64_t offset, void* p, size_t n) {
  if (!readAt<Raw>(fd, offset, p, n)) fail();
}
int ranges(dl_phdr_info* image, size_t, void* opaque) {
  auto& s = *static_cast<State*>(opaque);
  const uintptr_t anchor = reinterpret_cast<uintptr_t>(ndkp_qseg_image);
  bool owner = false;
  for (unsigned i = 0; i < image->dlpi_phnum; ++i) {
    const auto& p = image->dlpi_phdr[i];
    if (p.p_type == PT_LOAD && anchor >= image->dlpi_addr + p.p_vaddr &&
        anchor - (image->dlpi_addr + p.p_vaddr) < p.p_memsz) owner = true;
  }
  if (!owner) return 0;
  for (unsigned i = 0; i < image->dlpi_phnum; ++i) {
    const auto& p = image->dlpi_phdr[i];
    if (p.p_type == PT_LOAD && p.p_flags == (PF_R | PF_X))
      s.executable.push_back({image->dlpi_addr + p.p_vaddr, image->dlpi_addr + p.p_vaddr + p.p_filesz});
    if (p.p_type == PT_LOAD && anchor >= image->dlpi_addr + p.p_vaddr &&
        anchor - (image->dlpi_addr + p.p_vaddr) < p.p_memsz &&
        (p.p_flags != PF_R || anchor - (image->dlpi_addr + p.p_vaddr) > p.p_filesz ||
         512 > p.p_filesz - (anchor - (image->dlpi_addr + p.p_vaddr)))) fail();
  }
  return 1;
}
void assetRange(State& s) {
#if defined(NDKP_APK_VERIFY)
  struct stat st{}; uint8_t certificate[32];
  s.fd = ndkp_verified_apk(certificate, &st);
#else
  Mapping owner{};
  if (!inspectMaps<Raw>(reinterpret_cast<uintptr_t>(ndkp_qseg_image), &owner) || !cleanAbsolutePath(owner.path)) fail();
  const bool direct = endsWith(owner.path, ".apk");
  s.fd = direct ? Raw::open(owner.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : openExtractedLibraryApk<Raw>(owner);
  struct stat st{}; uint8_t certificate[32];
  if (s.fd < 0 || Raw::stat(s.fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      (direct && !mappedIdentity(owner, st)) ||
      !parseSignerCertSha256Fd<Raw>(s.fd, uint64_t(st.st_size), certificate)) fail();
#endif
  for (unsigned i = 0; i < 16; ++i) if ((certificate[i] ^ certificate[16 + i]) != s.inputs[32 + i]) fail();
  wipe(certificate, sizeof certificate);
  ZipDirectory cd{};
  if (!zipDirectory<Raw>(s.fd, uint64_t(st.st_size), cd)) fail();
  const char* wanted = reinterpret_cast<const char*>(ndkp_qseg_image + 256);
  const size_t wantedSize = strnlen(wanted, 128);
  if (wantedSize < 8 || wantedSize >= 128 || std::memcmp(wanted, "assets/", 7) || std::strstr(wanted, "..")) fail();
  uint64_t cursor = cd.offset; bool found = false;
  for (unsigned i = 0; i < cd.entries; ++i) {
    uint8_t h[46];
    if (cursor > cd.offset + cd.size || cd.offset + cd.size - cursor < sizeof h) fail();
    read(s.fd, cursor, h, sizeof h);
    const uint32_t span = 46u + le16(h + 28) + le16(h + 30) + le16(h + 32);
    if (le32(h) != 0x02014b50 || span > cd.offset + cd.size - cursor || le16(h + 34)) fail();
    if (le16(h + 28) == wantedSize) {
      char name[128]{}; read(s.fd, cursor + 46, name, wantedSize);
      if (!std::memcmp(name, wanted, wantedSize)) {
        const uint32_t local = le32(h + 42), size = le32(h + 24);
        if (found || le16(h + 10) || (le16(h + 8) & ~0x808u) ||
            le32(h + 20) != size || size != s.size || local >= cd.offset || cd.offset - local < 30) fail();
        uint8_t lh[30]; read(s.fd, local, lh, sizeof lh);
        if (le32(lh) != 0x04034b50 || le16(lh + 6) != le16(h + 8) || le16(lh + 8) ||
            le16(lh + 26) != wantedSize || (!(le16(h + 8) & 8) && std::memcmp(lh + 14, h + 16, 12))) fail();
        char localName[128]{}; read(s.fd, uint64_t(local) + 30, localName, wantedSize);
        if (std::memcmp(localName, name, wantedSize)) fail();
        s.offset = uint64_t(local) + 30 + wantedSize + le16(lh + 28);
        if (s.offset > cd.offset || size > cd.offset - s.offset) fail();
        found = true;
      }
    }
    cursor += span;
  }
  if (!found || cursor != cd.offset + cd.size) fail();
}
void containerDigest(State& s) {
  // SHA API is one-shot; a temporary bounded snapshot prevents hash/read races.
  std::vector<uint8_t> cipher(s.size);
  read(s.fd, s.offset, cipher.data(), cipher.size());
  uint8_t digest[32]; stringarmor::sha2::sha256(cipher.data(), cipher.size(), digest);
  if (!equal(digest, ndkp_qseg_image + 384, 32)) fail();
}
void rootKey(const State& s, uint8_t root[32]) { ndkp_qseg_derive(s.code, s.inputs, root); }
void indexKey(const State& s, uint8_t key[32]) {
  uint8_t root[32]; rootKey(s, root);
  const char domain[] = "NDKP-QSEG-index-v1";
  std::vector<uint8_t> material(domain, domain + sizeof domain - 1);
  material.insert(material.end(), ndkp_qseg_image + 24, ndkp_qseg_image + 40);
  hkdf(root, 32, ndkp_qseg_image + 72, material.data(), material.size(), key); wipe(root, sizeof root);
}
void chunkKey(const State& s, const ID& id, uint32_t kind, uint32_t chunk, uint8_t key[32]) {
  uint8_t root[32]; rootKey(s, root);
  const char domain[] = "NDKP-QSEG-v1";
  std::vector<uint8_t> info(domain, domain + sizeof domain - 1);
  info.insert(info.end(), id.begin(), id.end());
  const size_t n = info.size(); info.resize(n + 8); store32(info.data() + n, kind); store32(info.data() + n + 4, chunk);
  hkdf(root, 32, ndkp_qseg_image + 72, info.data(), info.size(), key); wipe(root, sizeof root);
}
void initialize(State& s) {
  if (s.ready) return;
  const uint8_t* h = ndkp_qseg_image;
  if (!equal(h, reinterpret_cast<const uint8_t*>("NDKPQSG1"), 8) || load32(h + 12) != 1 || load32(h + 16) != 2 ||
      load32(h + 8) < 32 || load32(h + 8) > MaxSize || !load32(h + 20) || load32(h + 20) > 16384 ||
      load32(h + 216) != load32(h + 20) * EntrySize || load32(h + 220) != EM_AARCH64) fail();
  for (unsigned i = 104; i < 152; ++i) if (h[i]) fail();
  for (unsigned i = 224; i < 256; ++i) if (h[i]) fail();
  for (unsigned i = 416; i < 512; ++i) if (h[i]) fail();
  ndkp_qseg_measure(s.code, s.inputs);
  if (!equal(s.code, h + 152, 32)) fail();
  dl_iterate_phdr(ranges, &s);
  if (s.executable.empty()) fail();
  s.size = load32(h + 8); assetRange(s); containerDigest(s);
  const uint32_t count = load32(h + 20), bytes = load32(h + 216);
  if (uint64_t(bytes) + 32 > s.size) fail();
  uint8_t prefix[16]; read(s.fd, s.offset, prefix, 16);
  if (!equal(prefix, reinterpret_cast<const uint8_t*>("QSEGDAT1"), 8) || load32(prefix + 8) != 1 || load32(prefix + 12) != bytes) fail();
  std::vector<uint8_t> directory(bytes); uint8_t tag[16], key[32], aad[32];
  read(s.fd, s.offset + 16, directory.data(), bytes); read(s.fd, s.offset + 16 + bytes, tag, 16);
  std::memcpy(aad, prefix, 16); std::memcpy(aad + 16, h + 24, 16); indexKey(s, key);
  const bool valid = ndkp_qseg_open(key, aad, sizeof aad, directory.data(), directory.size(), tag);
  wipe(key, sizeof key); if (!valid) fail();
  uint64_t cursor = 32 + bytes;
  for (uint32_t i = 0; i < count; ++i) {
    const uint8_t* e = directory.data() + i * EntrySize;
    ID id; std::memcpy(id.data(), e, 16);
    const uint32_t kind = load32(e + 16), chunk = load32(e + 20), offset = load32(e + 24), stored = load32(e + 28),
        plain = load32(e + 32), total = load32(e + 36), codec = load32(e + 40);
    if ((kind != 1 && kind != 2) || codec > 1 || load32(e + 44) != i || offset != cursor ||
        !stored || stored > plain || plain > (1u << 24) || !total || total > (1u << 24) ||
        cursor > s.size || stored > s.size - cursor || (kind == 1 && plain > 65536)) fail();
    Resource& r = s.resources[id];
    if (chunk != r.chunks.size() || (chunk && (r.kind != kind || r.size != total)) ||
        (kind == 2 && chunk) || (kind == 1 && chunk && r.chunks.back().plain != 65536)) fail();
    r.kind = kind; r.size = total;
    Chunk c{i, offset, stored, plain, codec, {}}; std::memcpy(c.entry.data(), e, EntrySize);
    r.chunks.push_back(c); cursor += stored;
  }
  if (cursor != s.size) fail();
  for (const auto& item : s.resources) {
    uint64_t size = 0; for (const auto& c : item.second.chunks) size += c.plain;
    if (size != item.second.size) fail();
  }
  s.ready = true;
}
Resource& resource(State& s, const uint8_t* ref) {
  const uintptr_t addr = reinterpret_cast<uintptr_t>(ref);
  bool valid = false;
  for (auto [begin, end] : s.executable) if (addr >= begin && addr <= end && 24 <= end - addr) valid = true;
  if (!valid) fail();
  ID id; std::memcpy(id.data(), ref, 16);
  auto found = s.resources.find(id);
  if (found == s.resources.end() || found->second.size != load32(ref + 16) || found->second.kind != load32(ref + 20)) fail();
  return found->second;
}
const uint8_t* restore(State& s, Resource& r, const ID& id) {
  if (r.data) return r.data;
  auto* out = static_cast<uint8_t*>(allocate(r.size)); size_t cursor = 0;
  for (uint32_t i = 0; i < r.chunks.size(); ++i) {
    const Chunk& c = r.chunks[i]; std::vector<uint8_t> cipher(c.stored);
    read(s.fd, s.offset + c.offset, cipher.data(), cipher.size());
    uint8_t key[32], aad[64]; chunkKey(s, id, r.kind, i, key);
    std::memcpy(aad, ndkp_qseg_image + 24, 16); std::memcpy(aad + 16, c.entry.data(), 48);
    const bool valid = ndkp_qseg_open(key, aad, sizeof aad, cipher.data(), cipher.size(), c.entry.data() + 48);
    wipe(key, sizeof key); if (!valid) { wipe(cipher.data(), cipher.size()); fail(); }
    if (c.codec) {
      z_stream z{}; z.next_in = cipher.data(); z.avail_in = c.stored; z.next_out = out + cursor; z.avail_out = c.plain;
      if (inflateInit2(&z, -15) != Z_OK) fail();
      const int result = inflate(&z, Z_FINISH);
      const bool ok = result == Z_STREAM_END && z.total_out == c.plain && z.total_in == c.stored;
      inflateEnd(&z); if (!ok) fail();
    } else { if (c.stored != c.plain) fail(); std::memcpy(out + cursor, cipher.data(), c.plain); }
    wipe(cipher.data(), cipher.size()); cursor += c.plain;
  }
  if (cursor != r.size) fail(); publish(out, r.size); r.data = out; return out;
}
}
extern "C" const uint8_t* ndkp_qseg_get(const uint8_t* ref) {
  State& s = state(); std::lock_guard<std::mutex> guard(s.mutex); initialize(s);
  Resource& r = resource(s, ref); ID id; std::memcpy(id.data(), ref, 16);
  return restore(s, r, id);
}
extern "C" void ndkp_qseg_copy(uint8_t* out, const uint8_t* ref, uint32_t offset, uint32_t length, uint32_t encoding) {
  const uint8_t* data = ndkp_qseg_get(ref);
  const uint32_t size = load32(ref + 16);
  if (!out || load32(ref + 20) != 2 || (encoding != 1 && encoding != 2) || length % encoding ||
      offset > size || length > size - offset) fail();
  std::memcpy(out, data + offset, length);
}
extern "C" void ndkp_qseg_verify() {
  State& s = state(); std::lock_guard<std::mutex> guard(s.mutex); initialize(s);
}
extern "C" void ndkp_qseg_recheck() {
  State& s = state(); std::lock_guard<std::mutex> guard(s.mutex); initialize(s);
  uint8_t code[32], inputs[48]; ndkp_qseg_measure(code, inputs);
  if (!equal(code, s.code, 32) || !equal(inputs, s.inputs, 48)) fail();
  containerDigest(s);
}
