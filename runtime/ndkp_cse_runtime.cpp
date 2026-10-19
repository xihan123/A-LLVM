// SPDX-License-Identifier: Apache-2.0
// Compile separately with -fno-lto. NDKP_CSE_VMP selects only crypto cores;
// never enable CSE/certificate binding on this bootstrap translation unit.
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error "hardened CSE requires Android arm64"
#endif
#include "cse_crypto.h"
#include "cse_region.h"
#include "apkcert.h"
#if defined(NDKP_APK_VERIFY)
#include "apkverify_runtime.h"
#endif
#include <elf.h>
#include <link.h>
#if defined(NDKP_QSEG)
#include "qseg.h"
#endif

namespace {
using namespace ndkp_cse;
using Raw = stringarmor::apkio::Raw;
using Posix = stringarmor::apkio::Posix;

[[noreturn]] void fail() {
  for (;;) Raw::call(__NR_exit_group, 127);
}

struct Image {
  uintptr_t anchor, regions;
  size_t regionsSize;
  uint8_t digest[32];
  unsigned matches = 0;
  bool valid = false;
};
int hashImage(dl_phdr_info* image, size_t, void* opaque) {
  auto& result = *static_cast<Image*>(opaque);
  bool owner = false;
  for (unsigned i = 0; i < image->dlpi_phnum; ++i) {
    const auto& p = image->dlpi_phdr[i];
    if (p.p_type == PT_LOAD && result.anchor >= image->dlpi_addr + p.p_vaddr &&
        result.anchor - (image->dlpi_addr + p.p_vaddr) < p.p_memsz) owner = true;
  }
  if (!owner) return 0;
  ++result.matches;
  if (image->dlpi_phnum == 0 || image->dlpi_phnum >= 1024) return 0;
  std::vector<uint8_t> material;
  const char domain[] = "NDKP-CODE-v1";
  material.insert(material.end(), domain, domain + sizeof domain - 1);
  unsigned executable = 0;
  bool regionsCovered = false;
  for (unsigned i = 0; i < image->dlpi_phnum; ++i) {
    const auto& p = image->dlpi_phdr[i];
    if (p.p_type == PT_DYNAMIC) {
      if (p.p_memsz % sizeof(Elf64_Dyn)) return 0;
      const auto* entries = reinterpret_cast<const Elf64_Dyn*>(image->dlpi_addr + p.p_vaddr);
      for (size_t j = 0; j < p.p_memsz / sizeof(Elf64_Dyn); ++j) {
        if (entries[j].d_tag == DT_NULL) break;
        if (entries[j].d_tag == DT_TEXTREL ||
            (entries[j].d_tag == DT_FLAGS && (entries[j].d_un.d_val & DF_TEXTREL))) return 0;
      }
    }
    if (p.p_type != PT_LOAD || !(p.p_flags & PF_X)) continue;
    if (p.p_flags != (PF_R | PF_X) || p.p_filesz != p.p_memsz || p.p_filesz > (1u << 28)) return 0;
    const uintptr_t start = image->dlpi_addr + p.p_vaddr;
    if (result.regions >= start && result.regions - start <= p.p_filesz &&
        result.regionsSize <= p.p_filesz - (result.regions - start)) regionsCovered = true;
    // Validate live page permissions before dereferencing, including execute-only remaps.
    auto* maps = Raw::stream("/proc/self/maps");
    if (!maps) return 0;
    uintptr_t covered = image->dlpi_addr + p.p_vaddr, end = covered + p.p_filesz;
    char line[PATH_MAX + 256];
    while (covered < end && Raw::gets(line, sizeof line, maps)) {
      unsigned long long start, stop; char perms[5] = {};
      if (std::sscanf(line, "%llx-%llx %4s", &start, &stop, perms) != 3) break;
      if (covered >= start && covered < stop) {
        if (perms[0] != 'r' || perms[1] == 'w' || perms[2] != 'x') break;
        covered = stop < end ? uintptr_t(stop) : end;
      }
    }
    const bool readable = covered == end && !Raw::error(maps);
    Raw::finish(maps);
    if (!readable) return 0;
    const auto* source = reinterpret_cast<const volatile uint8_t*>(image->dlpi_addr + p.p_vaddr);
    std::vector<uint8_t> bytes(size_t(p.p_filesz));
    for (size_t j = 0; j < bytes.size(); ++j) bytes[j] = source[j];
    // Match the sealer's strip-stable ELF-header canonicalization.
    for (size_t absolute : {size_t(40), size_t(41), size_t(42), size_t(43), size_t(44),
         size_t(45), size_t(46), size_t(47), size_t(58), size_t(59), size_t(60),
         size_t(61), size_t(62), size_t(63)})
      if (absolute >= p.p_offset && absolute - p.p_offset < bytes.size())
        bytes[absolute - p.p_offset] = 0;
    uint8_t entry[48]; store64(entry, p.p_vaddr); store64(entry + 8, p.p_filesz);
    stringarmor::sha2::sha256(bytes.data(), bytes.size(), entry + 16);
    material.insert(material.end(), entry, entry + sizeof entry);
    ++executable;
  }
  if (executable && regionsCovered) {
    stringarmor::sha2::sha256(material.data(), material.size(), result.digest);
    result.valid = true;
  }
  return 0;
}

template <class IO> bool package(uint8_t digest[32]) {
  const int fd = IO::open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  uint8_t name[4096]; size_t used = 0; bool done = false, ok = true;
  while (!done && used < sizeof name) {
    ssize_t n = IO::read(fd, name + used, sizeof name - used);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { ok = false; break; }
    const size_t limit = used + size_t(n);
    for (; used < limit; ++used) {
      if (name[used] == 0 || name[used] == ':') { done = true; break; }
    }
  }
  IO::close(fd);
  ok = ok && done && used != 0;
  if (ok) stringarmor::sha2::sha256(name, used, digest);
  wipe(name, sizeof name); return ok;
}

void inputs(const uint8_t* blob, uint8_t out[48]) {
  std::memset(out, 0, 48);
  if (load32(blob + 16) & 1) {
    uint8_t other[32];
    if (!package<Raw>(out) || !package<Posix>(other) || !equal(out, other, 32)) fail();
    wipe(other, sizeof other);
  }
  if (load32(blob + 16) & 2) {
#if defined(NDKP_APK_VERIFY)
    uint8_t a[32]; ndkp_verified_apk(a, nullptr);
    for (unsigned i = 0; i < 16; ++i) out[32 + i] = a[i] ^ a[16 + i];
    wipe(a, sizeof a);
#else
    uint8_t a[32], b[32]; struct stat sa{}, sb{};
    using namespace stringarmor::apkcert;
    Mapping ma{}, mb{};
    const uintptr_t anchor = reinterpret_cast<uintptr_t>(blob);
    if (!inspectMaps<Raw>(anchor, &ma) || !inspectMaps<Posix>(anchor, &mb) ||
        ma.start != mb.start || ma.end != mb.end || ma.inode != mb.inode ||
        ma.devMajor != mb.devMajor || ma.devMinor != mb.devMinor || std::strcmp(ma.path, mb.path) ||
        !certSha256ForLibrary<Raw>(blob, a, &sa) || !certSha256ForLibrary<Posix>(blob, b, &sb) ||
        sa.st_dev != sb.st_dev || sa.st_ino != sb.st_ino || sa.st_size != sb.st_size || !equal(a, b, 32)) fail();
    for (unsigned i = 0; i < 16; ++i) out[32 + i] = a[i] ^ a[16 + i];
    wipe(a, sizeof a); wipe(b, sizeof b);
#endif
  }
}

Image measure(const ModuleV1* module) {
  Image image{};
  image.anchor = reinterpret_cast<uintptr_t>(module->blob);
  image.regions = reinterpret_cast<uintptr_t>(module->regions);
  image.regionsSize = size_t(module->count) * sizeof(RegionV1);
  if (dl_iterate_phdr(hashImage, &image) != 0 || image.matches != 1 || !image.valid) fail();
  return image;
}

void initialize(const ModuleV1* module) {
  auto* state = reinterpret_cast<uint32_t*>(module->cache);
  uint32_t value = __atomic_load_n(state, __ATOMIC_ACQUIRE);
  if (value == 2) return;
  if (value > 2) fail();
  uint32_t expected = 0;
  if (__atomic_compare_exchange_n(state, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    Image image = measure(module);
    std::memcpy(module->cache + 4, image.digest, 32);
    inputs(module->blob, module->cache + 36);
    __atomic_store_n(state, 2, __ATOMIC_RELEASE);
  } else {
    while ((value = __atomic_load_n(state, __ATOMIC_ACQUIRE)) != 2) {
      if (value != 1) fail();
      Raw::call(__NR_sched_yield);
    }
  }
}
} // namespace

// cache points to aligned {u32 state; u8 actual_code_hash[32]; u8 inputs[48]}.
// Only public input digests persist; never retain a derived key in this cache.
extern "C" __attribute__((visibility("hidden"))) void ndkp_cse_decode_region_v1(
    uint8_t* out, const ndkp_cse::ModuleV1* module, const ndkp_cse::RegionV1* region) {
  using namespace ndkp_cse;
  if (!out || !module || !region || !module->blob || !module->cache || !module->regions) fail();
  const uint8_t* blob = module->blob;
  uint8_t* cache = module->cache;
  const uint32_t total = module->total;
  const uintptr_t base = reinterpret_cast<uintptr_t>(module->regions);
  const uintptr_t address = reinterpret_cast<uintptr_t>(region);
  if (module->count < 2 || module->count > (1u << 28) / 64 || address < base ||
      address - base >= uint64_t(module->count) * sizeof(RegionV1) ||
      (address - base) % sizeof(RegionV1)) fail();
  const uint32_t ordinal = uint32_t((address - base) / sizeof(RegionV1));
  const uint32_t offset = region->offset, outCapacity = region->out_capacity, encoding = region->encoding;
  if (total < HeaderSize || total > (1u << 28) || !equal(blob, Magic, 8) ||
      load32(blob + 8) != total || load32(blob + 12) != 1 || (load32(blob + 16) & ~3u) ||
      load32(blob + 20) != module->count || load32(blob + 20) > (total - HeaderSize) / 64 ||
      ordinal >= load32(blob + 20) || offset < HeaderSize || offset > total - 32) fail();
  for (size_t i = 104; i < 152; ++i) if (blob[i]) fail();
  for (size_t i = 216; i < HeaderSize; ++i) if (blob[i]) fail();
  initialize(module);
  const uint8_t* record = blob + offset;
  const uint32_t capacity = load32(record);
  if (capacity < 32 || capacity > MaxCapacity || (capacity & (capacity - 1)) ||
      capacity > total - offset - 32 || outCapacity != capacity - 16 ||
      load64(record + 4) != 0 || load32(record + 12) != ordinal) fail();
  uint8_t key[32], associated[40];
  derive(blob, cache + 4, cache + 36, key);
  aad(blob, ordinal, capacity, associated);
  std::vector<uint8_t> plain(record + 32, record + 32 + capacity);
  const bool valid = open(key, record + 4, associated, sizeof associated, plain.data(), plain.size(), record + 16);
  wipe(key, sizeof key);
  const uint32_t length = load32(plain.data());
  bool metadata = valid && length <= outCapacity && load32(plain.data() + 4) == encoding &&
      load32(plain.data() + 8) == ordinal && load32(plain.data() + 12) == 0 &&
      (encoding == 1 || encoding == 2) && length % encoding == 0;
  if (!metadata) { wipe(plain.data(), plain.size()); fail(); }
  std::memcpy(out, plain.data() + 16, length);
  wipe(plain.data(), plain.size());
}

extern "C" __attribute__((visibility("hidden"))) void ndkp_cse_recheck_module_v1(
    const ndkp_cse::ModuleV1* module) {
  if (!module || !module->blob || !module->cache || !module->regions ||
      module->total < HeaderSize || module->total > (1u << 28) ||
      module->count < 2 || module->count > (module->total - HeaderSize) / 64) fail();
  initialize(module);
  const Image image = measure(module);
  if (!equal(image.digest, module->blob + 152, 32) ||
      !equal(image.digest, module->cache + 4, 32)) fail();
  // Authenticate cached inputs against the final (unused decoy) record. The
  // generated guard checked pointers; measure authenticated the entire region table.
  const RegionV1* sentinel = module->regions + module->count - 1;
  if (sentinel->out_capacity > MaxCapacity - 16) fail();
  std::vector<uint8_t> scratch(sentinel->out_capacity);
  ndkp_cse_decode_region_v1(scratch.data(), module, sentinel);
  wipe(scratch.data(), scratch.size());
}

#if defined(NDKP_QSEG)
extern "C" void ndkp_qseg_measure(uint8_t code[32], uint8_t actualInputs[48]) {
  Image image{};
  image.anchor = reinterpret_cast<uintptr_t>(ndkp_qseg_image);
  image.regions = reinterpret_cast<uintptr_t>(&ndkp_qseg_measure);
  image.regionsSize = 4;
  if (dl_iterate_phdr(hashImage, &image) || image.matches != 1 || !image.valid) fail();
  std::memcpy(code, image.digest, 32);
  inputs(ndkp_qseg_image, actualInputs);
}
extern "C" void ndkp_qseg_derive(const uint8_t code[32], const uint8_t actualInputs[48], uint8_t key[32]) {
  ndkp_cse::derive(ndkp_qseg_image, code, actualInputs, key);
}
extern "C" bool ndkp_qseg_open(const uint8_t key[32], const uint8_t* aad, size_t an,
                               uint8_t* data, size_t size, const uint8_t tag[16]) {
  const uint8_t nonce[12] = {};
  return ndkp_cse::open(key, nonce, aad, an, data, size, tag);
}
#endif
