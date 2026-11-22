// Link-only observer: production acquisition, crypto, wiping and syscalls remain real.
#include "cse_region.h"
#include "scoped_fixture.h"
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
using ndkp_cse::ModuleV1;
using ndkp_cse::RegionV1;
using ndkp_cse::ScopedRegionV1;
struct Mapping {
  uint8_t* data;
  size_t size, capacity;
  ScopedRegionV1* lease;
  const RegionV1* region;
  const uint8_t* blob;
  unsigned ordinal, role = 0, detail = 0;
  bool readonly = false, published = false, unmapped = false, retired = false;
};
struct Pending {
  const ModuleV1* module = nullptr;
  const RegionV1* region = nullptr;
  ScopedRegionV1* lease = nullptr;
};
Mapping mappings[64]{};
unsigned mappedCount = 0, publishedCount = 0, retiredCount = 0, peakActive = 0;
unsigned read8Count = 0, read16Count = 0;
int defect = 0;
bool baseline = false, roChecked = false;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t barrier;
thread_local Pending pending;
thread_local unsigned activeStack[16];
thread_local unsigned activeCount = 0;

[[noreturn]] void reject(const char* reason) {
  std::printf("observer-reject %s\n", reason);
  std::fflush(stdout);
  _exit(90);
}
void require(bool value, const char* reason) { if (!value) reject(reason); }
void lock() { require(pthread_mutex_lock(&mutex) == 0, "mutex-lock"); }
void unlock() { require(pthread_mutex_unlock(&mutex) == 0, "mutex-unlock"); }
unsigned current(uint8_t* data) {
  for (unsigned i = mappedCount; i; --i)
    if (mappings[i - 1].data == data && !mappings[i - 1].unmapped) return i - 1;
  reject("unknown-live-mapping");
}
bool permissions(const void* data, size_t size, bool executable) {
  FILE* file = std::fopen("/proc/self/maps", "r");
  if (!file) return false;
  uintptr_t covered = reinterpret_cast<uintptr_t>(data), end = covered + size;
  char line[1024];
  bool valid = true;
  while (covered < end && std::fgets(line, sizeof line, file)) {
    unsigned long long first, last;
    char access[5]{};
    if (std::sscanf(line, "%llx-%llx %4s", &first, &last, access) != 3) { valid = false; break; }
    if (covered >= first && covered < last) {
      if (access[0] != 'r' || access[1] != '-' || access[2] != (executable ? 'x' : '-')) {
        valid = false; break;
      }
      covered = last < end ? uintptr_t(last) : end;
    }
  }
  valid = valid && covered == end && !std::ferror(file);
  std::fclose(file);
  return valid;
}
void readOnlyWriteFault(uint8_t* data) {
  pid_t child = fork();
  require(child >= 0, "ro-fork");
  if (!child) {
    std::signal(SIGSEGV, SIG_DFL);
    std::signal(SIGBUS, SIG_DFL);
    *reinterpret_cast<volatile uint8_t*>(data) ^= 1;
    _exit(0);
  }
  int status = 0;
  pid_t waited;
  do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  require(waited == child && WIFSIGNALED(status) &&
          (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS), "read-only-write-did-not-fault");
  std::printf("ro-write-fault signal=%d\n", WTERMSIG(status));
  roChecked = true;
}
uint32_t hash8(const char* data, size_t bytes) {
  uint32_t value = 2166136261u;
  for (size_t i = 0; i < bytes; ++i) value = (value ^ static_cast<uint8_t>(data[i])) * 16777619u;
  return value;
}
void verifyStatic(const char* data, const char* first) {
  require(data == first && hash8(data, ScopedBytes) == ScopedByteHash, "static-storage-changed");
  lock();
  for (unsigned i = 0; i < mappedCount; ++i) {
    uintptr_t pointer = reinterpret_cast<uintptr_t>(data), begin = reinterpret_cast<uintptr_t>(mappings[i].data);
    require(pointer < begin || pointer - begin >= mappings[i].size, "static-storage-is-a-lease");
  }
  unlock();
}
}

extern "C" {
void* __real_mmap(void*, size_t, int, int, int, off_t);
int __real_mprotect(void*, size_t, int);
int __real_munmap(void*, size_t);
uint8_t* __real_ndkp_cse_acquire_region_v1(const ModuleV1*, const RegionV1*, ScopedRegionV1*);
void __real_ndkp_cse_release_region_v1(ScopedRegionV1*);

uint8_t* __wrap_ndkp_cse_acquire_region_v1(const ModuleV1* module, const RegionV1* region,
                                         ScopedRegionV1* lease) {
  require(!pending.lease && lease && !lease->data && !lease->mapped && lease->state == 0, "lease-not-fresh");
  std::printf("acquire-attempt module=%p region=%p lease=%p\n", static_cast<const void*>(module),
              static_cast<const void*>(region), static_cast<void*>(lease));
  std::fflush(stdout);
  if (!module || !region) {
    uint8_t* result = __real_ndkp_cse_acquire_region_v1(module, region, lease);
    (void)result;
    reject("invalid-guard-returned");
  }
  uintptr_t base = reinterpret_cast<uintptr_t>(module->regions), address = reinterpret_cast<uintptr_t>(region);
  require(module->blob && module->cache && module->regions && module->count >= 2 &&
          address >= base && address - base < size_t(module->count) * sizeof(RegionV1) &&
          (address - base) % sizeof(RegionV1) == 0, "region-not-table-member");
  require(permissions(module->regions, size_t(module->count) * sizeof(RegionV1), true), "region-table-not-rx");
  pending = {module, region, lease};
  uint8_t* data = __real_ndkp_cse_acquire_region_v1(module, region, lease);
  lock();
  unsigned index = current(data);
  Mapping& mapping = mappings[index];
  require(mapping.lease == lease && mapping.readonly && !mapping.published && lease->data == data &&
          lease->mapped == mapping.size && lease->state == 1, "bad-publish");
  require(activeCount < sizeof activeStack / sizeof *activeStack, "lease-stack-overflow");
  activeStack[activeCount++] = index;
  mapping.published = true;
  ++publishedCount;
  unsigned live = 0;
  for (unsigned i = 0; i < mappedCount; ++i) live += mappings[i].published && !mappings[i].unmapped;
  if (live > peakActive) peakActive = live;
  std::printf("publish ordinal=%u data=%p lease=%p depth=%u tid=%lu region-rx=1\n", mapping.ordinal,
              static_cast<void*>(data), static_cast<void*>(lease), activeCount,
              static_cast<unsigned long>(pthread_self()));
  unlock();
  pending = {};
  return data;
}

void* __wrap_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
  if (!pending.lease) return __real_mmap(address, length, protection, flags, fd, offset);
  lock();
  size_t page = size_t(sysconf(_SC_PAGESIZE));
  require(page && !address && protection == (PROT_READ | PROT_WRITE) &&
          flags == (MAP_PRIVATE | MAP_ANONYMOUS) && fd == -1 && offset == 0 &&
          length >= pending.region->out_capacity && length % page == 0, "bad-anonymous-mapping-request");
  void* result = __real_mmap(address, length, protection, flags, fd, offset);
  require(result != MAP_FAILED && reinterpret_cast<uintptr_t>(result) % page == 0, "real-mmap-failed");
  require(mappedCount < sizeof mappings / sizeof *mappings, "mapping-record-overflow");
  for (unsigned i = 0; i < mappedCount; ++i)
    require(mappings[i].unmapped || mappings[i].data != result, "concurrent-leases-share-data");
  unsigned ordinal = unsigned(pending.region - pending.module->regions);
  Mapping& mapping = mappings[mappedCount++];
  mapping.data = static_cast<uint8_t*>(result);
  mapping.size = length;
  mapping.capacity = pending.region->out_capacity;
  mapping.lease = pending.lease;
  mapping.region = pending.region;
  mapping.blob = pending.module->blob;
  mapping.ordinal = ordinal;
  std::printf("real-mmap ordinal=%u data=%p mapped=%zu capacity=%zu page=%zu\n", ordinal, result,
              length, mapping.capacity, page);
  std::fflush(stdout);
  unlock();
  return result;
}

int __wrap_mprotect(void* data, size_t length, int protection) {
  lock();
  Mapping& mapping = mappings[current(static_cast<uint8_t*>(data))];
  require(length == mapping.size, "partial-protection");
  int result;
  if (protection == PROT_READ) {
    require(!mapping.readonly && !mapping.published && mapping.capacity < length, "bad-read-only-transition");
    std::memset(mapping.data + mapping.capacity, 0xa7, length - mapping.capacity);
    require(mapping.data[length - 1] == 0xa7, "padding-prefill-failed");
    std::printf("padding-nonzero bytes=%zu last=%u\n", length - mapping.capacity, mapping.data[length - 1]);
    result = defect == 3 ? 0 : __real_mprotect(data, length, protection);
    require(result == 0, "real-read-only-protection-failed");
    if (!roChecked) readOnlyWriteFault(mapping.data);
    require(permissions(data, length, false), "mapping-not-read-only");
    mapping.readonly = true;
  } else {
    require(protection == (PROT_READ | PROT_WRITE) && mapping.readonly && mapping.published, "bad-wipe-transition");
    result = __real_mprotect(data, length, protection);
    require(result == 0, "real-write-protection-failed");
    mapping.readonly = false;
  }
  std::printf("real-mprotect protection=%d data=%p bytes=%zu\n", protection, data, length);
  unlock();
  return result;
}

int __wrap_munmap(void* data, size_t length) {
  lock();
  Mapping& mapping = mappings[current(static_cast<uint8_t*>(data))];
  require(length == mapping.size && !mapping.readonly && mapping.published, "bad-unmap-transition");
  if (defect == 1) mapping.data[length - 1] = 0xa7;
  const volatile uint8_t* bytes = mapping.data;
  for (size_t i = 0; i < length; ++i) require(bytes[i] == 0, "whole-mapping-wipe-missed-a-byte");
  std::printf("whole-mapping-zero bytes=%zu capacity=%zu\n", length, mapping.capacity);
  int result = defect == 2 ? 0 : __real_munmap(data, length);
  require(result == 0, "real-munmap-failed");
  unsigned char residency[128]{};
  size_t page = size_t(sysconf(_SC_PAGESIZE));
  require(page && length / page <= sizeof residency, "mincore-buffer-bound");
  errno = 0;
  int resident = mincore(data, length, residency), error = errno;
  require(resident == -1 && error == ENOMEM, "mapping-still-mapped-after-release");
  mapping.unmapped = true;
  std::printf("real-munmap data=%p bytes=%zu mincore=-1 errno=%d\n", data, length, error);
  unlock();
  return result;
}

void __wrap_ndkp_cse_release_region_v1(ScopedRegionV1* lease) {
  lock();
  require(activeCount && mappings[activeStack[activeCount - 1]].lease == lease, "release-order-is-not-reverse");
  unsigned index = activeStack[activeCount - 1];
  Mapping& mapping = mappings[index];
  require(lease->state == 1 && lease->data == mapping.data && lease->mapped == mapping.size, "release-not-active");
  std::printf("release ordinal=%u lease=%p depth=%u\n", mapping.ordinal, static_cast<void*>(lease), activeCount);
  unlock();
  if (defect != 4) __real_ndkp_cse_release_region_v1(lease);
  lock();
  require(mapping.unmapped && !lease->data && !lease->mapped && lease->state == 2, "lease-not-retired");
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(lease);
  for (size_t i = 0; i < sizeof *lease; ++i)
    require(bytes[i] == (i == offsetof(ScopedRegionV1, state) ? 2 : 0), "retired-lease-padding-not-wiped");
  mapping.retired = true;
  ++retiredCount;
  --activeCount;
  std::printf("retire ordinal=%u data=0 mapped=0 state=2\n", mapping.ordinal);
  unlock();
}

uint32_t scoped_observe8(const char* __attribute__((noescape)) data, size_t bytes,
                         unsigned role, unsigned detail) noexcept {
  lock();
  if (!baseline) {
    require(activeCount, "business-read-without-a-lease");
    Mapping& mapping = mappings[activeStack[activeCount - 1]];
    // Multi acquires two regions before either read, so locate the byte region.
    if (role == 0) {
      unsigned index = current(reinterpret_cast<uint8_t*>(const_cast<char*>(data)));
      Mapping& selected = mappings[index];
      require(selected.published && selected.readonly && selected.capacity >= bytes, "byte-region-not-live");
    } else {
      require(mapping.data == reinterpret_cast<const uint8_t*>(data) && mapping.readonly &&
              mapping.capacity >= bytes, "nested-region-not-live");
      if (role == 2 || role == 4) { mapping.role = role; mapping.detail = detail; }
      if (role == 3 || role == 5)
        require(mapping.role == role - 1 && mapping.detail == detail, "child-release-damaged-parent");
    }
    require(permissions(data, bytes, false), "business-mapping-not-read-only");
  }
  ++read8Count;
  uint32_t value = hash8(data, bytes);
  require(bytes == ScopedBytes && value == ScopedByteHash, "byte-plaintext-mismatch");
  std::printf("business-read8 role=%u detail=%u depth=%u hash=%08x\n", role, detail, activeCount, value);
  unlock();
  return value;
}
uint32_t scoped_observe16(const char16_t* __attribute__((noescape)) data, size_t words) noexcept {
  lock();
  if (!baseline) {
    Mapping& mapping = mappings[current(reinterpret_cast<uint8_t*>(const_cast<char16_t*>(data)))];
    require(mapping.published && mapping.readonly && mapping.capacity >= words * 2 &&
            permissions(data, words * 2, false), "word-region-not-live");
  }
  uint32_t value = 2166136261u;
  for (size_t i = 0; i < words; ++i) {
    value = (value ^ uint8_t(data[i])) * 16777619u;
    value = (value ^ uint8_t(data[i] >> 8)) * 16777619u;
  }
  require(words == ScopedWords && value == ScopedWordHash, "utf16-plaintext-mismatch");
  ++read16Count;
  std::printf("business-read16 words=%zu hash=%08x\n", words, value);
  unlock();
  return value;
}
int scoped_thread_barrier(unsigned worker) noexcept {
  int result = pthread_barrier_wait(&barrier);
  require(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "thread-barrier-enter");
  lock();
  if (!baseline) {
    unsigned live = 0;
    for (unsigned i = 0; i < mappedCount; ++i)
      live += mappings[i].published && !mappings[i].unmapped && mappings[i].role == 4;
    require(live == 2, "thread-leases-not-simultaneously-live");
    if (!worker) std::puts("thread-leases distinct=1 simultaneously-live=2");
  }
  unlock();
  result = pthread_barrier_wait(&barrier);
  require(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "thread-barrier-leave");
  return 0;
}

int run_scoped(int mode) noexcept {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  defect = mode;
  baseline = mode == 100;
  const char* saved = scoped_static_value();
  verifyStatic(saved, saved);
  for (int branch = -1; branch <= 1; ++branch) {
    unsigned before = mappedCount;
    require(scoped_multi(branch) == 0, "multi-return-result");
    require(baseline || mappedCount - before == 2, "multi-region-acquisitions");
    verifyStatic(scoped_static_value(), saved);
  }
  unsigned before = mappedCount;
  unsigned index = 7;
  require(scoped_unused_driver(index) == static_cast<unsigned char>(saved[index]), "unused-driver-result");
  require(baseline || mappedCount - before == 2, "unused-caller-call-was-removed-or-merged");
  std::printf("unused-caller mapping-events=%u\n", mappedCount - before);
  before = mappedCount;
  require(scoped_recursive(2) == 0, "recursive-result");
  require(baseline || mappedCount - before == 3, "recursion-lifetimes-merged");
  verifyStatic(scoped_static_value(), saved);
  require(pthread_barrier_init(&barrier, nullptr, 2) == 0, "thread-barrier-init");
  int results[2] = {-1, -1};
  std::thread first([&] { results[0] = scoped_thread(0); });
  std::thread second([&] { results[1] = scoped_thread(1); });
  first.join(); second.join();
  require(pthread_barrier_destroy(&barrier) == 0 && !results[0] && !results[1], "thread-result");
  verifyStatic(scoped_static_value(), saved);
  require(!activeCount && mappedCount == publishedCount && publishedCount == retiredCount, "outstanding-leases");
  require(baseline ? mappedCount == 0 : mappedCount == 13 && peakActive >= 3 && roChecked, "lifecycle-counts");
  require(read8Count == 12 && read16Count == 2, "business-read-counts");
  std::printf("lifecycle mapped=%u published=%u retired=%u peak=%u read8=%u read16=%u static-stable=1\n",
              mappedCount, publishedCount, retiredCount, peakActive, read8Count, read16Count);
  return 0;
}
}
