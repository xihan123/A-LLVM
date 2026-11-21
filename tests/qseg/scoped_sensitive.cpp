// Signed QSEG fixture: explicit native callers, with optional test-only mmap observation.
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(NDKP_SCOPED_RUNNER)
int main(int argc, char** argv) {
  assert(argc == 4 && std::strlen(argv[3]) == 32);
  const pid_t child = fork(); assert(child >= 0);
  if (!child) {
    std::fprintf(stderr, "SCOPED:%s:CHILD_BEGIN mode=%s\n", argv[3], argv[2]); std::fflush(stderr);
    void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { std::fprintf(stderr, "LOAD_ERROR:%s\n", dlerror()); _exit(2); }
    auto entry = reinterpret_cast<void (*)(const char*, const char*)>(dlsym(library, "ndkp_scoped_test"));
    if (!entry) { std::fprintf(stderr, "LOAD_ERROR:%s\n", dlerror()); _exit(2); }
    entry(argv[2], argv[3]); _exit(0);
  }
  int status = 0; pid_t waited;
  do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  assert(waited == child);
  std::printf("SCOPED:%s:WAIT status=%d exited=%d code=%d signal=%d\n", argv[3], status,
      WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
      WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  return 0;
}
#else
#include <atomic>
#include <sys/mman.h>
#include <thread>
#include <vector>
#include "../../runtime/qseg.h"
#include "../../runtime/sha256.h"
#include "scoped_plan.h"

extern "C" const uint8_t ndkp_scoped_refs[];
namespace {
using Stats = ndkp_qseg_cache_stats_v1;
const char* token = nullptr;
size_t pageSize = 0;
unsigned scans = 0, realUnmaps = 0;
void event(const char* format, ...) {
  char message[1024];
  int prefix = std::snprintf(message, sizeof message, "SCOPED:%s:", token);
  assert(prefix > 0 && size_t(prefix) < sizeof message);
  va_list args; va_start(args, format);
  int count = std::vsnprintf(message + prefix, sizeof message - size_t(prefix), format, args); va_end(args);
  assert(count >= 0 && size_t(prefix) + size_t(count) + 1 < sizeof message);
  size_t bytes = size_t(prefix) + size_t(count); message[bytes++] = '\n';
  for (size_t sent = 0; sent < bytes;) {
    ssize_t n = write(STDERR_FILENO, message + sent, bytes - sent);
    if (n < 0 && errno == EINTR) continue;
    assert(n > 0); sent += size_t(n);
  }
}
size_t mapped(size_t size) { return (size + pageSize - 1) / pageSize * pageSize; }
Stats stats() { Stats value{}; ndkp_qseg_stats_v1(&value); return value; }
void emptyCache() {
  const Stats value = stats();
  assert(!value.active_bytes && !value.idle_bytes && !value.pinned_bytes &&
      !value.peak_resident_bytes && !value.evictions);
}
// Check every page in the saved interval; never read a released pointer.
bool mapping(uintptr_t begin, size_t size, bool absent) {
  FILE* maps = std::fopen("/proc/self/maps", "r"); assert(maps);
  const uintptr_t end = begin + size; assert(end > begin);
  uintptr_t covered = begin; bool overlap = false, readonly = true;
  char line[4096];
  while (std::fgets(line, sizeof line, maps)) {
    unsigned long left, right; char permissions[5]{};
    assert(std::sscanf(line, "%lx-%lx %4s", &left, &right, permissions) == 3);
    if (right <= begin || left >= end) continue;
    overlap = true;
    if (left > covered || std::strcmp(permissions, "r--p")) readonly = false;
    if (right > covered) covered = right;
  }
  assert(!std::ferror(maps) && std::feof(maps)); assert(std::fclose(maps) == 0);
  return absent ? !overlap : readonly && covered >= end;
}
const uint8_t* ref(unsigned index) { assert(index < 2); return ndkp_scoped_refs + index * 24; }
void check(const uint8_t* data, unsigned index) {
  assert(data && !(reinterpret_cast<uintptr_t>(data) % pageSize));
  const auto& resource = Resources[index];
  assert(mapping(reinterpret_cast<uintptr_t>(data), mapped(resource.size), false));
  uint8_t actual[32]; stringarmor::sha2::sha256(data, resource.size, actual);
  assert(!std::memcmp(actual, resource.digest, sizeof actual));
}
#if defined(NDKP_SCOPED_OBSERVER)
struct Observation {
  const char* phase = nullptr;
  unsigned index = 0;
  void* data = nullptr;
  bool enomem = false, rejectPadding = false;
} observation;
#endif
void arm(const char* phase, unsigned index, bool enomem = false, bool rejectPadding = false) {
#if defined(NDKP_SCOPED_OBSERVER)
  assert(!observation.phase && !observation.data);
  observation = {phase, index, nullptr, enomem, rejectPadding};
#else
  assert(!enomem && !rejectPadding); (void)phase; (void)index;
#endif
}
void acquired(const char* phase, const uint8_t* data, unsigned index) {
  check(data, index);
  unsigned paddingValue = 0;
#if defined(NDKP_SCOPED_OBSERVER)
  assert(observation.data == data && observation.index == index);
  paddingValue = 0xa5;
#endif
  const size_t size = Resources[index].size, rounded = mapped(size);
  const volatile uint8_t* bytes = data;
  for (size_t i = size; i < rounded; ++i) assert(bytes[i] == paddingValue);
  event("ACQUIRED phase=%s resource=%u begin=0x%llx bytes=%u mapped=%zu padding=%zu padding_value=%u", phase, index,
      (unsigned long long)reinterpret_cast<uintptr_t>(data), Resources[index].size, rounded, rounded - size, paddingValue);
}
void finalRelease(const char* phase, const uint8_t*& data, unsigned index) {
  const uintptr_t begin = reinterpret_cast<uintptr_t>(data);
  const size_t bytes = mapped(Resources[index].size);
  event("RELEASE_ATTEMPT phase=%s resource=%u begin=0x%llx mapped=%zu", phase, index,
      (unsigned long long)begin, bytes);
  data = nullptr;
  ndkp_qseg_sensitive_release_v1(ref(index));
  assert(mapping(begin, bytes, true));
  event("ABSENT phase=%s resource=%u begin=0x%llx mapped=%zu", phase, index,
      (unsigned long long)begin, bytes);
}
void nested(const uint8_t* owner, unsigned depth) {
  const uint8_t* borrowed = ndkp_qseg_sensitive_acquire_v1(ref(0));
  assert(borrowed == owner); check(borrowed, 0);
  if (depth) nested(owner, depth - 1);
  ndkp_qseg_sensitive_release_v1(ref(0));
  check(owner, 0);
}
void positive() {
  emptyCache();
  assert(mapped(Resources[0].size) < (1u << 20) && Resources[0].size > 65536);
  arm("concurrent", 0);
  const uint8_t* owner = ndkp_qseg_sensitive_acquire_v1(ref(0)); acquired("concurrent", owner, 0);
  nested(owner, 2); event("NESTED leases=3 owner_live=1");
  std::atomic<unsigned> ready{0}, held{0}; std::atomic<bool> go{false}, release{false};
  const uint8_t* pointers[8]{}; std::vector<std::thread> threads;
  for (unsigned i = 0; i < 8; ++i) {
    threads.emplace_back([&, i] {
      ++ready; while (!go.load()) std::this_thread::yield();
      const uint8_t* borrowed = ndkp_qseg_sensitive_acquire_v1(ref(0));
      pointers[i] = borrowed; check(borrowed, 0); ++held;
      while (!release.load()) std::this_thread::yield();
      ndkp_qseg_sensitive_release_v1(ref(0));
    });
  }
  while (ready.load() != 8) std::this_thread::yield();
  go.store(true); while (held.load() != 8) std::this_thread::yield();
  for (auto* pointer : pointers) assert(pointer == owner);
  check(owner, 0); emptyCache();
  release.store(true); for (auto& thread : threads) thread.join();
  check(owner, 0); event("CONCURRENT borrowers=8 same_pointer=1 owner_live_after_release=1");
  finalRelease("concurrent", owner, 0); emptyCache();
  arm("reload", 0); owner = ndkp_qseg_sensitive_acquire_v1(ref(0)); acquired("reload", owner, 0);
  finalRelease("reload", owner, 0); emptyCache();

  arm("mixed", 1);
  const uint8_t* sensitive = ndkp_qseg_sensitive_acquire_v1(ref(1)); acquired("mixed", sensitive, 1);
  const uint8_t* ordinary = ndkp_qseg_acquire_v1(ref(1)); assert(ordinary != sensitive); check(ordinary, 1);
  Stats active = stats(); assert(active.active_bytes == mapped(Resources[1].size) && !active.idle_bytes &&
      !active.pinned_bytes && active.peak_resident_bytes == active.active_bytes && !active.evictions);
  assert(ndkp_qseg_get(ref(1)) == ordinary);
  uint8_t copy[203 + 32]; std::memset(copy, 0xa5, sizeof copy);
  assert(Resources[1].size == 203); ndkp_qseg_copy(copy + 16, ref(1), 0, 203, 1);
  uint8_t digest[32]; stringarmor::sha2::sha256(copy + 16, 203, digest);
  assert(!std::memcmp(digest, Resources[1].digest, sizeof digest));
  for (unsigned i = 0; i < 16; ++i) assert(copy[i] == 0xa5 && copy[219 + i] == 0xa5);
  const uint8_t* inner = ndkp_qseg_sensitive_acquire_v1(ref(1)); assert(inner == sensitive);
  ndkp_qseg_sensitive_release_v1(ref(1)); check(sensitive, 1);
  finalRelease("mixed", sensitive, 1); check(ordinary, 1);
  ndkp_qseg_release_v1(ref(1));
  const Stats pinned = stats(); assert(!pinned.active_bytes && !pinned.idle_bytes && !pinned.evictions &&
      pinned.pinned_bytes == mapped(Resources[1].size) && pinned.peak_resident_bytes == pinned.pinned_bytes);
  assert(!std::memcmp(copy + 16, ordinary, 203));
  arm("mixed-reload", 1); sensitive = ndkp_qseg_sensitive_acquire_v1(ref(1));
  assert(sensitive != ordinary); acquired("mixed-reload", sensitive, 1);
  finalRelease("mixed-reload", sensitive, 1); check(ordinary, 1);
  const Stats final = stats(); assert(!std::memcmp(&pinned, &final, sizeof pinned));
  volatile uint8_t* copied = copy + 16;
  for (unsigned i = 0; i < 203; ++i) copied[i] = 0;
  for (unsigned i = 0; i < 203; ++i) assert(copied[i] == 0);
  for (unsigned i = 0; i < 16; ++i) assert(copy[i] == 0xa5 && copy[219 + i] == 0xa5);
  event("MIXED separate=1 ordinary_pinned=%llu ordinary_peak=%llu copy_bytes=203 copy_wiped=1",
      (unsigned long long)final.pinned_bytes, (unsigned long long)final.peak_resident_bytes);
#if defined(NDKP_SCOPED_OBSERVER)
  assert(scans == 4 && realUnmaps == 4 && !observation.phase && !observation.data);
  event("COMPLETE observer=1 releases=4 scans=%u real_unmaps=%u page=%zu", scans, realUnmaps, pageSize);
#else
  event("COMPLETE observer=0 releases=4 scans=0 real_unmaps=0 page=%zu", pageSize);
#endif
}
}

#if defined(NDKP_SCOPED_OBSERVER)
extern "C" void* __real_mmap(void*, size_t, int, int, int, off_t);
extern "C" int __real_munmap(void*, size_t);
extern "C" void* __wrap_mmap(void* address, size_t size, int prot, int flags, int fd, off_t offset) {
  const bool target = observation.phase && !observation.data && !address &&
      size == Resources[observation.index].size && prot == (PROT_READ | PROT_WRITE) &&
      flags == (MAP_PRIVATE | MAP_ANONYMOUS) && fd == -1 && offset == 0;
  if (target && observation.enomem) {
    event("MMAP_ENOMEM phase=%s bytes=%zu hits=1 errno=%d", observation.phase, size, ENOMEM);
    errno = ENOMEM; return MAP_FAILED;
  }
  void* result = __real_mmap(address, size, prot, flags, fd, offset);
  if (target) {
    assert(result != MAP_FAILED && !(reinterpret_cast<uintptr_t>(result) % pageSize));
    observation.data = result;
    std::memset(result, 0xa5, mapped(size));
    event("POISON phase=%s resource=%u begin=0x%llx bytes=%zu mapped=%zu padding=%zu value=165",
        observation.phase, observation.index, (unsigned long long)reinterpret_cast<uintptr_t>(result),
        size, mapped(size), mapped(size) - size);
  }
  return result;
}
extern "C" int __wrap_munmap(void* data, size_t size) {
  if (data != observation.data || !observation.phase) return __real_munmap(data, size);
  const size_t payload = Resources[observation.index].size;
  assert(size == mapped(payload) && size > payload);
  auto* bytes = static_cast<volatile uint8_t*>(data);
  if (observation.rejectPadding) { bytes[size - 1] = 0x7b; event("INJECT_PADDING offset=%zu value=123", size - 1); }
  size_t nonzero = 0, firstBad = size; unsigned firstValue = 0;
  for (size_t i = 0; i < size; ++i) {
    const uint8_t value = bytes[i];
    if (value) { if (!nonzero) { firstBad = i; firstValue = value; } ++nonzero; }
  }
  ++scans;
  event("ZERO_SCAN phase=%s resource=%u begin=0x%llx mapped=%zu checked=%zu padding=%zu nonzero=%zu first=%zu value=%u",
      observation.phase, observation.index, (unsigned long long)reinterpret_cast<uintptr_t>(data),
      size, size, size - payload, nonzero, firstBad, firstValue);
  if (nonzero) { event("REJECT_NONZERO real_unmaps=%u code=123", realUnmaps); _exit(123); }
  const int result = __real_munmap(data, size); ++realUnmaps;
  event("REAL_UNMAP phase=%s resource=%u begin=0x%llx mapped=%zu result=%d", observation.phase,
      observation.index, (unsigned long long)reinterpret_cast<uintptr_t>(data), size, result);
  assert(!result); observation.data = nullptr; observation.phase = nullptr;
  return result;
}
#endif

extern "C" __attribute__((visibility("default"))) void ndkp_scoped_test(const char* mode, const char* runToken) {
  token = runToken; const long page = sysconf(_SC_PAGESIZE);
  assert(page > 0 && !(page & (page - 1))); pageSize = size_t(page);
  event("AUTH_ATTEMPT apk_verify=0"); ndkp_qseg_verify(); event("AUTH_OK");
  if (!std::strcmp(mode, "positive")) { positive(); return; }
  if (!std::strcmp(mode, "enomem")) {
    arm("warmup", 1); const uint8_t* warm = ndkp_qseg_sensitive_acquire_v1(ref(1)); acquired("warmup", warm, 1);
    finalRelease("warmup", warm, 1); emptyCache();
    event("ATTEMPT mode=enomem"); arm("enomem", 0, true);
    ndkp_qseg_sensitive_acquire_v1(ref(0)); assert(false);
  }
  if (!std::strcmp(mode, "auth")) {
    event("ATTEMPT mode=auth");
    const uint8_t* data = ndkp_qseg_sensitive_acquire_v1(ref(0)); check(data, 0);
    ndkp_qseg_sensitive_release_v1(ref(0)); event("AUTH_BORROW_OK"); return;
  }
  arm("negative", 0, false, !std::strcmp(mode, "reject-padding"));
  const uint8_t* data = ndkp_qseg_sensitive_acquire_v1(ref(0)); acquired("negative", data, 0);
  if (!std::strcmp(mode, "write")) {
    event("ATTEMPT mode=write"); *const_cast<volatile uint8_t*>(data) ^= 1; assert(false);
  }
  if (!std::strcmp(mode, "reject-padding")) {
    finalRelease("negative", data, 0); assert(false);
  }
  finalRelease("negative", data, 0); event("ATTEMPT mode=%s", mode);
  if (!std::strcmp(mode, "double-release")) ndkp_qseg_sensitive_release_v1(ref(0));
  else if (!std::strcmp(mode, "invalid-ref")) {
    uint8_t fake[24]; std::memcpy(fake, ref(0), sizeof fake); ndkp_qseg_sensitive_acquire_v1(fake);
  } else assert(false);
  assert(false);
}
#endif
