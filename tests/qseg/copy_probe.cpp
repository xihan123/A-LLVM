// Test-owned buffers are deliberately separate from CSE globals and Java objects.
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "../../runtime/qseg.h"
#include "../../runtime/sha256.h"
#include "copy_plan.h"

namespace {
constexpr size_t ResourceCount = sizeof Resources / sizeof Resources[0];
constexpr size_t SliceCount = sizeof Slices / sizeof Slices[0];
constexpr size_t GuardSize = 16, ThreadCount = 8;
constexpr uint8_t Canary = 0xa5;
constexpr uint64_t IdleBudget = 1u << 20;
using Stats = ndkp_qseg_cache_stats_v1;
using Copy = void (*)(uint8_t*, const uint8_t*, uint32_t, uint32_t, uint32_t);
size_t mapped(size_t size) { return (size + ExpectedPageSize - 1) / ExpectedPageSize * ExpectedPageSize; }
void digest(const uint8_t* data, size_t size, const uint8_t expected[32]) {
  uint8_t actual[32]; stringarmor::sha2::sha256(data, size, actual);
  assert(!std::memcmp(actual, expected, sizeof actual));
}
bool mapping(uintptr_t begin, size_t size, bool absent) {
  FILE* maps = std::fopen("/proc/self/maps", "r"); assert(maps);
  const uintptr_t end = begin + size; assert(end > begin);
  uintptr_t covered = begin; bool overlaps = false, readonly = true;
  char line[4096];
  while (std::fgets(line, sizeof line, maps)) {
    unsigned long left, right; char permissions[5]{};
    if (std::sscanf(line, "%lx-%lx %4s", &left, &right, permissions) != 3 || right <= begin || left >= end) continue;
    overlaps = true;
    if (left > covered || std::strcmp(permissions, "r--p")) readonly = false;
    if (right > covered) covered = right;
  }
  std::fclose(maps);
  return absent ? !overlaps : readonly && covered >= end;
}
void resource(const uint8_t* data, const ProbeResource& expected) {
  assert(data && !(reinterpret_cast<uintptr_t>(data) % ExpectedPageSize));
  assert(mapping(reinterpret_cast<uintptr_t>(data), mapped(expected.size), false));
  digest(data, expected.size, expected.digest);
}
void no_leases(const Stats& value) {
  assert(!value.active_bytes && !value.pinned_bytes && value.idle_bytes <= IdleBudget);
}
struct Guarded {
  std::vector<uint8_t> storage;
  size_t size;
  explicit Guarded(size_t count) : storage(count + 2 * GuardSize, Canary), size(count) {}
  uint8_t* data() { return storage.data() + GuardSize; }
  void guards() const {
    for (size_t i = 0; i < GuardSize; ++i)
      assert(storage[i] == Canary && storage[GuardSize + size + i] == Canary);
  }
  void check(const uint8_t expected[32]) { guards(); digest(data(), size, expected); }
  void wipe() {
    volatile uint8_t* bytes = data();
    for (size_t i = 0; i < size; ++i) bytes[i] = 0;
    for (size_t i = 0; i < size; ++i) assert(bytes[i] == 0);
    guards();
  }
};
void print_stats(const char* label, const Stats& s, bool comma = true) {
  std::printf("\"%s\":{\"active\":%llu,\"idle\":%llu,\"pinned\":%llu,\"peak\":%llu,\"evictions\":%llu}%s",
      label, (unsigned long long)s.active_bytes, (unsigned long long)s.idle_bytes,
      (unsigned long long)s.pinned_bytes, (unsigned long long)s.peak_resident_bytes,
      (unsigned long long)s.evictions, comma ? "," : "");
}
}

int main(int argc, char** argv) {
  assert(argc == 3 && static_cast<uint64_t>(sysconf(_SC_PAGESIZE)) == ExpectedPageSize);
  assert(ResourceCount > 1 && Resources[0].kind == 2 && Resources[0].size == 203 && SliceCount == 6);
  uint64_t pressure_bytes = 0;
  for (size_t i = 1; i < ResourceCount; ++i) {
    assert(Resources[i].kind == 1); pressure_bytes += mapped(Resources[i].size);
  }
  assert(pressure_bytes > IdleBudget);
  void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) { std::fprintf(stderr, "%s\n", dlerror()); return 2; }
  void* onload = dlsym(library, "JNI_OnLoad");
  Dl_info info{}; assert(onload && dladdr(onload, &info));
  const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
  assert(reinterpret_cast<uintptr_t>(onload) == base + Offset_JNI_OnLoad);
  for (const auto& span : ExecutableSpans)
    digest(reinterpret_cast<const uint8_t*>(base + span.address), span.size, span.digest);
  auto copy = reinterpret_cast<Copy>(base + Offset_ndkp_qseg_copy);
  auto acquire = reinterpret_cast<const uint8_t* (*)(const uint8_t*)>(base + Offset_ndkp_qseg_acquire_v1);
  auto release = reinterpret_cast<void (*)(const uint8_t*)>(base + Offset_ndkp_qseg_release_v1);
  auto stats = reinterpret_cast<void (*)(Stats*)>(base + Offset_ndkp_qseg_stats_v1);
  auto ref = [&](size_t index) {
    const auto& expected = Resources[index];
    const auto* descriptor = reinterpret_cast<const uint8_t*>(base + expected.address);
    uint32_t size, kind; std::memcpy(&size, descriptor + 16, 4); std::memcpy(&kind, descriptor + 20, 4);
    assert(!std::memcmp(descriptor, expected.id, 16) && size == expected.size && kind == expected.kind);
    return descriptor;
  };
  const auto* target_ref = ref(0);
  auto checked_copy = [&](Guarded& out, const ProbeSlice& slice) {
    assert(out.size == slice.size);
    copy(out.data(), target_ref, slice.offset, slice.size, slice.encoding);
    out.check(slice.digest);
    Stats after{}; stats(&after); no_leases(after);
  };
  Stats initial{}; stats(&initial);
  assert(!initial.active_bytes && !initial.idle_bytes && !initial.pinned_bytes);

  if (std::strcmp(argv[2], "positive")) {
    // An authenticated valid copy must succeed in this same fresh process first.
    Guarded warmup(Resources[0].size); checked_copy(warmup, Slices[0]);
    uint8_t* out = warmup.data(); const uint8_t* descriptor = target_ref;
    uint32_t offset = 0, length = 1, encoding = 1;
    if (!std::strcmp(argv[2], "null-out")) out = nullptr;
    else if (!std::strcmp(argv[2], "kind1")) descriptor = ref(1);
    else if (!std::strcmp(argv[2], "encoding0")) encoding = 0;
    else if (!std::strcmp(argv[2], "encoding3")) encoding = 3;
    else if (!std::strcmp(argv[2], "odd-length")) encoding = 2;
    else if (!std::strcmp(argv[2], "offset")) { offset = Resources[0].size + 1; length = 0; }
    else if (!std::strcmp(argv[2], "length")) { offset = Resources[0].size; length = 1; }
    else if (!std::strcmp(argv[2], "length-max")) length = UINT32_MAX;
    else return 3;
    std::printf("case=%s valid-copy=verified invalid-copy=attempt\n", argv[2]); std::fflush(stdout);
    copy(out, descriptor, offset, length, encoding);
    return 4;
  }

  std::vector<Guarded> copies; copies.reserve(SliceCount);
  for (const auto& slice : Slices) copies.emplace_back(slice.size);
  std::vector<Guarded> concurrent; concurrent.reserve(ThreadCount);
  for (size_t i = 0; i < ThreadCount; ++i) concurrent.emplace_back(Resources[0].size);
  Guarded restored(Resources[0].size);
  std::vector<std::thread> threads; threads.reserve(ThreadCount);
  for (size_t i = 0; i < SliceCount; ++i) checked_copy(copies[i], Slices[i]);
  Stats copied{}, threaded{}, acquired{}, released{}, reclaimed{}, reloaded{}, final{};
  stats(&copied); no_leases(copied); assert(copied.idle_bytes == mapped(Resources[0].size));
  for (size_t i = 0; i < ThreadCount; ++i)
    for (size_t j = i + 1; j < ThreadCount; ++j) {
      const uintptr_t left = reinterpret_cast<uintptr_t>(concurrent[i].storage.data());
      const uintptr_t right = reinterpret_cast<uintptr_t>(concurrent[j].storage.data());
      assert(left + concurrent[i].storage.size() <= right || right + concurrent[j].storage.size() <= left);
    }
  std::atomic<bool> go{false}; std::atomic<size_t> ready{0};
  for (size_t i = 0; i < ThreadCount; ++i)
    threads.emplace_back([&, i] { ++ready; while (!go.load()) {} checked_copy(concurrent[i], Slices[0]); });
  while (ready.load() != ThreadCount) {}
  go.store(true); for (auto& thread : threads) thread.join();
  stats(&threaded); no_leases(threaded);
  const uint8_t* source = acquire(target_ref); resource(source, Resources[0]);
  stats(&acquired); assert(acquired.active_bytes == mapped(Resources[0].size) && !acquired.pinned_bytes);
  const uintptr_t old_begin = reinterpret_cast<uintptr_t>(source);
  const size_t old_size = mapped(Resources[0].size);
  source = nullptr;
  release(target_ref); // Only integer interval observations follow this release.
  stats(&released); no_leases(released);
  assert(released.idle_bytes == old_size && mapping(old_begin, old_size, false));
  bool absent = false, absent_after_acquire = false;
  size_t pressure_accesses = 0;
  for (size_t i = 1; i < ResourceCount; ++i) {
    const uint8_t* other = acquire(ref(i));
    absent_after_acquire = mapping(old_begin, old_size, true);
    resource(other, Resources[i]);
    release(ref(i));
    const bool after_release = mapping(old_begin, old_size, true);
    assert(!absent_after_acquire || after_release);
    ++pressure_accesses;
    absent = after_release;
    if (absent) break; // Stop before a later allocation could reuse the interval.
  }
  assert(absent && pressure_accesses);
  stats(&reclaimed); no_leases(reclaimed); assert(reclaimed.evictions > released.evictions);
  for (size_t i = 0; i < SliceCount; ++i) copies[i].check(Slices[i].digest);
  for (auto& out : concurrent) out.check(Resources[0].digest);
  checked_copy(restored, Slices[0]);
  stats(&reloaded); no_leases(reloaded);
  for (auto& out : copies) out.wipe();
  for (auto& out : concurrent) out.wipe();
  restored.wipe();
  stats(&final); no_leases(final);
  std::printf("{\"checkedSlices\":%zu,\"concurrentCopies\":%zu,\"independentBuffers\":true,"
      "\"copyReturnsNoLease\":true,\"allCanariesIntact\":true,\"zeroLengthUnchanged\":true,"
      "\"oddOffsetAllowed\":true,\"sourceFullDigest\":true,\"sourceReadonlyAfterRelease\":true,"
      "\"oldSourceBegin\":\"0x%llx\",\"oldSourceMappedBytes\":%zu,\"pressureAccesses\":%zu,"
      "\"absenceFirstObservedAfter\":\"%s\",\"sourceIntervalAbsentBeforeReload\":true,"
      "\"retainedCopyDigestAfterSourceReclaim\":true,\"reloadCopyDigest\":true,"
      "\"ownBuffersWipedReadback\":true,\"wipedBufferCount\":%zu,\"threadBufferAddresses\":[",
      SliceCount, ThreadCount, (unsigned long long)old_begin, old_size, pressure_accesses,
      absent_after_acquire ? "acquire" : "release", SliceCount + ThreadCount + 1);
  for (size_t i = 0; i < ThreadCount; ++i)
    std::printf("%s\"0x%llx\"", i ? "," : "", (unsigned long long)reinterpret_cast<uintptr_t>(concurrent[i].data()));
  std::printf("],\"stats\":{");
  print_stats("initial", initial); print_stats("copied", copied); print_stats("concurrent", threaded);
  print_stats("sourceAcquired", acquired); print_stats("sourceReleased", released);
  print_stats("sourceReclaimed", reclaimed); print_stats("reloaded", reloaded); print_stats("final", final, false);
  std::puts("}}");
  return 0;
}
