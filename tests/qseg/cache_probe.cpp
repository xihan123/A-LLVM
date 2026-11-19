// Hidden offsets and expected hashes come from the same authenticated fixture.
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
#include "cache_plan.h"

namespace {
constexpr uint64_t IdleBudget = 1u << 20;
constexpr size_t ResourceCount = sizeof Resources / sizeof Resources[0];
using Stats = ndkp_qseg_cache_stats_v1;
size_t mapped(size_t size) { return (size + ExpectedPageSize - 1) / ExpectedPageSize * ExpectedPageSize; }
void digest(const uint8_t* data, size_t size, const uint8_t expected[32]) {
  uint8_t actual[32]; stringarmor::sha2::sha256(data, size, actual);
  assert(!std::memcmp(actual, expected, sizeof actual));
}
// Check the complete interval, including page padding; adjacent maps may coalesce.
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
void target(const uint8_t* data) {
  resource(data, Resources[0]);
  for (const auto& chunk : TargetChunks) digest(data + chunk.offset, chunk.size, chunk.digest);
}
void print_stats(const char* label, const Stats& s, bool comma = true) {
  std::printf("\"%s\":{\"active\":%llu,\"idle\":%llu,\"pinned\":%llu,\"peak\":%llu,\"evictions\":%llu}%s",
      label, (unsigned long long)s.active_bytes, (unsigned long long)s.idle_bytes,
      (unsigned long long)s.pinned_bytes, (unsigned long long)s.peak_resident_bytes,
      (unsigned long long)s.evictions, comma ? "," : "");
}
}

int main(int argc, char** argv) {
  assert(argc == 3 && (!std::strcmp(argv[2], "read") || !std::strcmp(argv[2], "write")));
  assert(static_cast<uint64_t>(sysconf(_SC_PAGESIZE)) == ExpectedPageSize);
  assert(ResourceCount > 1 && Resources[0].size > 65536 && mapped(Resources[0].size) <= IdleBudget);
  uint64_t pressure = 0;
  for (size_t i = 1; i < ResourceCount; ++i) pressure += mapped(Resources[i].size);
  assert(pressure > IdleBudget);
  void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) { std::fprintf(stderr, "%s\n", dlerror()); return 2; }
  void* onload = dlsym(library, "JNI_OnLoad");
  Dl_info info{}; assert(onload && dladdr(onload, &info));
  const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
  assert(reinterpret_cast<uintptr_t>(onload) == base + Offset_JNI_OnLoad);
  for (const auto& span : ExecutableSpans)
    digest(reinterpret_cast<const uint8_t*>(base + span.address), span.size, span.digest);
  auto acquire = reinterpret_cast<const uint8_t* (*)(const uint8_t*)>(base + Offset_ndkp_qseg_acquire_v1);
  auto release = reinterpret_cast<void (*)(const uint8_t*)>(base + Offset_ndkp_qseg_release_v1);
  auto stats = reinterpret_cast<void (*)(Stats*)>(base + Offset_ndkp_qseg_stats_v1);
  auto ref = [&](size_t index) {
    const auto& expected = Resources[index];
    const auto* descriptor = reinterpret_cast<const uint8_t*>(base + expected.address);
    uint32_t size, kind; std::memcpy(&size, descriptor + 16, 4); std::memcpy(&kind, descriptor + 20, 4);
    assert(!std::memcmp(descriptor, expected.id, 16) && size == expected.size && kind == 1);
    return descriptor;
  };
  Stats initial{}, acquired{}, held{}, released{}, reclaimed{}, reloaded{}, final{};
  stats(&initial); assert(!initial.active_bytes && !initial.idle_bytes && !initial.pinned_bytes);
  const auto* target_ref = ref(0);
  std::atomic<bool> go{false}; std::atomic<unsigned> ready{0}; const uint8_t* results[8]{};
  std::vector<std::thread> threads;
  for (unsigned i = 0; i < 8; ++i)
    threads.emplace_back([&, i] { ++ready; while (!go.load()) {} results[i] = acquire(target_ref); });
  while (ready.load() != 8) {}
  go.store(true); for (auto& thread : threads) thread.join();
  const uint8_t* data = acquire(target_ref); // Nine paired leases; keep this one through pressure.
  for (auto* result : results) assert(result && result == data);
  target(data);
  if (!std::strcmp(argv[2], "write")) {
    std::puts("readonly=verified write=attempt"); std::fflush(stdout);
    *const_cast<volatile uint8_t*>(data) ^= 1;
    return 3;
  }
  for (unsigned i = 0; i < 8; ++i) release(target_ref);
  stats(&acquired); assert(acquired.active_bytes == mapped(Resources[0].size) && !acquired.pinned_bytes);
  for (size_t i = 1; i < ResourceCount; ++i) {
    const uint8_t* other = acquire(ref(i)); resource(other, Resources[i]); release(ref(i));
    target(data);
  }
  stats(&held);
  assert(held.active_bytes == mapped(Resources[0].size) && !held.pinned_bytes &&
         held.idle_bytes <= IdleBudget && held.evictions > acquired.evictions);
  const uintptr_t old_begin = reinterpret_cast<uintptr_t>(data);
  const size_t old_size = mapped(Resources[0].size);
  data = nullptr;
  release(target_ref); // Never dereference the old address after its final release.
  stats(&released);
  assert(!released.active_bytes && !released.pinned_bytes && released.idle_bytes <= IdleBudget);
  assert(mapping(old_begin, old_size, false)); // Newest idle item must survive this release.
  size_t pressure_accesses = 0;
  bool absent = false, absent_after_acquire = false;
  for (size_t i = 1; i < ResourceCount; ++i) {
    const uint8_t* other = acquire(ref(i));
    absent_after_acquire = mapping(old_begin, old_size, true);
    resource(other, Resources[i]);
    release(ref(i));
    ++pressure_accesses;
    // Observe immediately, before another allocation could reuse the old interval.
    absent = mapping(old_begin, old_size, true);
    assert(!absent_after_acquire || absent);
    if (absent) break;
  }
  assert(absent && pressure_accesses);
  stats(&reclaimed);
  assert(!reclaimed.active_bytes && !reclaimed.pinned_bytes && reclaimed.idle_bytes <= IdleBudget &&
         reclaimed.evictions > released.evictions);
  data = acquire(target_ref); target(data); stats(&reloaded); release(target_ref); data = nullptr;
  stats(&final);
  assert(reloaded.active_bytes == old_size && !final.active_bytes && !final.pinned_bytes && final.idle_bytes <= IdleBudget);
  std::printf("{\"concurrentFirstAcquires\":8,\"pairedTargetLeases\":10,\"sameFirstPointer\":true,"
      "\"fullDigest\":true,\"chunkDigests\":%zu,\"heldPressureResources\":%zu,\"postReleasePressureAccesses\":%zu,"
      "\"oldTargetBegin\":\"0x%llx\",\"oldTargetMappedBytes\":%zu,\"absenceFirstObservedAfter\":\"%s\","
      "\"releasedTargetStillReadonly\":true,\"targetIntervalAbsentBeforeReload\":true,\"reloadDigest\":true,\"readonly\":true,\"stats\":{",
      sizeof TargetChunks / sizeof TargetChunks[0], ResourceCount - 1, pressure_accesses,
      (unsigned long long)old_begin, old_size, absent_after_acquire ? "acquire" : "release");
  print_stats("initial", initial); print_stats("acquired", acquired); print_stats("heldPressure", held);
  print_stats("released", released); print_stats("reclaimed", reclaimed); print_stats("reloaded", reloaded);
  print_stats("final", final, false); std::puts("}}");
  return 0;
}
