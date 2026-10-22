// 生命周期独立自检：使用生产缓存实现，密码和 APK 输入由测试桩替代；不声称认证测试。
#include <sys/mman.h>
#include <sys/wait.h>
#include <cassert>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
static unsigned clearedMappings = 0;
static int checkedMunmap(void* data, size_t size);
#define munmap checkedMunmap
#include "../../runtime/ndkp_qseg_runtime.cpp"
#undef munmap
static int checkedMunmap(void* data, size_t size) {
  const auto* p = static_cast<const volatile uint8_t*>(data);
  for (size_t i = 0; i < size; ++i) assert(p[i] == 0);
  ++clearedMappings;
  return ::munmap(data, size);
}
extern "C" const uint8_t ndkp_qseg_image[512] = {};
extern "C" void ndkp_qseg_measure(uint8_t code[32], uint8_t inputs[48]) { std::memset(code, 0, 32); std::memset(inputs, 0, 48); }
extern "C" void ndkp_qseg_derive(const uint8_t[32], const uint8_t[48], uint8_t key[32]) { std::memset(key, 0, 32); }
extern "C" bool ndkp_qseg_open(const uint8_t[32], const uint8_t*, size_t, uint8_t*, size_t, const uint8_t[16]) { return true; }

static uint8_t refs[5][24];
static void setup(const char* path) {
  State& s = state();
  s.fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600); assert(s.fd >= 0);
  s.ready = true;
  s.executable.push_back({reinterpret_cast<uintptr_t>(refs), reinterpret_cast<uintptr_t>(refs) + sizeof refs});
  uint32_t offset = 0;
  for (unsigned i = 0; i < 5; ++i) {
    refs[i][0] = i + 1;
    ID id{}; id[0] = i + 1;
    Resource& r = s.resources[id]; r.kind = i == 4 ? 2 : 1;
    r.size = i == 3 ? 2 * IdleBudget : 700000;
    store32(refs[i] + 16, r.size); store32(refs[i] + 20, r.kind);
    for (uint32_t n = 0; n < r.size;) {
      uint32_t plain = std::min(uint32_t(65536), r.size - n);
      std::vector<uint8_t> bytes(plain, uint8_t(i + 65));
      assert(pwrite(s.fd, bytes.data(), bytes.size(), offset) == ssize_t(bytes.size()));
      r.chunks.push_back(Chunk{uint32_t(r.chunks.size()), offset, plain, plain, 0, {}});
      offset += plain; n += plain;
    }
  }
}
static ndkp_qseg_cache_stats_v1 stats() {
  ndkp_qseg_cache_stats_v1 out{}; ndkp_qseg_stats_v1(&out); return out;
}
static void expectFailure(void (*test)(), int code, bool signal = false) {
  pid_t pid = fork(); assert(pid >= 0);
  if (!pid) { test(); _exit(0); }
  int status = 0; assert(waitpid(pid, &status, 0) == pid);
  assert(signal ? WIFSIGNALED(status) && WTERMSIG(status) == code : WIFEXITED(status) && WEXITSTATUS(status) == code);
}
int main(int argc, char** argv) {
  assert(argc == 2); setup(argv[1]);
  const auto* outer = ndkp_qseg_acquire_v1(refs[0]);
  assert(outer[0] == 65 && outer[699999] == 65);
  assert(ndkp_qseg_acquire_v1(refs[0]) == outer);
  ndkp_qseg_release_v1(refs[0]); assert(stats().active_bytes == mappingSize(700000));
  expectFailure([] { auto* p = ndkp_qseg_acquire_v1(refs[0]); *const_cast<volatile uint8_t*>(p) ^= 1; }, SIGSEGV, true);
  for (unsigned i : {1u, 2u}) {
    assert(ndkp_qseg_acquire_v1(refs[i])[0] == i + 65);
    ndkp_qseg_release_v1(refs[i]);
  }
  assert(stats().evictions && outer[699999] == 65);
  ndkp_qseg_release_v1(refs[0]); assert(stats().idle_bytes <= IdleBudget);
  const auto* big = ndkp_qseg_acquire_v1(refs[3]); assert(big[0] == 68);
  assert(stats().active_bytes >= 2 * IdleBudget);
  ndkp_qseg_release_v1(refs[3]); assert(!state().resources[ID{4}].data);
  ndkp_qseg_acquire_v1(refs[1]);
  const auto* legacy = ndkp_qseg_get(refs[1]);
  ndkp_qseg_release_v1(refs[1]);
  assert(stats().pinned_bytes == mappingSize(700000) && legacy[0] == 66);
  struct Borrow {
    const uint8_t* ref;
    explicit Borrow(const uint8_t* r): ref(r) { ndkp_qseg_acquire_v1(ref); }
    ~Borrow() { ndkp_qseg_release_v1(ref); }
  };
  try { Borrow value(refs[0]); throw std::runtime_error("fixture"); } catch (const std::runtime_error&) {}
  assert(!stats().active_bytes);
  std::atomic<bool> go{false}; std::vector<std::thread> threads;
  for (unsigned t = 0; t < 8; ++t) threads.emplace_back([&, t] {
    while (!go.load()) {}
    for (unsigned n = 0; n < 100; ++n) {
      const unsigned i = (t + n) % 3;
      const auto* p = ndkp_qseg_acquire_v1(refs[i]);
      assert(p[0] == i + 65 && p[699999] == i + 65);
      ndkp_qseg_release_v1(refs[i]);
    }
  });
  go.store(true); for (auto& t : threads) t.join();
  uint8_t copied[66]; std::memset(copied, 0xcc, sizeof copied);
  ndkp_qseg_copy(copied + 1, refs[4], 8, 64, 2);
  assert(copied[0] == 0xcc && copied[65] == 0xcc);
  for (unsigned i = 1; i < 65; ++i) assert(copied[i] == 69);
  assert(!stats().active_bytes && stats().idle_bytes <= IdleBudget && legacy[699999] == 66);
  expectFailure([] { ndkp_qseg_release_v1(refs[0]); }, 127);
  expectFailure([] { uint8_t invalid[24]{}; ndkp_qseg_acquire_v1(invalid); }, 127);
  assert(clearedMappings == stats().evictions);
  std::printf("page=%ld active=%llu idle=%llu pinned=%llu peak=%llu evictions=%llu wiped=%u\n",
      sysconf(_SC_PAGESIZE), (unsigned long long)stats().active_bytes, (unsigned long long)stats().idle_bytes,
      (unsigned long long)stats().pinned_bytes, (unsigned long long)stats().peak_resident_bytes,
      (unsigned long long)stats().evictions, clearedMappings);
  close(state().fd); assert(unlink(argv[1]) == 0);
}
