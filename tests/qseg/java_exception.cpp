// Included only in the fresh fixture's registration TU, before signing/sealing.
#include <jni.h>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include "qseg.h"
#include "sha256.h"

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*);

namespace java_exception {
constexpr size_t Page = 4096, Budget = 1u << 20, Count = 17;
constexpr size_t MaxMaps = 32768, MaxCandidates = 262144, MaxReadBytes = 256u << 20;
struct Chunk { uint32_t offset, size; uint8_t digest[32]; };
struct Resource {
  uint64_t rva; uint32_t size, chunks;
  uint8_t id[16], digest[32], prefix[32]; Chunk chunk[256];
  uintptr_t live = 0;
};
struct Span { uint64_t rva, size; uint8_t digest[32]; };
struct Mapping { uintptr_t begin, end; bool readonly, anonymous; };
using Stats = ndkp_qseg_cache_stats_v1;
Resource resources[Count]; Span spans[8]; Mapping maps[MaxMaps];
uint8_t plan_bytes[1u << 20], scratch[16u << 20];
size_t map_count = 0, span_count = 0, cursor = 0, plan_size = 0, event_index = 0, sequence = 0;
uintptr_t base = 0; uint64_t onload_rva = 0;
int mode = 0, memory_fd = -1; bool configured = false, finished = false;
char token[33]{};
jobject sentinel = nullptr;

[[noreturn]] void fail(const char* message) {
  std::fprintf(stderr, "QSEG_JAVA_EXCEPTION_FAIL:%s:%s\n", token, message);
  std::fflush(stderr); _exit(125);
}
void require(bool condition, const char* message) { if (!condition) fail(message); }
size_t rounded(const Resource& r) { return (size_t(r.size) + Page - 1) / Page * Page; }
const uint8_t* ref(const Resource& r) { return reinterpret_cast<const uint8_t*>(base + r.rva); }
const char* case_name() { return mode == 1 ? "caught" : "rethrow"; }

void bytes(void* target, size_t count) {
  require(count <= plan_size - cursor, "truncated binary plan");
  std::memcpy(target, plan_bytes + cursor, count); cursor += count;
}
uint64_t integer(size_t count) {
  require(count <= 8 && count <= plan_size - cursor, "truncated integer");
  uint64_t result = 0;
  for (size_t i = 0; i < count; ++i) result |= uint64_t(plan_bytes[cursor++]) << (i * 8);
  return result;
}
bool hash_matches(const uint8_t* data, size_t size, const uint8_t expected[32]) {
  uint8_t actual[32]; stringarmor::sha2::sha256(data, size, actual);
  return std::memcmp(actual, expected, 32) == 0;
}
bool content(const uint8_t* data, const Resource& r) {
  if (!hash_matches(data, r.size, r.digest)) return false;
  for (size_t i = 0; i < r.chunks; ++i)
    if (!hash_matches(data + r.chunk[i].offset, r.chunk[i].size, r.chunk[i].digest)) return false;
  return true;
}
void read_memory(uintptr_t address, uint8_t* target, size_t size) {
  require(address <= UINTPTR_MAX - size, "memory read overflow");
  size_t done = 0;
  while (done < size) {
    ssize_t count = pread(memory_fd, target + done, size - done, static_cast<off_t>(address + done));
    if (count < 0 && errno == EINTR) continue;
    require(count > 0 && size_t(count) <= size - done, "self/mem read failed or truncated");
    done += size_t(count);
  }
}

// Fixed read buffers avoid a stdio allocation reusing a just-reclaimed interval.
// Absence is valid only after a complete, strict parse and a successful close.
void read_maps() {
  int input = open("/proc/self/maps", O_RDONLY | O_CLOEXEC); require(input >= 0, "open maps failed");
  map_count = 0; size_t text_bytes = 0, used = 0; uintptr_t previous = 0;
  char block[4096], line[8192];
  for (;;) {
    ssize_t count = read(input, block, sizeof block);
    if (count < 0 && errno == EINTR) continue;
    require(count >= 0, "maps read failed");
    if (!count) break;
    text_bytes += size_t(count); require(text_bytes <= 8u << 20, "maps byte bound exhausted");
    for (ssize_t index = 0; index < count; ++index) {
      require(block[index] && used < sizeof line - 1, "maps NUL or long line");
      line[used++] = block[index];
      if (block[index] != '\n') continue;
      line[used] = 0; used = 0;
      require(map_count < MaxMaps, "maps count bound exhausted");
      unsigned long long left, right, offset, inode; unsigned major, minor;
      char permissions[5]{}; int tail = 0;
      require(std::sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n", &left, &right,
                         permissions, &offset, &major, &minor, &inode, &tail) == 7 && tail > 0,
              "maps parse failed");
      require(left < right && right <= UINTPTR_MAX && left >= previous && left % Page == 0 && right % Page == 0 &&
              std::strlen(permissions) == 4 && (permissions[0] == 'r' || permissions[0] == '-') &&
              (permissions[1] == 'w' || permissions[1] == '-') &&
              (permissions[2] == 'x' || permissions[2] == '-') &&
              (permissions[3] == 'p' || permissions[3] == 's'), "maps interval/permissions/order invalid");
      const char* path = line + tail;
      while (*path == ' ' || *path == '\t') ++path;
      const bool anonymous = inode == 0 && (*path == '\n' || *path == '\0' || !std::strncmp(path, "[anon:", 6));
      maps[map_count++] = {uintptr_t(left), uintptr_t(right), !std::strcmp(permissions, "r--p"), anonymous};
      previous = uintptr_t(right);
    }
  }
  require(!used && map_count > 0, "maps missing newline or empty EOF");
  require(close(input) == 0, "close maps failed");
}
bool interval(uintptr_t begin, size_t size, bool absent) {
  require(begin && begin <= UINTPTR_MAX - size, "mapping interval overflow");
  read_maps();
  const uintptr_t end = begin + size; uintptr_t covered = begin;
  bool overlap = false, readonly = true;
  for (size_t i = 0; i < map_count; ++i) {
    const Mapping& m = maps[i];
    if (m.end <= begin || m.begin >= end) continue;
    overlap = true;
    if (m.begin > covered || !m.readonly) readonly = false;
    if (m.end > covered) covered = m.end;
  }
  if (absent) {
    require(!overlap || (readonly && covered >= end), "released target partial overlap or permission drift");
    return !overlap;
  }
  return overlap && readonly && covered >= end;
}
void verify_live(const Resource& r) {
  require(r.live && interval(r.live, rounded(r), false), "active target mapping lost or writable");
  read_memory(r.live, scratch, r.size);
  require(content(scratch, r), "active target full/chunk digest differs");
  require(interval(r.live, rounded(r), false), "active target mapping changed during read");
}
void discover(Resource& r) {
  require(!r.live, "target rediscovery forbidden");
  read_maps();
  uintptr_t found = 0; size_t matches = 0, candidates = 0, read_bytes = 0;
  // Candidates are fixed from this complete snapshot; any unreadable candidate fails the observation.
  for (size_t i = 0; i < map_count; ++i) {
    const Mapping m = maps[i];
    if (!m.readonly || !m.anonymous || m.end - m.begin < rounded(r)) continue;
    for (uintptr_t address = m.begin; address <= m.end - rounded(r); address += Page) {
      require(++candidates <= MaxCandidates && read_bytes <= MaxReadBytes - 32, "discovery scan bound exhausted");
      uint8_t prefix[32]; read_memory(address, prefix, 32); read_bytes += 32;
      if (std::memcmp(prefix, r.prefix, 32)) continue;
      require(read_bytes <= MaxReadBytes - r.size, "discovery byte bound exhausted");
      read_memory(address, scratch, r.size); read_bytes += r.size;
      if (content(scratch, r)) { found = address; ++matches; }
    }
  }
  require(candidates && matches == 1, "active target mapping is missing or nonunique");
  require(interval(found, rounded(r), false), "discovered target interval changed");
  r.live = found; verify_live(r);
}
void stats(Stats& s, uint64_t expected) {
  ndkp_qseg_stats_v1(&s);
  require(s.active_bytes == expected && !s.pinned_bytes && s.idle_bytes <= Budget, "cache statistics differ");
}
uint64_t active_cost(unsigned mask) {
  uint64_t result = 0;
  for (size_t i = 0; i < 3; ++i) if (mask & (1u << i)) result += rounded(resources[i]);
  return result;
}
void active(unsigned mask) {
  for (size_t i = 0; i < 3; ++i) if (mask & (1u << i)) verify_live(resources[i]);
}
void hex(const uint8_t* value, size_t size, char* out) {
  const char* alphabet = "0123456789abcdef";
  for (size_t i = 0; i < size; ++i) { out[i * 2] = alphabet[value[i] >> 4]; out[i * 2 + 1] = alphabet[value[i] & 15]; }
  out[size * 2] = 0;
}
void print_start(int event, int depth, const Stats& s) {
  std::printf("QSEG_JAVA_EXCEPTION:{\"token\":\"%s\",\"case\":\"%s\",\"seq\":%zu,\"event\":%d,\"depth\":%d,"
      "\"active\":%" PRIu64 ",\"idle\":%" PRIu64 ",\"pinned\":%" PRIu64 ",\"peak\":%" PRIu64 ",\"evictions\":%" PRIu64 ",\"targetLoans\":0",
      token, case_name(), sequence++, event, depth, s.active_bytes, s.idle_bytes, s.pinned_bytes,
      s.peak_resident_bytes, s.evictions);
}
bool in_rx(uint64_t rva, size_t size) {
  for (size_t i = 0; i < span_count; ++i)
    if (rva >= spans[i].rva && size <= spans[i].size && rva - spans[i].rva <= spans[i].size - size) return true;
  return false;
}

void configure(JNIEnv* env, jclass, jbyteArray input, jstring run_token, jint run_mode, jobject supplied) {
  require(!env->ExceptionCheck(), "pending exception at configure entry");
  require(!configured && input && run_token && (run_mode == 1 || run_mode == 2), "invalid configure state");
  const char* text = env->GetStringUTFChars(run_token, nullptr);
  require(text && std::strlen(text) == 32, "invalid token length");
  for (size_t i = 0; i < 32; ++i) require((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'), "invalid token");
  std::memcpy(token, text, 32); env->ReleaseStringUTFChars(run_token, text);
  mode = run_mode;
  const jsize length = env->GetArrayLength(input);
  require(length >= 32 && size_t(length) <= sizeof plan_bytes, "plan size bound");
  plan_size = size_t(length); env->GetByteArrayRegion(input, 0, length, reinterpret_cast<jbyte*>(plan_bytes));
  require(!env->ExceptionCheck(), "plan array copy failed");
  uint8_t magic[8]; bytes(magic, 8);
  require(!std::memcmp(magic, "QJEX01\0\0", 8) && integer(4) == Page && integer(4) == Budget && integer(4) == Count,
          "binary plan header differs");
  span_count = integer(4); onload_rva = integer(8);
  require(span_count > 0 && span_count <= 8 && sysconf(_SC_PAGESIZE) == long(Page), "plan span/page bound");
  uint64_t pressure = 0;
  for (size_t i = 0; i < Count; ++i) {
    Resource& r = resources[i]; r.rva = integer(8); r.size = integer(4); r.chunks = integer(4);
    require(r.size >= 32 && r.size <= sizeof scratch && r.chunks == (r.size + 65535u) / 65536u && r.chunks <= 256,
            "resource size/chunk bound");
    bytes(r.id, 16); bytes(r.digest, 32); bytes(r.prefix, 32);
    for (size_t j = 0; j < r.chunks; ++j) {
      Chunk& c = r.chunk[j]; c.offset = integer(4); c.size = integer(4); bytes(c.digest, 32);
      require(c.offset == j * 65536 && c.size == (r.size - c.offset < 65536 ? r.size - c.offset : 65536), "chunk coverage differs");
    }
    for (size_t j = 0; j < i; ++j) require(std::memcmp(r.id, resources[j].id, 16), "duplicate resource identity");
    if (i >= 3) { require(rounded(r) <= Budget, "pressure exceeds budget"); pressure += rounded(r); }
  }
  require(rounded(resources[0]) + rounded(resources[1]) <= Budget && rounded(resources[0]) + rounded(resources[2]) <= Budget && pressure > Budget,
          "target/pressure mapping budget differs");
  for (size_t i = 0; i < span_count; ++i) {
    spans[i].rva = integer(8); spans[i].size = integer(8); bytes(spans[i].digest, 32);
    require(spans[i].size && spans[i].size <= 256u << 20 && spans[i].rva <= UINTPTR_MAX - spans[i].size,
            "RX span bounds");
  }
  require(cursor == plan_size, "trailing binary plan data");
  Dl_info info{}; require(dladdr(reinterpret_cast<void*>(&configure), &info) && info.dli_fbase, "probe dladdr failed");
  base = reinterpret_cast<uintptr_t>(info.dli_fbase);
  require(onload_rva <= UINTPTR_MAX - base && reinterpret_cast<uintptr_t>(&JNI_OnLoad) == base + onload_rva && in_rx(onload_rva, 1),
          "JNI_OnLoad offset differs");
  for (size_t i = 0; i < span_count; ++i) {
    require(spans[i].rva <= UINTPTR_MAX - base && spans[i].size <= UINTPTR_MAX - base - spans[i].rva,
            "RX address overflow");
    require(hash_matches(reinterpret_cast<const uint8_t*>(base + spans[i].rva), spans[i].size, spans[i].digest), "loaded RX differs");
  }
  for (const Resource& r : resources) {
    require(in_rx(r.rva, 24) && r.rva <= UINTPTR_MAX - base, "descriptor is not RX");
    uint32_t size, kind; std::memcpy(&size, ref(r) + 16, 4); std::memcpy(&kind, ref(r) + 20, 4);
    require(!std::memcmp(ref(r), r.id, 16) && size == r.size && kind == 1, "loaded descriptor differs");
  }
  memory_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC); require(memory_fd >= 0, "open self/mem failed");
  Stats initial{}; stats(initial, 0);
  require(supplied, "null sentinel");
  jclass expected = env->FindClass("java/lang/IllegalStateException");
  require(expected && !env->ExceptionCheck(), "sentinel class resolution failed");
  jclass actual = env->GetObjectClass(supplied);
  require(actual && !env->ExceptionCheck() && env->IsSameObject(actual, expected), "sentinel exact type differs");
  jmethodID get_message = env->GetMethodID(expected, "getMessage", "()Ljava/lang/String;");
  require(get_message && !env->ExceptionCheck(), "sentinel message method failed");
  auto message = static_cast<jstring>(env->CallObjectMethod(supplied, get_message));
  require(!env->ExceptionCheck() && message, "sentinel message failed");
  const char* message_text = env->GetStringUTFChars(message, nullptr);
  require(message_text && !env->ExceptionCheck() && !std::strcmp(message_text, "qseg-java-exception-sentinel-v1"),
          "sentinel message differs");
  env->ReleaseStringUTFChars(message, message_text);
  env->DeleteLocalRef(message); env->DeleteLocalRef(actual); env->DeleteLocalRef(expected);
  sentinel = env->NewGlobalRef(supplied);
  require(sentinel && !env->ExceptionCheck(), "sentinel global reference failed");
  // Authentication is supplied by the signed final plan and loaded RX. No target loan is taken here.
  Stats ready{}; stats(ready, 0); configured = true;
  print_start(0, 0, ready);
  std::puts(",\"pendingClear\":true,\"sentinelIdentity\":true,\"caughtIdentity\":false}"); std::fflush(stdout);
}

void observe(JNIEnv* env, jclass, jint event, jobject supplied, jobject caught) {
  // This must remain the first JNI operation, including in the deliberate pending control.
  require(!env->ExceptionCheck(), "pending exception at observer entry");
  require(configured && !finished, "observe outside case");
  require(supplied && env->IsSameObject(supplied, sentinel), "sentinel identity differs");
  const bool needs_caught = event == 3 || (event == 4 && mode == 2);
  require(needs_caught ? caught && env->IsSameObject(caught, sentinel) : !caught, "caught identity differs");
  require(event_index < 4 && event == int(event_index + 1), "observer event order differs");
  ++event_index;
  const size_t outer = mode == 1 ? 1 : 2;
  if (event == 1) discover(resources[outer]);
  if (event == 2) discover(resources[0]);
  const int discovered = event == 1 ? int(outer) : event == 2 ? 0 : -1;
  const uintptr_t discovered_begin = discovered >= 0 ? resources[discovered].live : 0;
  const size_t discovered_size = discovered >= 0 ? rounded(resources[discovered]) : 0;
  const unsigned mask = event == 4 ? 0 : (1u << outer) | (event == 2 ? 1u : 0);
  const uint64_t cost = active_cost(mask);
  Stats before{}; stats(before, cost); active(mask);
  const int reclaim = event == 3 ? 0 : event == 4 ? int(outer) : -1;
  uintptr_t old_begin = 0; size_t old_size = 0; bool absent = false;
  if (reclaim >= 0) {
    old_begin = resources[reclaim].live; old_size = rounded(resources[reclaim]);
    require(interval(old_begin, old_size, false), "released target must initially remain readonly");
  }
  size_t steps = 0;
  for (size_t i = 3; i < Count; ++i) {
    active(mask); Stats pre{}; stats(pre, cost);
    const uint8_t* other = ndkp_qseg_acquire_v1(ref(resources[i]));
    require(other, "pressure acquire failed");
    const bool after_acquire = reclaim >= 0 && interval(old_begin, old_size, true);
    if (after_acquire) resources[reclaim].live = 0;
    Stats held{}; stats(held, cost + rounded(resources[i])); active(mask);
    require(interval(reinterpret_cast<uintptr_t>(other), rounded(resources[i]), false) && content(other, resources[i]),
            "pressure resource differs");
    ndkp_qseg_release_v1(ref(resources[i])); other = nullptr; ++steps;
    absent = after_acquire || (reclaim >= 0 && interval(old_begin, old_size, true));
    if (absent) resources[reclaim].live = 0;
    Stats post{}; stats(post, cost); active(mask);
    if (absent) break;
  }
  Stats after{}; stats(after, cost); active(mask);
  require(after.evictions > before.evictions && (reclaim < 0 || absent), "pressure/reclamation was ineffective");
  print_start(event, event == 2 ? 1 : 0, after);
  std::printf(",\"steps\":%zu,\"readonly\":true,\"digests\":true,\"pendingClear\":true,"
              "\"sentinelIdentity\":true,\"caughtIdentity\":%s", steps, needs_caught ? "true" : "false");
  if (discovered >= 0) {
    char id[33]; hex(resources[discovered].id, 16, id);
    std::printf(",\"discovered\":\"%s\",\"discoveredBegin\":\"0x%" PRIxPTR "\",\"discoveredBytes\":%zu",
                id, discovered_begin, discovered_size);
  }
  if (reclaim >= 0) {
    char id[33]; hex(resources[reclaim].id, 16, id);
    std::printf(",\"reclaimed\":\"%s\",\"oldBegin\":\"0x%" PRIxPTR "\",\"oldBytes\":%zu,"
                "\"releasedReadonly\":true,\"absent\":true", id, old_begin, old_size);
  }
  std::puts("}"); std::fflush(stdout);
}

void finish(JNIEnv* env, jclass, jint first, jint again) {
  require(!env->ExceptionCheck(), "pending exception at finish entry");
  require(configured && !finished && event_index == 4, "finish before case completed");
  require(first == (mode == 1 ? 73 : 91) && again == first, "real wrapper semantics differ");
  require(!resources[0].live && !resources[mode == 1 ? 1 : 2].live, "target address not discarded");
  Stats final{}; stats(final, 0);
  require(close(memory_fd) == 0, "close self/mem failed"); memory_fd = -1;
  env->DeleteGlobalRef(sentinel); sentinel = nullptr; finished = true;
  print_start(10, 0, final);
  std::printf(",\"first\":%d,\"again\":%d,\"semanticReentry\":true,\"pendingClear\":true,"
              "\"sentinelIdentity\":true,\"caughtIdentity\":false}\n", first, again); std::fflush(stdout);
}

void reject(JNIEnv* env, jclass cls, jint kind, jobject value) {
  require(!env->ExceptionCheck() && configured && !finished && event_index == 0 && (kind == 1 || kind == 2),
          "invalid rejection control");
  if (kind == 2) require(env->Throw(static_cast<jthrowable>(value)) == 0, "control Throw failed");
  std::fprintf(stderr, "QSEG_JAVA_EXCEPTION_CONTROL:%s:%s:ATTEMPT\n", token,
               kind == 1 ? "reject-substitute" : "reject-pending"); std::fflush(stderr);
  observe(env, cls, 1, value, nullptr);
  fail("rejection returned");
}
} // namespace java_exception

static int java_exception_register(JNIEnv* env) {
  jclass cls = env->FindClass("sample/Probe"); if (!cls) return -1;
  const JNINativeMethod methods[] = {
      {const_cast<char*>("configure"), const_cast<char*>("([BLjava/lang/String;ILjava/lang/Throwable;)V"), reinterpret_cast<void*>(&java_exception::configure)},
      {const_cast<char*>("observe"), const_cast<char*>("(ILjava/lang/Throwable;Ljava/lang/Throwable;)V"), reinterpret_cast<void*>(&java_exception::observe)},
      {const_cast<char*>("finish"), const_cast<char*>("(II)V"), reinterpret_cast<void*>(&java_exception::finish)},
      {const_cast<char*>("reject"), const_cast<char*>("(ILjava/lang/Throwable;)V"), reinterpret_cast<void*>(&java_exception::reject)}};
  int status = env->RegisterNatives(cls, methods, 4); env->DeleteLocalRef(cls);
  return status == 0 && !env->ExceptionCheck() ? 0 : -1;
}
