// SPDX-License-Identifier: Apache-2.0
// Bootstrap only: compile without obfuscation or LTO, once per protected DSO.
#include "apkverify.h"
#include "apkverify_runtime.h"
#include "apkcert.h"
#include "apkverify_policy.h" // Generated public certificate fingerprint, never a private key.
#include <android/api-level.h>
#include <algorithm>
#include <pthread.h>
#include <string>
#include <vector>
#include <zlib.h>

namespace {
using namespace stringarmor::apkcert;
using Raw = stringarmor::apkio::Raw;
using Posix = stringarmor::apkio::Posix;
[[noreturn]] void fail() { for (;;) Raw::call(__NR_exit_group, 127); }
bool identity(const struct stat& a, const struct stat& b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
         a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
         a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
bool readFile(void* opaque, uint64_t offset, void* out, size_t length) {
  return readAt<Raw>(*static_cast<int*>(opaque), offset, out, length);
}
struct File { int fd; std::string path; struct stat stat; };
struct State {
  std::vector<File> files;
  int source = -1;
  Mapping mapping{};
  File extracted{-1, {}, {}};
  File directory{-1, {}, {}};
  ~State() {
    for (const auto& f : files) Raw::close(f.fd);
    if (extracted.fd >= 0) Raw::close(extracted.fd);
    if (directory.fd >= 0) Raw::close(directory.fd);
  }
};
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
thread_local bool entering;
State& state() { static State s; return s; }

void unchanged(const File& file) {
  struct stat current{};
  if (Raw::stat(file.fd, &current) || !identity(file.stat, current)) fail();
}
// Android may extract either STORED or raw-DEFLATE entries. Compare bounded chunks
// against the signed archive before trusting the extracted library's origin.
void checkExtracted(State& s) {
  char root[PATH_MAX], entry[PATH_MAX]; const char* relative;
  if (!extractedLibraryPaths(s.mapping.path, root, entry, relative)) fail();
  int fd = Raw::open(s.mapping.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st{};
  if (fd < 0 || Raw::stat(fd, &st) || !S_ISREG(st.st_mode) || !mappedIdentity(s.mapping, st)) fail();
  s.extracted = {fd, s.mapping.path, st};
  ZipLibrary item{}; bool found = false;
  const File& apk = s.files[0];
  if (!zipHasLibrary<Raw>(apk.fd, apk.stat.st_size, entry, found, &item) || !found ||
      item.size != uint64_t(st.st_size)) fail();
  uint8_t input[32768], output[32768], actual[32768];
  uint64_t consumed = 0, produced = 0;
  z_stream stream{};
  if (item.method == 8 && inflateInit2(&stream, -MAX_WBITS) != Z_OK) fail();
  int status = Z_OK;
  do {
    if (stream.avail_in == 0 && consumed < item.compressed) {
      size_t n = size_t(std::min<uint64_t>(sizeof input, item.compressed - consumed));
      if (!readAt<Raw>(apk.fd, item.offset + consumed, input, n)) fail();
      consumed += n; stream.next_in = input; stream.avail_in = unsigned(n);
    }
    size_t n;
    if (item.method == 8) {
      stream.next_out = output; stream.avail_out = sizeof output;
      status = inflate(&stream, Z_NO_FLUSH); n = sizeof output - stream.avail_out;
      if ((status != Z_OK && status != Z_STREAM_END) || (status != Z_STREAM_END && !n && !stream.avail_in && consumed == item.compressed)) fail();
    } else {
      n = stream.avail_in; std::memcpy(output, input, n); stream.avail_in = 0;
    }
    if (n > item.size - produced || !readAt<Raw>(fd, produced, actual, n) || std::memcmp(actual, output, n)) fail();
    produced += n;
  } while (item.method == 8 ? status != Z_STREAM_END : consumed < item.compressed);
  if (produced != item.size || consumed != item.compressed || stream.avail_in) fail();
  if (item.method == 8) inflateEnd(&stream);
  unchanged(s.extracted);
}

File checked(int fd, const std::string& path) {
  struct stat before{}, after{}, other{};
  int check = Posix::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  bool ok = fd >= 0 && check >= 0 && Raw::stat(fd, &before) == 0 && Posix::stat(check, &other) == 0 &&
      S_ISREG(before.st_mode) && before.st_size > 0 && identity(before, other);
  if (check >= 0) Posix::close(check);
  ndkp_apkverify::Result result{}; ndkp_apkverify::Error error;
  const int api = android_get_device_api_level();
  if (api < 26) fail();
  if (!ok || !ndkp_apkverify::verify(readFile, &fd, uint64_t(before.st_size), ndkp_expected_certificate,
      unsigned(api), result, error) || Raw::stat(fd, &after) || !identity(before, after)) fail();
  return {fd, path, after};
}
// Recognize only Android's package-private installation directory, never a shared APK folder.
bool installedRoot(const std::string& path, std::string& root) {
  const char* suffix = nullptr;
  if (path.compare(0, 10, "/data/app/") == 0) suffix = path.c_str() + 10;
  else if (path.compare(0, 12, "/mnt/expand/") == 0) {
    const char* end = std::strchr(path.c_str() + 12, '/');
    if (end && end != path.c_str() + 12 && std::strncmp(end, "/app/", 5) == 0) suffix = end + 5;
  }
  if (!suffix) return false;
  const char* slash = std::strchr(suffix, '/');
  if (!slash || slash == suffix) fail();
  if (std::strncmp(suffix, "~~", 2) == 0) {
    const char* next = std::strchr(slash + 1, '/');
    if (!next || next == slash + 1) fail(); slash = next;
  }
  if (std::strchr(slash + 1, '/') || !endsWith(slash + 1, ".apk")) fail();
  root.assign(path.c_str(), size_t(slash - path.c_str())); return true;
}
void initialize(State& s) {
  const uintptr_t anchor = reinterpret_cast<uintptr_t>(&ndkp_verified_apk);
  Mapping other{};
  if (!inspectMaps<Raw>(anchor, &s.mapping) || !inspectMaps<Posix>(anchor, &other) ||
      !cleanAbsolutePath(s.mapping.path) || !s.mapping.inode ||
      s.mapping.start != other.start || s.mapping.end != other.end ||
      s.mapping.inode != other.inode || s.mapping.devMajor != other.devMajor ||
      s.mapping.devMinor != other.devMinor || std::strcmp(s.mapping.path, other.path)) fail();
  bool direct = endsWith(s.mapping.path, ".apk");
  int source = direct ? Raw::open(s.mapping.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
                      : openExtractedLibraryApk<Raw>(s.mapping);
  if (source < 0) fail();
  char path[PATH_MAX]{};
  if (direct) std::strcpy(path, s.mapping.path);
  else {
    char proc[64]; std::snprintf(proc, sizeof proc, "/proc/self/fd/%d", source);
    long n = Raw::result(Raw::call(__NR_readlinkat, AT_FDCWD, reinterpret_cast<long>(proc),
                                 reinterpret_cast<long>(path), sizeof(path) - 1));
    if (n <= 0 || n >= long(sizeof(path) - 1)) fail(); path[n] = 0;
  }
  if (!cleanAbsolutePath(path)) fail();
  s.files.push_back(checked(source, path));
  if (direct && !mappedIdentity(s.mapping, s.files[0].stat)) fail();
  if (!direct) checkExtracted(s);
  std::string root;
  if (installedRoot(path, root)) {
    int dirfd = Raw::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int retained = Raw::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat snapshot{}, enumerated{};
    if (retained < 0 || Raw::stat(retained, &snapshot) || Raw::stat(dirfd, &enumerated) || !identity(snapshot, enumerated)) fail();
    s.directory = {retained, root, snapshot};
    if (dirfd < 0) fail(); auto* dir = Raw::directory(dirfd);
    bool base = false; size_t count = 0;
    for (;;) {
      errno = 0; const dirent* e = Raw::next(dir);
      if (!e) { if (errno) fail(); break; }
      if (!endsWith(e->d_name, ".apk")) continue;
      if (++count > 128) fail();
      base |= std::strcmp(e->d_name, "base.apk") == 0;
      std::string sibling = root + "/" + e->d_name;
      if (sibling == path) continue;
      int fd = Raw::openat(dirfd, e->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
      s.files.push_back(checked(fd, sibling));
    }
    Raw::finish(dir);
    if (!base || count != s.files.size()) fail();
    unchanged(s.directory);
  }
  // Recheck every snapshot after the entire set is verified before publishing any state.
  for (const auto& f : s.files) {
    unchanged(f);
  }
  s.source = source;
}
}
extern "C" int ndkp_verified_apk(uint8_t certificate[32], struct stat* output) {
  if (entering || !certificate) fail();
  entering = true;
  if (pthread_mutex_lock(&mutex)) fail();
  State& s = state(); if (s.source < 0) initialize(s);
  for (const auto& f : s.files) {
    unchanged(f);
  }
  if (s.extracted.fd >= 0) unchanged(s.extracted);
  if (s.directory.fd >= 0) unchanged(s.directory);
  if (output) *output = s.files[0].stat;
  std::memcpy(certificate, ndkp_expected_certificate, 32);
  int fd = s.source;
  if (pthread_mutex_unlock(&mutex)) fail();
  entering = false; return fd;
}
// Covers native-only selections and executes before any application constructors.
__attribute__((constructor(101))) static void verifyBeforeUse() {
  uint8_t certificate[32]; ndkp_verified_apk(certificate, nullptr);
}
