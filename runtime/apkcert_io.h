// SPDX-License-Identifier: Apache-2.0
#ifndef NDKP_APKCERT_IO_H
#define NDKP_APKCERT_IO_H
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__aarch64__) && defined(__ANDROID__)
#include <asm/unistd.h>
#endif

namespace stringarmor { namespace apkio {
struct Posix {
  static int open(const char* p, int f) { return ::open(p, f); }
  static int openat(int d, const char* p, int f) { return ::openat(d, p, f); }
  static int close(int d) { return ::close(d); }
  static int stat(int d, struct stat* s) { return ::fstat(d, s); }
  static ssize_t read(int d, void* p, size_t n) { return ::read(d, p, n); }
  static ssize_t pread(int d, void* p, size_t n, off64_t o) { return ::pread64(d, p, n, o); }
  static FILE* stream(const char* p) { return std::fopen(p, "re"); }
  static char* gets(char* p, int n, FILE* s) { return std::fgets(p, n, s); }
  static bool error(FILE* s) { return std::ferror(s) != 0; }
  static void finish(FILE* s) { std::fclose(s); }
  static DIR* directory(int fd) { return ::fdopendir(fd); }
  static const dirent* next(DIR* d) { return ::readdir(d); }
  static void finish(DIR* d) { ::closedir(d); }
};

#if defined(__aarch64__) && defined(__ANDROID__)
struct Raw {
  static long call(long number, long a = 0, long b = 0, long c = 0,
                   long d = 0, long e = 0, long f = 0) {
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    register long x3 asm("x3") = d;
    register long x4 asm("x4") = e;
    register long x5 asm("x5") = f;
    register long x8 asm("x8") = number;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                 "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return x0;
  }
  static long result(long value) {
    if (value < 0 && value >= -4095) { errno = int(-value); return -1; }
    return value;
  }
  static int openat(int d, const char* p, int f) {
    long r;
    do { r = call(__NR_openat, d, reinterpret_cast<long>(p), f); } while (r == -EINTR);
    return int(result(r));
  }
  static int open(const char* p, int f) { return openat(AT_FDCWD, p, f); }
  // Linux releases the fd even if close reports EINTR; never retry it.
  static int close(int d) { return int(result(call(__NR_close, d))); }
  static int stat(int d, struct stat* s) {
    long r;
    do { r = call(__NR_fstat, d, reinterpret_cast<long>(s)); } while (r == -EINTR);
    return int(result(r));
  }
  static ssize_t read(int d, void* p, size_t n) {
    return result(call(__NR_read, d, reinterpret_cast<long>(p), long(n)));
  }
  static ssize_t pread(int d, void* p, size_t n, off64_t o) {
    return result(call(__NR_pread64, d, reinterpret_cast<long>(p), long(n), long(o)));
  }
  struct Stream { int fd; size_t pos = 0, size = 0; bool failed = false; char buf[4096]; };
  static Stream* stream(const char* p) {
    const int fd = open(p, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return nullptr;
    auto* s = new Stream; s->fd = fd; return s;
  }
  static char* gets(char* p, int n, Stream* s) {
    int used = 0;
    while (used < n - 1) {
      if (s->pos == s->size) {
        ssize_t count;
        do { count = read(s->fd, s->buf, sizeof s->buf); } while (count < 0 && errno == EINTR);
        if (count <= 0) { s->failed |= count < 0; break; }
        s->pos = 0; s->size = size_t(count);
      }
      const char ch = s->buf[s->pos++]; p[used++] = ch;
      if (ch == '\n') break;
    }
    p[used] = 0; return used ? p : nullptr;
  }
  static bool error(Stream* s) { return s->failed; }
  static void finish(Stream* s) { close(s->fd); delete s; }
  struct Directory { int fd; size_t pos = 0, size = 0; uint8_t buf[8192]; dirent entry{}; };
  static Directory* directory(int fd) { auto* d = new Directory; d->fd = fd; return d; }
  static const dirent* next(Directory* d) {
    if (d->pos == d->size) {
      long count;
      do { count = call(__NR_getdents64, d->fd, reinterpret_cast<long>(d->buf), sizeof d->buf); }
      while (count == -EINTR);
      if (count <= 0) { if (count < 0) result(count); return nullptr; }
      d->pos = 0; d->size = size_t(count);
    }
    const uint8_t* p = d->buf + d->pos;
    if (d->size - d->pos < 20) { errno = EIO; return nullptr; }
    const size_t length = size_t(p[16]) | size_t(p[17]) << 8;
    if (length < 20 || length > d->size - d->pos) { errno = EIO; return nullptr; }
    const char* name = reinterpret_cast<const char*>(p + 19);
    const void* end = std::memchr(name, 0, length - 19);
    if (!end || static_cast<const char*>(end) - name >= long(sizeof d->entry.d_name)) {
      errno = EIO; return nullptr;
    }
    std::strcpy(d->entry.d_name, name); d->pos += length; return &d->entry;
  }
  static void finish(Directory* d) { close(d->fd); delete d; }
};
#endif
}} // namespace stringarmor::apkio
#endif
