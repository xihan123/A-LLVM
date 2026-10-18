// SPDX-License-Identifier: Apache-2.0
#ifndef NDKP_RAW_SYSCALL_H
#define NDKP_RAW_SYSCALL_H
#include <asm/unistd.h>

static __inline__ __attribute__((always_inline)) long
ndkp_raw_syscall3(long number, long a, long b, long c) {
#if defined(__aarch64__)
  register long x0 __asm__("x0") = a;
  register long x1 __asm__("x1") = b;
  register long x2 __asm__("x2") = c;
  register long x8 __asm__("x8") = number;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
  return x0;
#elif defined(__arm__)
  register long r0 __asm__("r0") = a;
  register long r1 __asm__("r1") = b;
  register long r2 __asm__("r2") = c;
  // r7 may hold the Thumb frame pointer, so preserve it inside the asm.
  __asm__ volatile("mov r12, r7\n\tmov r7, %3\n\tsvc #0\n\tmov r7, r12"
      : "+r"(r0) : "r"(r1), "r"(r2), "r"(number) : "r12", "memory", "cc");
  return r0;
#elif defined(__x86_64__)
  long result;
  __asm__ volatile("syscall" : "=a"(result) : "0"(number), "D"(a), "S"(b), "d"(c)
      : "rcx", "r11", "memory", "cc");
  return result;
#elif defined(__i386__)
  long result;
  __asm__ volatile("int $0x80" : "=a"(result) : "0"(number), "b"(a), "c"(b), "d"(c)
      : "memory", "cc");
  return result;
#else
#error "unsupported Linux syscall ABI"
#endif
}

static __inline__ __attribute__((always_inline, noreturn)) void ndkp_raw_terminate(void) {
  long pid = ndkp_raw_syscall3(__NR_getpid, 0, 0, 0);
  if (pid > 0) ndkp_raw_syscall3(__NR_kill, pid, 9, 0);
  // A denied termination syscall must never fall through into business code.
  for (;;) ndkp_raw_syscall3(__NR_exit_group, 127, 0, 0);
}
#endif
