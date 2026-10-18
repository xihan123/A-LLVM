// Link with --wrap to make accidental libc termination or debug writes observable.
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

pid_t __wrap_getpid(void) { return -1; }
int __wrap_kill(pid_t pid, int sig) { (void)pid; (void)sig; return 0; }
long __wrap_syscall(long nr, ...) { (void)nr; return 0; }
ssize_t __wrap_write(int fd, const void* data, size_t n) { (void)fd; (void)data; return n; }

// Run before SelfCheck's priority-101 constructor.
__attribute__((constructor(100))) static void deny_kill(void) {
  if (!getenv("NDKP_TEST_DENY_KILL")) return;
  struct sock_filter rules[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {sizeof rules / sizeof rules[0], rules};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) _exit(98);
}
