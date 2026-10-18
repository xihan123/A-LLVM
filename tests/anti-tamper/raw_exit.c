// Raw termination must work even when libc termination entrypoints are replaced.
#include "raw_syscall.h"
#include <assert.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

pid_t __wrap_getpid(void) { return -1; }
int __wrap_kill(pid_t pid, int sig) { (void)pid; (void)sig; return 0; }
int __wrap_tgkill(pid_t pid, pid_t tid, int sig) { (void)pid; (void)tid; (void)sig; return 0; }
int __wrap_raise(int sig) { (void)sig; return 0; }
long __wrap_syscall(long number, ...) { (void)number; return 0; }

int main(void) {
  for (int deny = 0; deny < 2; ++deny) {
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
      alarm(10);
      if (deny) {
        struct sock_filter rules[] = {
          BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
          BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 1),
          BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
          BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog program = {sizeof rules / sizeof rules[0], rules};
        assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        assert(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
      }
      ndkp_raw_terminate();
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (deny) assert(WIFEXITED(status) && WEXITSTATUS(status) == 127);
    else assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  }
  puts("raw termination: libc hooks bypassed, exit_group fallback OK");
}
