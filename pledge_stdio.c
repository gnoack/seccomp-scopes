#include <sys/mman.h>  /* PROT_* flags */

#include <sys/syscall.h>  /* syscall numbers */

#include "bpf_helper.h"
#include "pledge_stdio.h"
#include "pledge_internal.h"


void append_stdio_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_STDIO)) {
    return;
  }

  BPFINTO(prog) {
    // Reading and writing
    _RET_EQ(__NR_read,           SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_readv,          SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pread64,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_preadv,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_preadv2,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_write,          SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_writev,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pwrite64,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pwritev,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pwritev2,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_sendfile,       SECCOMP_RET_ALLOW);  // data copy between fds
    // Stat
    _RET_EQ(__NR_fstat,          SECCOMP_RET_ALLOW);
#ifdef __NR_fstat64
    _RET_EQ(__NR_fstat64,        SECCOMP_RET_ALLOW);
#endif  // __NR_fstat64
    // Time
    _RET_EQ(__NR_clock_gettime,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_clock_getres,   SECCOMP_RET_ALLOW);
    // Closing file descriptors
    _RET_EQ(__NR_close,          SECCOMP_RET_ALLOW);
  }
}


void append_memory_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_STDIO)) {
    return;
  }

  // PROT_EXEC is *not* allowed.
  int permitted_prot_flags = PROT_READ | PROT_WRITE;

  DECLARELABEL(out);
  BPFINTO(prog) {
    // Generic memory allocation
    _RET_EQ(__NR_brk,            SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_munmap,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_madvise,        SECCOMP_RET_ALLOW);

    // mmap(), mmap2(), mprotect() only allowed if prot is not PROT_EXEC
    //
    // if (nr == __NR_mmap2 || nr == __NR_mmap || nr == __NR_mprotect) {
    //   int prot = arg2;
    //   if ((prot | permitted_prot_flags) == permitted_prot_flags) {
    //     return SECCOMP_RET_ALLOW;
    //   }
    // }
#ifdef __NR_mmap2
    _JEQ(__NR_mmap2,    2 /* checkprot */, 0);
#endif  // __NR_mmap2

#ifdef __NR_mmap
    _JEQ(__NR_mmap,     1 /* checkprot */, 0);
#else
    _NOP();  // To keep jump sizes correct.
#endif  // __NR_mmap

    _JEQ(__NR_mprotect, 0 /* checkprot */, ELSE_TO(out));

    // checkprot:
    _LD_ARG(2);  // acc := prot (same arg position on all three syscalls)
    _OR(permitted_prot_flags);
    _RET_EQ(permitted_prot_flags, SECCOMP_RET_ALLOW);  // 2 instructions

    LABEL(out);
    _LD_NR();
  };
}
