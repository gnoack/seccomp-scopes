#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/net.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <elf.h>

#include <asm/unistd.h>
#include <bsd/stdlib.h>  /* reallocarray */

#include <errno.h>
#include <fcntl.h>  /* open() flags */
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>  /* bool */
#include <stddef.h>  /* for offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf_helper.h"
#include "pledge_internal.h"
#include "pledge_dns.h"
#include "pledge_inet.h"


#if defined(__i386__)
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR	AUDIT_ARCH_X86_64
#elif defined(__ARM_EABI__)
# define ARCH_NR        AUDIT_ARCH_ARM
#else
# warning "Platform does not support seccomp filter yet"
# define ARCH_NR	0
#endif


static void append_filter_prefix(struct sock_fprog* prog) {
  BPFINTO(prog) {
    // break on architecture mismatch
    _LD_ARCH();
    _RET_NEQ(ARCH_NR,        SECCOMP_RET_KILL);
    // load the syscall number
    _LD_NR();
  }
};


static void append_filter_suffix(struct sock_fprog* prog) {
  BPFINTO(prog) {
    // exit and exit_group are always allowed
    _RET_EQ(__NR_exit,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_exit_group, SECCOMP_RET_ALLOW);
    // gettimeofday usually gets called through vdso(7)
    _RET_EQ(__NR_gettimeofday,   SECCOMP_RET_ALLOW);
    // otherwise, break
    _RET(SECCOMP_RET_TRAP);
  }
};


static void append_stdio_filter(unsigned int scopes, struct sock_fprog* prog) {
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


// Opening paths read-only
static void append_rpath_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_RPATH)) {
    return;
  }

  BPFINTO(prog) {
    _RET_EQ(__NR_chdir, SECCOMP_RET_ALLOW);
  }
}


// File creation stuff
static void append_cpath_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_CPATH)) {
    return;
  }

  BPFINTO(prog) {
    _RET_EQ(__NR_link,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_linkat,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_mkdir,     SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_mkdirat,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_rename,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_renameat,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_rmdir,     SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_symlink,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_unlink,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_unlinkat,  SECCOMP_RET_ALLOW);
  }
}


// Special files
static void append_dpath_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_DPATH)) {
    return;
  }

  BPFINTO(prog) {
    _RET_EQ(__NR_mknod,     SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_mknodat,   SECCOMP_RET_ALLOW);
  }
}


static void append_memory_filter(unsigned int scopes, struct sock_fprog* prog) {
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

static void append_open_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & (SCOPE_RPATH | SCOPE_WPATH | SCOPE_CPATH))) {
    return;
  }

  bool may_read = scopes & SCOPE_RPATH;
  bool may_write = scopes & SCOPE_WPATH;
  bool may_rdwr = may_read && may_write;
  bool may_create = scopes & SCOPE_CPATH;

  // We are first checking the access mode (can be masked),
  // then the other flags in the same open() argument.
  //
  // To avoid recalculating jump targets, depending on the pledged
  // promises, some access mode comparisons are comparing to
  // O_ACCMODE+1, which is not possible. Pseudocode:
  //
  // if (nr == __NR_openat) {
  //   flags = arg2;
  // } else if (nr == __NR_open || nr == __NR_creat) {
  //   flags = arg1;
  // } else {
  //   goto exit;
  // }
  // access_mode = flags & O_ACCMODE;
  // if (access_mode == O_RDONLY ||
  //     access_mode == O_ACCMODE+1 ||  /* can't happen */
  //     access_mode == O_ACCMODE+1) {  /* can't happen */
  //   if ((flags | permitted_open_flags) == permitted_open_flags) {
  //     return SECCOMP_RET_ALLOW;
  //   }
  // }
  // exit:
  //
  // The lines marked as "can't happen" may be O_WRONLY and O_RDWR instead.
  //
  // We need to calculate the permitted_open_flags ahead of time.
  // permitted_open_flags includes O_ACCMODE, because that was checked
  // before already.
  int permitted_open_flags = O_ACCMODE;
  if (may_write) {
    permitted_open_flags |= O_TRUNC | O_APPEND;
  }
  if (may_create) {
    permitted_open_flags |= O_CREAT | O_EXCL;
#ifdef O_TMPFILE
    permitted_open_flags |= O_TMPFILE;
#endif  // O_TMPFILE
  }

  // Construct the filter
  DECLARELABEL(checkother);
  DECLARELABEL(cleanup);
  DECLARELABEL(check_flags_argument);
  DECLARELABEL(handle_open_and_creat);
  BPFINTO(prog) {
    // For openat, take 'flags' value from arg 2.
    _JEQ(__NR_openat, 0, ELSE_TO(handle_open_and_creat));
    _LD_ARG(2);  // acc := flags (arg 2)
    _JMP(TO(check_flags_argument));

    LABEL(handle_open_and_creat);
    // For open and creat, take 'flags' value from arg 1.
    _JEQ(__NR_open, 1, 0);
    _JEQ(__NR_creat, 0, ELSE_TO(cleanup));
    _LD_ARG(1);  // acc := flags (arg 1)

    LABEL(check_flags_argument);
    _SET_X_TO_A();  // store X := flags
    // acc := flags & O_ACCMODE
    _AND(O_ACCMODE);
    // Check read/write modes
    _JEQ((may_read  ? O_RDONLY : O_ACCMODE+1), THEN_TO(checkother), 0);  // jeq rdonly checkother
    _JEQ((may_write ? O_WRONLY : O_ACCMODE+1), THEN_TO(checkother), 0);  // jeq wronly checkother
    _JEQ((may_rdwr  ? O_RDWR   : O_ACCMODE+1), THEN_TO(checkother), ELSE_TO(cleanup));  // jne rdwr   cleanup

    LABEL(checkother);  // check the other flag bits
    // if ((flags | permitted) == permitted) return SECCOMP_RET_ALLOW;
    _SET_A_TO_X();  // flags
    _OR(permitted_open_flags);
    _RET_EQ(permitted_open_flags, SECCOMP_RET_ALLOW);

    LABEL(cleanup);
    _LD_NR();
  }
}

static void fill_filter(unsigned int scopes, struct sock_fprog* prog) {
  append_filter_prefix(prog);

  append_stdio_filter(scopes, prog);
  append_open_filter(scopes, prog);
  append_memory_filter(scopes, prog);
  append_rpath_filter(scopes, prog);
  append_cpath_filter(scopes, prog);
  append_dpath_filter(scopes, prog);
  append_inet_filter(scopes, prog);
  append_dns_filter(scopes, prog);

  append_filter_suffix(prog);
}


/* Write OR'd SCOPE_* values to scope_flags, or returns -1. */
static int parse_promises(const char* promises, unsigned int* scope_flags) {
  unsigned int flags = 0;

  char* promises_copy = strdup(promises);
  char* strtok_arg0 = promises_copy;
  char* saveptr = NULL;
  char* item = NULL;
  while ((item = strtok_r(strtok_arg0, " ", &saveptr))) {
    strtok_arg0 = NULL;

    // TODO: This could be a lookup map.
    if (!strcmp(item, "stdio")) {
      flags |= SCOPE_STDIO;
    } else if (!strcmp(item, "rpath")) {
      flags |= SCOPE_RPATH;
    } else if (!strcmp(item, "wpath")) {
      flags |= SCOPE_WPATH;
    } else if (!strcmp(item, "cpath")) {
      flags |= SCOPE_CPATH;
    } else if (!strcmp(item, "dpath")) {
      flags |= SCOPE_DPATH;
    } else if (!strcmp(item, "inet")) {
      flags |= SCOPE_INET;
    } else if (!strcmp(item, "dns_experimental")) {
      flags |= SCOPE_DNS;
    } else {
      errno = EINVAL;
      free(promises_copy);
      return -1;
    }
  }
  *scope_flags = flags;
  free(promises_copy);
  return 0;
}


int pledge(const char* promises, const char* paths[]) {
  int retval = 0;
  struct sock_filter filter_code[BPFSIZE];
  struct sock_fprog prog = {
    .len = 0,
    .filter = filter_code,
  };

  if (paths) {
    // We don't support passing paths on Linux,
    // the argument purely exists for OpenBSD compatibility
    // and in the hope this will be fixed in the kernel. :)
    errno = E2BIG;
    goto error;
  }

  unsigned int scopes = 0;
  if (parse_promises(promises, &scopes) == -1) {
    errno = EINVAL;
    goto error;
  }
  fill_filter(scopes, &prog);

  // Same privilege restrictions should apply to child processes.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    errno = EPERM;  // TODO: Find better error code.
    goto error;
  }
  // Enable the filter.
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    errno = EPERM;
    goto error;
  }

  goto success;

 error:
  retval = -1;

 success:
  return retval;
}
