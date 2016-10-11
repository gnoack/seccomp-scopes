#include <sys/types.h>
#include <sys/resource.h>
#include <sys/prctl.h>

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
#include <stddef.h>  /* for offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#define _LD_STRUCT_VALUE(field)                                         \
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS,                                        \
           offsetof(struct seccomp_data, field))

#define _JMP(j)              BPF_STMT(BPF_JMP+BPF_JA+BPF_K,  (j))
#define _JEQ(value, jt, jf)  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (value), (jt), (jf))
#define _RET(value)          BPF_STMT(BPF_RET+BPF_K,         (value))
#define _OR(value)           BPF_STMT(BPF_ALU+BPF_OR+BPF_K,  (value))
#define _AND(value)          BPF_STMT(BPF_ALU+BPF_AND+BPF_K, (value))
#define _SET_X_TO_A()        BPF_STMT(BPF_MISC+BPF_TAX,      0)
#define _SET_A_TO_X()        BPF_STMT(BPF_MISC+BPF_TXA,      0)

#define _LD_ARCH() _LD_STRUCT_VALUE(arch)
#define _LD_NR() _LD_STRUCT_VALUE(nr)
#define _LD_ARG(n) _LD_STRUCT_VALUE(args[n])

#define _RET_EQ(value, result) \
  _JEQ((value), 0, 1),         \
  _RET((result))

#define _RET_NEQ(value, result) \
  _JEQ((value), 1, 0),          \
  _RET((result))


struct sock_filter filter_prefix[] = {
  // break on architecture mismatch
  _LD_ARCH(),
  _RET_NEQ(ARCH_NR,        SECCOMP_RET_KILL),
  // load the syscall number
  _LD_NR(),
};


struct sock_filter filter_suffix[] = {
  // exit and exit_group are always allowed
  _RET_EQ(__NR_exit,       SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_exit_group, SECCOMP_RET_ALLOW),
  // gettimeofday usually gets called through vdso(7)
  _RET_EQ(__NR_gettimeofday,   SECCOMP_RET_ALLOW),
  // otherwise, break
  _RET(SECCOMP_RET_TRAP),
};


/* Flags for the individual promise scopes. */
#define SCOPE_STDIO 0x00000001
#define SCOPE_RPATH 0x00000002
#define SCOPE_WPATH 0x00000004
#define SCOPE_CPATH 0x00000008
#define SCOPE_INET  0x00000010


struct sock_filter stdio_filter[] = {
  // Memory allocation
  _RET_EQ(__NR_brk,            SECCOMP_RET_ALLOW),
#ifdef __NR_mmap
  _RET_EQ(__NR_mmap,           SECCOMP_RET_ALLOW),
#endif  // __NR_mmap
#ifdef __NR_mmap2
  _RET_EQ(__NR_mmap2,          SECCOMP_RET_ALLOW),
#endif  // __NR_mmap2
  _RET_EQ(__NR_munmap,         SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_madvise,        SECCOMP_RET_ALLOW),
  // Reading and writing
  _RET_EQ(__NR_read,           SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_readv,          SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_pread64,        SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_preadv,         SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_preadv2,        SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_write,          SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_writev,         SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_pwrite64,       SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_pwritev,        SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_pwritev2,       SECCOMP_RET_ALLOW),
  // Stuff
  _RET_EQ(__NR_fstat,          SECCOMP_RET_ALLOW),
#ifdef __NR_fstat64
  _RET_EQ(__NR_fstat64,        SECCOMP_RET_ALLOW),
#endif  // __NR_fstat64
  // Time
  _RET_EQ(__NR_clock_gettime,  SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_clock_getres,   SECCOMP_RET_ALLOW),
  // Closing file descriptors
  _RET_EQ(__NR_close,          SECCOMP_RET_ALLOW),
};


// Opening paths read-only
struct sock_filter rpath_filter[] = {
  _RET_EQ(__NR_chdir, SECCOMP_RET_ALLOW),
};


// Opening paths write-only
struct sock_filter wpath_filter[] = {
};



// File creation stuff
struct sock_filter cpath_filter[] = {
  _RET_EQ(__NR_creat,     SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_mkdir,     SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_mkdirat,   SECCOMP_RET_ALLOW),
};


// Internet
// TODO: This does not restrict well enough.
struct sock_filter inet_filter[] = {
  _RET_EQ(__NR_accept,    SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_accept4,   SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_bind,      SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_connect,   SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_listen,    SECCOMP_RET_ALLOW),
  // socketcall(2) is not used any more in modern glibc versions.
};


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
    } else if (!strcmp(item, "inet")) {
      flags |= SCOPE_INET;
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

void append_filter(struct sock_fprog* prog, struct sock_filter* filter, size_t filter_size) {
  size_t old_size = prog->len;
  prog->len += filter_size;
  prog->filter = reallocarray(prog->filter, sizeof(prog->filter[0]), prog->len);
  memcpy(prog->filter + old_size, filter, filter_size * sizeof(filter[0]));
}

#define APPEND_FILTER(prog, filter) \
  append_filter(prog, filter, sizeof(filter)/sizeof(filter[0]))

static void append_open_filter(unsigned int scopes, struct sock_fprog* prog) {
  int may_read = scopes & SCOPE_RPATH;
  int may_write = scopes & SCOPE_WPATH;
  int may_rdwr = may_read && may_write;
  int may_create = scopes & SCOPE_CPATH;

  // We are first checking the access mode (can be masked),
  // then the other flags in the same open() argument.
  //
  // To avoid recalculating jump targets, depending on the pledged
  // promises, some access mode comparisons are comparing to
  // O_ACCMODE+1, which is not possible. Pseudocode:
  //
  // if (nr == __NR_openat) {
  //   flags = arg2;
  // } else if (nr == __NR_open) {
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
  struct sock_filter openflags_filter[] = {
    _JEQ(__NR_openat, 0, 2),
    _LD_ARG(2),  // acc := flags (arg 2)
    _JMP(2),     // goto entry

    _JEQ(__NR_open, 0, 11),
    _LD_ARG(1),  // acc := flags (arg 1)

    // entry:
    _SET_X_TO_A(),  // store X := flags
    // acc := flags & O_ACCMODE
    _AND(O_ACCMODE),
    // Check read/write modes
    _JEQ((may_read  ? O_RDONLY : O_ACCMODE+1), 2, 0),  // jeq rdonly checkother
    _JEQ((may_write ? O_WRONLY : O_ACCMODE+1), 1, 0),  // jeq wronly checkother
    _JEQ((may_rdwr  ? O_RDWR   : O_ACCMODE+1), 0, 4),  // jne rdwr   cleanup
    // checkother:
    // if ((flags | permitted) == permitted) return SECCOMP_RET_ALLOW;
    _SET_A_TO_X(),  // flags
    _OR(permitted_open_flags),
    _JEQ(permitted_open_flags, 0, 1),  // skip 1 if not equal
    _RET(SECCOMP_RET_ALLOW),
    // cleanup:
    _LD_NR(),
  };
  APPEND_FILTER(prog, openflags_filter);
}

static void fill_filter(unsigned int scopes, struct sock_fprog* prog) {
  APPEND_FILTER(prog, filter_prefix);

  if (scopes & SCOPE_STDIO) {
    APPEND_FILTER(prog, stdio_filter);
  }
  if (scopes & (SCOPE_RPATH | SCOPE_WPATH | SCOPE_CPATH)) {
    append_open_filter(scopes, prog);
  }
  if (scopes & SCOPE_RPATH) {
    APPEND_FILTER(prog, rpath_filter);
  }
  if (scopes & SCOPE_WPATH) {
    APPEND_FILTER(prog, wpath_filter);
  }
  if (scopes & SCOPE_CPATH) {
    APPEND_FILTER(prog, cpath_filter);
  }
  if (scopes & SCOPE_INET) {
    APPEND_FILTER(prog, inet_filter);
  }

  APPEND_FILTER(prog, filter_suffix);
}


int pledge(const char* promises, const char* paths[]) {
  int retval = 0;
  struct sock_fprog prog = {
    .len = 0,
    .filter = malloc(0),  // TODO: Error checking.
  };

  if (paths) {
    // We don't support passing paths on Linux,
    // the argument purely exists for OpenBSD compatibility
    // and in the hope this will be fixed in the kernel. :)
    errno = E2BIG;
    retval = -1;
    goto cleanup;
  }

  unsigned int scopes = 0;
  if (parse_promises(promises, &scopes) == -1) {
    errno = EINVAL;
    retval = -1;
    goto cleanup;
  }
  fill_filter(scopes, &prog);

  // Actually enable this.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    errno = EPERM;  // TODO: Find better error code.
    retval = -1;
    goto cleanup;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    errno = EPERM;
    retval = -1;
    goto cleanup;
  }

 cleanup:
  free(prog.filter);
  return retval;
}
