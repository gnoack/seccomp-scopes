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

#define __LD_STRUCT_VALUE(field)                                         \
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS,                                        \
           offsetof(struct seccomp_data, field))

#define __JMP(j)              BPF_STMT(BPF_JMP+BPF_JA+BPF_K,  (j))
#define __JEQ(value, jt, jf)  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (value), (jt), (jf))
#define __RET(value)          BPF_STMT(BPF_RET+BPF_K,         (value))
#define __OR(value)           BPF_STMT(BPF_ALU+BPF_OR+BPF_K,  (value))
#define __AND(value)          BPF_STMT(BPF_ALU+BPF_AND+BPF_K, (value))
#define __SET_X_TO_A()        BPF_STMT(BPF_MISC+BPF_TAX,      0)
#define __SET_A_TO_X()        BPF_STMT(BPF_MISC+BPF_TXA,      0)
#define __NOP()               __JMP(0)  // There is probably another way.

#define __LD_ARCH() __LD_STRUCT_VALUE(arch)
#define __LD_NR() __LD_STRUCT_VALUE(nr)
#define __LD_ARG(n) __LD_STRUCT_VALUE(args[n])

#define __RET_EQ(value, result) \
  __JEQ((value), 0, 1),         \
  __RET((result))

#define __RET_NEQ(value, result) \
  __JEQ((value), 1, 0),          \
  __RET((result))


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

static struct sock_filter filter_prefix[] = {
  // break on architecture mismatch
  __LD_ARCH(),
  __RET_NEQ(ARCH_NR,        SECCOMP_RET_KILL),
  // load the syscall number
  __LD_NR(),
};


static struct sock_filter filter_suffix[] = {
  // exit and exit_group are always allowed
  __RET_EQ(__NR_exit,       SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_exit_group, SECCOMP_RET_ALLOW),
  // gettimeofday usually gets called through vdso(7)
  __RET_EQ(__NR_gettimeofday,   SECCOMP_RET_ALLOW),
  // otherwise, break
  __RET(SECCOMP_RET_TRAP),
};


/* Flags for the individual promise scopes. */
#define SCOPE_STDIO 0x00000001
#define SCOPE_RPATH 0x00000002
#define SCOPE_WPATH 0x00000004
#define SCOPE_CPATH 0x00000008
#define SCOPE_DPATH 0x00000010
#define SCOPE_INET  0x00000020


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
    // Stuff
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
static struct sock_filter rpath_filter[] = {
  __RET_EQ(__NR_chdir, SECCOMP_RET_ALLOW),
};


// File creation stuff
static struct sock_filter cpath_filter[] = {
  __RET_EQ(__NR_link,      SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_linkat,    SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_mkdir,     SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_mkdirat,   SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_rename,    SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_renameat,  SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_rmdir,     SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_symlink,   SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_unlink,    SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_unlinkat,  SECCOMP_RET_ALLOW),
};


// Special files
static struct sock_filter dpath_filter[] = {
  __RET_EQ(__NR_mknod,     SECCOMP_RET_ALLOW),
  __RET_EQ(__NR_mknodat,   SECCOMP_RET_ALLOW),
};


// Internet (IPv4, IPv6)
static struct sock_filter inet_filter[] = {
  // socket(domain, type, protocol)
  // domain == AF_INET || domain == AF_INET6
  // type == SOCK_STREAM || type == SOCK_DGRAM
  // type may be or'd with SOCK_NONBLOCK, SOCK_CLOEXEC
  __JEQ(__NR_socket, 0, 7),  // if (nr != __NR_socket) goto exit
  __LD_ARG(0),  // domain
  __JEQ(AF_INET,  1, 0),  // if (domain==AF_INET ||
  __JEQ(AF_INET6, 0, 3),  //     domain==AF_INET6) {
  __LD_ARG(1),  // type, TODO: extra flags
  __RET_EQ(SOCK_STREAM,    SECCOMP_RET_ALLOW),
  __RET_EQ(SOCK_DGRAM,     SECCOMP_RET_ALLOW),
  __LD_NR(),
  // exit:

  __RET_EQ(__NR_accept,    SECCOMP_RET_ALLOW),
  // accept(socket, *address, *address_len)

  __RET_EQ(__NR_accept4,   SECCOMP_RET_ALLOW),
  // accept4(socket, *address, *address_len, flags)
  // flags can be SOCK_NONBLOCK, SOCK_CLOEXEC

  __RET_EQ(__NR_bind,      SECCOMP_RET_ALLOW),
  // bind(socket, *address, *address_len)

  __RET_EQ(__NR_connect,   SECCOMP_RET_ALLOW),
  // connect(socket, *address, *address_len)

  __RET_EQ(__NR_listen,    SECCOMP_RET_ALLOW),
  // listen(socket, backlog)
  // backlog is a hint

#ifdef __NR_recv
  __RET_EQ(__NR_recv,      SECCOMP_RET_ALLOW),
  // recv(socket, *buf, len, flags)
#endif  // __NR_recv

#ifdef __NR_send
  __RET_EQ(__NR_send,      SECCOMP_RET_ALLOW),
  // send(socket, *buf, len, flags)
#endif  // __NR_send

  __RET_EQ(__NR_recvfrom,  SECCOMP_RET_ALLOW),
  // recvfrom(socket, *buf, len, flags, *src_addr, *addrlen)

  __RET_EQ(__NR_sendto,    SECCOMP_RET_ALLOW),
  // sendto(socket, *buf, len, flags, *dest_addr, *addrlen)

  __RET_EQ(__NR_recvmsg,   SECCOMP_RET_ALLOW),
  // recvmsg(socket, *msg, flags)

  __RET_EQ(__NR_sendmsg,   SECCOMP_RET_ALLOW),
  // sendmsg(socket, *msg, flags)

  // socketcall(2) is not used any more in modern glibc versions.

  // TODO: sendmmsg, setsockopt, getsockopt, socketpair, getpeername
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
    } else if (!strcmp(item, "dpath")) {
      flags |= SCOPE_DPATH;
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

static void append_filter(struct sock_fprog* prog, struct sock_filter* filter, size_t filter_size) {
  size_t old_size = prog->len;
  prog->len += filter_size;
  if (prog->len >= BPFSIZE) {
    errx(1, "BPF code using too much space.");
  }
  memcpy(prog->filter + old_size, filter, filter_size * sizeof(filter[0]));
}

#define APPEND_FILTER(prog, filter) \
  append_filter(prog, filter, sizeof(filter)/sizeof(filter[0]))

static void append_memory_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_STDIO)) {
    return;
  }

  // PROT_EXEC is *not* allowed.
  int permitted_prot_flags = PROT_READ | PROT_WRITE;
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

    _JEQ(__NR_mprotect, 0 /* checkprot */, 4 /* out */);

    // checkprot:
    _LD_ARG(2);  // acc := prot (same arg position on all three syscalls)
    _OR(permitted_prot_flags);
    _RET_EQ(permitted_prot_flags, SECCOMP_RET_ALLOW);  // 2 instructions

    // out:
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
  DECLARELABEL(handle_open_and_creat);
  DECLARELABEL(entry);
  BPFINTO(prog) {
    _JEQ(__NR_openat, 0, ELSE_TO(handle_open_and_creat));
    _LD_ARG(2);  // acc := flags (arg 2)
    _JMP(TO(entry));

    LABEL(handle_open_and_creat);
    _JEQ(__NR_open, 1, 0);
    _JEQ(__NR_creat, 0, 10 /* cleanup */);
    _LD_ARG(1);  // acc := flags (arg 1)

    LABEL(entry);
    _SET_X_TO_A();  // store X := flags
    // acc := flags & O_ACCMODE
    _AND(O_ACCMODE);
    // Check read/write modes
    _JEQ((may_read  ? O_RDONLY : O_ACCMODE+1), 2, 0);  // jeq rdonly checkother
    _JEQ((may_write ? O_WRONLY : O_ACCMODE+1), 1, 0);  // jeq wronly checkother
    _JEQ((may_rdwr  ? O_RDWR   : O_ACCMODE+1), 0, 4);  // jne rdwr   cleanup
    // checkother:
    // if ((flags | permitted) == permitted) return SECCOMP_RET_ALLOW;
    _SET_A_TO_X();  // flags
    _OR(permitted_open_flags);
    _JEQ(permitted_open_flags, 0, 1);  // skip 1 if not equal
    _RET(SECCOMP_RET_ALLOW);
    // cleanup:
    _LD_NR();
  }
}

static void fill_filter(unsigned int scopes, struct sock_fprog* prog) {
  APPEND_FILTER(prog, filter_prefix);

  append_stdio_filter(scopes, prog);
  append_open_filter(scopes, prog);
  append_memory_filter(scopes, prog);
  if (scopes & SCOPE_RPATH) {
    APPEND_FILTER(prog, rpath_filter);
  }
  if (scopes & SCOPE_CPATH) {
    APPEND_FILTER(prog, cpath_filter);
  }
  if (scopes & SCOPE_DPATH) {
    APPEND_FILTER(prog, dpath_filter);
  }
  if (scopes & SCOPE_INET) {
    APPEND_FILTER(prog, inet_filter);
  }

  APPEND_FILTER(prog, filter_suffix);
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

  // Actually enable this.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    errno = EPERM;  // TODO: Find better error code.
    goto error;
  }
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
