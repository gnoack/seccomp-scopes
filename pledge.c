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
#include <fcntl.h>  /* O_RDONLY */
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
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, field))

#define _JEQ(value, jt, jf)                             \
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (value), jt, jf)

#define _RET(value) \
  BPF_STMT(BPF_RET+BPF_K, (value))

#define _LD_ARCH() _LD_STRUCT_VALUE(arch)
#define _LD_NR() _LD_STRUCT_VALUE(nr)
#define _LD_ARG(n) _LD_STRUCT_VALUE(args[n])

#define _RET_EQ(value, result) \
  _JEQ((value), 0, 1),         \
  _RET((result))

#define _RET_NEQ(value, result) \
  _JEQ((value), 1, 0),          \
  _RET((result))


struct sock_filter filter_prelude[] = {
  // break on architecture mismatch
  _LD_ARCH(),
  _RET_NEQ(ARCH_NR,        SECCOMP_RET_KILL),
  // load the syscall number
  _LD_NR(),
};


struct sock_filter filter_appendix[] = {
  // exit and exit_group are always allowed
  _RET_EQ(__NR_exit,       SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_exit_group, SECCOMP_RET_ALLOW),
  // otherwise, break
  _RET(SECCOMP_RET_TRAP),
};


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
  _RET_EQ(__NR_clock_gettime,  SECCOMP_RET_ALLOW),
  _RET_EQ(__NR_close,          SECCOMP_RET_ALLOW),
};


// Opening paths read-only
struct sock_filter rpath_filter[] = {
  _JEQ(__NR_open, 0, 4),                 // skip 4 if acc != __NR_open
  _LD_ARG(1),                            // acc := 'mode' argument
  _RET_EQ(O_RDONLY, SECCOMP_RET_ALLOW),  // allow if readonly mode (2 instr)
  _LD_NR(),                              // acc := syscall number
};


// Opening paths write-only
// TODO: Make sure this can't create files.
struct sock_filter wpath_filter[] = {
  _JEQ(__NR_open, 0, 4),                 // skip 4 if acc != __NR_open
  _LD_ARG(1),                            // acc := 'mode' argument
  // TODO: for fopen(..., "w"), arg1 is 0x241.
  // That is O_EXCL (0x200) | ??? (0x40) | O_WRONLY (0x1).
  // Compare /usr/include/asm{,-generic}/fcntl.h
  // Compare http://osxr.org:8080/glibc/source/libio/fileops.c#0266
  // omode = O_WRONLY, oflags = O_CREAT|O_TRUNC
  // mode := omode | oflags
  // TODO: This is also creating files.
  _RET_EQ(O_WRONLY|O_CREAT|O_TRUNC, SECCOMP_RET_ALLOW),  // allow if writeonly mode (2 instr)
  _LD_NR(),                              // acc := syscall number
};


void append_filter(struct sock_fprog* prog, struct sock_filter* filter, size_t filter_size) {
  size_t old_size = prog->len;
  prog->len += filter_size;
  prog->filter = reallocarray(prog->filter, sizeof(prog->filter[0]), prog->len);
  memcpy(prog->filter + old_size, filter, filter_size * sizeof(filter[0]));
}


#define APPEND_FILTER(prog, filter) append_filter(prog, filter, sizeof(filter)/sizeof(filter[0]))


static int fill_filter(const char* promises, struct sock_fprog* prog) {
  APPEND_FILTER(prog, filter_prelude);

  // Split promises string into items.
  char* promises_copy = strdup(promises);
  char* strtok_arg0 = promises_copy;
  char* saveptr = NULL;
  char* item = NULL;
  while ((item = strtok_r(strtok_arg0, " ", &saveptr))) {
    strtok_arg0 = NULL;

    if (!strcmp(item, "stdio")) {
      APPEND_FILTER(prog, stdio_filter);
    } else if (!strcmp(item, "rpath")) {
      APPEND_FILTER(prog, rpath_filter);
    } else if (!strcmp(item, "wpath")) {
      APPEND_FILTER(prog, wpath_filter);
    } else {
      free(promises_copy);
      errno = EINVAL;
      return -1;
    }
  }
  APPEND_FILTER(prog, filter_appendix);
  free(promises_copy);
  return 0;
}


int pledge(const char* promises, const char* paths[]) {
  struct sock_fprog prog = {
    .len = 0,
    .filter = malloc(0),  // TODO: Error checking.
  };

  if (paths) {
    // We don't support paths on Linux,
    // the argument purely exists for OpenBSD compatibility
    // and in the hope this will be fixed in the kernel. :)
    return E2BIG;
  }

  if (fill_filter(promises, &prog) == -1) {
    goto cleanup;
  }

  // Actually enable this.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    errno = EPERM;  // TODO: Find better error code.
    goto cleanup;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    errno = EPERM;
    goto cleanup;
  }

 cleanup:
  free(prog.filter);
  return errno ? -1 : 0;
}
