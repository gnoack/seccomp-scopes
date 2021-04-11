#include <sys/prctl.h>  /* prctl() */

#include <linux/audit.h>  /* ARCH_NR */

#include <asm/unistd.h>  /* syscall numbers */

#include <errno.h>  /* ERRNO */
#include <malloc.h>
#include <string.h>  /* stddup, strcmp, strtok_r */

#include "bpf_helper.h"
#include "pledge_internal.h"
#include "pledge_dns.h"
#include "pledge_inet.h"
#include "pledge_path.h"
#include "pledge_stdio.h"


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
    // gettimeofday gets called through vdso(7) on AMD64
    // and can't be filtered in this case.
    // clock_gettime is equivalent and is used for other
    //
    _RET_EQ(__NR_gettimeofday,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_clock_gettime, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_clock_getres,  SECCOMP_RET_ALLOW);
    // otherwise, break
    _RET(SECCOMP_RET_TRAP);
  }
};


static void fill_filter(unsigned int scopes, struct sock_fprog* prog) {
  append_filter_prefix(prog);

  // Roughly ordered in order of syscall likelihood.
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
#ifndef __GLIBC__
    } else if (!strcmp(item, "dns_experimental")) {
      // DNS support is not supported on Glibc.
      flags |= SCOPE_DNS;
#endif // not __GLIBC__
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
    return -1;
  }

  unsigned int scopes = 0;
  if (parse_promises(promises, &scopes) < 0) {
    errno = EINVAL;
    return -1;
  }
  fill_filter(scopes, &prog);

  // Same privilege restrictions should apply to child processes.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    errno = EPERM;  // TODO: Find better error code.
    return -1;
  }
  // Enable the filter.
  // TODO: Use seccomp(2).
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
    errno = EPERM;
    return -1;
  }

  return 0;
}
