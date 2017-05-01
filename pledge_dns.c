/*
 * EXPERIMENTAL: The DNS filter code is not working well with the
 * glibc dns client libraries.  Glibc switches between different
 * lookup backends depending on the contents of /etc/nsswitch.conf,
 * which get read at the time of first usage.  The backends are
 * implemented as shared libraries (NSS Modules), get loaded in at
 * runtime and we would need to parse nsswitch.conf first in order to
 * predict which syscalls will be required.
 */

// Needed for gethostbyname() call.
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <asm/unistd.h>  /* syscall numbers */

#include "bpf_helper.h"
#include "pledge_dns.h"
#include "pledge_internal.h"


// TODO: This is very experimental and grants much too broad permissions.
void append_dns_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_DNS)) {
    return;
  }

  // This is a bad bad hack just to initialize libnss, so that
  // subsequent calls can skip various syscalls.  Without this, we
  // would also need to permit: socket(), connect(), mmap2(),
  // mprotect(), munmap(), uname()

  // Libnss is very flexible and it is difficult to hardcode the
  // filter; the domain name lookup can happen in very different
  // places depending on your configuration.

  // TODO: We should not need to issue a DNS request to initialize the
  // library!
  struct hostent* h = gethostbyname("www");

  BPFINTO(prog) {
    // TODO: This tries opening:
    // /run/systemd/machines/$HOSTNAME (-1) -- glibc is systemd specific now? o_O
    // /sys/fs/kdbus/0-system/bus (-1)
    // /dev/urandom
    // /etc/hosts - this too, but why open it every time?!
    _RET_EQ(__NR_open, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_fstat64, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_read, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_close, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getpid, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_rt_sigprocmask, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getsockopt, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_setsockopt, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_clock_gettime,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getsockname,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_geteuid32,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_ppoll,  SECCOMP_RET_ALLOW);
  }
}
