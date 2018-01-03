/*
 * musl: DNS scope works on musl.
 * Known issue: Opens up open() and socket() syscalls too broadly.
 *
 * glibc: You can't pledge DNS on glibc -- on DNS lookups, glibc is
 * looking up shared library plugins via it's NSS service, and these
 * can do all kinds of syscalls.
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


void append_dns_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_DNS)) {
    return;
  }

#ifdef __GLIBC__
#warning "DNS scope is not supported on glibc.  libnss is too complicated."
  return;
#else // not __GLIBC__
  BPFINTO(prog) {
    // TODO: open() permission is too broad.
    // (This is used for /etc/hosts, /etc/resolv.conf)
    _RET_EQ(__NR_open, SECCOMP_RET_ALLOW);  // /etc/hosts
    _RET_EQ(__NR_readv, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_close, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_fcntl64, SECCOMP_RET_ALLOW);

    // TODO: socket() permission is too broad. (used for DNS requests)
    _RET_EQ(__NR_socket, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_poll, SECCOMP_RET_ALLOW);
  }
#endif  // not __GLIBC__
}
