// An experimental way of reliably putting together BPF code.

#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>

#include "../bpf_helper.h"

// -------------------------------------------------------------------
// Main function putting together a test BPF.
// -------------------------------------------------------------------

// TODO(gnoack): Convert this to a test checking for correct jumps.
int main() {
  DECLARELABEL(deny);

  // In the filter, TO(x) calculates the relative position of label x
  // (== how many instructions to be skipped from here to get to x).
  // LABEL(x) declares the position of label x.
  BPFFILTER(inet_filter) {
    _LD_NR();
    // socket(domain, type, protocol)
    // domain == AF_INET || domain == AF_INET6
    // type == SOCK_STREAM || type == SOCK_DGRAM
    // type may be or'd with SOCK_NONBLOCK, SOCK_CLOEXEC
    _JEQ(__NR_socket, 0, ELSE_TO(deny));  // if (nr != __NR_socket) goto deny
    _LD_ARG(0);  // domain
    _JEQ(AF_INET,  1, 0);  // if (domain==AF_INET ||
    _JEQ(AF_INET6, 0, 3);  //     domain==AF_INET6) {
    _LD_ARG(1);  // type, TODO: extra flags
    _RET_EQ(SOCK_STREAM,    SECCOMP_RET_ALLOW);
    _RET_EQ(SOCK_DGRAM,     SECCOMP_RET_ALLOW);
    _LD_NR();
    LABEL(deny);
    _RET(SECCOMP_RET_TRAP);
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    errx(1, "Can't set NO_NEW_PRIVS.");
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &inet_filter) == -1) {
    errx(1, "Can't set seccomp filter.");
  }

  puts("OK");
}
