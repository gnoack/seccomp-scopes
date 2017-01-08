#include "testlib.h"

#include "../bpf_helper.h"

// Some made up dummy values for the sake of the example.
#define __NR_socket 123
#define AF_INET 1
#define AF_INET6 2
#define SOCK_STREAM 3
#define SOCK_DGRAM 4

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  // TODO: Check for correct jumps.
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

  expect(inet_filter.filter[1].code == BPF_JMP+BPF_JEQ+BPF_K,
         "should be JEQ instruction");
  expect(inet_filter.filter[1].jt == 0,
         "if true, jump nowhere");
  expect(inet_filter.filter[1].jf == 9,
         "if false, skip 9 instructions");
}
