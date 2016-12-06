// An experimental way of reliably putting together BPF code.
//
// BPF code needs to know how many instructions to skip, and counting
// instructions manually is error prone.
//
// On the downside, this is technically written to count instructions
// at runtime, and to check at runtime whether hardcoded label
// positions are correct.
//
// On the upside, gcc can optimize away the counter and the related
// checks.
//
// All checks that should be optimized away have an error message with
// the substring "BADBPF".  If your compiled binary doesn't contain
// that word, the counter is probably compiled away.

#include <asm/unistd.h>
#include <stdio.h>
#include <err.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>


#define _BPF_STMT(...) do {                                             \
    __filter[__filter_ip] = (struct sock_filter) BPF_STMT(__VA_ARGS__); \
    __filter_ip++;                                                      \
  } while(0);

#define _BPF_JUMP(...) do {                                             \
    __filter[__filter_ip] = (struct sock_filter) BPF_JUMP(__VA_ARGS__); \
    __filter_ip++;                                                      \
  } while(0);

#define _JMP(j)              _BPF_STMT(BPF_JMP+BPF_JA+BPF_K,  (j))
#define _JEQ(value, jt, jf)  _BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (value), (jt), (jf))
#define _RET(value)          _BPF_STMT(BPF_RET+BPF_K,         (value))
#define _OR(value)           _BPF_STMT(BPF_ALU+BPF_OR+BPF_K,  (value))
#define _AND(value)          _BPF_STMT(BPF_ALU+BPF_AND+BPF_K, (value))
#define _SET_X_TO_A()        _BPF_STMT(BPF_MISC+BPF_TAX,      0)
#define _SET_A_TO_X()        _BPF_STMT(BPF_MISC+BPF_TXA,      0)
#define _NOP()               _JMP(0)  // There is probably another way.

#define _LD_STRUCT_VALUE(field)                                         \
  _BPF_STMT(BPF_LD+BPF_W+BPF_ABS,                                       \
            offsetof(struct seccomp_data, field))

#define _LD_ARCH() _LD_STRUCT_VALUE(arch)
#define _LD_NR() _LD_STRUCT_VALUE(nr)
#define _LD_ARG(n) _LD_STRUCT_VALUE(args[n])

#define _RET_EQ(value, result) \
  _JEQ((value), 0, 1);         \
  _RET((result))

#define _RET_NEQ(value, result) \
  _JEQ((value), 1, 0);          \
  _RET((result))


// Convert an absolute label position into a relative one, as needed
// in BPF code (== how many instructions to skip).
#define TO(name) (name - __filter_ip - 1)

// At the place where the label is, check that the predicted label
// position is correct.
#define LABEL(name)                                                     \
  if (__filter_ip != name) {                                            \
    errx(1, "BADBPF: Label " #name " is at position %d, not %d", __filter_ip, name); \
  }


#define BPFFILTER                               \
  unsigned __filter_ip = 0;                          \
  static struct sock_filter __filter[20];

#define BPFFILTER_DONE(name)                                     \
  if (__filter_ip >= (sizeof(__filter) / sizeof(__filter[0]))) { \
    errx(1, "BADBPF: BPF code using too much space.");           \
  }                                                              \
  struct sock_fprog name = {                                     \
    .len = __filter_ip,                                          \
    .filter = __filter,                                          \
  };


int main() {
  // Declare label positions ahead of time.
  unsigned deny = 11;

  // In the filter, TO(x) calculates the relative position of label x
  // (== how many instructions to be skipped from here to get to x).
  // LABEL(x) declares the position of label x.
  BPFFILTER {
    _LD_NR();
    // socket(domain, type, protocol)
    // domain == AF_INET || domain == AF_INET6
    // type == SOCK_STREAM || type == SOCK_DGRAM
    // type may be or'd with SOCK_NONBLOCK, SOCK_CLOEXEC
    _JEQ(__NR_socket, 0, TO(deny));  // if (nr != __NR_socket) goto deny
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
  BPFFILTER_DONE(inet_filter);

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    errx(1, "Can't set NO_NEW_PRIVS.");
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &inet_filter) == -1) {
    errx(1, "Can't set seccomp filter.");
  }

  puts("OK");
}
