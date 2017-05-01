#include <sys/socket.h>

#include <asm/unistd.h>  /* syscall numbers */

#include "bpf_helper.h"
#include "pledge_inet.h"
#include "pledge_internal.h"

// Internet (IPv4, IPv6)
void append_inet_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_INET)) {
    return;
  }

  DECLARELABEL(not_socket);
  BPFINTO(prog) {
    // socket(domain, type, protocol)
    // Should be allowed if:
    //     domain == AF_INET || domain == AF_INET6
    // and type == SOCK_STREAM || type == SOCK_DGRAM
    //     and type may be or'd with SOCK_NONBLOCK, SOCK_CLOEXEC
    _JEQ(__NR_socket, 0, ELSE_TO(not_socket));  // if (nr != __NR_socket) goto not_socket
    _LD_ARG(0);  // socket() domain
    _JEQ(AF_INET,  1, 0);                     // if (domain==AF_INET ||
    _JEQ(AF_INET6, 0, ELSE_TO(not_socket));   //     domain==AF_INET6) {
    _LD_ARG(1);  // socket() type, TODO: extra flags
    _RET_EQ(SOCK_STREAM,    SECCOMP_RET_ALLOW);
    _RET_EQ(SOCK_DGRAM,     SECCOMP_RET_ALLOW);
    _LD_NR();

    LABEL(not_socket);
    _RET_EQ(__NR_accept,    SECCOMP_RET_ALLOW);
    // accept(socket, *address, *address_len)

    _RET_EQ(__NR_accept4,   SECCOMP_RET_ALLOW);
    // accept4(socket, *address, *address_len, flags)
    // flags can be SOCK_NONBLOCK, SOCK_CLOEXEC

    _RET_EQ(__NR_bind,      SECCOMP_RET_ALLOW);
    // bind(socket, *address, *address_len)

    _RET_EQ(__NR_connect,   SECCOMP_RET_ALLOW);
    // connect(socket, *address, *address_len)

    _RET_EQ(__NR_listen,    SECCOMP_RET_ALLOW);
    // listen(socket, backlog)
    // backlog is a hint

#ifdef __NR_recv
    _RET_EQ(__NR_recv,      SECCOMP_RET_ALLOW);
    // recv(socket, *buf, len, flags)
#endif  // __NR_recv

#ifdef __NR_send
    _RET_EQ(__NR_send,      SECCOMP_RET_ALLOW);
    // send(socket, *buf, len, flags)
#endif  // __NR_send

    _RET_EQ(__NR_recvfrom,  SECCOMP_RET_ALLOW);
    // recvfrom(socket, *buf, len, flags, *src_addr, *addrlen)

    _RET_EQ(__NR_sendto,    SECCOMP_RET_ALLOW);
    // sendto(socket, *buf, len, flags, *dest_addr, *addrlen)

    _RET_EQ(__NR_recvmsg,   SECCOMP_RET_ALLOW);
    // recvmsg(socket, *msg, flags)

    _RET_EQ(__NR_sendmsg,   SECCOMP_RET_ALLOW);
    // sendmsg(socket, *msg, flags)

    _RET_EQ(__NR_sendmmsg,  SECCOMP_RET_ALLOW);
    // sendmmsg(socket, *msgvec, vlen, flags) (multiplexed sendmsg)

    // socketcall(2) is not used any more in modern glibc versions.

    // TODO: setsockopt, getsockopt, socketpair, getpeername
  }
};
