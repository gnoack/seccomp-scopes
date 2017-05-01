#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "testlib.h"

void test_ipv4tcp() { socket(AF_INET, SOCK_STREAM, 0); }
void test_ipv6tcp() { socket(AF_INET6, SOCK_STREAM, 0); }
void test_ipv4udp() { socket(AF_INET, SOCK_DGRAM, 0); }
void test_ipv6udp() { socket(AF_INET6, SOCK_DGRAM, 0); }
void test_x25()     { socket(AF_X25, SOCK_DGRAM, 0); }
void test_inetraw() { socket(AF_INET, SOCK_RAW, 0); }

void test_gethostbyname() {
  struct hostent* unused = gethostbyname("www.google.com");
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  // socket() without inet permission crashes.
  expect_crash("stdio", test_ipv4tcp);

  // socket() with inet permission in working scenarios.
  expect_ok("stdio inet", test_ipv4tcp);
  expect_ok("stdio inet", test_ipv6tcp);
  expect_ok("stdio inet", test_ipv4udp);
  expect_ok("stdio inet", test_ipv6udp);

  // socket() with inet permission with x25 crashes
  expect_crash("stdio inet", test_x25);
  // socket() with inet permission with raw socket crashes
  expect_crash("stdio inet", test_inetraw);

  expect_ok("inet dns_experimental", test_gethostbyname);
  // inet alone is not enough for gethostbyname().
  expect_crash("inet", test_gethostbyname);
}
