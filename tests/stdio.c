#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <err.h>

#include "pledge.h"
#include "testlib.h"

void test_printing() {
  printf("(Writing to stdout)");
  fflush(stdout);
  printf("\n");
}

void* (*my_calloc)(size_t, size_t) = calloc;

void test_alloc_and_free() {
  // Note: Using my own pointer to calloc.  Without this, the compiler
  // notices that this code is essentially a noop and optimizes both
  // the malloc and the free away, rendering this test useless in -O1.
  void* x = my_calloc(2000, 1024 * 20);
  free(x);
}

void test_madvise() {
  char* x = malloc(10);
  madvise(x, 10, MADV_RANDOM);
  free(x);
}

void test_gettimeofday() {
  struct timeval time = {};
  gettimeofday(&time, NULL);
}

void test_clock_gettime() {
  struct timespec res;
  if (clock_getres(CLOCK_MONOTONIC, &res)) {
    errx(1, "clock_getres");
  }
  if (clock_gettime(CLOCK_MONOTONIC, &res)) {
    errx(1, "clock_gettime");
  }
}

void test_sendfile() {
  ssize_t result = sendfile(STDOUT_FILENO, STDIN_FILENO, NULL, 0);
  // result doesn't matter much to check that the call is filtered.
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  expect_ok("stdio", test_printing);
  expect_crash("", test_printing);

  expect_ok("stdio", test_alloc_and_free);
  expect_crash("", test_alloc_and_free);

  expect_ok("stdio", test_madvise);
  expect_crash("", test_madvise);

  expect_ok("stdio", test_sendfile);
  expect_crash("", test_sendfile);

  // Getting the time is always permitted.
  // Different ways to get the time are used by different libcs
  // and the gettimeofday() syscall is going through vdso on AMD64.
  // For consisency, getting the time is always permitted, even
  // without pledged scope.
  expect_ok("", test_gettimeofday);
  expect_ok("stdio", test_clock_gettime);
  expect_ok("", test_clock_gettime);
}
