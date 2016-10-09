#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <err.h>

#include "pledge.h"
#include "testlib.h"

void test_printing() {
  printf("Writing to stdout: OK\n");
}

void test_alloc_and_free() {
  char* x = malloc(2000 * 1024 * 20);
  free(x);
}

void test_madvise() {
  char* x = malloc(10);
  madvise(x, 10, MADV_RANDOM);
  free(x);
}

void test_time() {
  struct timeval time = {};
  gettimeofday(&time, NULL);

  // TODO: Test clock_gettimeofday().
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  expect_ok("stdio", test_printing);
  expect_crash("", test_printing);

  expect_ok("stdio", test_alloc_and_free);
  expect_crash("", test_alloc_and_free);

  expect_ok("stdio", test_madvise);
  expect_crash("", test_madvise);

  expect_ok("stdio", test_time);
  expect_crash("", test_time);
}
