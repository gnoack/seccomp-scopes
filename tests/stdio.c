#include <stdio.h>
#include <stdlib.h>
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

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  expect_ok("stdio", test_printing);
  expect_crash("", test_printing);

  expect_ok("stdio", test_alloc_and_free);
  expect_crash("", test_alloc_and_free);
}
