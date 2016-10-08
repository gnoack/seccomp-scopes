#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "pledge.h"
#include "testlib.h"

void test_file_writing() {
  FILE* f = fopen(".throwaway-test-output", "w");
  char* buf = "Hello, world.";
  size_t size = fwrite(buf, sizeof(buf), 1, f);
  if (ferror(f)) {
    puts("Error writing: BROKEN");
  }
  fclose(f);

  puts("Writing files with 'wpath': OK");
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  expect_ok("stdio wpath", test_file_writing);
  expect_crash("stdio rpath", test_file_writing);
  expect_crash("stdio", test_file_writing);
}
