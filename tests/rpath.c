#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include "pledge.h"
#include "testlib.h"

void test_file_reading() {
  FILE* f = fopen("example-file", "r");
  char buf[100];
  do {
    size_t size = fread(buf, sizeof(buf), 1, f);
    if (ferror(f)) {
      puts("Error reading stream: BROKEN");
    }
  } while (!feof(f));
  fclose(f);
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  expect_ok("stdio rpath", test_file_reading);
  expect_crash("stdio wpath", test_file_reading);
  expect_crash("stdio", test_file_reading);
}
