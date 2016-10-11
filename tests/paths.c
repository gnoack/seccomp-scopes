#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

#include "pledge.h"
#include "testlib.h"

void test_fopen_file_writing() {
  FILE* f = fopen(".throwaway-test-output", "w");
  char* buf = "Hello, world.";
  size_t size = fwrite(buf, sizeof(buf), 1, f);
  if (ferror(f)) {
    puts("Error writing: BROKEN");
  }
  fclose(f);

  puts("Writing files with 'wpath': OK");
}

void test_fopen_file_reading() {
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

void test_open_file_reading() {
  int fd = open("example-file", O_RDONLY);
  if (fd == -1) {
    puts("Error opening file for read: BROKEN");
  }
  char buf[10];
  if (read(fd, &buf, 10) != 10) {
    puts("Did not read 10 bytes");
  }
  if (close(fd) == -1) {
    puts("Error closing");
  }
}

void test_open_file_writing() {
  int fd = open(".throwaway-test-output", O_WRONLY|O_TRUNC);
  if (fd == -1) {
    puts("Error opening file for write: BROKEN");
  }
  if (write(fd, "moo", 3) != 3) {
    puts("Did not write 3 bytes");
  }
  if (close(fd) == -1) {
    puts("Error closing");
  }
}

void test_open_for_append() {
  close(open(".throwaway-test-output", O_WRONLY|O_APPEND));
}

void test_open_rdwr() {
  close(open(".throwaway-test-output", O_RDWR|O_TRUNC));
}

void test_open_file_creating() {
  int fd = open(".throwaway-test-output", O_WRONLY|O_CREAT|O_TRUNC);
  if (fd == -1) {
    puts("Error opening file for read: BROKEN");
  }
  if (write(fd, "moo", 3) != 3) {
    puts("Did not write 3 bytes");
  }
  if (close(fd) == -1) {
    puts("Error closing");
  }
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  expect_ok("stdio rpath", test_open_file_reading);
  expect_crash("stdio wpath", test_open_file_reading);
  expect_crash("stdio", test_open_file_reading);

  expect_ok("stdio wpath cpath", test_open_file_creating);
  expect_crash("stdio wpath", test_open_file_creating);
  expect_crash("stdio rpath", test_open_file_creating);
  expect_crash("stdio", test_open_file_creating);

  expect_ok("stdio wpath", test_open_file_writing);
  expect_crash("stdio rpath", test_open_file_writing);
  expect_crash("stdio", test_open_file_writing);

  expect_ok("stdio rpath", test_fopen_file_reading);
  expect_crash("stdio wpath", test_fopen_file_reading);
  expect_crash("stdio", test_fopen_file_reading);

  // fopen opens in O_CREAT mode
  expect_ok("stdio wpath cpath", test_fopen_file_writing);
  expect_crash("stdio wpath", test_fopen_file_writing);
  expect_crash("stdio rpath", test_fopen_file_writing);
  expect_crash("stdio", test_fopen_file_writing);

  expect_ok("stdio wpath", test_open_for_append);
  expect_crash("stdio rpath", test_open_for_append);
  expect_crash("stdio", test_open_for_append);

  // wpath+rpath unlocks O_RDWR, but one alone is not enough.
  expect_ok("stdio wpath rpath", test_open_rdwr);
  expect_crash("stdio wpath", test_open_rdwr);
  expect_crash("stdio rpath", test_open_rdwr);
}
