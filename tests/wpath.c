#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include "pledge.h"

int main(int argc, char* argv[]) {
  if (pledge("stdio wpath", NULL) == -1) {
    errx(1, "Could not pledge: BROKEN");
  }

  FILE* f = fopen(".throwaway-test-output", "w");
  char* buf = "Hello, world.";
  size_t size = fwrite(buf, sizeof(buf), 1, f);
  if (ferror(f)) {
    puts("Error writing: BROKEN");
  }
  fclose(f);

  puts("Writing files with 'wpath': OK");
}
