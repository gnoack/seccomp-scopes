#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include "pledge.h"

int main(int argc, char* argv[]) {
  if (pledge("stdio", NULL) == -1) {
    errx(1, "Could not pledge: BROKEN");
  }

  // This message is a test in itself.
  printf("Writing to stdout: OK\n");

  char* x = malloc(2000 * 1024 * 20);
  free(x);
  printf("Allocating and freeing memory: OK\n");
}
