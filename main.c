#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include "pledge.h"

int main(int argc, char* argv[]) {
  if (pledge("stdio", NULL) == -1) {
    errx(1, "Could not pledge.");
  }

  printf("Printing should work.\n");

  // Allocate and free some space to try memory management.
  char* x = malloc(2000 * 1024 * 20);
  free(x);

  printf("DONE :)\n");
}
