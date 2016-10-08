#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include "pledge.h"

int main(int argc, char* argv[]) {
  if (pledge("stdio rpath", NULL) == -1) {
    errx(1, "Could not pledge: BROKEN");
  }

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
