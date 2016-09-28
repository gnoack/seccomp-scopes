#include <stdio.h>
#include <err.h>

#include "pledge.h"

int main(int argc, char* argv[]) {
  if (pledge("stdio", NULL) == -1) {
    errx(1, "Could not pledge.");
  }

  printf("i am doing something evil\n");
}
