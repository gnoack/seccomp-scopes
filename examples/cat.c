#include <err.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pledge.h>

#define BUFSIZE 4096

// A simple version of cat,
// only supporting file names as arguments.
int main(int argc, char* argv[]) {
  argc--;

  FILE* inputs[argc];

  // Open input files.
  for (int i=0; i<argc; i++) {
    inputs[i] = fopen(argv[i+1], "r");
  }

  // No new file descriptors any more.
  pledge("stdio", NULL);

  // Copy from inputs to stdout.
  char buf[BUFSIZE];
  for (int i=0; i<argc; i++) {
    size_t n;
    while ((n = fread(&buf, 1, sizeof(buf), inputs[i])) > 0) {
      if (fwrite(&buf, 1, n, stdout) != n) {
        errx(1, "Failed write()");
      }
    }
    fclose(inputs[i]);
  }
}
