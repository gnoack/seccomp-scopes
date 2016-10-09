#define _GNU_SOURCE
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pledge.h"
#include "testlib.h"

typedef void (*status_handler)(int status);

// Global variables initialized by init_test() below.
static char* only_test_to_run = NULL;
static char* promises_to_run_with = NULL;
static char* argv0 = NULL;

// Info about the currently executing test.
static const char* current_test_name = NULL;
static const char* current_test_promises = NULL;

static void failmsg(const char* msg) {
  puts("****************");
  puts(" F A I L U R E");
  puts("****************");
  puts(msg);

  printf("Debug? (Y/n) ");
  fflush(stdout);
  int c = fgetc(stdin);
  if (c != EOF && tolower(c) == 'y') {
    char* gdb_cmd = NULL;
    if (asprintf(&gdb_cmd, "run %s '%s'",
                 current_test_name, current_test_promises) == -1) {
      errx(1, "asprintf failed");
    }
    if (execl("/usr/bin/gdb", "gdb", "-ex", gdb_cmd, argv0, NULL) == -1) {
      free(gdb_cmd);
      errx(1, "Can't start gdb");
    }
  }
  exit(1);
}

static void pledge_run(const char* proc_name, test_proc proc,
                       const char* promises) {
  printf("# Running %s with '%s'\n",
         proc_name, promises);
  fflush(stdout);
  if (pledge(promises, NULL) == -1) {
    errx(1, "Could not pledge: BROKEN");
  }
  proc();
}

static void fork_pledge_wait(const char* name,
                             const char* promises,
                             test_proc proc,
                             status_handler handle_status) {
  current_test_name = name;
  current_test_promises = promises;

  if (only_test_to_run) {
    current_test_promises = promises;

    // In debugging mode, only run a specific test.
    if (!strcmp(name, only_test_to_run)) {
      pledge_run(name, proc, promises_to_run_with);
      exit(0);
    }
    return;
  }
  pid_t pid = fork();
  if (pid == -1) {
    errx(1, "Could not fork");
  } else if (pid == 0) {
    // Child
    /* printf("Child PID %d\n", getpid()); */
    /* sleep(10); */
    pledge_run(name, proc, promises);
    exit(0);
  } else {
    // Parent
    int status = 0;
    pid_t foundpid = waitpid(pid, &status, 0);
    if (foundpid == -1 || foundpid != pid) {
      errx(1, "Error waiting for child");
    }

    handle_status(status);
  }
}

static void expect_ok_status(int status) {
  if (WIFEXITED(status)) {
    puts("Exited normally: OK");
  } else if (WIFSIGNALED(status)) {
    failmsg("Unexpected sandbox violation: FAIL");
  } else {
    errx(1, "Subprocess neither exited nor stopped: BROKEN");
  }
}

static void expect_crash_status(int status) {
  if (WIFEXITED(status)) {
    failmsg("Program worked but sandbox should have prevented it: FAIL");
  } else if (WIFSIGNALED(status)) {
    puts("Sandbox violation correctly caught: OK");
  } else {
    errx(1, "Subprocess neither exited nor stopped: BROKEN");
  }
}

void do_expect_ok(const char* name, const char* promises, test_proc proc) {
  fork_pledge_wait(name, promises, proc, expect_ok_status);
}

void do_expect_crash(const char* name, const char* promises, test_proc proc) {
  fork_pledge_wait(name, promises, proc, expect_crash_status);
}

void init_test(int argc, char* argv[]) {
  if (argc > 0) {
    argv0 = argv[0];
  }
  if (argc > 2) {
    only_test_to_run = argv[1];
    promises_to_run_with = argv[2];
  }
}
