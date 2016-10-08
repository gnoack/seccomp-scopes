
// Test procedure
typedef void (*test_proc)();

void init_test(int argc, char* argv[]);
#define expect_ok(promises, proc) do_expect_ok(#proc, promises, proc)
#define expect_crash(promises, proc) do_expect_crash(#proc, promises, proc)

// Use the macros above instead.
void do_expect_ok(const char* name, const char* promises, test_proc proc);
void do_expect_crash(const char* name, const char* promises, test_proc proc);
