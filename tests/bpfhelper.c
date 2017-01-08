#include "testlib.h"
#include <stdint.h>

#include "../bpf_helper.h"

void expect_jeq(struct sock_filter* instruction, uint8_t jt, uint8_t jf,
                const char* msg) {
  expect(instruction->code == BPF_JMP+BPF_JEQ+BPF_K,
         "should be JEQ instruction");
  expect(instruction->jt == jt, msg);
  expect(instruction->jf == jf, msg);
}

void test_simple_jump() {
  DECLARELABEL(skip_coffee);

  BPFFILTER(inet_filter) {
    _JEQ(0xcafe, 0, ELSE_TO(skip_coffee));
    _RET(0xcafe);
    LABEL(skip_coffee);
  };

  expect_jeq(&inet_filter.filter[0], 0, 1, "if false, skip 1");
}

void test_multiple_jumps_to_same_label() {
  DECLARELABEL(prime);
  DECLARELABEL(fallback);

  BPFFILTER(prime_filter) {
    _JEQ(2, THEN_TO(prime), 0);
    _JEQ(3, THEN_TO(prime), 0);
    _JEQ(5, THEN_TO(prime), 0);
    _JEQ(7, THEN_TO(prime), ELSE_TO(fallback));
    LABEL(prime)
    _RET(1); // Prime
    LABEL(fallback);
    _RET(0); // Probably not prime
  };

  expect_jeq(&prime_filter.filter[0], 3, 0, "if true, skip 3");
  expect_jeq(&prime_filter.filter[1], 2, 0, "if true, skip 2");
  expect_jeq(&prime_filter.filter[2], 1, 0, "if true, skip 1");
  expect_jeq(&prime_filter.filter[3], 0, 1, "if false, skip 1");
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  test_simple_jump();
  test_multiple_jumps_to_same_label();
}
