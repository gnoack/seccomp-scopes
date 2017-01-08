#include "testlib.h"

#include "../bpf_helper.h"

void test_simple_jump() {
  DECLARELABEL(skip_coffee);

  // *_TO(x) calculates the relative position of label x
  // (== how many instructions to be skipped from here to get to x).
  // LABEL(x) declares the position of label x.
  BPFFILTER(inet_filter) {
    _JEQ(0xcafe, 0, ELSE_TO(skip_coffee));
    _RET(0xcafe);
    LABEL(skip_coffee);
  };

  expect(inet_filter.filter[0].code == BPF_JMP+BPF_JEQ+BPF_K,
         "should be JEQ instruction");
  expect(inet_filter.filter[0].jt == 0,
         "if true, jump nowhere");
  expect(inet_filter.filter[0].jf == 1,
         "if false, skip 1 instructions");
}

int main(int argc, char* argv[]) {
  init_test(argc, argv);

  test_simple_jump();
}
