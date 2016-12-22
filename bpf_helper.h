// Helper macros for constructing BPF bytecode.
//
// This code looks like it's doing unnecessary work, but most of the
// safety checks are optimized away at compile time.
//
// All checks that should be optimized away have an error message with
// the substring "BADBPF".  If your compiled binary doesn't contain
// that word, all these checks have disappeared.

#include <err.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

// TODO(gnoack): This is very inflexible and not clever at all.
#define BPFSIZE 100

#define _BPF_STMT(...) do {                                             \
    __code[__filter->len] = (struct sock_filter) BPF_STMT(__VA_ARGS__); \
    __filter->len++;                                                    \
    if (__filter->len >= BPFSIZE) {                                     \
      errx(1, "BADBPF: BPF code using too much space.");                \
    }                                                                   \
  } while(0);

#define _BPF_JUMP(...) do {                                             \
    __code[__filter->len] = (struct sock_filter) BPF_JUMP(__VA_ARGS__); \
    __filter->len++;                                                    \
    if (__filter->len >= BPFSIZE) {                                     \
      errx(1, "BADBPF: BPF code using too much space.");                \
    }                                                                   \
  } while(0);

#define _JMP(j)              _BPF_STMT(BPF_JMP+BPF_JA+BPF_K,  (j))
#define _JEQ(value, jt, jf)  _BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (value), (jt), (jf))
#define _RET(value)          _BPF_STMT(BPF_RET+BPF_K,         (value))
#define _OR(value)           _BPF_STMT(BPF_ALU+BPF_OR+BPF_K,  (value))
#define _AND(value)          _BPF_STMT(BPF_ALU+BPF_AND+BPF_K, (value))
#define _SET_X_TO_A()        _BPF_STMT(BPF_MISC+BPF_TAX,      0)
#define _SET_A_TO_X()        _BPF_STMT(BPF_MISC+BPF_TXA,      0)
#define _NOP()               _JMP(0)  // Gets optimized away by the x86 BPF JIT.

#define _LD_STRUCT_VALUE(field)                                         \
  _BPF_STMT(BPF_LD+BPF_W+BPF_ABS,                                       \
            offsetof(struct seccomp_data, field))

// TODO(gnoack): Double check whether LD_ARG(n) is platform independent.
#define _LD_ARCH() _LD_STRUCT_VALUE(arch)
#define _LD_NR() _LD_STRUCT_VALUE(nr)
#define _LD_ARG(n) _LD_STRUCT_VALUE(args[n])

#define _RET_EQ(value, result) \
  _JEQ((value), 0, 1);         \
  _RET((result))

#define _RET_NEQ(value, result) \
  _JEQ((value), 1, 0);          \
  _RET((result))

// -------------------------------------------------------------------
// Define the implicit place to gather BPF code.
// -------------------------------------------------------------------

#define BPFFILTER(name)                              \
  struct sock_filter __code[BPFSIZE];                \
  struct sock_fprog name = {                         \
    .len = 0,                                        \
    .filter = __code,                                \
  };                                                 \
  struct sock_fprog* __filter = &name;

// Use this to append to an existing sock_fprog*.
#define BPFINTO(progptr)                        \
  struct sock_filter* __code = progptr->filter; \
  struct sock_fprog* __filter = progptr;


// -------------------------------------------------------------------
// Tracking labels in BPF code
// -------------------------------------------------------------------
// In BPF, you can only jump downwards.  At the callsite, we store the
// current code position into a callsite struct with the label's name.
// At the jump target where the label is declared, we retroactively
// fill in the JT, JF or K values of the callsite instruction.
//
// A well-optimizing compiler will optimize away most of the relevant
// code, as long as the jumps is always skipping the same number of
// instructions.
//
// It's a known limitation that there can be only one callsite for
// each label.  If you need more, use multiple labels instead.
typedef struct {
  int ip;
  enum {
    JT = 0,
    JF = 1,
    K = 2,
  } argtype;
} callsite;

#define DECLARELABEL(name)                                              \
  callsite __##name##_callsite = { .ip = -1, .argtype = -1 };

#define TO_GENERIC(name, type)                                          \
  (__##name##_callsite.ip = __filter->len,                              \
   __##name##_callsite.argtype = type,                                  \
   0)

#define TO(name) TO_GENERIC(name, K)
#define THEN_TO(name) TO_GENERIC(name, JT)
#define ELSE_TO(name) TO_GENERIC(name, JF)

#define LABEL(name)                                                     \
  if (__##name##_callsite.ip != -1) {                                   \
    int csip = __##name##_callsite.ip;                                  \
    switch (__##name##_callsite.argtype) {                              \
    case K:                                                             \
      __code[csip].k = __filter->len - csip - 1;                        \
      break;                                                            \
    case JT:                                                            \
      __code[csip].jt = __filter->len - csip - 1;                       \
      break;                                                            \
    case JF:                                                            \
      __code[csip].jf = __filter->len - csip - 1;                       \
      break;                                                            \
    default:                                                            \
      errx(1, "BADBPF: Unknown callsite type. (Is " #name " called?)"); \
    }                                                                   \
  }
