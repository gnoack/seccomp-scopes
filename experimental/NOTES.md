# BPF compiler

## Compile time / BPF instantiation time / BPF Runtime

The compilation happens in three steps:

* Compile time (when these Python scripts are executed)
* BPF instantiation time (when the program is preparing the BPF bytecode)
* BPF runtime (when the BPF filter runs)

# Optimizations

## C code to be inserted above BPF instantiation

It should be possible to define some C code which is to be inserted at
BPF instantiation time, right above the BPF code.

This can be used to precalculate some variables depending on the
installed scopes, such as "a mask of permitted flags for open()",
depending on which scopes are requested:

    int permitted_open_flags = O_ACCMODE;
    if (SCOPE_wpath) {
      permitted_open_flags |= O_TRUNC | O_APPEND;
    }
    // ...

## Idea: Extract this code as a early pass on the AST

Maybe some of this C code can be generated on the fly and extracted
from the other code.  This could be done as a step on the AST.

Example: If the input is (in pseudocode):

    int permitted_open_flags = O_ACCMODE | (SCOPE_wpath ? O_TRUNC | O_APPEND : 0);
    If (arg(1) | permitted_open_flags == permitted_open_flags) {
      return SECCOMP_RET_ALLOW;
    }

This code is side effect free and the compiler can easily determine that the
definition of `permitted_open_flags` can be entirely calculated at least at
BPF instantiation time.  The compiler could pull this out on its own.

## HasScope() condition

Add a HasScope("rpath")-like condition construct, which can be
optimized out either at compile time (if the scope is not required at
all by the program), or which can be switched when instantiating the
BPF.

Rough idea:

    class HasScope(_Condition):
      def __init__(self, name):
        self.name = name

      def compile_condition(self, then_label, else_label, emit):
        # TODO(gnoack): Depending on configuration, we should be
        # able to skip scope-dependent paths altogether.
        # TODO(gnoack): Pull this functionality down to the emitter?
        emit.jmp("SCOPE_%s ? %s : %s" % (self.name, then_label, else_label))

This does not work, because the emitter makes the assumption that
you're passing a simple label, not something fancy like a C ternary
operator.

### Optimizing away non-required scopes at Compile time

Maybe this should be done in a pass over the AST, so that the entire
HasScope() check disappears in the AST already.

### Switching on scope at BPF instantiation time

The emitted C code could look like this:

    ...
    _JMP(SCOPE_rpath ? rpath_enabled : rpath_not_enabled),
    ...

## Idea: Deduplicate equal basic blocks

If the compiler had a notion of what a basic block is, it could
deduplicate the basic blocks which are the same, such as the one that
returns with 'allow'.
