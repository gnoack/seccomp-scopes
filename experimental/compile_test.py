#!/usr/bin/python

# TODO(gnoack): Write this as a proper unit test.

from ast import *
from compile import SmartEmit, PrintingEmit

rule = Do(
  If(HasScope("rpath"),
     Do(
       If(And(Or(Eq(SysNr(), Value("__NR_open")),
                 Eq(SysNr(), Value("__NR_openat"))),
              Eq(BinaryOr(Arg(1), Value("permitted_open_flags")),
                 Value("permitted_open_flags"))),
          Return(Value("SECCOMP_RET_ALLOW")),
       ),
       If(Or(Eq(SysNr(), Value("__NR_read")),
             Eq(SysNr(), Value("__NR_write"))),
          Return(Value("SECCOMP_RET_ALLOW")),
       ),
     ),
  ),
  Return(Value("SECCOMP_RET_DENY")),
)

emit = SmartEmit(PrintingEmit())
rule.compile_stmt(emit)
