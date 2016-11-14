#!/usr/bin/python

import collections

from ast import *


class CompileException(Exception):
  pass


Label = collections.namedtuple('Label', ('name',))


class CPrintingEmit(object):
  """Emit instructions and labels by printing them."""
  def __init__(self):
    self.count = 0
    self.labels = {}
    self.later = []

  def _lookup_labels(self, arg, ip):
    if isinstance(arg, Label):
      try:
        instructions_to_skip = self.labels[arg.name] - ip - 1
      except KeyError:
        raise CompileException("Tried to jump to unresolved label %r" % arg.name)
      if instructions_to_skip:
        arg = "%d /* %s */" % (instructions_to_skip, arg.name)
      else:
        arg = "0"
    return arg

  def _emit(self, fmt, *args, count=1):
    self.later.append((self.count, fmt, args))
    self.count += count

  def jmp(self, label):
    self._emit("    _JMP(%s),", Label(label))

  def jmp_if_scope(self, scope_name, then_label, else_label):
    self._emit("#ifdef %s",         scope_name,        count=0)
    self._emit("    _JMP(%s),",     Label(then_label), count=0)
    self._emit("#else",                                count=0)
    self._emit("    _JMP(%s),",     Label(else_label), count=0)
    self._emit("#end if  /* %s */", scope_name,        count=0)
    self.count += 1

  def jeq(self, value, then_label, else_label):
    self._emit("    _JEQ(%s, %s, %s),", value, Label(then_label), Label(else_label))

  def ld_nr(self):
    self._emit("    _LD_NR(),")

  def ld_arg(self, num):
    self._emit("    _LD_ARG(%d),", num)

  def label(self, label):
    self.labels[label] = self.count
    self._emit("// %s:", label, count=0)

  def ret(self, value):
    self._emit("    _RET(%s),", value)

  def binary_or(self, value):
    self._emit("    _OR(%s),", value)

  def comment(self, comment):
    self._emit("    // %s", comment, count=0)

  def flush(self):
    for ip, fmt, args in self.later:
      print(fmt % tuple([self._lookup_labels(arg, ip) for arg in args]))


class PrintingEmit(object):
  """Emit instructions and labels by printing them."""
  # Note: These instructions are just for debugging now.

  def jmp(self, label):
    print("    JMP  ", label)

  def jmp_if_scope(self, scope_name, then_label, else_label):
    print("#ifdef ", scope_name)
    print("    JMP  ", then_label)
    print("#else")
    print("    JMP  ", else_label)
    print("#endif /*", scope_name, "*/")

  def jeq(self, value, then_label, else_label):
    print("    JEQ  ", ", ".join((value, then_label, else_label)))

  def ld_nr(self):
    print("    LDNR ")

  def ld_arg(self, num):
    print("    LDARG", num)

  def label(self, label):
    print("%s:" % label)

  def ret(self, value):
    print("    RET  ", value)

  def binary_or(self, value):
    print("    OR   ", value)

  def comment(self, comment):
    print("    //", comment)

  def flush(self):
    pass


class SmartEmit(object):
  """Track liveness, track what's loaded to the A register."""

  def __init__(self, delegate):
    self.delegate = delegate
    self.live = True

    # Symbolic value of the A register (e.g. 'NR', 'ARG0', 'ARG1', ...)
    self.a = None  # unknown
    self.a_by_label = {}

  def _join(self, a, b):
    # Join symbolic execution flow states,
    # in this case joins symbolic A register values
    if a == b:
      return a
    else:
      return None

  def _register_jump(self, label):
    # Figure out what's the A register content when entering the given
    # label.  When we see the first jump to the label, we note down
    # the current content.  When we see subsequent jumps, we check
    # that it matches.  If it doesn't match, we invalidate what we
    # know about A at label entry and enforce to load A fresh later.
    if label not in self.a_by_label:
      # first jump to that label, just assign value
      self.a_by_label[label] = self.a
    else:
      # join symbolic execution flow states
      self.a_by_label[label] = self._join(self.a_by_label[label], self.a)

  def jmp(self, label):
    if not self.live:
      return

    self.delegate.jmp(label)
    self._register_jump(label)

  def jmp_if_scope(self, scope_name, then_label, else_label):
    if not self.live:
      return

    self.delegate.jmp_if_scope(scope_name, then_label, else_label)
    self._register_jump(then_label)
    self._register_jump(else_label)

  def jeq(self, value, then_label, else_label):
    if not self.live:
      return

    self.delegate.jeq(value, then_label, else_label)
    self._register_jump(then_label)
    self._register_jump(else_label)

  def ld_nr(self):
    if not self.live:
      return

    if self.a == 'NR':
      self.delegate.comment('already loaded NR')
    else:
      self.delegate.ld_nr()
      self.a = 'NR'

  def ld_arg(self, num):
    if not self.live:
      return

    if self.a == 'ARG%d' % num:
      self.delegate.comment('already loaded ARG%d' % num)
    else:
      self.delegate.ld_arg(num)
      self.a = 'ARG%d' % num

  def label(self, label):
    # label is live if there were previous jumps
    label_is_live = self.live or label in self.a_by_label
    self.live = label_is_live
    if not self.live:
      return

    if label in self.a_by_label:
      # Join symbolic execution states
      self.a = self._join(self.a, self.a_by_label[label])
      # Label only needs to be printed if there was an actual jump
      self.delegate.label(label)

  def ret(self, value):
    if not self.live:
      return

    self.delegate.ret(value)
    self.live = False

  def binary_or(self, value):
    self.delegate.binary_or(value)

  def comment(self, comment):
    self.delegate.comment(comment)

  def flush(self):
    self.delegate.flush()
