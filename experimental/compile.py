#!/usr/bin/python

from ast import *

class PrintingEmit(object):
  """Emit instructions and labels by printing them."""
  # Note: Thes instructions are just for debugging now.

  def jmp(self, label):
    print("    JMP  ", label)

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

  def comment(self, comment):
    print("    //", comment)


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
    # the current content.  Whne we see subsequent jumps, we check
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
      self.a = self._join(self.a, self.a_by_label)
      # Label only needs to be printed if there was an actual jump
      self.delegate.label(label)

  def ret(self, value):
    if not self.live:
      return

    self.delegate.ret(value)
    self.live = False

  def comment(self, comment):
    self.delegate.comment(comment)
