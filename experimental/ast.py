#!/usr/bin/python

from label import new_label

class _Expr(object):
  def is_condition(self):
    return False

  def is_input(self):
    return False

  def is_value(self):
    return False

  def is_statement(self):
    return False

  def get_labelname(self):
    """A clever name for a label pointing here"""
    return None


class _Condition(_Expr):
  def compile_condition(self, then_label, else_label, emit):
    raise NotImplementedError("Subclass responsibility")

  def is_condition(self):
    return True


class Or(_Condition):
  def __init__(self, *exprs):
    self.exprs = exprs

  def compile_condition(self, then_label, else_label, emit):
    for e in self.exprs[:-1]:
      try_next_label = new_label('try_next')
      e.compile_condition(then_label, try_next_label, emit)
      emit.label(try_next_label)

    self.exprs[-1].compile_condition(then_label, else_label, emit)


class And(_Condition):
  def __init__(self, *exprs):
    self.exprs = exprs

  def compile_condition(self, then_label, else_label, emit):
    for e in self.exprs[:-1]:
      check_next_label = new_label('check_next')
      e.compile_condition(check_next_label, else_label, emit)
      emit.label(check_next_label)

    self.exprs[-1].compile_condition(then_label, else_label, emit)


class Eq(_Condition):
  def __init__(self, lhs, rhs):
    self.lhs = lhs
    self.rhs = rhs

  def compile_condition(self, then_label, else_label, emit):
    # TODO(gnoack): These are the wrong categories.  What is really
    # supported here is:
    #  - lhs puts its value into the A register
    #  - rhs is a value we can use as immediate value
    assert self.lhs.is_input()
    assert self.rhs.is_value()
    self.lhs.compile_expression(emit)
    emit.jeq(self.rhs.value, then_label, else_label)


class Not(_Condition):
  def __init__(self, cond):
    self.cond = cond

  def compile_condition(self, then_label, else_label, emit):
    assert self.cond.is_condition()
    self.cond.compile_condition(else_label, then_label, emit)


class Value(_Expr):
  def __init__(self, value):
    self.value = value

  def is_value(self):
    return True


class HasScope(_Condition):
  def __init__(self, name):
    self.name = name

  def compile_condition(self, then_label, else_label, emit):
    emit.jmp_if_scope(self.name, then_label, else_label)


class _Input(_Expr):
  def is_input(self):
    return True


class SysNr(_Input):
  def compile_expression(self, emit):
    emit.ld_nr()


class Arg(_Input):
  def __init__(self, num):
    self.num = num

  def compile_expression(self, emit):
    emit.ld_arg(self.num)


# TODO(gnoack): A statement is not an expression.
class _Stmt(_Expr):
  def compile_stmt(self, emit):
    raise NotImplementedError("Subclass responsibility")

  def is_statement(self):
    return True


class Return(_Stmt):
  def __init__(self, expr):
    assert expr.is_value()
    self.expr = expr

  def compile_stmt(self, emit):
    emit.ret(self.expr.value)

  def get_labelname(self):
    return "return " + self.expr.value


class If(_Stmt):
  def __init__(self, cond, then_branch, else_branch=None):
    self.cond = cond
    self.then_branch = then_branch
    self.else_branch = else_branch or Do()

  def compile_stmt(self, emit):
    assert self.cond.is_condition()
    then_label = new_label("then_branch", block=self.then_branch)
    else_label = new_label("else_branch", block=self.else_branch)
    done_label = new_label("done_branch")

    self.cond.compile_condition(then_label, else_label, emit)
    emit.label(then_label)
    self.then_branch.compile_stmt(emit)
    emit.jmp(done_label)
    emit.label(else_label)
    self.else_branch.compile_stmt(emit)
    emit.label(done_label)


class Do(_Stmt):
  def __init__(self, *stmts):
    self.stmts = stmts

  def compile_stmt(self, emit):
    for stmt in self.stmts:
      stmt.compile_stmt(emit)

  def get_labelname(self):
    if self.stmts:
      return self.stmts[0].get_labelname()
    return None
