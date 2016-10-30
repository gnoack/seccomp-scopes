#!/usr/bin/python

from label import new_label

class _ASTNode(object):
  def is_condition(self):
    return False

  def is_expr(self):
    return False

  def is_value(self):
    return False

  def is_statement(self):
    return False

  def get_labelname(self):
    """A clever name for a label pointing here"""
    return None


# A statement is an AST node, which, when compiled,
# just emits instructions which maybe modify the value
# of the A register.
class _Stmt(_ASTNode):
  def compile_stmt(self, emit):
    raise NotImplementedError("Subclass responsibility")

  def is_statement(self):
    return True


# An expression is an AST node, which, when compiled,
# puts a value into the A register.
class _Expr(_ASTNode):
  def compile_expression(self, emit):
    raise NotImplementedError("Subclass responsibility")

  def is_expr(self):
    return True


# A value is a special kind of expression, whose value
# is known at BPF instantiation time and which can be
# used as immediate argument to a BPF instruction.
class Value(_Expr):
  def __init__(self, value):
    self.value = value

  def is_value(self):
    return True

  def compile_expression(self, emit):
    # TODO(gnoack): Implement this.
    raise NotImplementedError("I should implement this")


# A condition is an expression-like AST node, which,
# when compiled, jumps to the 'then' or 'else' label.
class _Condition(_ASTNode):
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
    assert self.lhs.is_expr()
    assert self.rhs.is_value()
    self.lhs.compile_expression(emit)
    emit.jeq(self.rhs.value, then_label, else_label)


class Not(_Condition):
  def __init__(self, cond):
    self.cond = cond

  def compile_condition(self, then_label, else_label, emit):
    assert self.cond.is_condition()
    self.cond.compile_condition(else_label, then_label, emit)


class BinaryOr(_Expr):
  def __init__(self, expr, value):
    self.expr = expr
    self.value = value

  def compile_expression(self, emit):
    assert self.expr.is_expr()
    assert self.value.is_value()
    self.expr.compile_expression(emit)
    emit.binary_or(self.value.value)


class HasScope(_Condition):
  def __init__(self, name):
    self.name = name

  def compile_condition(self, then_label, else_label, emit):
    emit.jmp_if_scope(self.name, then_label, else_label)


class SysNr(_Expr):
  def compile_expression(self, emit):
    emit.ld_nr()


class Arg(_Expr):
  def __init__(self, num):
    self.num = num

  def compile_expression(self, emit):
    emit.ld_arg(self.num)


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
