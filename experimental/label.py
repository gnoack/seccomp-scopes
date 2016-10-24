import re

_label_counter = 0
def new_label(name, block=None):
  """generate a new label name based on name, or based on block if provided.

  Params:
    name: a string
    block: an AST Statement object, which responds to get_labelname()
  """
  if block:
    name = block.get_labelname() or name

  name = re.sub(r'[^a-zA-Z0-9]', '_', name).lower()

  global _label_counter
  _label_counter += 1
  return "%s_%d" % (name, _label_counter)
