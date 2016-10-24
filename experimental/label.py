
_label_counter = 0
def new_label(name):
  global _label_counter
  _label_counter += 1
  return "%s_%d" % (name, _label_counter)
