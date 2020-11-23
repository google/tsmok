"""Range dictionary."""


class RangeDict(dict):
  """Implimentation of Range dictionary."""

  def __getitem__(self, item):
    if not isinstance(item, range):
      for key in self:
        if item in key:
          return self[key]
      raise KeyError(item)
    else:
      return super().__getitem__(item)

  def __contains__(self, item):
    if not isinstance(item, range):
      for key in self:
        if item in key:
          return True
      return False
    else:
      return super().__contains__(item)
