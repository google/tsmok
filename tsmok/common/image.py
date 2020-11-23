"""Base class for binary images."""

import abc
import io


class Image(abc.ABC):
  """Represent the loaded to emulator a binary image."""

  def __init__(self, image: io.BufferedReader):
    self.name = image.name
    self.text_start = None
    self.text_end = None
    self.entry_point = None
    self.mem_regions = []
    self.func_symbols = dict()

    self._load(image)

  @abc.abstractmethod
  def _load(self, image) -> None:
    raise NotImplementedError()
