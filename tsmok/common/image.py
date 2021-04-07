"""Base class for binary images."""

import abc
import io


class Image(abc.ABC):
  """Represent the loaded to emulator a binary image."""

  def __init__(self, image: io.BufferedReader, load_addr: int):
    self.name = image.name
    self.text_start = None
    self.text_end = None
    self.entry_point = None
    self.mem_regions = []
    self.func_symbols = dict()
    self.load_offset = 0

    self._load(image, load_addr)

  @abc.abstractmethod
  def _load(self, image: io.BufferedReader, load_addr: int) -> None:
    raise NotImplementedError()
