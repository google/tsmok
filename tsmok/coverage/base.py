"""Base class for Coverage."""

import abc
import logging
import os.path


class CoverageConvertorBase(abc.ABC):
  """Implementation of the base class for Coverage generator."""

  def __init__(self, name, log_level=logging.ERROR):
    abc.ABC.__init__(self)
    self.name = name

    self.log = logging.getLogger(self.name)
    self.log.setLevel(log_level)
    self.log_level = log_level

  @abc.abstractmethod
  def dump(self, output: str):
    pass


class Line:
  """Base class for Line representation."""

  def __init__(self):
    self.count = 0
    self.lineno = 0

  def update_counter(self):
    self.count += 1

  def __eq__(self, other):
    if isinstance(other, Line):
      return self.addr == other.addr
    elif isinstance(other, int):
      return self.addr == other
    else:
      raise KeyError('Unsupported value type')


class Function:
  """Represents function block of code."""

  def __init__(self, name):
    self.name = name
    self.lines = []
    self.lineno = 0
    self.called = 0

  def lines_coverage_percentages(self):
    if not self.lines:
      return 0

    covered = sum(1 for line in self.lines if line.count != 0)
    return (covered / len(self.lines)) * 100.0

  def returned_percent(self):
    return None


class Source:
  """Represents Source file."""

  def __init__(self, name='', path=''):
    self.name = name
    self.path = path
    self.funcs = None
    self.data = None

  def get_full_path(self):
    if os.path.isabs(self.name):
      return self.name
    return os.path.abspath(self.path + '/' + self.name)

  def __str__(self):
    return self.path + '/' + self.name


class CoverageRepresentationBase(abc.ABC):
  """Implementation of the base class for Coverage Representation."""

  def __init__(self, name, log_level=logging.ERROR):
    abc.ABC.__init__(self)
    self.name = name
    self.sources = []
    self.runs = 0

    self.log = logging.getLogger(self.name)
    self.log.setLevel(log_level)
    self.log_level = log_level

  @abc.abstractmethod
  def load_source(self, source):
    pass

  @abc.abstractmethod
  def update_block_coverage(self, add: int, size: int):
    pass


class CoverageFormatBase(abc.ABC):
  """Base representation of coverage storage format."""

  def __init__(self, name, log_level=logging.ERROR):
    abc.ABC.__init__(self)
    self.name = name

    self.log = logging.getLogger(self.name)
    self.log.setLevel(log_level)
    self.log_level = log_level

  @abc.abstractmethod
  def dump(self) -> str:
    raise NotImplementedError()

  @abc.abstractmethod
  def load(self, data: bytes):
    raise NotImplementedError()

  @abc.abstractmethod
  def clear(self):
    raise NotImplementedError()

  @abc.abstractmethod
  def export(self, rep: CoverageRepresentationBase):
    raise NotImplementedError()


class CoverageCollectorBase(abc.ABC):
  """Implementation of the base interface for Coverage."""

  def __init__(self, name, cov: CoverageFormatBase, log_level=logging.ERROR):
    abc.ABC.__init__(self)
    self.name = name
    self.cov = cov

    self.log = logging.getLogger(self.name)
    self.log.setLevel(log_level)
    self.log_level = log_level

  @abc.abstractmethod
  def start(self, emu, images):
    raise NotImplementedError()

  @abc.abstractmethod
  def stop(self):
    raise NotImplementedError()
