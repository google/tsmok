"""OPTEE UTEE Attributes."""

import struct
import tsmok.optee.crypto as crypto


OPTEE_ATTR_BIT_PROTECTED = 1 << 28
OPTEE_ATTR_BIT_VALUE = 1 << 29


class OpteeUteeAttribute:
  """Defines OPTEE Utee Attribute base class."""

  FORMAT = '<2Q2I'

  def __init__(self):
    self.atype = 0

  @staticmethod
  def size():
    return struct.calcsize(OpteeUteeAttribute.FORMAT)

  @staticmethod
  def create(data):
    """Creates OpteeUteeAttribute derived object based on parsing raw data.

    Args:
      data: raw binary data

    Returns:
      OpteeUteeAttribute derived object.

    Raises:
      ValueError exception is raised if size of data is not enough for parsing.
    """

    sz = struct.calcsize(OpteeUteeAttribute.FORMAT)

    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    a, b, atype, _ = struct.unpack(OpteeUteeAttribute.FORMAT, data[:sz])
    if atype & OPTEE_ATTR_BIT_VALUE:
      attr = OpteeUteeAttributeValue()
      attr.a = a
      attr.b = b
    else:
      attr = OpteeUteeAttributeMemory()
      attr.addr = a
      attr.size = b

    attr.atype = crypto.OpteeAttr(atype)

    return attr


class OpteeUteeAttributeValue(OpteeUteeAttribute):
  """Defines OPTEE Utee Attribute Value class."""

  def __init__(self, data=None):
    OpteeUteeAttribute.__init__(self)
    if data:
      if isinstance(data, bytes):
        self.load(data)
      else:
        raise ValueError('Wrong type of data')
    else:
      self.a = 0
      self.b = 0

  def load(self, data):
    """Loads OpteeUteeAttributeValue object from raw data.

    Args:
      data: raw binary data to be parsed

    Returns:
      The size of parsed data.

    Raises:
      ValueError exception is raised if size of data is not enough for parsing.
    """
    sz = struct.calcsize(self.FORMAT)

    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    self.a, self.b, atype = struct.unpack(self.FORMAT, data[:sz])
    if not atype & OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Parsed attribute is not VALUE one')

    self.atype = crypto.OpteeAttr(atype)
    return sz

  def __str__(self):
    out = 'OpteeUteeAttributeValue:\n'
    out += f'\ta: {self.a}\n'
    out += f'\tb: {self.b}\n'
    out += f'\ttype: {str(self.atype)}\n'

    return out


class OpteeUteeAttributeMemory(OpteeUteeAttribute):
  """Defines OPTEE Utee Attribute Memory reference class."""

  def __init__(self, data=None):
    OpteeUteeAttribute.__init__(self)
    if data:
      if isinstance(data, bytes):
        self.load(data)
      else:
        raise ValueError('Wrong type of data')
    else:
      self.addr = 0
      self.size = 0
      self.data = None

  def load(self, data):
    """Loads OpteeUteeAttributeMemory object from raw data.

    Args:
      data: raw binary data to be parsed

    Returns:
      The size of parsed data.

    Raises:
      ValueError exception is raised if size of data is not enough for parsing.
    """
    sz = struct.calcsize(self.FORMAT)

    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    self.addr, self.size, atype = struct.unpack(self.FORMAT, data[:sz])
    if atype & OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Parsed attribute is VALUE one, not Memory')

    self.atype = crypto.OpteeAttr(atype)
    return sz

  def __str__(self):
    out = 'OpteeUteeAttributeValue:\n'
    out += f'\tptr:  0x{self.addr:08x}\n'
    out += f'\tsize: {self.size}\n'
    out += f'\ttype: {str(self.atype)}\n'
    out += f'\tdata: {str(self.data)}\n'

    return out

