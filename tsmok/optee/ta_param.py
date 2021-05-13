"""OPTEE TA Parameter types."""

import abc
import enum
import struct

import tsmok.common.error as error
import tsmok.optee.message as message


class OpteeTaParamType(enum.IntEnum):
  NONE = 0
  VALUE_INPUT = 1
  VALUE_OUTPUT = 2
  VALUE_INOUT = 3
  MEMREF_INPUT = 5
  MEMREF_OUTPUT = 6
  MEMREF_INOUT = 7


class OpteeTaParamArgs:
  """Container for OPTEE TA parameters."""

  NUM_PARAMS = 4
  FORMAT = '<9Q'

  def __init__(self, params=None):
    if params and len(params) > self.NUM_PARAMS:
      raise ValueError('Wrong number of parameters')
    self.params = params or []
    if not all(isinstance(t, OpteeTaParam) for t in self.params):
      raise TypeError('At least one of parameter has wrong type')

    for i in range(self.NUM_PARAMS - len(self.params)):
      self.params.append(OpteeTaParamNone())

  @staticmethod
  def size():
    return struct.calcsize(OpteeTaParamArgs.FORMAT)

  def load_to_mem(self, loader, addr):
    """Loads the Optee parameters to memery.

    Args:
      loader: a function to load parameters data to Emu memory.
      addr: the address to load data. If NULL, the `loader` function should
            allocate the address.

    Returns:
      Address where parameters was loaded.

    Raises:
      ValueError, if wrong parameters were specified.
    """
    if not callable(loader):
      raise ValueError('loader argument is not a function')

    param_types = 0
    values = []
    if self.params:
      for i, p in enumerate(self.params):
        if isinstance(p, OpteeTaParamMemref):
          data = p.data
          if p.size and not data:
            data = b'\x00' * p.size
          if data:
            p.addr = loader(p.addr, data)
            if not p.size:
              p.size = len(data)
        param_types |= (int(p.type) & 0xf) << (i * 4)
        values += p.values()

    data = struct.pack(self.FORMAT, param_types, *values)
    return loader(addr, data)

  def load_from_mem(self, loader, addr):
    """Load OPTEE TA parameters from memory.

    Args:
      loader: a function to load parameters data from Emu memory.
      addr: the address to load data from.

    Returns:
      None

    Raises:
      ValueError, if wrong parameters were specified.
    """

    if not callable(loader):
      raise ValueError('loader argument is not a function')

    data = loader(addr, self.size())
    data = struct.unpack(self.FORMAT, data)
    self.params = []
    for i in range(self.NUM_PARAMS):
      t = OpteeTaParamType((data[0] >> (i * 4)) & 0xf)
      if t == OpteeTaParamType.NONE:
        continue

      p = OpteeTaParam.get_type(t)()
      p.init_from_values(data[1 + i * 2], data[1 + i * 2 + 1])
      if isinstance(p, OpteeTaParamMemref):
        if p.addr != 0 and p.size != 0:
          p.data = loader(p.addr, p.size)
      self.params.append(p)


class OpteeTaParam(abc.ABC):
  """Defines Optee TA params type."""

  def __init__(self, t):
    self.type = t

  @abc.abstractmethod
  def init_from_values(self, val1, val2):
    raise NotImplementedError()

  @abc.abstractmethod
  def values(self):
    raise NotImplementedError()

  @staticmethod
  def get_type(t):
    """Returns OpteeTaParam type based on OpteeTaParamType.

    Args:
      t: OpteeTaParamType type to be created

    Returns:
      Corresponding OpteeTaParam type
    """
    type_map = {
        OpteeTaParamType.NONE: OpteeTaParamNone,
        OpteeTaParamType.VALUE_INPUT: OpteeTaParamValueInput,
        OpteeTaParamType.VALUE_OUTPUT: OpteeTaParamValueOutput,
        OpteeTaParamType.VALUE_INOUT: OpteeTaParamValueInOut,
        OpteeTaParamType.MEMREF_INPUT: OpteeTaParamMemrefInput,
        OpteeTaParamType.MEMREF_OUTPUT: OpteeTaParamMemrefOutput,
        OpteeTaParamType.MEMREF_INOUT: OpteeTaParamMemrefInOut,
    }

    return type_map[t]

  def convert_to_msg_param(self):
    """Converts OpteeTaParam to OpteeMsgParam.

    Returns:
      Converted OpteeTaParam object

    Raises:
      Error exception in case of error.
    """
    type_map = {
        OpteeTaParamType.NONE: message.OpteeMsgParamNone,
        OpteeTaParamType.VALUE_INPUT: message.OpteeMsgParamValueInput,
        OpteeTaParamType.VALUE_OUTPUT: message.OpteeMsgParamValueOutput,
        OpteeTaParamType.VALUE_INOUT: message.OpteeMsgParamValueInOut,
        OpteeTaParamType.MEMREF_INPUT: message.OpteeMsgParamTempMemInput,
        OpteeTaParamType.MEMREF_OUTPUT: message.OpteeMsgParamTempMemOutput,
        OpteeTaParamType.MEMREF_INOUT: message.OpteeMsgParamTempMemInOut,
    }

    try:
      msg_param = type_map[self.type]()
    except ValueError:
      raise error.Error(f'Can not convert Optee Msg type {self.attr} '
                        'to OpteeTaParam')

    if isinstance(self, OpteeTaParamValue):
      msg_param.a = self.a
      msg_param.b = self.b
    elif isinstance(self, OpteeTaParamMemref):
      msg_param.addr = self.addr
      msg_param.size = self.size
      msg_param.data = self.data

    return msg_param


class OpteeTaParamValue(OpteeTaParam):
  """Base class for OpteeTaParam value."""

  FMT = '<2I'

  def __init__(self, t, a=0, b=0):
    if t not in [
        OpteeTaParamType.VALUE_INPUT,
        OpteeTaParamType.VALUE_OUTPUT,
        OpteeTaParamType.VALUE_INOUT,
    ]:
      raise ValueError(f'Wrong type: {t}')
    OpteeTaParam.__init__(self, t)
    self.a = a
    self.b = b

  def init_from_values(self, val1, val2):
    self.a = val1
    self.b = val2

  def values(self):
    return [self.a, self.b]

  def __bytes__(self):
    return struct.pack(self.FMT, self.a, self.b)

  def __str__(self):
    return f'{str(self.type)}: a = 0x{self.a:08x}, b = {self.b:08x}'


class OpteeTaParamValueInput(OpteeTaParamValue):

  def __init__(self, a=0, b=0):
    OpteeTaParamValue.__init__(self, OpteeTaParamType.VALUE_INPUT,
                               a, b)


class OpteeTaParamValueOutput(OpteeTaParamValue):

  def __init__(self, a=0, b=0):
    OpteeTaParamValue.__init__(self, OpteeTaParamType.VALUE_OUTPUT,
                               a, b)


class OpteeTaParamValueInOut(OpteeTaParamValue):

  def __init__(self, a=0, b=0):
    OpteeTaParamValue.__init__(self, OpteeTaParamType.VALUE_INOUT,
                               a, b)


class OpteeTaParamMemref(OpteeTaParam):
  """Base class for OpteeTaParam memref."""

  def __init__(self, t, data: bytes = None, addr: int = 0, size: int = 0):
    if t not in [
        OpteeTaParamType.MEMREF_INPUT,
        OpteeTaParamType.MEMREF_OUTPUT,
        OpteeTaParamType.MEMREF_INOUT
    ]:
      raise ValueError(f'Wrong type: {t}')
    OpteeTaParam.__init__(self, t)
    self.addr = addr
    self.size = size
    self.data = data or b''

  def values(self):
    return [self.addr, self.size]

  def init_from_values(self, val1, val2):
    self.addr = val1
    self.size = val2

  def __bytes__(self):
    data = self.data
    if not data and self.size:
      data = b'\x00' * self.size
    return data

  def __str__(self):
    return (f'{str(self.type)}: buffer addr = 0x{self.addr:08x}, size = '
            f'{self.size} data = {self.data}')


class OpteeTaParamMemrefInput(OpteeTaParamMemref):

  def __init__(self, data=None, addr=0, size=0):
    OpteeTaParamMemref.__init__(self, OpteeTaParamType.MEMREF_INPUT,
                                data, addr, size)


class OpteeTaParamMemrefOutput(OpteeTaParamMemref):

  def __init__(self, data=None, addr=0, size=0):
    OpteeTaParamMemref.__init__(self,
                                OpteeTaParamType.MEMREF_OUTPUT,
                                data, addr, size)


class OpteeTaParamMemrefInOut(OpteeTaParamMemref):

  def __init__(self, data=None, addr=0, size=0):
    OpteeTaParamMemref.__init__(self, OpteeTaParamType.MEMREF_INOUT,
                                data, addr, size)


class OpteeTaParamNone(OpteeTaParam):
  """OPTEE TA None param."""

  def __init__(self, *_):
    OpteeTaParam.__init__(self, OpteeTaParamType.NONE)

  def values(self):
    return [0, 0]

  def init_from_values(self, val1, val2):
    # do nothing
    pass

  def __str__(self):
    return f'{str(self.type)}'

  def __bytes__(self):
    return b''
