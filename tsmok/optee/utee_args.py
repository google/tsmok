# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OPTEE UTEE Parameter types."""

import abc
import enum
import struct

import tsmok.common.error as error
import tsmok.optee.message as message


class OpteeUteeParamType(enum.IntEnum):
  NONE = 0
  VALUE_INPUT = 1
  VALUE_OUTPUT = 2
  VALUE_INOUT = 3
  MEMREF_INPUT = 5
  MEMREF_OUTPUT = 6
  MEMREF_INOUT = 7


class OpteeUteeParamArgs:
  """Container for OPTEE UTEE parameters."""

  NUM_PARAMS = 4
  FORMAT = '<9Q'

  def __init__(self, params=None):
    if params and len(params) > self.NUM_PARAMS:
      raise ValueError('Wrong number of parameters')
    self.params = params or []
    if not all(isinstance(t, OpteeUteeParam) for t in self.params):
      raise TypeError('At least one of parameter has wrong type')

    for i in range(self.NUM_PARAMS - len(self.params)):
      self.params.append(OpteeUteeParamNone())

  @staticmethod
  def size():
    return struct.calcsize(OpteeUteeParamArgs.FORMAT)

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
        if isinstance(p, OpteeUteeParamMemref):
          data = p.data
          if p.size:
            if not data:
              data = b'\x00' * p.size
            elif p.size > len(data):
              data += b'\x00' * (p.size - len(data))
            else:
              data = data[:p.size]
          if data:
            p.addr = loader(p.addr, data)
            if not p.size:
              p.size = len(data)
        param_types |= (int(p.type) & 0xf) << (i * 4)
        values += p.values()

    data = struct.pack(self.FORMAT, param_types, *values)
    return loader(addr, data)

  def load_from_mem(self, loader, addr):
    """Load OPTEE UTEE parameters from memory.

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
      t = OpteeUteeParamType((data[0] >> (i * 4)) & 0xf)
      if t == OpteeUteeParamType.NONE:
        continue

      p = OpteeUteeParam.get_type(t)()
      p.init_from_values(data[1 + i * 2], data[1 + i * 2 + 1])
      if isinstance(p, OpteeUteeParamMemref):
        if p.addr != 0 and p.size != 0:
          p.data = loader(p.addr, p.size)
      self.params.append(p)


class OpteeUteeParam(abc.ABC):
  """Defines Optee UTEE params type."""

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
    """Returns OpteeUteeParam type based on OpteeUteeParamType.

    Args:
      t: OpteeUteeParamType type to be created

    Returns:
      Corresponding OpteeUteeParam type
    """
    type_map = {
        OpteeUteeParamType.NONE: OpteeUteeParamNone,
        OpteeUteeParamType.VALUE_INPUT: OpteeUteeParamValueInput,
        OpteeUteeParamType.VALUE_OUTPUT: OpteeUteeParamValueOutput,
        OpteeUteeParamType.VALUE_INOUT: OpteeUteeParamValueInOut,
        OpteeUteeParamType.MEMREF_INPUT: OpteeUteeParamMemrefInput,
        OpteeUteeParamType.MEMREF_OUTPUT: OpteeUteeParamMemrefOutput,
        OpteeUteeParamType.MEMREF_INOUT: OpteeUteeParamMemrefInOut,
    }

    return type_map[t]

  def convert_to_msg_param(self):
    """Converts OpteeUteeParam to OpteeMsgParam.

    Returns:
      Converted OpteeUteeParam object

    Raises:
      Error exception in case of error.
    """
    type_map = {
        OpteeUteeParamType.NONE: message.OpteeMsgParamNone,
        OpteeUteeParamType.VALUE_INPUT: message.OpteeMsgParamValueInput,
        OpteeUteeParamType.VALUE_OUTPUT: message.OpteeMsgParamValueOutput,
        OpteeUteeParamType.VALUE_INOUT: message.OpteeMsgParamValueInOut,
        OpteeUteeParamType.MEMREF_INPUT: message.OpteeMsgParamTempMemInput,
        OpteeUteeParamType.MEMREF_OUTPUT: message.OpteeMsgParamTempMemOutput,
        OpteeUteeParamType.MEMREF_INOUT: message.OpteeMsgParamTempMemInOut,
    }

    try:
      msg_param = type_map[self.type]()
    except ValueError:
      raise error.Error(f'Can not convert Optee Msg type {self.attr} '
                        'to OpteeUteeParam')

    if isinstance(self, OpteeUteeParamValue):
      msg_param.a = self.a
      msg_param.b = self.b
    elif isinstance(self, OpteeUteeParamMemref):
      msg_param.addr = self.addr
      msg_param.size = self.size
      msg_param.data = self.data

    return msg_param


class OpteeUteeParamValue(OpteeUteeParam):
  """Base class for OpteeUteeParam value."""

  FMT = '<2I'

  def __init__(self, t, a=0, b=0):
    if t not in [
        OpteeUteeParamType.VALUE_INPUT,
        OpteeUteeParamType.VALUE_OUTPUT,
        OpteeUteeParamType.VALUE_INOUT,
    ]:
      raise ValueError(f'Wrong type: {t}')
    OpteeUteeParam.__init__(self, t)
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


class OpteeUteeParamValueInput(OpteeUteeParamValue):

  def __init__(self, a=0, b=0):
    OpteeUteeParamValue.__init__(self, OpteeUteeParamType.VALUE_INPUT, a, b)


class OpteeUteeParamValueOutput(OpteeUteeParamValue):

  def __init__(self, a=0, b=0):
    OpteeUteeParamValue.__init__(self, OpteeUteeParamType.VALUE_OUTPUT, a, b)


class OpteeUteeParamValueInOut(OpteeUteeParamValue):

  def __init__(self, a=0, b=0):
    OpteeUteeParamValue.__init__(self, OpteeUteeParamType.VALUE_INOUT, a, b)


class OpteeUteeParamMemref(OpteeUteeParam):
  """Base class for OpteeUteeParam memref."""

  def __init__(self, t, data: bytes = None, addr: int = 0, size: int = 0):
    if t not in [
        OpteeUteeParamType.MEMREF_INPUT,
        OpteeUteeParamType.MEMREF_OUTPUT,
        OpteeUteeParamType.MEMREF_INOUT
    ]:
      raise ValueError(f'Wrong type: {t}')
    OpteeUteeParam.__init__(self, t)
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


class OpteeUteeParamMemrefInput(OpteeUteeParamMemref):

  def __init__(self, data=None, addr=0, size=0):
    OpteeUteeParamMemref.__init__(self, OpteeUteeParamType.MEMREF_INPUT,
                                  data, addr, size)


class OpteeUteeParamMemrefOutput(OpteeUteeParamMemref):

  def __init__(self, data=None, addr=0, size=0):
    OpteeUteeParamMemref.__init__(self, OpteeUteeParamType.MEMREF_OUTPUT,
                                  data, addr, size)


class OpteeUteeParamMemrefInOut(OpteeUteeParamMemref):

  def __init__(self, data=None, addr=0, size=0):
    OpteeUteeParamMemref.__init__(self, OpteeUteeParamType.MEMREF_INOUT,
                                  data, addr, size)


class OpteeUteeParamNone(OpteeUteeParam):
  """OPTEE UTEE None param."""

  def __init__(self, *_):
    OpteeUteeParam.__init__(self, OpteeUteeParamType.NONE)

  def values(self):
    return [0, 0]

  def init_from_values(self, val1, val2):
    # do nothing
    pass

  def __str__(self):
    return f'{str(self.type)}'

  def __bytes__(self):
    return b''


OPTEE_ATTR_BIT_PROTECTED = 1 << 28
OPTEE_ATTR_BIT_VALUE = 1 << 29


class OpteeUteeAttribute:
  """Defines OPTEE Utee Attribute base class."""

  TYPE_FMT = 'I'
  BODY_FMT = '2Q'
  FORMAT = '<' + BODY_FMT + TYPE_FMT + 'I'  # 32bit padding

  def __init__(self):
    self.atype = 0

  @abc.abstractmethod
  def values(self):
    raise NotImplementedError()

  @staticmethod
  def size_():
    return struct.calcsize(OpteeUteeAttribute.FORMAT)

  @staticmethod
  def create(data):
    """Creates OpteeUteeAttribute derived object from raw data from mem.

    Args:
      data: raw binary data

    Returns:
      OpteeUteeAttribute derived object.

    Raises:
      ValueError exception is raised if size of data is not enough for parsing.
    """

    sz = OpteeUteeAttribute.size_()

    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    a, b, atype, _ = struct.unpack(OpteeUteeAttribute.FORMAT, data[:sz])
    if atype & OPTEE_ATTR_BIT_VALUE:
      attr = OpteeUteeAttributeValue(atype, a, b)
    else:
      attr = OpteeUteeAttributeMemory(atype, addr=a, size=b)

    return attr

  def load_to_mem(self, loader, addr):
    """Loads the Optee attribute to memery.

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

    if isinstance(self, OpteeUteeAttributeMemory):
      data = self.data
      if self.size and not data:
        data = b'\x00' * self.size
      if data:
        self.addr = loader(self.addr, data)
        if not self.size:
          self.size = len(data)
    values = self.values()

    data = struct.pack(self.FORMAT, *values, 0)
    return loader(addr, data)

  @staticmethod
  def create_from_mem(loader, addr):
    """Load OPTEE UTEE attribute from memory.

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

    data = loader(addr, OpteeUteeAttribute.size_())

    attr = OpteeUteeAttribute.create(data)

    if isinstance(attr, OpteeUteeAttributeMemory):
      if attr.addr != 0 and attr.size != 0:
        attr.data = loader(attr.addr, attr.size)

    return attr


class OpteeUteeAttributeValue(OpteeUteeAttribute):
  """Defines OPTEE Utee Attribute Value class."""

  def __init__(self, atype, a=0, b=0):
    OpteeUteeAttribute.__init__(self)
    if not atype & OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Wrong Attribute type')

    self.a = a
    self.b = b
    self.atype = atype

  def values(self):
    return [self.a, self.b, self.atype]

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

    self.a, self.b, self.atype, _ = struct.unpack(self.FORMAT, data[:sz])
    if not self.atype & OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Parsed attribute is not VALUE one')

    return sz

  def __str__(self):
    out = 'OpteeUteeAttributeValue:\n'
    out += f'\ttype: 0x{self.atype:x}\n'
    out += f'\ta: {self.a}\n'
    out += f'\tb: {self.b}\n'

    return out


class OpteeUteeAttributeMemory(OpteeUteeAttribute):
  """Defines OPTEE Utee Attribute Memory reference class."""

  def __init__(self, atype, data=None, addr=0, size=0):
    OpteeUteeAttribute.__init__(self)
    if atype & OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Wrong Attribute type')

    self.addr = addr
    self.size = size
    self.data = data
    self.atype = atype

  def values(self):
    return [self.addr, self.size, self.atype]

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

    self.addr, self.size, self.atype, _ = struct.unpack(self.FORMAT, data[:sz])
    if self.atype & OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Parsed attribute is VALUE one, not Memory')

    return sz

  def __str__(self):
    out = 'OpteeUteeAttributeMemory:\n'
    out += f'\ttype: 0x{self.atype:x}\n'
    out += f'\tptr:  0x{self.addr:08x}\n'
    out += f'\tsize: {self.size}\n'
    out += f'\tdata: {str(self.data)}\n'

    return out

