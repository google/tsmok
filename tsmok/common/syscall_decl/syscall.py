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

"""Base system call parser."""

import abc
import enum
import struct


class ArgFlags(enum.IntEnum):
  IN = 0
  OUT = 1
  RES_IN = 2
  RES_OUT = 3
  ARRAY = 4
  ARRAY_LEN = 5


class ArgTypeInfo:
  """Syscall argument type information."""

  def __init__(self, atype=None, name='', options=None):
    self.atype = atype
    self.name = name.strip()
    self.options = options or []

  def __call__(self, *args):
    out = self.atype(*args)
    out.name = self.name
    out.options = self.options
    return out


class Syscall:
  """System call definition class."""

  CALLDELIM = b'\xb7\xe3'
  ARGDELIM = b'\xa5\xc9'

  CALL_FMT = '<B'
  NAME = ''
  NR = None
  RET = None
  ARGS_INFO = []

  def __init__(self, *args):
    arg_list = list(args)
    self._args = []
    self._args_dict = dict()
    self._options_dict = dict()
    for info in self.ARGS_INFO:
      if arg_list:
        arg = info(arg_list.pop(0))
      else:
        arg = info()
      setattr(self, arg.name, arg)
      self._args.append(arg)

      # create different maps to make easy access to a specific argument
      self._args_dict[arg.name] = arg
      for op in arg.options:
        if op not in self._options_dict:
          self._options_dict[op] = [arg]
        else:
          self._options_dict[op].append(arg)

  def arg_by_name(self, name):
    return self._args_dict[name]

  def args_by_options(self, op_name):
    return self._options_dict[op_name]

  def load_args_to_mem(self, loader):
    if not callable(loader):
      raise ValueError('loader argument is not a function')
    for a in self._args:
      if isinstance(a, Ptr):
        a.load_to_mem(loader)

  def load_args_from_mem(self, loader):
    if not callable(loader):
      raise ValueError('loader argument is not a function')
    for a in self._args:
      if isinstance(a, Ptr):
        a.load_from_mem(loader)

  def number(self):
    return self.NR

  def args(self):
    return [a.arg() for a in self._args]

  def args_out_resources(self):
    for a in  self._args:
      if ArgFlags.RES_OUT in a.options:
        yield (a.name, a.value())

  @classmethod
  def parse_args_data(cls, data):
    """Splits input data to list of chunks for futher parsing by args.

    Args:
      data: raw binary data.

    Returns:
      List of data chunks for futher parsing by args.

    Raises:
      ValueError/TypeError exception in case of error.
    """
    if not data:
      raise ValueError('Not enough data to parse')

    try:
      # skip magic if it present
      off = 0
      if data[off:off + 2] == cls.CALLDELIM:
        off += 2

      number = struct.unpack(cls.CALL_FMT, data[off:off + 1])[0]
      if cls.NR != number:
        raise TypeError('Wrong Syscall data')
      off += 1

      return list(filter(None, data[off:].split(cls.ARGDELIM)))
    except struct.error:
      raise ValueError('Not enough data to parse')

  @classmethod
  def parse_arg_n_value(cls, idx, arg_data):
    val, _ = cls.ARGS_INFO[idx].atype.parse(arg_data)
    return val

  @classmethod
  def parse_arg_value(cls, arg, arg_data):
    val, _ = arg.atype.parse(arg_data)
    return val

  @classmethod
  def create(cls, data):
    """Create system call arguments from raw data.

    Args:
      data: raw binary data.

    Returns:
      None

    Raises:
      ValueError/TypeError exception in case of error.
    """

    if not data:
      raise ValueError('Not enough data to parse')

    try:
      # skip magic if it present
      off = 0
      if data[off:off + 2] == cls.CALLDELIM:
        off += 2

      number = struct.unpack(cls.CALL_FMT, data[off:off + 1])[0]
      if cls.NR != number:
        raise TypeError('Wrong Syscall data')
      off += 1

      args = list(filter(None, data[off:].split(cls.ARGDELIM)))
    except struct.error:
      raise ValueError('Not enough data to parse')
    values = []
    for info in cls.ARGS_INFO:
      try:
        val, _ = info.atype.parse(args.pop(0))
        values.append(val)
      except (ValueError, IndexError):
        # Not enough data for all args.
        break

    return cls(*values)

  @staticmethod
  def parse_call_number(data):
    # skip magic if it present
    off = 0
    if data[off:off + 2] == Syscall.CALLDELIM:
      off += 2
    if len(data[off:off +1]) < struct.calcsize(Syscall.CALL_FMT):
      raise ValueError('Not enough data')

    return struct.unpack(Syscall.CALL_FMT, data[off:off+1])[0]

  def __bytes__(self):
    out = self.CALLDELIM
    out += struct.pack(self.CALL_FMT, self.NR)
    for a in self._args:
      out += self.ARGDELIM
      out += bytes(a)
    return out

  def __str__(self):
    out = f'Syscall: name {self.NAME}, '
    out += f'id {self.NR} ( '
    for a in self._args:
      out += f'{a}, '
    out += f') -> {self.RET}.'
    return out


class Arg(abc.ABC):
  """Base class for syscall argument."""

  def __init__(self):
    self.name = ''
    self.options = []

  def __str__(self):
    out = f'{self.name}'
    if self.options:
      out += ' [ flags: '
      for o in self.options:
        out += f'{str(o)} '
      out += ']'
    return out

  @abc.abstractmethod
  def value(self):
    raise NotImplementedError()

  @abc.abstractmethod
  def arg(self):
    raise NotImplementedError()

  @classmethod
  def parse(cls, data):
    raise NotImplementedError()

  @abc.abstractmethod
  def reset(self):
    raise NotImplementedError()


class Ptr(Arg):
  """Base class for pointer syscall argument."""

  def __init__(self, addr=0):
    super().__init__()
    self.addr = addr

  def arg(self):
    return self.addr

  def reset(self):
    self.addr = 0

  def load_to_mem(self, loader):
    if not callable(loader):
      raise ValueError('loader argument is not a function')
    self.addr = loader(self.addr, bytes(self))

  @abc.abstractmethod
  def load_from_mem(self, loader):
    raise NotImplementedError

  def __str__(self):
    out = super().__str__()
    if self.addr:
      out += f': at 0x{self.addr:x}'
    return out


class Array(Ptr):
  """Base class for array type of arguments."""

  def __init__(self, addr=0, size=0):
    Ptr.__init__(self, addr)
    self._size = size

  def set_size(self, size):
    self._size = size

  def reset(self):
    Ptr.reset(self)
    self._size = 0


class Int(Arg):
  """Base INT type for syscall argument."""

  def __init__(self, val):
    super().__init__()
    self.val = val

  def value(self):
    return self.val

  def arg(self):
    return self.val

  def reset(self):
    self.val = None

  @classmethod
  def parse(cls, data):
    sz = struct.calcsize(cls.FMT)
    if len(data) < sz:
      raise ValueError()

    val = struct.unpack(cls.FMT, data[:sz])[0]
    return val, sz

  def __str__(self):
    out = super().__str__()
    if self.val is not None:
      out += f': {self.val}'
    return out

  def __bytes__(self):
    if self.val is None:
      return b''
    return struct.pack(self.FMT, self.val)


class Void(Arg):
  """VOID syscall argument."""

  def __init__(self):
    Arg.__init__(self)

  def __bytes__(self):
    return b''

  def value(self):
    return None

  def arg(self):
    return 0

  @classmethod
  def parse(cls, data: bytes) -> int:
    return None, 0

  def __str__(self):
    return 'Void ' + super().__str__()


class VoidPtr(Array):
  """'VOID *' argument for syscall."""

  def __init__(self, data=None):
    Array.__init__(self, 0, 0)
    self._data = data or b''
    self._size = len(self._data)

  def value(self):
    return self._data

  def __len__(self):
    return len(self._data)

  @classmethod
  def parse(cls, data):
    return data, len(data)

  def reset(self):
    Array.reset(self)
    self._data = None

  def __bytes__(self):
    return self._data

  def __str__(self):
    out = 'Void * ' + super().__str__()
    if self._data:
      if isinstance(self._data, bytes):
        out += f' Data {self._data[:8].hex()}... '
      else:
        out += f' Data: {self._data}'
    return out

  def load_from_mem(self, loader):
    if self._size and self.addr:
      self._data = loader(self.addr, self._size)


class Int32(Int):
  """INT32 argument for syscall."""

  FMT = '<I'

  def __init__(self, val=0):
    super().__init__(val)

  def __str__(self):
    return 'Int32 ' + super().__str__()


class Int64(Int):
  """INT64 argument for syscall."""

  FMT = '<Q'

  def __init__(self, val=0):
    super().__init__(val)

  def __str__(self):
    return 'Int64 ' + super().__str__()


class Int32Ptr(Ptr, Int32):
  """'INT32 *' argument for syscall."""

  def __init__(self, val=0):
    Ptr.__init__(self, 0)
    Int32.__init__(self, val)

  def arg(self):
    return Ptr.arg(self)

  def value(self):
    return Int32.value(self)

  def reset(self):
    Ptr.reset(self)
    Int.reset(self)

  @classmethod
  def parse(cls, data):
    return super(cls, cls).parse(data)

  def __str__(self):
    out = 'Int32 * ' + Int.__str__(self)
    if self.addr:
      out += f' at 0x{self.addr:x}'
    return out

  def load_from_mem(self, loader):
    if self.addr:
      data = loader(self.addr, struct.calcsize(self.FMT))
      self.val = struct.unpack(self.FMT, data)(0)


class Int64Ptr(Ptr, Int64):
  """'INT64 *' argument for syscall."""

  def __init__(self, val=0):
    Ptr.__init__(self, 0)
    Int64.__init__(self, val)

  def arg(self):
    return Ptr.arg(self)

  def value(self):
    return Int64.value(self)

  def reset(self):
    Ptr.reset(self)
    Int.reset(self)

  @classmethod
  def parse(cls, data):
    return super(cls, cls).parse(data)

  def __str__(self):
    out = 'INT64 * '+ Int.__str__(self)
    if self.addr:
      out += f' at 0x{self.addr:x}'
    return out

  def load_from_mem(self, loader):
    if self.addr:
      data = loader(self.addr, struct.calcsize(self.FMT))
      self.val = struct.unpack(self.FMT, data)(0)

