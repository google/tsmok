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

"""OPTEE TA Calls grammar."""

import struct
import lark

import tsmok.common.error as error
import tsmok.common.syscall_decl.parser.general as parser
import tsmok.common.syscall_decl.syscall as syscall
import tsmok.optee.utee_args as utee_args


ta_call_parser = lark.Lark(r"""
?start: syscall+
%import .sys_grammar (syscall, syscallname, syscallnumber, arg, argname)
%import .sys_grammar (arglist, type, typename, type_options, type_opt)
%import .sys_grammar (in_res, out_res, void_ptr, int32, int64, int32_ptr)
%import .sys_grammar (int64_ptr, void, _in_, _out_, array, array_len, NUMBER)

%extend typename: "utee_param_ptr" -> utee_param_ptr
                 | "utee_attribute_ptr" -> utee_attribute_ptr
                 | "utee_attribute_array" -> utee_attribute_array
                 | "uuid_ptr" -> uuid_ptr
                 | "object_info_ptr" -> object_info_ptr
                 | "time_ptr" -> time_ptr

%import common.WS
%ignore WS
""", start='start', parser='lalr', import_paths=[parser.IMPORT_PATH])


class UteeParamArg(syscall.Ptr, utee_args.OpteeUteeParamArgs):
  """OPTEE UTEE Param pointer type for parser."""

  HDR_FMT = '<H'
  ARGDELIM = b'\xb7\xc9'

  def __init__(self, params=None):
    syscall.Ptr.__init__(self, 0)
    utee_args.OpteeUteeParamArgs.__init__(self, params or [])

  def arg(self):
    return syscall.Ptr.arg(self)

  def value(self):
    return self.params

  def reset(self):
    self.params = ([utee_args.OpteeUteeParamNone()] *
                   utee_args.OpteeUteeParamArgs.NUM_PARAMS)

  @classmethod
  def parse(cls, data):
    param_actions = {
        utee_args.OpteeUteeParamType.NONE: cls._setup_none_param,
        utee_args.OpteeUteeParamType.VALUE_INPUT: cls._setup_int_param,
        utee_args.OpteeUteeParamType.VALUE_OUTPUT: cls._setup_int_param,
        utee_args.OpteeUteeParamType.VALUE_INOUT: cls._setup_int_param,
        utee_args.OpteeUteeParamType.MEMREF_INPUT: cls._setup_buffer_param,
        utee_args.OpteeUteeParamType.MEMREF_OUTPUT: cls._setup_buffer_param,
        utee_args.OpteeUteeParamType.MEMREF_INOUT: cls._setup_buffer_param,
    }

    sz = struct.calcsize(cls.HDR_FMT)
    if len(data) < sz:
      raise ValueError('Wrong size of data')

    ptypes = struct.unpack(cls.HDR_FMT, data[:sz])[0]
    idx = data[sz:].find(cls.ARGDELIM)
    off = sz
    if idx < 0:
      args = []
    else:
      off += idx
      args = data[off:].lstrip(cls.ARGDELIM).split(cls.ARGDELIM)
    params = []
    for i in range(utee_args.OpteeUteeParamArgs.NUM_PARAMS):
      try:
        t = utee_args.OpteeUteeParamType((ptypes >> (i * 4)) & 0x7)
      except ValueError:
        continue

      param = utee_args.OpteeUteeParam.get_type(t)()
      params.append(param)
      if isinstance(param, utee_args.OpteeUteeParamNone) or not args:
        continue

      try:
        off += len(cls.ARGDELIM)
        off += param_actions[t](param, args.pop(0))
      except (ValueError, IndexError):
        break
    return params, off

  @classmethod
  def _setup_int_param(cls, param, data):
    sz = struct.calcsize(utee_args.OpteeUteeParamValue.FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    a, b = struct.unpack(utee_args.OpteeUteeParamValue.FMT, data[:sz])
    param.a = a
    param.b = b
    return sz

  @classmethod
  def _setup_buffer_param(cls, param, data):
    param.data = data
    return len(data)

  @classmethod
  def _setup_none_param(cls, param, data):
    del param, data  # unused in this function
    return 0

  def load_to_mem(self, loader):
    self.addr = utee_args.OpteeUteeParamArgs.load_to_mem(self, loader,
                                                         self.addr)

  def __bytes__(self):
    out = b''
    ptypes = 0
    for i, p in enumerate(self.params):
      if not isinstance(p, utee_args.OpteeUteeParamNone):
        out += self.ARGDELIM + bytes(p)
      ptypes |= (int(p.type) & 0xf) << (i * 4)
    return struct.pack(self.HDR_FMT, ptypes) + out

  def __str__(self):
    out = 'OPTEE UTEE Param * ['
    for p in self.params:
      out += str(p) + '; '
    out += '] ' + super().__str__()
    return out

  def __len__(self):
    raise NotImplementedError()

  def load_from_mem(self, loader):
    utee_args.OpteeUteeParamArgs.load_from_mem(self, loader, self.addr)


class UteeAttributeArg(syscall.Ptr):
  """OPTEE UTEE Attribute pointer type for parser."""

  def __init__(self, attr=None):
    syscall.Ptr.__init__(self, 0)
    self.attr = attr

  def arg(self):
    return syscall.Ptr.arg(self)

  def value(self):
    return self.attr

  def reset(self):
    self.attr = None

  @classmethod
  def parse(cls, data):

    sz = struct.calcsize(utee_args.OpteeUteeAttribute.TYPE_FMT)
    if len(data) < sz:
      raise ValueError('Wrong size of data')

    atype = struct.unpack(utee_args.OpteeUteeAttribute.TYPE_FMT, data[:sz])[0]
    if atype & utee_args.OPTEE_ATTR_BIT_VALUE:
      attr = cls._setup_value_attr(atype, data[sz:])
    else:
      attr = cls._setup_memref_attr(atype, data[sz:])

    return attr, utee_args.OpteeUteeAttribute.size_()

  @classmethod
  def _setup_value_attr(cls, atype, data):
    sz = struct.calcsize(utee_args.OpteeUteeAttributeValue.BODY_FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    a, b = struct.unpack(utee_args.OpteeUteeAttributeValue.BODY_FMT, data[:sz])
    attr = utee_args.OpteeUteeAttributeValue(atype, a, b)
    return attr

  @classmethod
  def _setup_memref_attr(cls, atype, data):
    attr = utee_args.OpteeUteeAttributeMemory(atype, data)
    return attr

  def load_to_mem(self, loader):
    self.addr = self.attr.load_to_mem(loader, self.addr)

  def __bytes__(self):
    if not self.attr:
      return b''

    if isinstance(self.attr, utee_args.OpteeUteeAttributeValue):
      return struct.pack('<' + self.attr.TYPE_FMT + self.attr.BODY_FMT,
                         self.attr.atype, self.attr.a, self.attr.b)
    else:
      return struct.pack(self.attr.TYPE_FMT, self.attr.atype) + self.attr.data

  def __str__(self):
    out = 'OPTEE UTEE Attribute * ['
    if self.attr:
      out += str(self.attr)
    out += ' ]' + super().__str__()
    return out

  def __len__(self):
    raise NotImplementedError()

  def load_from_mem(self, loader):
    if self.addr:
      self.attr = utee_args.OpteeUteeAttribute.create_from_mem(
          loader, self.addr)


class UteeAttributeArray(syscall.Array):
  """OPTEE UTEE Attribute array type for parser."""

  HDR_FMT = '<H'
  ARGDELIM = b'\xb7\xc9'

  def __init__(self, attrs=None):
    syscall.Array.__init__(self, 0, 0)
    self.attrs = attrs or []

  def arg(self):
    return syscall.Ptr.arg(self)

  def value(self):
    return self.attrs

  def reset(self):
    self.attrs = []

  @classmethod
  def parse(cls, data):

    args_data = list(filter(None, data.split(cls.ARGDELIM)))

    attrs = []
    for adata in args_data:
      sz = struct.calcsize(utee_args.OpteeUteeAttribute.TYPE_FMT)
      if len(adata) < sz:
        # not enough data to parse
        continue

      atype = struct.unpack(utee_args.OpteeUteeAttribute.TYPE_FMT,
                            adata[:sz])[0]
      if atype & utee_args.OPTEE_ATTR_BIT_VALUE:
        attr = cls._setup_value_attr(atype, adata[sz:])
      else:
        attr = cls._setup_memref_attr(atype, adata[sz:])
      attrs.append(attr)

    return attrs, len(data)

  @classmethod
  def _setup_value_attr(cls, atype, data):
    sz = struct.calcsize(utee_args.OpteeUteeAttribute.BODY_FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    a, b = struct.unpack(utee_args.OpteeUteeAttribute.BODY_FMT, data[:sz])
    attr = utee_args.OpteeUteeAttributeValue(atype, a, b)
    return attr

  @classmethod
  def _setup_memref_attr(cls, atype, data):
    attr = utee_args.OpteeUteeAttributeMemory(atype, data)
    return attr

  def load_to_mem(self, loader):
    if not callable(loader):
      raise ValueError('loader argument is not a function')

    adata = b''
    for attr in self.attrs:
      if isinstance(attr, utee_args.OpteeUteeAttributeMemory):
        data = attr.data
        if attr.size and not data:
          data = b'\x00' * attr.size
        if data:
          attr.addr = loader(attr.addr, data)
          if not attr.size:
            attr.size = len(data)
      adata += struct.pack(attr.FORMAT, *attr.values(), 0)

    self.addr = loader(self.addr, adata)

  def __bytes__(self):
    if not self.attrs:
      return b''

    out = b''
    for attr in self.attrs:
      out += self.ARGDELIM
      if isinstance(attr, utee_args.OpteeUteeAttributeValue):
        out += struct.pack('<' + attr.TYPE_FMT + attr.BODY_FMT,
                           attr.atype, attr.a, attr.b)
      else:
        out += struct.pack(attr.TYPE_FMT, attr.atype) + attr.data

    return out

  def __str__(self):
    out = 'OPTEE UTEE Attribute array ['
    for attr in self.attrs:
      if attr:
        out += str(attr) + ', '
    out += ' ] ' + super().__str__()
    return out

  def __len__(self):
    raise NotImplementedError()

  def load_from_mem(self, loader):
    if not self._size or not self.addr:
      raise ValueError('Size is not specified!')

    if not callable(loader):
      raise ValueError('loader argument is not a function')

    data = loader(self.addr, self._size)
    sz = utee_args.OpteeUteeAttribute.size_()
    off = 0
    size = len(data)

    self.attrs = []
    while off < size:
      attr = utee_args.OpteeUteeAttribute.create(data[off:off+sz])
      off += sz

      if isinstance(attr, utee_args.OpteeUteeAttributeMemory):
        if attr.addr != 0 and attr.size != 0:
          attr.data = loader(attr.addr, attr.size)
      self.attrs.append(attr)


class TimePtr(syscall.VoidPtr):
  """OPTEE Time pointer type for parser."""

  FMT = '<2I'

  def __str__(self):
    out = 'Time * ' + syscall.Ptr.__str__(self)
    if self._data:
      out += f' Data {self._data[:8].hex()}... '
    return out

  def load_from_mem(self, loader):
    if self._size and self.addr:
      self._data = loader(self.addr, struct.calcsize(self.FMT))


class UuidPtr(syscall.VoidPtr):
  """OPTEE UUID pointer type for parser."""

  FMT = '<I2H8B'

  def __str__(self):
    out = 'Uuid * ' + syscall.Ptr.__str__(self)
    if self._data:
      out += f' Data {self._data[:8].hex()}... '
    return out

  def load_from_mem(self, loader):
    if self._size and self.addr:
      self._data = loader(self.addr, struct.calcsize(self.FMT))


class ObjectInfoPtr(syscall.VoidPtr):
  """OPTEE ObjectInfo pointer type for parser."""

  FMT = '<7I'

  def __str__(self):
    out = 'ObjectInfo * ' + syscall.Ptr.__str__(self)
    if self._data:
      out += f' Data {self._data[:8].hex()}... '
    return out


class OpteeArgsTransformer(parser.SyscallTransformer):
  """OPTEE Syscall transformer."""

  def __init__(self):
    parser.SyscallTransformer.__init__(self)

  def utee_param_ptr(self, *args):
    return UteeParamArg

  def utee_attribute_ptr(self, *args):
    return UteeAttributeArg

  def utee_attribute_array(self, *args):
    return UteeAttributeArray

  def time_ptr(self, *args):
    return TimePtr

  def object_info_ptr(self, *args):
    return ObjectInfoPtr

  def uuid_ptr(self, *args):
    return UuidPtr


def parse(data):
  try:
    tree = ta_call_parser.parse(data)
    return OpteeArgsTransformer().transform(tree)
  except lark.GrammarError:
    raise error.Error('Failed to parse')
