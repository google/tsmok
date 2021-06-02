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
%import .sys_grammar (int64_ptr, void, _in_, _out_, NUMBER)

%extend typename: "optee_utee_param_ptr" -> utee_param_ptr

%import common.WS
%ignore WS
""", start='start', parser='lalr', import_paths=[parser.IMPORT_PATH])


class UteeParamArg(syscall.Ptr, utee_args.OpteeUteeParamArgs):
  """OPTEE TA Param pointer type for parser."""

  HDR_FMT = '<H'
  ARGDELIM = b'\xb7\xc9'

  def __init__(self, params=None):
    syscall.Ptr.__init__(self, 0)
    utee_args.OpteeUteeParamArgs.__init__(self, params or [])

  def arg(self):
    return syscall.Ptr.arg(self)

  def value(self):
    return self.params

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
    out = 'OPTEE TA Param * ['
    for p in self.params:
      out += str(p) + '; '
    out += '] ' + super().__str__()
    return out


class TaTransformer(parser.SyscallTransformer):

  def __init__(self):
    parser.SyscallTransformer.__init__(self)

  def utee_param_ptr(self, *args):
    return UteeParamArg


def parse(data):
  try:
    tree = ta_call_parser.parse(data)
    return TaTransformer().transform(tree)
  except lark.GrammarError:
    raise error.Error('Failed to parse')
