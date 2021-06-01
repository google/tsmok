"""OPTEE TA Calls grammar."""

import struct
import lark

import tsmok.common.error as error
import tsmok.common.syscall_decl.parser.general as parser
import tsmok.common.syscall_decl.syscall as syscall
import tsmok.optee.ta_param as ta_param


ta_call_parser = lark.Lark(r"""
?start: syscall+
%import .sys_grammar (syscall, syscallname, syscallnumber, arg, argname)
%import .sys_grammar (arglist, type, typename, type_options, type_opt)
%import .sys_grammar (in_res, out_res, void_ptr, int32, int64, int32_ptr)
%import .sys_grammar (int64_ptr, void, _in_, _out_, NUMBER)

%extend typename: "optee_ta_param_ptr" -> ta_param_ptr

%import common.WS
%ignore WS
""", start='start', parser='lalr', import_paths=[parser.IMPORT_PATH])


class TaParamArg(syscall.Ptr, ta_param.OpteeTaParamArgs):
  """OPTEE TA Param pointer type for parser."""

  HDR_FMT = '<H'
  ARGDELIM = b'\xb7\xc9'

  def __init__(self, params=None):
    syscall.Ptr.__init__(self, 0)
    ta_param.OpteeTaParamArgs.__init__(self, params or [])

  def arg(self):
    return syscall.Ptr.arg(self)

  def value(self):
    return self.params

  @classmethod
  def parse(cls, data):
    param_actions = {
        ta_param.OpteeTaParamType.NONE: cls._setup_none_param,
        ta_param.OpteeTaParamType.VALUE_INPUT: cls._setup_int_param,
        ta_param.OpteeTaParamType.VALUE_OUTPUT: cls._setup_int_param,
        ta_param.OpteeTaParamType.VALUE_INOUT: cls._setup_int_param,
        ta_param.OpteeTaParamType.MEMREF_INPUT: cls._setup_buffer_param,
        ta_param.OpteeTaParamType.MEMREF_OUTPUT: cls._setup_buffer_param,
        ta_param.OpteeTaParamType.MEMREF_INOUT: cls._setup_buffer_param,
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
    for i in range(ta_param.OpteeTaParamArgs.NUM_PARAMS):
      try:
        t = ta_param.OpteeTaParamType((ptypes >> (i * 4)) & 0x7)
      except ValueError:
        continue

      param = ta_param.OpteeTaParam.get_type(t)()
      params.append(param)
      if isinstance(param, ta_param.OpteeTaParamNone) or not args:
        continue

      try:
        off += len(cls.ARGDELIM)
        off += param_actions[t](param, args.pop(0))
      except (ValueError, IndexError):
        break
    return params, off

  @classmethod
  def _setup_int_param(cls, param, data):
    sz = struct.calcsize(ta_param.OpteeTaParamValue.FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    a, b = struct.unpack(ta_param.OpteeTaParamValue.FMT, data[:sz])
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
    self.addr = ta_param.OpteeTaParamArgs.load_to_mem(self, loader, self.addr)

  def __bytes__(self):
    out = b''
    ptypes = 0
    for i, p in enumerate(self.params):
      if not isinstance(p, ta_param.OpteeTaParamNone):
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

  def ta_param_ptr(self, *args):
    return TaParamArg


def parse(data):
  try:
    tree = ta_call_parser.parse(data)
    return TaTransformer().transform(tree)
  except lark.GrammarError:
    raise error.Error('Failed to parse')
