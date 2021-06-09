"""Base system call parser."""

import os.path
import lark

import tsmok.common.error as error
import tsmok.common.syscall_decl.syscall as syscall


IMPORT_PATH = os.path.dirname(__file__)


base_parser = lark.Lark(r"""
?start: syscall+
%import .sys_grammar (syscall, syscallname, syscallnumber, arg, argname)
%import .sys_grammar (arglist, type, typename, type_options, type_opt)
%import .sys_grammar (in_res, out_res, void_ptr, int32, int64, int32_ptr)
%import .sys_grammar (int64_ptr, void, _in_, _out_, NUMBER)

%import common.WS
%ignore WS
""", start='start', parser='lalr', import_paths=[IMPORT_PATH])


@lark.v_args(inline=True)
class SyscallTransformer(lark.Transformer):
  """Syscall grammar transformer."""

  def __init__(self):
    pass

  def syscall(self, name, num, args, ret):
    s = type(name + '_syscall', (syscall.Syscall,),
             {
                 'NAME': name,
                 'NR': num,
                 'ARGS_INFO': args,
                 'RET': ret,
             }
            )
    return s

  def syscallname(self, name):
    return str(name).replace(' ', '_').strip('"\'')

  def syscallnumber(self, val):
    return int(val)

  def arglist(self, *args):
    return list(args)

  def argname(self, name):
    return str(name).replace(' ', '_').strip('"\'')

  def arg(self, name, atype):
    atype.name = name
    return atype

  def type(self, atype, flags=None):
    flags = flags or []
    return syscall.ArgTypeInfo(atype=atype, options=list(flags))

  def type_options(self, *args):
    return args

  def void(self, val=None):
    return syscall.Void

  def int32(self):
    return syscall.Int32

  def int64(self):
    return syscall.Int64

  def int32_ptr(self):
    return syscall.Int32Ptr

  def int64_ptr(self):
    return syscall.Int64Ptr

  def void_ptr(self, *args):
    return syscall.VoidPtr

  def in_res(self, *args):
    return syscall.ArgFlags.RES_IN

  def out_res(self, *args):
    return syscall.ArgFlags.RES_OUT

  def _in_(self, *args):
    return syscall.ArgFlags.IN

  def _out_(self, *args):
    return syscall.ArgFlags.OUT

  def array(self, *args):
    return syscall.ArgFlags.ARRAY

  def array_len(self, *args):
    return syscall.ArgFlags.ARRAY_LEN


def parse(data):
  try:
    tree = base_parser.parse(data)
    return SyscallTransformer().transform(tree)
  except lark.GrammarError:
    raise error.Error('Failed to parse')
