"""OPTEE TA Parameter types."""

import enum
import struct
from typing import List

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


OPTEE_NUM_PARAMS = 4
# struct utee_params {
#   uint64_t types;
#       /* vals[n * 2]     corresponds to either value.a or memref.buffer
#        * vals[n * 2 + ]  corresponds to either value.b or memref.size
#        * when converting to/from struct tee_ta_param
#        */
#   uint64_t vals[TEE_NUM_PARAMS * 2];
# };
OPTEE_PARAMS_PARSE_FORMAT = '<9Q'

OPTEE_PARAMS_DATA_SIZE = struct.calcsize(OPTEE_PARAMS_PARSE_FORMAT)


class OpteeTaParam:
  """Defines Optee TA params type."""

  def __init__(self, t):
    self.type = t

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

  def values(self):
    return [self.a, self.b]

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

  def __init__(self, t, addr: int = 0, size: int = 0):
    if t not in [
        OpteeTaParamType.MEMREF_INPUT,
        OpteeTaParamType.MEMREF_OUTPUT,
        OpteeTaParamType.MEMREF_INOUT
    ]:
      raise ValueError(f'Wrong type: {t}')
    OpteeTaParam.__init__(self, t)
    self.addr = addr
    self.size = size
    self.data = None

  def values(self):
    return [self.addr, self.size]

  def __str__(self):
    return (f'{str(self.type)}: buffer addr = 0x{self.addr:08x}, size = '
            f'{self.size} data = {self.data}')


class OpteeTaParamMemrefInput(OpteeTaParamMemref):

  def __init__(self, addr=0, size=0):
    OpteeTaParamMemref.__init__(self, OpteeTaParamType.MEMREF_INPUT,
                                addr, size)


class OpteeTaParamMemrefOutput(OpteeTaParamMemref):

  def __init__(self, addr=0, size=0):
    OpteeTaParamMemref.__init__(self,
                                OpteeTaParamType.MEMREF_OUTPUT,
                                addr, size)


class OpteeTaParamMemrefInOut(OpteeTaParamMemref):

  def __init__(self, addr=0, size=0):
    OpteeTaParamMemref.__init__(self, OpteeTaParamType.MEMREF_INOUT,
                                addr, size)


class OpteeTaParamNone(OpteeTaParam):

  def __init__(self, *_):
    OpteeTaParam.__init__(self, OpteeTaParamType.NONE)

  def values(self):
    return [0, 0]

  def __str__(self):
    return f'{str(self.type)}'


def optee_params_from_data(data):
  """Converts OpteeTaParams into plain bytes."""

  data = struct.unpack(OPTEE_PARAMS_PARSE_FORMAT, data)
  params = []
  for i in range(OPTEE_NUM_PARAMS):
    t = OpteeTaParamType((data[0] >> (i * 4)) & 0xf)
    if t != OpteeTaParamType.NONE:
      params.append(OpteeTaParam.get_type(t)(data[1 + i * 2],
                                             data[1 + i * 2 + 1]))

  return params


def optee_params_to_data(params: List[OpteeTaParam]):
  """Converts plain bytes into OpteeTaParams."""
  for i in range(OPTEE_NUM_PARAMS - len(params)):
    params.append(OpteeTaParamNone())

  param_types = 0
  values = []
  for i in range(OPTEE_NUM_PARAMS):
    p = params[i]
    param_types |= (int(p.type) & 0xf) << (i * 4)
    values += p.values()

  return struct.pack(OPTEE_PARAMS_PARSE_FORMAT, param_types,
                     *values)
