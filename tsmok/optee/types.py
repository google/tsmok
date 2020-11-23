"""Main Optee TEE types."""
import struct
from typing import Any, List
import uuid
import tsmok.common.error as error
import tsmok.optee.const as optee_const


# typedef struct {
#         uint32_t objectType;
#         __extension__ union {
#                 uint32_t keySize;       /* used in 1.1 spec */
#                 uint32_t objectSize;    /* used in 1.1.1 spec */
#         };
#         __extension__ union {
#                 uint32_t maxKeySize;    /* used in 1.1 spec */
#                 uint32_t maxObjectSize; /* used in 1.1.1 spec */
#         };
#         uint32_t objectUsage;
#         uint32_t dataSize;
#         uint32_t dataPosition;
#         uint32_t handleFlags;
# } TEE_ObjectInfo;
class OpteeObjectInfo:
  """Defines OPTEE Object Info."""

  # default initialization
  def __init__(self):
    self.obj_type = optee_const.OpteeObjectType.DATA
    self.object_usage = optee_const.OpteeUsage.DEFAULT
    self.handle_flags = optee_const.OpteeHandleFlags.INITIALIZED
    self.max_object_size = optee_const.OPTEE_OBJECT_ID_MAX_LEN
    self.object_size = 0
    self.data_size = 0
    self.data_position = 0

  def data(self):
    return struct.pack('<7I', int(self.obj_type),
                       self.object_size, self.max_object_size,
                       int(self.object_usage), self.data_size,
                       self.data_position, int(self.handle_flags))


class OpteeParam:
  """Defines Optee TA params type."""

  def __init__(self, t):
    self.type = t

  @staticmethod
  def get_type(t):
    """Returns OpteeParam type based on OpteeParamType.

    Args:
      t: OpteeParamType type to be created

    Returns:
      Corresponding OpteeParam type
    """
    type_map = {
        optee_const.OpteeParamType.NONE: OpteeParamNone,
        optee_const.OpteeParamType.VALUE_INPUT: OpteeParamValueInput,
        optee_const.OpteeParamType.VALUE_OUTPUT: OpteeParamValueOutput,
        optee_const.OpteeParamType.VALUE_INOUT: OpteeParamValueInOut,
        optee_const.OpteeParamType.MEMREF_INPUT: OpteeParamMemrefInput,
        optee_const.OpteeParamType.MEMREF_OUTPUT: OpteeParamMemrefOutput,
        optee_const.OpteeParamType.MEMREF_INOUT: OpteeParamMemrefInOut,
    }

    return type_map[t]


class OpteeParamValue(OpteeParam):
  """Base class for OpteeParam value."""

  def __init__(self, t, a=0, b=0):
    if t not in [
        optee_const.OpteeParamType.VALUE_INPUT,
        optee_const.OpteeParamType.VALUE_OUTPUT,
        optee_const.OpteeParamType.VALUE_INOUT
    ]:
      raise ValueError(f'Wrong type: {t}')
    OpteeParam.__init__(self, t)
    self.a = a
    self.b = b

  def values(self):
    return [self.a, self.b]

  def __str__(self):
    return f'{str(self.type)}: a = 0x{self.a:08x}, b = {self.b:08x}'


class OpteeParamValueInput(OpteeParamValue):

  def __init__(self, a=0, b=0):
    OpteeParamValue.__init__(self, optee_const.OpteeParamType.VALUE_INPUT, a, b)


class OpteeParamValueOutput(OpteeParamValue):

  def __init__(self, a=0, b=0):
    OpteeParamValue.__init__(self, optee_const.OpteeParamType.VALUE_OUTPUT, a,
                             b)


class OpteeParamValueInOut(OpteeParamValue):

  def __init__(self, a=0, b=0):
    OpteeParamValue.__init__(self, optee_const.OpteeParamType.VALUE_INOUT, a, b)


class OpteeParamMemref(OpteeParam):
  """Base class for OpteeParam memref."""

  def __init__(self, t, ptr: int = 0, size: int = 0):
    if t not in [
        optee_const.OpteeParamType.MEMREF_INPUT,
        optee_const.OpteeParamType.MEMREF_OUTPUT,
        optee_const.OpteeParamType.MEMREF_INOUT
    ]:
      raise ValueError(f'Wrong type: {t}')
    OpteeParam.__init__(self, t)
    self.ptr = ptr
    self.size = size
    self.data = None

  def values(self):
    return [self.ptr, self.size]

  def __str__(self):
    return (f'{str(self.type)}: buffer ptr = 0x{self.ptr:08x}, size = '
            f'{self.size} data = {self.data}')


class OpteeParamMemrefInput(OpteeParamMemref):

  def __init__(self, ptr=0, size=0):
    OpteeParamMemref.__init__(self, optee_const.OpteeParamType.MEMREF_INPUT,
                              ptr, size)


class OpteeParamMemrefOutput(OpteeParamMemref):

  def __init__(self, ptr=0, size=0):
    OpteeParamMemref.__init__(self, optee_const.OpteeParamType.MEMREF_OUTPUT,
                              ptr, size)


class OpteeParamMemrefInOut(OpteeParamMemref):

  def __init__(self, ptr=0, size=0):
    OpteeParamMemref.__init__(self, optee_const.OpteeParamType.MEMREF_INOUT,
                              ptr, size)


class OpteeParamNone(OpteeParam):

  def __init__(self, *_):
    OpteeParam.__init__(self, optee_const.OpteeParamType.NONE)

  def values(self):
    return [0, 0]

  def __str__(self):
    return f'{str(self.type)}'


def optee_params_from_data(data):
  """Converts OpteeParams into plain bytes."""

  data = struct.unpack(optee_const.OPTEE_PARAMS_PARSE_FORMAT, data)
  params = []
  for i in range(optee_const.OPTEE_NUM_PARAMS):
    t = optee_const.OpteeParamType((data[0] >> (i * 4)) & 0xf)
    if t != optee_const.OpteeParamType.NONE:
      params.append(OpteeParam.get_type(t)(data[1 + i * 2],
                                           data[1 + i * 2 + 1]))

  return params


def optee_params_to_data(params: List[OpteeParam]):
  """Converts plain bytes into OpteeParams."""
  for i in range(optee_const.OPTEE_NUM_PARAMS - len(params)):
    params.append(OpteeParamNone())

  param_types = 0
  values = []
  for i in range(optee_const.OPTEE_NUM_PARAMS):
    p = params[i]
    param_types |= (int(p.type) & 0xf) << (i * 4)
    values += p.values()

  return struct.pack(optee_const.OPTEE_PARAMS_PARSE_FORMAT, param_types,
                     *values)


class OpteeProperty:
  """Defines base class for OPTEE Properties."""

  def __init__(self, ptype: optee_const.OpteePropertyType, name: bytes,
               value: Any):
    self.name = name
    self.value = value
    self.type = ptype

  def __eq__(self, other):
    if isinstance(other, self.__class__):
      return self.name == other.name
    elif isinstance(other, bytes):
      return self.name == other
    else:
      raise error.Error(f'OpteeProperty[{self.name}]: wrong type to compare')

  def get_value(self) -> Any:
    if callable(self.value):
      return self.value()
    else:
      return self.value

  def data(self) -> bytes:
    pass


class OpteePropertyBool(OpteeProperty):

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, optee_const.OpteePropertyType.BOOL, name,
                           value)

  def data(self) -> bytes:
    val = self.get_value()
    return struct.pack('<I', val)


class OpteePropertyU32(OpteeProperty):

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, optee_const.OpteePropertyType.U32, name, value)

  def data(self) -> bytes:
    val = self.get_value()
    return struct.pack('<I', val)


class OpteePropertyUuid(OpteeProperty):
  """Defines OPTEE Property UUID."""

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, optee_const.OpteePropertyType.UUID, name,
                           value)

  def data(self) -> bytes:
    val = self.get_value()
    if not isinstance(val, uuid.UUID):
      raise error.Error(f'Incorrect value type: {type(val)}. Should be Uuid')

    fields = val.fields
    arg3 = (fields[3] << 56) | (fields[4] << 48) | fields[5]
    data = struct.pack('<I2H', fields[0], fields[1], fields[2])
    data += struct.pack('>Q', arg3)
    return data


class OpteePropertyIdentity(OpteeProperty):
  """Defines OPTEE Propery Identity."""

  def __init__(self, name: bytes, login_type: optee_const.OpteeMsgLoginType,
               uid: uuid.UUID):
    OpteeProperty.__init__(self, optee_const.OpteePropertyType.IDENTITY, name, \
        (login_type, uid))

  def data(self) -> bytes:
    login, uid = self.get_value()
    if not isinstance(uid, uuid.UUID):
      raise error.Error(f'Incorrect type: {type(uid)}. Should be UUID')
    data = struct.pack('<I', int(login))
    fields = uid.fields
    arg3 = (fields[3] << 56) | (fields[4] << 48) | fields[5]
    data += struct.pack('<I2H', fields[0], fields[1], fields[2])
    data += struct.pack('>Q', arg3)
    return data


class OpteePropertyString(OpteeProperty):

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, optee_const.OpteePropertyType.STRING, name,
                           value)

  def data(self) -> bytes:
    return self.get_value()


class OpteePropertyBinBlock(OpteeProperty):

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, optee_const.OpteePropertyType.BINARY_BLOCK,
                           name, value)

  def data(self) -> bytes:
    return self.get_value()


class OpteeMsgArg:
  """OPTEE SMC message argument."""

  FORMAT = '<8I'

  def __init__(self, cmd):
    self.cmd = cmd
    self.func = 0
    self.session = 0
    self.cancel_id = 0
    self.ret = 0
    self.ret_origin = 0
    self.params = []
    self._shm_reg = None

  def size(self):
    return (struct.calcsize(self.FORMAT) +
            len(self.params) * struct.calcsize(OpteeMsgParam.FORMAT))

  def __bytes__(self):
    out = struct.pack(self.FORMAT, self.cmd, self.func, self.session,
                      self.cancel_id, 0, self.ret, self.ret_origin,
                      len(self.params))
    for param in self.params:
      out += bytes(param)

    return out


class OpteeMsgParam:
  FORMAT = '<4Q'

  def __init__(self, attr: optee_const.OpteeMsgAttrType):
    self.attr = attr


class OpteeMsgParamNone(OpteeMsgParam):

  def __init__(self):
    OpteeMsgParam.__init__(self, optee_const.OpteeMsgAttrType.NONE)

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr, 0, 0, 0)


class OpteeMsgParamValue(OpteeMsgParam):
  """OPTEE Value SMC message base parameter."""

  def __init__(self, attr, a, b, c):
    if attr not in [optee_const.OpteeMsgAttrType.VALUE_INOUT,
                    optee_const.OpteeMsgAttrType.VALUE_INPUT,
                    optee_const.OpteeMsgAttrType.VALUE_OUTPUT]:
      raise ValueError(f'Wrong type for OpteeMsgParamValue: {attr}')
    OpteeMsgParam.__init__(self, attr)
    self.a = a
    self.b = b
    self.c = c

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr, self.a, self.b, self.c)


class OpteeMsgParamValueInput(OpteeMsgParamValue):

  def __init__(self, a=0, b=0, c=0):
    OpteeMsgParamValue.__init__(self, optee_const.OpteeMsgAttrType.VALUE_INPUT,
                                a, b, c)


class OpteeMsgParamValueInOut(OpteeMsgParamValue):

  def __init__(self, a=0, b=0, c=0):
    OpteeMsgParamValue.__init__(self, optee_const.OpteeMsgAttrType.VALUE_INOUT,
                                a, b, c)


class OpteeMsgParamValueOutput(OpteeMsgParamValue):

  def __init__(self, a=0, b=0, c=0):
    OpteeMsgParamValue.__init__(self, optee_const.OpteeMsgAttrType.VALUE_OUTPUT,
                                a, b, c)


class OpteeMsgParamTempMem(OpteeMsgParam):
  """OPTEE Temporary Memory SMC message base parameter."""

  def __init__(self, attr, buf_ptr, size, shm_ref):
    if attr not in [optee_const.OpteeMsgAttrType.TMEM_INOUT,
                    optee_const.OpteeMsgAttrType.TMEM_INPUT,
                    optee_const.OpteeMsgAttrType.TMEM_OUTPUT]:
      raise ValueError(f'Wrong type for OpteeMsgParamTempMem: {attr}')
    OpteeMsgParam.__init__(self, attr)
    self.buf_ptr = buf_ptr
    self.size = size
    self.shm_ref = shm_ref
    self.data = None

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr, self.buf_ptr, self.size,
                       self.shm_ref)


class OpteeMsgParamTempMemInput(OpteeMsgParamTempMem):

  def __init__(self, buf_ptr=0, size=0, shm_ref=0):
    OpteeMsgParamTempMem.__init__(self, optee_const.OpteeMsgAttrType.TMEM_INPUT,
                                  buf_ptr, size, shm_ref)


class OpteeMsgParamTempMemInOut(OpteeMsgParamTempMem):

  def __init__(self, buf_ptr=0, size=0, shm_ref=0):
    OpteeMsgParamTempMem.__init__(self, optee_const.OpteeMsgAttrType.TMEM_INOUT,
                                  buf_ptr, size, shm_ref)


class OpteeMsgParamTempMemOutput(OpteeMsgParamTempMem):

  def __init__(self, buf_ptr=0, size=0, shm_ref=0):
    OpteeMsgParamTempMem.__init__(self,
                                  optee_const.OpteeMsgAttrType.TMEM_OUTPUT,
                                  buf_ptr, size, shm_ref)


class OpteeMsgParamRegMem(OpteeMsgParam):
  """OPTEE Registered Memory SMC message base parameter."""

  def __init__(self, attr, offset, size, shm_ref):
    if attr not in [optee_const.OpteeMsgAttrType.RMEM_INOUT,
                    optee_const.OpteeMsgAttrType.RMEM_INPUT,
                    optee_const.OpteeMsgAttrType.RMEM_OUTPUT]:
      raise ValueError(f'Wrong type for OpteeMsgParamRegMem: {attr}')
    OpteeMsgParam.__init__(self, attr)
    self.offset = offset
    self.size = size
    self.shm_ref = shm_ref
    self.data = None

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr, self.offset, self.size,
                       self.shm_ref)


class OpteeMsgParamRegMemInput(OpteeMsgParamRegMem):
  """OPTEE Registered Memory SMC message input parameter."""

  def __init__(self, offset=0, size=0, shm_ref=0):
    OpteeMsgParamRegMem.__init__(self, optee_const.OpteeMsgAttrType.RMEM_INPUT,
                                 offset, size, shm_ref)


class OpteeMsgParamRegMemInOut(OpteeMsgParamRegMem):

  def __init__(self, offset=0, size=0, shm_ref=0):
    OpteeMsgParamRegMem.__init__(self, optee_const.OpteeMsgAttrType.RMEM_INOUT,
                                 offset, size, shm_ref)


class OpteeMsgParamRegMemOutput(OpteeMsgParamRegMem):

  def __init__(self, offset=0, size=0, shm_ref=0):
    OpteeMsgParamRegMem.__init__(self, optee_const.OpteeMsgAttrType.RMEM_OUTPUT,
                                 offset, size, shm_ref)
