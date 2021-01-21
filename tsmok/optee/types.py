"""Main Optee TEE types."""

import struct
from typing import Any, List
import uuid
import tsmok.common.error as error
import tsmok.hw.devices.rpmb as rpmb
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
    self.max_object_size = optee_const.OPTEE_OBJECT_ID_MAX_LEN  # max_key_size
    self.object_size = 0  #  can be used as key_size
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
        optee_const.OpteeParamType.VALUE_INOUT,
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


class OpteeCrypObjTypeAttr:
  """Defines OPTEE Object type attributes."""

  FORMAT = '<I4H'

  def __init__(self, data=None):
    if data:
      if isinstance(data, bytes):
        self.load(data)
      else:
        raise ValueError('Wrong type of data')
    else:
      self.attr_id = 0
      self.flags = 0
      self.ops_index = 0
      self.raw_offs = 0
      self.raw_size = 0

  def load(self, data):
    sz = struct.calcsize(self.FORMAT)

    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    self.attr_id, self.flags, self.ops_index, self.raw_offs, self.raw_size = \
        struct.unpack(self.FORMAT, data[:sz])
    return sz

  @staticmethod
  def size():
    return struct.calcsize(OpteeCrypObjTypeAttr.FORMAT)

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr_id, self.flags, self.ops_index,
                       self.raw_offs, self.raw_size)

  def __str__(self):
    out = 'OpteeCrypObjTypeAttribute:\n'
    out += f'attr id:     {str(self.attr_id)}\n'
    out += f'flags:       {self.flags}\n'
    out += f'ops index:   {self.ops_index}\n'
    out += f'raw offset:  {self.raw_offs}\n'
    out += f'raw size:    {self.raw_size}\n'

    return out


class OpteeCrypObjTypeProperty:
  """Defines OPTEE Crypto object type property."""

  FORMAT = '<I3H2B'

  def __init__(self, data=None):
    if data:
      if isinstance(data, bytes):
        self.load(data)
      else:
        raise ValueError('Wrong type of data')
    else:
      self.obj_type = 0
      self.min_size = 0
      self.max_size = 0
      self.alloc_size = 0
      self.quanta = 0
      self.attrs = []

  def load(self, data):
    """Loads OpteeCrypObjTypeProperty object from raw data.

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

    self.obj_type, self.min_size, self.max_size, self.alloc_size, self.quanta, num = \
        struct.unpack(self.FORMAT, data[:sz])

    attr_sz = OpteeCrypObjTypeAttr.size()
    if len(data[sz:]) < attr_sz * num:
      raise ValueError(f'Not enough data: {len(data)} < {sz + attr_sz * num}')

    off = sz
    for _ in range(num):
      attr = OpteeCrypObjTypeAttr()
      off += attr.load(data[off:])
      self.attrs.append(attr)

    return sz + attr_sz * num

  def __str__(self):
    out = 'OpteeCrypObjTypeProperty:\n'
    out += f'obj type:   {str(self.obj_type)}\n'
    out += f'min size:   {self.min_size}\n'
    out += f'max size:   {self.max_size}\n'
    out += f'alloc size: {self.alloc_size}\n'
    out += f'quanta:     {self.quanta}\n'
    out += 'Attributes:\n'
    for a in self.attrs:
      out += str(a) + '\n'

    return out

  @staticmethod
  def min_size():
    return struct.calcsize(OpteeCrypObjTypeProperty.FORMAT)

  @staticmethod
  def get_needed_total_size(data):
    _, _, _, _, _, num = struct.unpack(OpteeCrypObjTypeProperty.FORMAT, data)
    return (struct.calcsize(OpteeCrypObjTypeProperty.FORMAT) +
            OpteeCrypObjTypeAttr.size() * num)


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
    if atype & optee_const.OPTEE_ATTR_BIT_VALUE:
      attr = OpteeUteeAttributeValue()
      attr.a = a
      attr.b = b
    else:
      attr = OpteeUteeAttributeMemory()
      attr.ptr = a
      attr.size = b

    attr.atype = optee_const.OpteeAttr(atype)

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
    if not atype & optee_const.OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Parsed attribute is not VALUE one')

    self.atype = optee_const.OpteeAttr(atype)
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
      self.ptr = 0
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

    self.ptr, self.size, atype = struct.unpack(self.FORMAT, data[:sz])
    if atype & optee_const.OPTEE_ATTR_BIT_VALUE:
      raise ValueError('Parsed attribute is VALUE one, not Memory')

    self.atype = optee_const.OpteeAttr(atype)
    return sz

  def __str__(self):
    out = 'OpteeUteeAttributeValue:\n'
    out += f'\tptr:  0x{self.ptr:08x}\n'
    out += f'\tsize: {self.size}\n'
    out += f'\ttype: {str(self.atype)}\n'
    out += f'\tdata: {str(self.data)}\n'

    return out


class OpteeMsgArg:
  """OPTEE SMC message argument."""

  FORMAT = '<8I'

  def __init__(self, arg):
    self.func = 0
    self.session = 0
    self.cancel_id = 0
    self.ret = 0
    self.ret_origin = 0
    self.params = []
    self.shm_reg = None

    if isinstance(arg, int):
      self.cmd = arg
    elif isinstance(arg, bytes):
      self._load(arg)
    else:
      raise ValueError(f'Wrong type of argument: {type(arg)}')

  def _load(self, data):
    """Loads Optee Message arguments from raw bytes data."""

    sz = struct.calcsize(self.FORMAT)
    self.cmd, self.func, self.session, self.cancel_id, _, self.ret, \
        self.ret_origin, num = struct.unpack(self.FORMAT, data[:sz])

    sz_needed = sz + struct.calcsize(OpteeMsgParam.FORMAT) * num
    if len(data) < sz_needed:
      raise ValueError(f'Not enough data: {len(data)} < {sz_needed}')

    off = sz
    for i in range(num):
      param = OpteeMsgParam.create(data[off:])
      self.params.append(param)
      off += struct.calcsize(param.FORMAT)

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

  def __str__(self):
    out = 'MsgArg:\n'
    out += f'    cmd: {self.cmd}, func: {self.func}\n'
    out += f'    shm id {self.shm_reg}, session: {self.session}\n'
    out += f'    cancel_id: {self.cancel_id}, ret: 0x{self.ret:08x}\n'
    out += f'    ret_origin: 0x{self.ret_origin:08x}\n'

    out += '  Params:\n'
    for p in self.params:
      out += '    ' + str(p) + '\n'

    return out


class OpteeMsgParam:
  """OPTEE Message Parameters base type."""

  FORMAT = '<4Q'

  def __init__(self, attr: optee_const.OpteeMsgAttrType):
    self.attr = attr

  @staticmethod
  def create(data):
    """Static method to create OPTEE Message parameter from raw data."""

    type_map = {
        optee_const.OpteeMsgAttrType.NONE: OpteeMsgParamNone,
        optee_const.OpteeMsgAttrType.VALUE_INPUT: OpteeMsgParamValueInput,
        optee_const.OpteeMsgAttrType.VALUE_OUTPUT: OpteeMsgParamValueOutput,
        optee_const.OpteeMsgAttrType.VALUE_INOUT: OpteeMsgParamValueInOut,
        optee_const.OpteeMsgAttrType.RMEM_INPUT: OpteeMsgParamRegMemInput,
        optee_const.OpteeMsgAttrType.RMEM_OUTPUT: OpteeMsgParamRegMemOutput,
        optee_const.OpteeMsgAttrType.RMEM_INOUT: OpteeMsgParamRegMemInOut,
        optee_const.OpteeMsgAttrType.TMEM_INPUT: OpteeMsgParamTempMemInput,
        optee_const.OpteeMsgAttrType.TMEM_OUTPUT: OpteeMsgParamTempMemOutput,
        optee_const.OpteeMsgAttrType.TMEM_INOUT: OpteeMsgParamTempMemInOut,
    }

    sz = struct.calcsize(OpteeMsgParam.FORMAT)
    attr, a, b, c = struct.unpack(OpteeMsgParam.FORMAT, data[:sz])

    attr &= ~optee_const.OPTEE_MSG_ATTR_META

    param_type = type_map[attr]
    return param_type(a, b, c)


class OpteeMsgParamNone(OpteeMsgParam):

  def __init__(self):
    OpteeMsgParam.__init__(self, optee_const.OpteeMsgAttrType.NONE)

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr, 0, 0, 0)

  def __str__(self):
    return f'    {str(self.attr)}'


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

  def __str__(self):
    return (f'    {str(self.attr)}: a: 0x{self.a:08x}, b: 0x{self.b:08x},'
            f'c: 0x{self.c:08x}')


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

  def __str__(self):
    return (f'    {str(self.attr)}: ptr: 0x{self.buf_ptr:08x},'
            f'size: 0x{self.size:08x}, shm: 0x{self.shm_ref:08x}')


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

  def __str__(self):
    return (f'    {str(self.attr)}: offset: 0x{self.offset:08x},'
            f'size: 0x{self.size:08x}, shm: 0x{self.shm_ref:08x}')


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


class OpteeRpmbRequest:
  """OPTEE RPMB Request structure."""

  FORMAT = '<3H'

  def __init__(self, data=None):
    self.frames = []
    if not data:
      self.cmd = 0
      self.dev_id = 0
      self.block_count = 0
    else:
      self.load(data)

  def load(self, data):
    """Parses OPTEE RPMB Request object from raw data.

    Args:
      data: raw binary data to be parsed

    Returns:
      The size of parsed data.

    Raises:
      ValueError exception is raised if size of data is not enough for parsing.
    """
    size = struct.calcsize(self.FORMAT)
    sz = len(data)
    if sz < size:
      raise ValueError('Not enough data')

    cmd, self.dev_id, self.block_count = struct.unpack(self.FORMAT,
                                                       data[:size])

    self.cmd = optee_const.OpteeRpmbRequestCmd(cmd)

    frame_size = struct.calcsize(rpmb.RpmbFrame.FORMAT)
    while (sz - size) >= frame_size:
      frame = rpmb.RpmbFrame(data[size:frame_size + size])
      self.frames.append(frame)
      size += frame_size

    return size

  def __bytes__(self):
    out = struct.pack(self.FORMAT, self.cmd, self.dev_id, self.block_count)
    for f in self.frames:
      out += bytes(f)

    return out

  def __str__(self):
    out = 'OPTEE RPMB Request:\n'
    out += f'\tCMD:         {str(self.cmd)}\n'
    out += f'\tDEV ID:      {self.dev_id}\n'
    out += f'\tBLOCK COUNT: {self.block_count}\n'
    for f in self.frames:
      out += str(f)

    return out


class OpteeRpmbDeviceInfo:
  """OPTEE RPMB Device Information structure."""

  FORMAT = '<16s3B'

  def __init__(self, data=None):
    if not data:
      self.cid = b'\x00' * rpmb.CID_SIZE
      self.rpmb_size_multi = 0
      self.rel_write_sector_count = 0  # Reliable Write Sector Count
      self.ret_code = 0
    else:
      self.load(data)

  def load(self, data):
    size = struct.calcsize(self.FORMAT)
    if len(data) < size:
      raise ValueError('Not enough data')

    self.cid, self.rpmb_size_multi, self.rel_write_sector_count, self.ret_code = \
       struct.unpack(self.FORMAT, data[:size])

    return size

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.cid, self.rpmb_size_multi,
                       self.rel_write_sector_count, self.ret_code)

  def __str__(self):
    out = 'OPTEE RPMB Device Info:\n'
    out += f'\tCID: {self.cid.hex()}\n'
    out += f'\tSize multi: {self.rpmb_size_multi}\n'
    out += f'\tReliable Write Sector Count: {self.rel_write_sector_count}\n'
    out += f'\tRet Code: {self.ret_code}\n'

    return out
