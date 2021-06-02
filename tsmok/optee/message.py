"""OPTEE Messages consts and types."""

import enum
import struct

import tsmok.common.error as error
import tsmok.optee.utee_args as utee_args


class OpteeMsgCmd(enum.IntEnum):
  """OPTEE OpteeMsgFunc.CALL_WITH_ARG commands types."""

  # OPEN_SESSION opens a session to a Trusted Application.
  # The first two parameters are tagged as meta, holding two value
  # parameters to pass the following information:
  # param[0].u.value.a-b uuid of Trusted Application
  # param[1].u.value.a-b uuid of Client
  # param[1].u.value.c Login class of client OpteeMsgLoginType
  OPEN_SESSION = 0
  # INVOKE_COMMAND invokes a command a previously opened
  # session to a Trusted Application.  struct optee_msg_arg::func is Trusted
  # Application function, specific to the Trusted Application.
  INVOKE_COMMAND = 1
  # CLOSE_SESSION closes a previously opened session to
  # Trusted Application.
  CLOSE_SESSION = 2
  # CANCEL cancels a currently invoked command.
  CANCEL = 3
  # REGISTER_SHM registers a shared memory reference. The
  # information is passed as:
  # [in] param[0].attr     OpteeMsgAttrType.TMEM_INPUT
  #          [| OPTEE_MSG_ATTR_FRAGMENT]
  # [in] param[0].u.tmem.buf_ptr   physical address (of first fragment)
  # [in] param[0].u.tmem.size    size (of first fragment)
  # [in] param[0].u.tmem.shm_ref   holds shared memory reference
  # The shared memory can optionally be fragmented, temp memrefs can follow
  # each other with all but the last with the OPTEE_MSG_ATTR_FRAGMENT bit set.
  REGISTER_SHM = 4
  # UNREGISTER_SHM unregisteres a previously registered shared
  # memory reference. The information is passed as:
  # [in] param[0].attr     OpteeMsgAttrType.RMEM_INPUT
  # [in] param[0].u.rmem.shm_ref   holds shared memory reference
  # [in] param[0].u.rmem.offs    0
  # [in] param[0].u.rmem.size    0
  UNREGISTER_SHM = 5


class OpteeMsgAttrType(enum.IntEnum):
  """OPTEE SMC OpteeMsgFunc.CALL_WITH_ARG argument types."""

  NONE = 0x0
  VALUE_INPUT = 0x1
  VALUE_OUTPUT = 0x2
  VALUE_INOUT = 0x3
  RMEM_INPUT = 0x5
  RMEM_OUTPUT = 0x6
  RMEM_INOUT = 0x7
  TMEM_INPUT = 0x9
  TMEM_OUTPUT = 0xa
  TMEM_INOUT = 0xb


# Meta parameter to be absorbed by the Secure OS and not passed
# to the Trusted Application.
# Currently only used with OpteeMsgCmd.OPEN_SESSION.
OPTEE_MSG_ATTR_META = (1 << 8)

# Pointer to a list of pages used to register user-defined SHM buffer.
# Used with OpteeMsgAttrType.TMEM_*.
# buf_ptr should point to the beginning of the buffer. Buffer will contain
# list of page addresses. OP-TEE core can reconstruct contiguous buffer from
# that page addresses list. Page addresses are stored as 64 bit values.
# Last entry on a page should point to the next page of buffer.
# Every entry in buffer should point to a 4k page beginning (12 least
# significant bits must be equal to zero).
OPTEE_MSG_ATTR_NONCONTIG = (1 << 9)


class OpteeMsgLoginType(enum.IntEnum):
  PUBLIC = 0x0
  USER = 0x1
  GROUP = 0x2
  APPLICATION = 0x4
  APPLICATION_USER = 0x5
  APPLICATION_GROUP = 0x6
  TRUSTED_APP = 0xF0000000


class OpteeMsgRpcCmdType(enum.IntEnum):
  """OPTEE MSG RPC command types."""

  LOAD_TA = 0
  RPMB = 1
  FS = 2
  GET_TIME = 3
  WAIT_QUEUE = 4
  SUSPEND = 5
  SHM_ALLOC = 6
  SHM_FREE = 7
  SQL_FS_RESERVED = 8
  CMD_GPROF = 9
  SOCKET = 10
  BENCH_REG = 20


class OpteeMsgRpcShmType(enum.IntEnum):
  APPL = 0  # Memory that can be shared with a non-secure user space application
  KERNEL = 1  # Memory only shared with non-secure kernel


class OpteeMsgRpcWaitQueueType(enum.IntEnum):
  SLEEP = 0
  WAKEUP = 1


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

  def __init__(self, attr: OpteeMsgAttrType):
    self.attr = attr

  @staticmethod
  def create(data):
    """Static method to create OPTEE Message parameter from raw data."""

    type_map = {
        OpteeMsgAttrType.NONE: OpteeMsgParamNone,
        OpteeMsgAttrType.VALUE_INPUT: OpteeMsgParamValueInput,
        OpteeMsgAttrType.VALUE_OUTPUT: OpteeMsgParamValueOutput,
        OpteeMsgAttrType.VALUE_INOUT: OpteeMsgParamValueInOut,
        OpteeMsgAttrType.RMEM_INPUT: OpteeMsgParamRegMemInput,
        OpteeMsgAttrType.RMEM_OUTPUT: OpteeMsgParamRegMemOutput,
        OpteeMsgAttrType.RMEM_INOUT: OpteeMsgParamRegMemInOut,
        OpteeMsgAttrType.TMEM_INPUT: OpteeMsgParamTempMemInput,
        OpteeMsgAttrType.TMEM_OUTPUT: OpteeMsgParamTempMemOutput,
        OpteeMsgAttrType.TMEM_INOUT: OpteeMsgParamTempMemInOut,
    }

    sz = struct.calcsize(OpteeMsgParam.FORMAT)
    attr, a, b, c = struct.unpack(OpteeMsgParam.FORMAT, data[:sz])

    attr &= ~OPTEE_MSG_ATTR_META

    param_type = type_map[attr]
    return param_type(a, b, c)

  def convert_to_utee_param(self):
    """Converts OpteeMsgParam to OpteeUteeParam.

    Returns:
      Converted OpteeUteeParam object

    Raises:
      Error exception in case of error.
    """
    type_map = {
        OpteeMsgAttrType.NONE: utee_args.OpteeUteeParamNone,
        OpteeMsgAttrType.VALUE_INPUT: utee_args.OpteeUteeParamValueInput,
        OpteeMsgAttrType.VALUE_OUTPUT: utee_args.OpteeUteeParamValueOutput,
        OpteeMsgAttrType.VALUE_INOUT: utee_args.OpteeUteeParamValueInOut,
        OpteeMsgAttrType.TMEM_INPUT: utee_args.OpteeUteeParamMemrefInput,
        OpteeMsgAttrType.TMEM_OUTPUT: utee_args.OpteeUteeParamMemrefOutput,
        OpteeMsgAttrType.TMEM_INOUT: utee_args.OpteeUteeParamMemrefInOut,
    }

    try:
      param = type_map[self.attr]()
    except ValueError:
      raise error.Error(f'Can not convert Optee Msg type {self.attr} '
                        'to OpteeUteeParam')

    if isinstance(self, OpteeMsgParamValue):
      param.a = self.a
      param.b = self.b
    elif isinstance(self, OpteeMsgParamTempMem):
      param.addr = self.addr
      param.size = self.size
      param.data = self.data

    return param


class OpteeMsgParamNone(OpteeMsgParam):

  def __init__(self):
    OpteeMsgParam.__init__(self, OpteeMsgAttrType.NONE)

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr, 0, 0, 0)

  def __str__(self):
    return f'    {str(self.attr)}'


class OpteeMsgParamValue(OpteeMsgParam):
  """OPTEE Value SMC message base parameter."""

  def __init__(self, attr, a, b, c):
    if attr not in [OpteeMsgAttrType.VALUE_INOUT,
                    OpteeMsgAttrType.VALUE_INPUT,
                    OpteeMsgAttrType.VALUE_OUTPUT]:
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
    OpteeMsgParamValue.__init__(self, OpteeMsgAttrType.VALUE_INPUT,
                                a, b, c)


class OpteeMsgParamValueInOut(OpteeMsgParamValue):

  def __init__(self, a=0, b=0, c=0):
    OpteeMsgParamValue.__init__(self, OpteeMsgAttrType.VALUE_INOUT,
                                a, b, c)


class OpteeMsgParamValueOutput(OpteeMsgParamValue):

  def __init__(self, a=0, b=0, c=0):
    OpteeMsgParamValue.__init__(self, OpteeMsgAttrType.VALUE_OUTPUT,
                                a, b, c)


class OpteeMsgParamTempMem(OpteeMsgParam):
  """OPTEE Temporary Memory SMC message base parameter."""

  def __init__(self, attr, addr, size, shm_ref):
    if attr not in [OpteeMsgAttrType.TMEM_INOUT,
                    OpteeMsgAttrType.TMEM_INPUT,
                    OpteeMsgAttrType.TMEM_OUTPUT]:
      raise ValueError(f'Wrong type for OpteeMsgParamTempMem: {attr}')
    OpteeMsgParam.__init__(self, attr)
    self.addr = addr
    self.size = size
    self.shm_ref = shm_ref
    self.data = None

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr, self.addr, self.size,
                       self.shm_ref)

  def __str__(self):
    return (f'    {str(self.attr)}: addr: 0x{self.addr:08x},'
            f'size: 0x{self.size:08x}, shm: 0x{self.shm_ref:08x}')


class OpteeMsgParamTempMemInput(OpteeMsgParamTempMem):

  def __init__(self, addr=0, size=0, shm_ref=0):
    OpteeMsgParamTempMem.__init__(self, OpteeMsgAttrType.TMEM_INPUT,
                                  addr, size, shm_ref)


class OpteeMsgParamTempMemInOut(OpteeMsgParamTempMem):

  def __init__(self, addr=0, size=0, shm_ref=0):
    OpteeMsgParamTempMem.__init__(self, OpteeMsgAttrType.TMEM_INOUT,
                                  addr, size, shm_ref)


class OpteeMsgParamTempMemOutput(OpteeMsgParamTempMem):

  def __init__(self, addr=0, size=0, shm_ref=0):
    OpteeMsgParamTempMem.__init__(self,
                                  OpteeMsgAttrType.TMEM_OUTPUT,
                                  addr, size, shm_ref)


class OpteeMsgParamRegMem(OpteeMsgParam):
  """OPTEE Registered Memory SMC message base parameter."""

  def __init__(self, attr, offset, size, shm_ref):
    if attr not in [OpteeMsgAttrType.RMEM_INOUT,
                    OpteeMsgAttrType.RMEM_INPUT,
                    OpteeMsgAttrType.RMEM_OUTPUT]:
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
    OpteeMsgParamRegMem.__init__(self, OpteeMsgAttrType.RMEM_INPUT,
                                 offset, size, shm_ref)


class OpteeMsgParamRegMemInOut(OpteeMsgParamRegMem):

  def __init__(self, offset=0, size=0, shm_ref=0):
    OpteeMsgParamRegMem.__init__(self, OpteeMsgAttrType.RMEM_INOUT,
                                 offset, size, shm_ref)


class OpteeMsgParamRegMemOutput(OpteeMsgParamRegMem):

  def __init__(self, offset=0, size=0, shm_ref=0):
    OpteeMsgParamRegMem.__init__(self, OpteeMsgAttrType.RMEM_OUTPUT,
                                 offset, size, shm_ref)
