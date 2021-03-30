"""Trusty AVB client."""

import enum
import struct
import tsmok.common.error as error
import tsmok.trusty.ipc as trusty_ipc


class AvbCmdType(enum.IntEnum):
  READ_ROLLBACK_INDEX = 0 << 1
  WRITE_ROLLBACK_INDEX = 1 << 1
  GET_VERSION = 2 << 1
  READ_PERMANENT_ATTRIBUTES = 3 << 1
  WRITE_PERMANENT_ATTRIBUTES = 4 << 1
  READ_LOCK_STATE = 5 << 1
  WRITE_LOCK_STATE = 6 << 1
  LOCK_BOOT_STATE = 7 << 1


AVB_CMD_RESP_FLAG = 0x1


class AvbError(enum.IntEnum):
  """Error codes for AVB protocol."""
  NONE = 0
  INVALID = 1
  INTERNAL = 2


class AvbMessage:
  """Serial header for communicating with AVB server."""

  HDR_FORMAT = '<2I'

  def __init__(self, cmd=0, result=0, payload=None):
    self.cmd = cmd
    self.result = result
    self.payload = payload or b''

    self.response = False

  @staticmethod
  def size_base():
    return struct.calcsize(AvbMessage.HDR_FORMAT)

  def size(self):
    return struct.calcsize(AvbMessage.HDR_FORMAT) + len(self.payload)

  def load(self, data):
    """Init AvbMessage from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    cmd, self.result = \
        struct.unpack(self.HDR_FORMAT, data[:self.size_base()])

    if cmd & AVB_CMD_RESP_FLAG:
      self.response = True
    self.cmd = AvbCmdType(cmd & ~AVB_CMD_RESP_FLAG)

    self.payload = data[self.size_base():]

    return len(data)

  def __bytes__(self):
    cmd = self.cmd
    if self.response:
      cmd |= AVB_CMD_RESP_FLAG

    out = struct.pack(self.HDR_FORMAT, cmd, self.result)
    if isinstance(self.payload, str):
      out += self.payload.encode()
    else:
      out += bytes(self.payload)
    return out

  def __str__(self):
    out = 'AVB Command:\n'
    out += f'\tcmd: {str(self.cmd)}\n'
    out += f'\tresponse: {str(self.response)}\n'
    out += f'\tresult: 0x{self.result}\n'
    out += f'\tpayload: {str(self.payload)}\n'
    return out


class AvbPayloadRollbackReq:
  """AVB Payload for Rollback request."""

  FORMAT = '<QI'

  def __init__(self, slot=0, value=0):
    self.value = value
    self.slot = slot

  @staticmethod
  def size():
    return struct.calcsize(AvbPayloadRollbackReq.FORMAT)

  def load(self, data):
    """Init AvbPayloadRollbackResp from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    self.value, self.slot = \
        struct.unpack(self.FORMAT, data[:self.size()])

    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.value, self.slot)

  def __str__(self):
    out = 'AVB Payload RollbackReq:\n'
    out += f'\tvalue: {self.value}\n'
    out += f'\tslot: {self.slot}\n'
    return out


class AvbPayloadRollbackResp:
  """AVB Payload for Rollback response."""

  FORMAT = '<Q'

  def __init__(self, value=0):
    self.value = value

  @staticmethod
  def size():
    return struct.calcsize(AvbPayloadRollbackResp.FORMAT)

  def load(self, data):
    """Init AvbPayloadVersionResp from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    self.value = struct.unpack(self.FORMAT, data[:self.size()])[0]

    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.value)

  def __str__(self):
    out = 'AVB Payload RollbackResp:\n'
    out += f'\tvalue: {self.value}\n'
    return out


class AvbPayloadVersionResp:
  """AVB Payload for Version response."""

  FORMAT = '<I'

  def __init__(self, version=0):
    self.version = version

  @staticmethod
  def size():
    return struct.calcsize(AvbPayloadVersionResp.FORMAT)

  def load(self, data):
    """Init AvbPayloadVersionResp from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    self.version = struct.unpack(self.FORMAT, data[:self.size()])[0]

    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.value)

  def __str__(self):
    out = 'AVB Payload RollbackResp:\n'
    out += f'\tvalue: {self.value}\n'
    return out


class Avb:
  """Trusty AVB client."""

  def __init__(self, client: trusty_ipc.IpcClient):
    self._client = client
    self._client.connect('com.android.trusty.avb')

  def _response_check(self, ctype: AvbCmdType, msg: AvbMessage) -> bool:
    if msg.cmd != ctype or not msg.response:
      return False

    if msg.result != AvbError.NONE:
      return False
    return True

  def get_version(self):
    """Returns current AVB TA version.

    Args:
      None

    Returns:
      AVB version number.

    Raises:
      error.Error in case of error
    """
    msg = AvbMessage(AvbCmdType.GET_VERSION)
    self._client.send(bytes(msg))

    data = self._client.recv()
    msg = AvbMessage()
    msg.load(data)
    if not self._response_check(AvbCmdType.GET_VERSION, msg):
      raise error.Error(f'AVB: GET_VERSION: wrong response or error:\n{msg}')

    ver = AvbPayloadVersionResp()
    ver.load(msg.payload)

    return ver.version

  def lock_state_read(self):
    """Reads current LockState.

    Args:
      None

    Returns:
      Current Lock state

    Raises:
      error.Error in case of error
    """
    msg = AvbMessage(AvbCmdType.READ_LOCK_STATE)
    self._client.send(bytes(msg))

    data = self._client.recv()
    msg = AvbMessage()
    msg.load(data)
    if not self._response_check(AvbCmdType.READ_LOCK_STATE, msg):
      raise error.Error('AVB: READ_LOCK_STATE: wrong response '
                        f'or error:\n{msg}')

    if len(msg.payload) < 1:
      raise error.Error('AVB: READ_LOCK_STATE: No STATE data is received!')
    state = struct.unpack('<B', msg.payload[:1])[0]

    return state

  def lock_state_write(self, state):
    """Writes LockState.

    Args:
      state: LockState to write

    Returns:
      None

    Raises:
      error.Error in case of error
    """
    msg = AvbMessage(AvbCmdType.WRITE_LOCK_STATE)
    msg.payload = struct.pack('<B', state)
    self._client.send(bytes(msg))

    data = self._client.recv()
    msg = AvbMessage()
    msg.load(data)
    if not self._response_check(AvbCmdType.WRITE_LOCK_STATE, msg):
      raise error.Error('AVB: WRITE_LOCK_STATE: wrong response '
                        f'or error:\n{msg}')

  def rollback_index_read(self, idx):
    """Reads Rollback Index value for specific slot.

    Args:
      idx: the slot number to read rollback index from

    Returns:
      Rollback index value

    Raises:
      error.Error in case of error
    """
    msg = AvbMessage(AvbCmdType.READ_ROLLBACK_INDEX)
    msg.payload = bytes(AvbPayloadRollbackReq(idx, 0))

    self._client.send(bytes(msg))
    data = self._client.recv()

    msg = AvbMessage()
    msg.load(data)
    if not self._response_check(AvbCmdType.READ_ROLLBACK_INDEX, msg):
      raise error.Error('AVB: READ_ROLLBACK_INDEX: wrong response '
                        f'or error:\n{msg}')

    resp = AvbPayloadRollbackResp()
    resp.load(msg.payload)
    return resp.value

  def rollback_index_write(self, idx, value):
    """Writes Rollback Index value to specific slot.

    Args:
      idx: the slot number to write rollback index
      value: the value to write

    Returns:
      None

    Raises:
      error.Error in case of error
    """
    msg = AvbMessage(AvbCmdType.WRITE_ROLLBACK_INDEX)
    msg.payload = bytes(AvbPayloadRollbackReq(idx, value))

    self._client.send(bytes(msg))
    data = self._client.recv()

    msg = AvbMessage()
    msg.load(data)
    if not self._response_check(AvbCmdType.WRITE_ROLLBACK_INDEX, msg):
      raise error.Error('AVB: WRITE_ROLLBACK_INDEX: wrong response '
                        f'or error:\n{msg}')

    resp = AvbPayloadRollbackResp()
    resp.load(msg.payload)
    if resp.value != value:
      raise error.Error('RollbackIndexWrite: written value does not '
                        f'match received: {value} != {resp.value}')

  def perm_attr_read(self):
    """Reads AVB Permanent Attributes.

    Args:
      None

    Returns:
      Raw binary of AVB permanent attributes

    Raises:
      error.Error in case of error
    """
    msg = AvbMessage(AvbCmdType.READ_PERMANENT_ATTRIBUTES)

    self._client.send(bytes(msg))
    data = self._client.recv()

    msg = AvbMessage()
    msg.load(data)
    if not self._response_check(AvbCmdType.READ_PERMANENT_ATTRIBUTES, msg):
      raise error.Error('AVB: READ_PERMANENT_ATTRIBUTES: wrong response '
                        f'or error:\n{msg}')

    return msg.payload

  def perm_attr_write(self, data):
    """Write AVB Permanent Attributes.

    Args:
      data: raw binary of AVB permanent attributes.

    Returns:
      None

    Raises:
      error.Error in case of error
    """
    msg = AvbMessage(AvbCmdType.WRITE_PERMANENT_ATTRIBUTES)
    msg.payload = data
    self._client.send(bytes(msg))

    data = self._client.recv()
    msg = AvbMessage()
    msg.load(data)
    if not self._response_check(AvbCmdType.WRITE_PERMANENT_ATTRIBUTES, msg):
      raise error.Error('AVB: WRITE_PERMANENT_ATTRIBUTES: wrong response '
                        f'or error:\n{msg}')
