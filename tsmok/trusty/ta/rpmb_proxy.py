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

"""Trusty RPMB Proxy."""

import enum
import struct
import tsmok.common.error as error
import tsmok.hw.devices.rpmb as rpmb
import tsmok.trusty.ipc as trusty_ipc


class StorageCmd(enum.IntEnum):
  """Storage Commands."""
  FILE_DELETE = 1 << 1
  FILE_OPEN = 2 << 1
  FILE_CLOSE = 3 << 1
  FILE_READ = 4 << 1
  FILE_WRITE = 5 << 1
  FILE_GET_SIZE = 6 << 1
  FILE_SET_SIZE = 7 << 1
  RPMB_SEND = 8 << 1
  # transaction support
  END_TRANSACTION = 9 << 1


STORAGE_CMD_RESP_BIT = 1


class Error(enum.IntEnum):
  """Error codes for storage protocol.

  NO_ERROR:           all OK
  ERR_GENERIC:        unknown error. Can occur when there's an
                      internal server error, e.g. the server runs out
                      of memory or is in a bad state.
  ERR_NOT_VALID:      input not valid. May occur if the arguments
                      passed into the command are not valid, for
                      example if the file handle passed in is not a
                      valid one.
  ERR_UNIMPLEMENTED:  the command passed in is not recognized
  ERR_ACCESS:         the file is not accessible in the requested mode
  ERR_NOT_FOUND:      the file was not found
  ERR_EXIST           the file exists when it shouldn't as in with
                      OPEN_CREATE | OPEN_EXCLUSIVE.
  ERR_TRANSACT        returned by various operations to indicate that
                      current transaction is in error state. Such
                      state could be only cleared by sending
                      STORAGE_END_TRANSACTION message.
  """
  NO_ERROR = 0
  ERR_GENERIC = 1
  ERR_NOT_VALID = 2
  ERR_UNIMPLEMENTED = 3
  ERR_ACCESS = 4
  ERR_NOT_FOUND = 5
  ERR_EXIST = 6
  ERR_TRANSACT = 7


class MessageFlags(enum.IntFlag):
  """Protocol-level flags in storage Message.

     BATCH:             if set, command belongs to a batch
                        transaction. No response will be sent by
                        the server until it receives a command
                        with this flag unset, at which point a
                        cummulative result for all messages sent
                        with BATCH will be
                        sent. This is only supported by the
                        non-secure disk proxy server.
     PRE_COMMIT:        if set, indicates that server need to
                        commit pending changes before processing
                        this message.
     POST_COMMIT:       if set, indicates that server need to
                        commit pending changes after processing
                        this message.
     TRANSACT_COMPLETE: if set, indicates that server need to
                                 commit current transaction after
                                 processing this message. It is an alias
                                 for POST_COMMIT.
  """
  BATCH = 0x1
  PRE_COMMIT = 0x2
  POST_COMMIT = 0x4
  TRANSACT_COMPLETE = POST_COMMIT


class Message:
  """Generic req/resp format for all storage commands.

  cmd:        one of enum StorageCmd
  op_id:      client chosen operation identifier for an instance
              of a command or atomic grouping of commands (transaction).
  flags:      one or many of enum MessageFlags or'ed together.
  size:       total size of the message including this header
  result:     one of Error
  payload:    beginning of command specific message format
  """

  HDR_FORMAT = '<6I'

  def __init__(self, cmd=0, op_id=0, flags=0, result=0, payload=None):
    self.cmd = cmd
    self.op_id = op_id
    self.flags = flags
    self.result = result
    self.payload = payload or b''

    self.response = False

  @staticmethod
  def size_base():
    return struct.calcsize(Message.HDR_FORMAT)

  def size(self):
    return struct.calcsize(Message.HDR_FORMAT) + len(self.payload)

  def load(self, data):
    """Init Message from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    cmd, self.op_id, flags, full_size, result, _ = \
        struct.unpack(self.HDR_FORMAT, data[:self.size_base()])

    if cmd & STORAGE_CMD_RESP_BIT:
      self.response = True
    self.cmd = StorageCmd(cmd & ~STORAGE_CMD_RESP_BIT)
    self.flags = MessageFlags(flags)
    self.result = Error(result)

    if len(data) < full_size:
      raise ValueError(f'Not enough data: {len(data)} < {full_size}')

    self.payload = data[self.size_base():full_size]

    return full_size

  def __bytes__(self):
    cmd = self.cmd
    if self.response:
      cmd |= STORAGE_CMD_RESP_BIT

    out = struct.pack(self.HDR_FORMAT, cmd, self.op_id, self.flags,
                      self.size(), self.result, 0)
    if isinstance(self.payload, str):
      out += self.payload.encode()
    else:
      out += bytes(self.payload)
    return out

  def __str__(self):
    out = 'Storage Message:\n'
    out += f'\tcmd: {str(self.cmd)}\n'
    out += f'\tresponse: {str(self.response)}\n'
    out += f'\top_id: {str(self.op_id)}\n'
    out += f'\tflags: {str(self.flags)}\n'
    out += f'\tresult: 0x{self.result}\n'
    out += f'\tpayload: {str(self.payload)}\n'
    return out


class RpmbSendRequest:
  """Request format for RPMB_SEND command.

    Format of data:
      reliable_write_size(4 bytes): size in bytes of reliable write region
      write_size(4 bytes): size in bytes of write region
      read_size(4 bytes): number of bytes to read for a read request
      payload(reliable_write_size + write_size bytes): start of reliable write
          region, followed by write region.

    Only used in proxy<->server interface.
  """

  HDR_FORMAT = '<4I'

  def __init__(self, read_size=0, rel_write_data=None, write_data=None):
    self.read_size = read_size
    self.rel_write_data = rel_write_data or b''
    self.write_data = write_data or b''

  @staticmethod
  def size_base():
    return struct.calcsize(RpmbSendRequest.HDR_FORMAT)

  def size(self):
    return (struct.calcsize(RpmbSendRequest.HDR_FORMAT) +
            len(self.rel_write_data) + len(self.write_data))

  def load(self, data):
    """Init RpmbSendRequest from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    rel_write_size, write_size, self.read_size, _ = \
        struct.unpack(self.HDR_FORMAT, data[:self.size_base()])

    if len(data[self.size_base():]) < (rel_write_size +
                                       write_size):
      raise ValueError(f'Not enough data: {len(data)} < '
                       f'{rel_write_size + write_size}')

    off = self.size_base()
    if rel_write_size:
      if rel_write_size & (rpmb.MMC_BLOCK_SIZE - 1):
        raise ValueError('Invalid reliable write size {rel_write_size}')
      self.rel_write_data = data[off:off + rel_write_size]

    off += rel_write_size
    if write_size:
      if write_size & (rpmb.MMC_BLOCK_SIZE - 1):
        raise ValueError(f'Invalid write size {write_size}')
      self.write_data = data[off:off + write_size]

    if self.read_size & (rpmb.MMC_BLOCK_SIZE - 1):
      raise ValueError(f'Invalid read size {self.read_size}')

    return self.size_base() + rel_write_size + write_size

  def __bytes__(self):
    out = struct.pack(self.HDR_FORMAT, len(self.rel_write_data),
                      len(self.write_data), self.read_size, 0)
    out += bytes(self.rel_write_data)
    out += bytes(self.write_data)
    return out

  def __str__(self):
    out = 'RpmbSendRequest:\n'
    out += f'\tread_size: {self.read_size}\n'
    out += f'\treliable write data ({len(self.rel_write_data)} bytes):\n'
    if self.rel_write_data:
      out += f'{str(self.rel_write_data)}\n'
    out += f'\twrite data ({len(self.write_data)} bytes):\n'
    if self.write_data:
      out += f'{str(self.write_data)}\n'
    return out


class RpmbProxy:
  """Trusty RPMB proxy."""

  def __init__(self, client: trusty_ipc.IpcClient, rpmb_dev):
    self._client = client
    self._rpmb = rpmb_dev

    self._cmd_handlers = {
        StorageCmd.RPMB_SEND: self._rpmb_send,
    }

    self._client.set_event_handler(trusty_ipc.IpcEventType.MESSAGE,
                                   self._on_message)
    self._client.connect('com.android.trusty.storage.proxy')

    # read out all RPMB events
    while self._client.poll_event() and self._client.handle:
      pass

    if not self._client.handle:
      raise error.Error('RPMB IPC Channel was closed!')

  def _not_implemented(self, msg):
    msg.result = Error.ERR_UNIMPLEMENTED
    msg.payload = b''

  def _rpmb_send(self, msg):
    req = RpmbSendRequest()
    req.load(msg.payload)

    resp = self._rpmb.process_frames_data(
        req.rel_write_data + req.write_data, req.read_size)

    msg.payload = bytes(resp)[:req.read_size]

  def _on_message(self):
    """Custom ON-MESSAGE handler for IPC client.

    Raises:
      error.Error in case of any error.
    """
    data = self._client.recv(False)

    msg = Message()
    msg.load(data)

    try:
      self._cmd_handlers[msg.cmd](msg)
    except KeyError:
      self._not_implemented(msg)
    msg.response = True
    self._client.send(bytes(msg), False)
