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

"""Trusty IPC types and functions."""

import enum
import struct
import weakref

import tsmok.common.error as error
import tsmok.common.misc as misc


class IpcHandler:
  """Trusty IPC handler."""

  def __init__(self, client_id=0, ver=0, mem=None, mem_id=0):
    self.client_id = client_id
    self.version = ver
    self.shm_mem = mem
    self.mem_obj_id = mem_id

  def valid(self):
    return self.shm_mem and self.mem_obj_id

  def __str__(self):
    return (f'IPC Handler: ID = {self.client_id}, VER = {self.version}, '
            f'MEM ID = {self.mem_obj_id}')


class IpcOpCode(enum.IntEnum):
  CONNECT = 0x1
  GET_EVENT = 0x2
  SEND = 0x3
  RECV = 0x4
  DISCONNECT = 0x5
  HAS_EVENT = 0x100

IPC_OPCODE_RESP_FLAG = 0x8000


class IpcEventType(enum.IntFlag):
  NONE = 0x0
  READY = 0x1
  ERROR = 0x2
  HUP = 0x4
  MESSAGE = 0x8
  SEND_UNBLOCKED = 0x10


class IpcCmd:
  """Trusty IPC command message."""

  HDR_FORMAT = '<2H3I'

  def __init__(self, opcode=0, flags=0, status=0, handle=0,
               payload=None):
    self.opcode = opcode
    self.flags = flags
    self.status = status
    self.handle = handle
    self.response = False
    self.payload = payload or b''

  @staticmethod
  def size_base():
    return struct.calcsize(IpcCmd.HDR_FORMAT)

  def size(self):
    return struct.calcsize(IpcCmd.HDR_FORMAT) + len(self.payload)

  def get_payload_size(self, data) -> int:
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    _, _, _, _, payload_len = struct.unpack(
        self.HDR_FORMAT, data[:self.size_base()])

    return payload_len

  def load(self, data):
    """Init IpcCmd from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    opcode, self.flags, self.status, self.handle, payload_len = \
        struct.unpack(self.HDR_FORMAT, data[:self.size_base()])

    if opcode & IPC_OPCODE_RESP_FLAG:
      self.response = True
    self.opcode = IpcOpCode(opcode & ~IPC_OPCODE_RESP_FLAG)

    if len(data[self.size_base():]) < payload_len:
      raise ValueError(f'Not enough data: {len(data)} < '
                       f'{self.size_base() + payload_len}')

    off = self.size_base()
    self.payload = data[off:off + payload_len]

    return off + payload_len

  def __bytes__(self):
    opcode = self.opcode
    if self.response:
      opcode |= IPC_OPCODE_RESP_FLAG

    out = struct.pack(self.HDR_FORMAT, opcode, self.flags, self.status,
                      self.handle, len(self.payload))
    if isinstance(self.payload, str):
      out += self.payload.encode()
    else:
      out += bytes(self.payload)
    return out

  def __str__(self):
    out = 'IPC Command:\n'
    out += f'\topcode: {str(self.opcode)}\n'
    out += f'\tresponse: {str(self.response)}\n'
    out += f'\tflags: 0x{self.flags}\n'
    out += f'\tstatus: 0x{self.status}\n'
    out += f'\thandle: 0x{self.handle}\n'
    out += f'\tpayload: {str(self.payload)}\n'
    return out


class IpcPayloadConnectRequest:
  """IPC Payload for Connect request."""

  FORMAT = '<2Q'

  def __init__(self, cookie=0, name=None):
    self.cookie = cookie
    self.name = name or ''

  @staticmethod
  def size_base():
    return struct.calcsize(IpcPayloadConnectRequest.FORMAT)

  def size(self):
    return (struct.calcsize(IpcPayloadConnectRequest.FORMAT) +
            len(self.name) +
            1  # '\0' at the end of `name''
           )

  def __len__(self):
    return self.size()

  def load(self, data):
    """Init IpcPayloadConnectRequest from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    self.cookie, _ = \
        struct.unpack(self.FORMAT, data[:self.size_base()])

    self.name = data[self.size_base():]
    return len(data)

  def __bytes__(self):
    out = struct.pack(self.FORMAT, self.cookie, 0)

    if isinstance(self.name, str):
      out += self.name.encode()
    else:
      out += bytes(self.name)
    out += b'\x00'
    return out

  def __str__(self):
    out = 'IPC Payload Connect Request:\n'
    out += f'\tcookie: 0x{self.cookie:x}\n'
    out += f'\tname: {str(self.name)}\n'
    return out


class IpcPayloadWaitRequest:
  """IPC Payload for Wait request."""

  FORMAT = '<Q'

  def __init__(self):
    pass

  @staticmethod
  def size():
    return struct.calcsize(IpcPayloadWaitRequest.FORMAT)

  def __len__(self):
    return self.size()

  def load(self, data):
    """Init IpcPayloadWaitRequest from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, 0)

  def __str__(self):
    out = 'IPC Payload Wait Request.\n'
    return out


class IpcPayloadEvent:
  """IPC Payload for Event request."""
  FORMAT = '<2IQ'

  def __init__(self, event=0, handle=0, cookie=0):
    self.event = event
    self.handle = handle
    self.cookie = cookie

  @staticmethod
  def size():
    return struct.calcsize(IpcPayloadEvent.FORMAT)

  def __len__(self):
    return self.size()

  def load(self, data):
    """Init IpcPayloadEvent from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    event, self.handle, self.cookie = \
        struct.unpack(self.FORMAT, data[:self.size()])

    try:
      self.event = IpcEventType(event)
    except KeyError:
      raise error.Error(f'Unknown event type 0x{event:x}')
    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.event, self.handle, self.cookie)

  def __str__(self):
    out = 'IPC Payload Event:\n'
    out += f'\tevent: {str(self.event)}\n'
    out += f'\thandle: 0x{self.handle:x}\n'
    out += f'\tcookie: 0x{self.cookie:x}\n'
    return out


class IpcPayloadHasEvent:
  """IPC Payload for HasEvent request."""
  FORMAT = '<B'

  def __init__(self, has_event=False):
    self.has_event = has_event

  @staticmethod
  def size():
    return struct.calcsize(IpcPayloadHasEvent.FORMAT)

  def __len__(self):
    return self.size()

  def load(self, data):
    """Init IpcPayloadHasEvent from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    has_event = struct.unpack(self.FORMAT, data[:self.size()])
    self.has_event = bool(has_event)

    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.has_event)

  def __str__(self):
    out = 'IPC Payload HasEvent:\n'
    out += '\thas_event: {str(self.has_event)}\n'
    return out


class IpcClient:
  """Trusty IPC Client interface."""

  def __init__(self, name, mgr, cookie):
    self.name = name
    self.mgr = mgr
    self.handle = None
    self.cookie = cookie

    self.completed = False

    self._default_event_handlers = {
        IpcEventType.READY: self._on_ready,
        IpcEventType.ERROR: self._on_error,
        IpcEventType.HUP: self._on_hup,
        IpcEventType.MESSAGE: self._on_msg,
        IpcEventType.SEND_UNBLOCKED: self._on_send_unblocked,
    }

    self._custom_event_handlers = dict()

  def __str__(self):
    return (f'IPC Client {self.name}: handle {self.handle}, '
            f'cookie {self.cookie}')

  def _on_ready(self):
    self.completed = True

  def _on_error(self):
    raise error.Error('Received Event error: '
                      f'client cookie = {self.client} handle = {self.handle}')

  def _on_hup(self):
    self.completed = True
    self.disconnect()

  def _on_msg(self):
    self.completed = True

  def _on_send_unblocked(self):
    pass

  def _process_single_event(self, event):
    if event in self._custom_event_handlers:
      self._custom_event_handlers[event]()
    else:
      try:
        self._default_event_handlers[event]()
      except KeyError:
        raise error.Error(f'Unknown Event type: {event}')

  def process_event(self, events, handle):
    """Process received events.

    Args:
     events: Received events mask
     handle: A client handle recipient for events

    Returns:
      None

    Raises:
      error.Error is case of any error
    """
    if not self.handle:
      raise error.Error(f'{self.name}: ProcessEvent: Client is disconnected '
                        'or was not connected!')

    if handle != self.handle:
      raise error.Error(f'{self.name}: ProcessEvent: handles are not match: '
                        f'{self.handle} != {handle}')

    for e in list(IpcEventType):
      if events & e:
        self._process_single_event(e)

  def set_event_handler(self, event, callback):
    self._custom_event_handlers[event] = callback

  def reset_event_handler(self, event):
    try:
      del self._custom_event_handlers[event]
    except KeyError:
      pass  # do nothing if handler for the event is not present

  def connect(self, port):
    self.mgr.connect(self, port)

  def disconnect(self):
    self.mgr.disconnect(self)

  def send(self, data, wait=True):
    self.mgr.send(self, data, wait)

  def recv(self, wait=True):
    return self.mgr.recv(self, wait)

  def poll_event(self):
    return self.mgr.pull_event(self.handle)


class IpcManager:
  """Trusty IPC Client Manager."""

  CHECK_MAX_ITER = 1000

  def __init__(self, tee, mid, size):
    self._tee = weakref.ref(tee)
    self._mgr_id = mid
    self._size = size
    self._clients = dict()
    self._ipc_handler = self._tee().ipc_init(self._mgr_id, self._size)

  def _get_tee(self):
    tee = self._tee()

    if not tee:
      raise error.Error('TEE emulator was destroyed')
    return tee

  def pull_event(self, handle=None) -> bool:
    """Checks income events for clients.

    Args:
      handle: client id to check events for.
              if None, check events for all clients.

    Returns:
      True if at lease one non-empty event was received, False - otherwise.

    Raises:
      error.Error in case of error.
    """
    ev = self._get_tee().ipc_get_event(self._ipc_handler, handle)
    if ev.event == IpcEventType.NONE:
      return False

    try:
      client = self._clients[ev.cookie]
    except KeyError:
      raise error.Error(f'Unknown Event cookie {ev.cookie}')

    client.process_event(ev.event, ev.handle)

    return True

  def _wait_for_complete(self, client):
    client.completed = False

    for _ in range(self.CHECK_MAX_ITER):
      self.pull_event()
      if client.completed:
        return
    raise error.Error('Time out for wait_for_complete')

  def get_client(self, name):
    cookie = misc.get_next_available_key(self._clients)
    client = IpcClient('IPC-Client-' + name, self, cookie)
    self._clients[cookie] = client
    return client

  def connect(self, client, port):
    if client.handle:
      return

    handle = self._get_tee().ipc_connect(self._ipc_handler, port, client.cookie)
    client.handle = handle
    self._wait_for_complete(client)

  def disconnect(self, client):
    if not client.handle:
      return

    self._get_tee().ipc_disconnect(self._ipc_handler, client.handle)
    client.handle = None

  def send(self, client, data, wait):
    if not client.handle:
      raise error.Error(f'SEND failed: client {client.name} is not connected')

    self._get_tee().ipc_send(self._ipc_handler, client.handle, data)
    if wait:
      self._wait_for_complete(client)

  def recv(self, client, wait):
    if not client.handle:
      raise error.Error(f'RECV failed: client {client.name} is not connected')

    if wait:
      self._wait_for_complete(client)
    return self._get_tee().ipc_recv(self._ipc_handler, client.handle)

  def shutdown(self):
    if self._ipc_handler:
      for c in self._clients.values():
        if c.handle:
          c.disconnect()

      if self._ipc_handler:
        self._get_tee().ipc_shutdown(self._ipc_handler)
        self._ipc_handler = None
