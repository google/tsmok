"""RPMB base implementation."""

import enum
import hashlib
import hmac
import struct

import tsmok.common.error as error
import tsmok.common.hw as hw
import tsmok.emu.arm as arm


CID_SIZE = 16


class RpmbReturn(enum.IntEnum):
  OK = 0
  ERROR = 1


class RpmbRequestType(enum.IntEnum):
  AUTH_KEY_PROG = 0x0001
  READ_WRITE_COUNTER = 0x0002
  WRITE_DATA = 0x0003
  READ_DATA = 0x0004
  RESULT_READ = 0x0005


class RpmbResponseType(enum.IntEnum):
  AUTH_KEY_PROG = 0x0100
  READ_WRITE_COUNTER = 0x0200
  WRITE_DATA = 0x0300
  READ_DATA = 0x0400


class RpmbReturnCode(enum.IntEnum):
  OK = 0x00
  ERROR_GENERAL = 0x01
  ERROR_AUTHENTICATION = 0x02
  ERROR_COUNTER = 0x03
  ERROR_ADDRESS = 0x04
  ERROR_WRITE = 0x05
  ERROR_READ = 0x06
  ERROR_AUTH_NOT_PROG = 0x07
  ERROR_WRITE_COUNTER_EXPIRED = 0x80


class RpmbFrame:
  """RPMB Frame structure."""

  STUFF_SIZE = 196
  MAC_SIZE = 32
  DATA_SIZE = 256
  NONCE_SIZE = 16

  MAC_CALC_OFFSET = 228

  FORMAT = '>196s32s256s16sI4H'

  def __init__(self, data=None):
    if not data:
      self.stuff = b'\x00' * self.STUFF_SIZE
      self.mac = b'\x00' * self.MAC_SIZE
      self.data = b'\x00' * self.DATA_SIZE
      self.nonce = b'\x00' * self.NONCE_SIZE
      self.write_counter = 0
      self.address = 0
      self.block_count = 0
      self.result = 0
      self.request = 0
    else:
      self.load(data)

  def load(self, data):
    """Parse RPMB Frame object from raw data.

    Args:
      data: raw binary data to be parsed

    Returns:
      The size of parsed data.

    Raises:
      ValueError exception is raised if size of data is not enough for parsing.
    """

    size = struct.calcsize(self.FORMAT)
    if len(data) < size:
      raise ValueError('Not enough data')

    self.stuff, self.mac, self.data, self.nonce, self.write_counter, \
       self.address, self.block_count, self.result, req = \
       struct.unpack(self.FORMAT, data[:size])

    self.request = RpmbRequestType(req)

    return size

  def get_bytes_for_mac(self):
    return bytes(self)[self.MAC_CALC_OFFSET:]

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.stuff, self.mac, self.data, self.nonce,
                       self.write_counter, self.address, self.block_count,
                       self.result, self.request)

  def __str__(self):
    out = 'RPMB Frame:\n'
    out += f'\tstuff:         {self.stuff.hex()}\n'
    out += f'\tmac:           {self.mac.hex()}\n'
    out += f'\tdata:          {self.data.hex()}\n'
    out += f'\tnonce:         {self.nonce.hex()}\n'
    out += f'\twrite counter: {self.write_counter}\n'
    out += f'\taddress:       0x{self.address:08x}\n'
    out += f'\tblock count:   {self.block_count}\n'
    out += f'\tresult:        {self.result}\n'
    out += f'\trequest:       {str(self.request)}\n'

    return out


class RpmbDevice(hw.DeviceBase):
  """RPMB device implemantation."""

  SINGLE_SIZE = 128*1024
  BLOCK_SIZE = 256
  EXPIRED_COUNTER = 1<<32

  def __init__(self, cid, size_multi=1, key=None, write_counter=0):
    hw.DeviceBase.__init__(self, 'RPMB')

    self.size_multi = size_multi
    self.write_counter = write_counter
    if len(cid) != CID_SIZE:
      raise error.Error('RPMB: wrong size of CID')

    self.cid = cid
    self.key = key
    self.size = self.size_multi * self.SINGLE_SIZE
    self.rel_write_sector_count = 0

    self._data = b'\x00' * self.size

    self.emu = None

    self._req_handlers = {
        RpmbRequestType.AUTH_KEY_PROG: self._auth_key_prog,
        RpmbRequestType.READ_WRITE_COUNTER: self._read_write_counter,
        RpmbRequestType.WRITE_DATA: self._write_data,
        RpmbRequestType.READ_DATA: self._read_data,
        RpmbRequestType.RESULT_READ: self._result_read,
        }

  def _calc_mac(self, data):
    if not self.key:
      return b'\x00' * RpmbFrame.NONCE_SIZE

    return hmac.new(self.key, data, digestmod=hashlib.sha256).digest()

  def _ret_error(self, resp_type, resp_error):
    resp = RpmbFrame()
    resp.request = resp_type
    resp.result = resp_error
    return bytes(resp)

  def _auth_key_prog(self, frame):
    self.key = frame.mac
    return self._ret_error(RpmbResponseType.AUTH_KEY_PROG, RpmbReturnCode.OK)

  def _read_write_counter(self, frame):
    if not self.key:
      return self._ret_error(RpmbResponseType.READ_WRITE_COUNTER,
                             RpmbReturnCode.ERROR_AUTH_NOT_PROG)

    resp = RpmbFrame()
    resp.request = RpmbResponseType.READ_WRITE_COUNTER
    resp.result = RpmbReturnCode.OK
    resp.write_counter = self.write_counter
    resp.nonce = frame.nonce

    resp.mac = self._calc_mac(resp.get_bytes_for_mac())
    return bytes(resp)

  def _write_data(self, frame):
    if not self.key:
      return self._ret_error(RpmbResponseType.WRITE_DATA,
                             RpmbReturnCode.ERROR_AUTH_NOT_PROG)

    if self.write_counter == self.EXPIRED_COUNTER:
      return self._ret_error(RpmbResponseType.WRITE_DATA,
                             RpmbReturnCode.ERROR_WRITE |
                             RpmbReturnCode.ERROR_WRITE_COUNTER_EXPIRED)

    off = frame.address * self.BLOCK_SIZE

    if off < 0 or off > self.size:
      return self._ret_error(RpmbResponseType.WRITE_DATA,
                             RpmbReturnCode.ERROR_ADDRESS)

    if not frame.block_count:
      return self._ret_error(RpmbResponseType.WRITE_DATA,
                             RpmbReturnCode.ERROR_GENERAL)

    if off + frame.block_count * self.BLOCK_SIZE > self.size:
      return self._ret_error(RpmbResponseType.WRITE_DATA,
                             RpmbReturnCode.ERROR_GENERAL)

    mac = self._calc_mac(frame.get_bytes_for_mac())
    if mac != frame.mac:
      return self._ret_error(RpmbResponseType.WRITE_DATA,
                             RpmbReturnCode.ERROR_AUTHENTICATION)

    if frame.write_counter != self.write_counter:
      return self._ret_error(RpmbResponseType.WRITE_DATA,
                             RpmbReturnCode.ERROR_COUNTER)

    mod_data = bytearray(self._data)
    mod_data[off:off + self.BLOCK_SIZE] = frame.data
    self._data = bytes(mod_data)
    self.write_counter += 1

    resp = RpmbFrame()
    resp.request = RpmbResponseType.WRITE_DATA
    resp.address = frame.address
    resp.result = RpmbReturnCode.OK
    resp.write_counter = self.write_counter
    resp.mac = self._calc_mac(resp.get_bytes_for_mac())

    return bytes(resp)

  def _read_data(self, frame):
    if not self.key:
      return self._ret_error(RpmbResponseType.READ_DATA,
                             RpmbReturnCode.ERROR_AUTH_NOT_PROG)

    off = frame.address * self.BLOCK_SIZE

    if off < 0 or off > self.size:
      return self._ret_error(RpmbResponseType.READ_DATA,
                             RpmbReturnCode.ERROR_ADDRESS)

    if not frame.block_count:
      return self._ret_error(RpmbResponseType.READ_DATA,
                             RpmbReturnCode.ERROR_GENERAL)

    if off + frame.block_count * self.BLOCK_SIZE > self.size:
      return self._ret_error(RpmbResponseType.READ_DATA,
                             RpmbReturnCode.ERROR_GENERAL)

    if frame.write_counter != 0:
      return self._ret_error(RpmbResponseType.READ_DATA,
                             RpmbReturnCode.ERROR_COUNTER)

    frames = []
    data = b''
    for i in range(frame.block_count):
      resp = RpmbFrame()
      resp.request = RpmbResponseType.READ_DATA
      resp.nonce = frame.nonce
      resp.address = frame.address
      resp.result = RpmbReturnCode.OK

      addr = off + i * self.BLOCK_SIZE
      resp.data = self._data[addr:addr + self.BLOCK_SIZE]

      frames.append(resp)
      data += resp.get_bytes_for_mac()

    frames[-1].mac = self._calc_mac(data)
    out = b''
    for fr in frames:
      out += bytes(fr)

    return out

  def _result_read(self, frames):
    self.log.error('RPMB Frame request RESULT_READ is not supported')
    raise NotImplementedError('RPMB Frame request RESULT_READ is not '
                              'supported')

  def register(self, emu: arm.ArmEmu):
    self.log.info('Device %s registring...', self.name)
    self.emu = emu

  def process_frame(self, frame):
    self.log.info('Process %s:', frame)

    return self._req_handlers[frame.request](frame)

  def dump(self):
    return self._data
