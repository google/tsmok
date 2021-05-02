"""OPTEE RPMB types and storage implementation."""

import enum
import struct
import tsmok.hw.devices.rpmb as rpmb


class OpteeRpmbRequestCmd(enum.IntEnum):
  DATA_REQUEST = 0
  GET_DEV_INFO = 1


class OpteeRpmbGetDevInfoReturn(enum.IntEnum):
  OK = 0x00
  ERROR = 0x01


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

    self.cmd = OpteeRpmbRequestCmd(cmd)

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
