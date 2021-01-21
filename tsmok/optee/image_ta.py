"""OPTEE TA base image."""

import collections
import struct
import uuid


TaHeader = collections.namedtuple('TaHeader',
                                  ['uuid', 'stack_size', 'flag',
                                   'entry_offset'])


class TaImage:
  """Defines TA base binary image."""

  def __init__(self):
    self.stack_size = None
    self.uuid = None

  def _parse_ta_header(self, data: bytes):
    # TA_UUID
    stack_size, flags, ptr = struct.unpack('<2IQ', data[16:])

    arg0, arg1, arg2 = struct.unpack('I2H', data[:8])
    arg3 = struct.unpack('>Q', data[8:16])[0]
    uid = uuid.UUID(int=(arg0 << 96) | (arg1 << 80) | (arg2 << 64) | arg3)

    return TaHeader(uid, stack_size, flags, ptr)
