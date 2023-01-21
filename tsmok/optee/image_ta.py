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
