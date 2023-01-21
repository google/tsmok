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

"""OPTEE Properties consts and types."""

import enum
import struct
from typing import Any
import uuid
import tsmok.common.error as error
import tsmok.optee.message as message


class OpteePropsetType(enum.IntEnum):
  TEE_IMPLEMENTATION = 0xFFFFFFFD
  CURRENT_CLIENT = 0xFFFFFFFE
  CURRENT_TA = 0xFFFFFFFF


class OpteePropertyType(enum.IntEnum):
  BOOL = 0
  U32 = 1
  UUID = 2
  IDENTITY = 3,  # TEE_Identity
  STRING = 4,  # zero terminated string of char
  BINARY_BLOCK = 5,  # zero terminated base64 coded string


class OpteeProperty:
  """Defines base class for OPTEE Properties."""

  def __init__(self, ptype: OpteePropertyType, name: bytes,
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
    OpteeProperty.__init__(self, OpteePropertyType.BOOL, name,
                           value)

  def data(self) -> bytes:
    val = self.get_value()
    return struct.pack('<I', val)


class OpteePropertyU32(OpteeProperty):

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, OpteePropertyType.U32, name, value)

  def data(self) -> bytes:
    val = self.get_value()
    return struct.pack('<I', val)


class OpteePropertyUuid(OpteeProperty):
  """Defines OPTEE Property UUID."""

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, OpteePropertyType.UUID, name,
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

  def __init__(self, name: bytes, login_type: message.OpteeMsgLoginType,
               uid: uuid.UUID):
    OpteeProperty.__init__(self, OpteePropertyType.IDENTITY, name, \
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
    OpteeProperty.__init__(self, OpteePropertyType.STRING, name,
                           value)

  def data(self) -> bytes:
    return self.get_value()


class OpteePropertyBinBlock(OpteeProperty):

  def __init__(self, name: bytes, value):
    OpteeProperty.__init__(self, OpteePropertyType.BINARY_BLOCK,
                           name, value)

  def data(self) -> bytes:
    return self.get_value()
