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

"""OPTEE storage types."""

import abc
import enum
import struct

import tsmok.optee.error as optee_error

OPTEE_DATA_MAX_POSITION = 0xFFFFFFFF


class OpteeObjectType(enum.IntEnum):
  """Defines main OPTEE object types."""

  AES = 0xA0000010
  DES = 0xA0000011
  DES3 = 0xA0000013
  HMAC_MD5 = 0xA0000001
  HMAC_SHA1 = 0xA0000002
  HMAC_SHA224 = 0xA0000003
  HMAC_SHA256 = 0xA0000004
  HMAC_SHA384 = 0xA0000005
  HMAC_SHA512 = 0xA0000006
  RSA_PUBLIC_KEY = 0xA0000030
  RSA_KEYPAIR = 0xA1000030
  DSA_PUBLIC_KEY = 0xA0000031
  DSA_KEYPAIR = 0xA1000031
  DH_KEYPAIR = 0xA1000032
  ECDSA_PUBLIC_KEY = 0xA0000041
  ECDSA_KEYPAIR = 0xA1000041
  ECDH_PUBLIC_KEY = 0xA0000042
  ECDH_KEYPAIR = 0xA1000042
  HKDF_IKM = 0xA10000C0
  GENERIC_SECRET = 0xA0000000
  CORRUPTED_OBJECT = 0xA00000BE
  DATA = 0xA00000BF
  RSA_FROM_PKCS8 = 0xA2000001
  EXPORT_FROM_RSA = 0xA2000002
  EXPORT_FROM_DSA = 0xA2000003
  IMPORT_DSA_KEY = 0xA2000004


class OpteeHandleFlags(enum.IntFlag):
  PERSISTENT = 0x00010000
  INITIALIZED = 0x00020000
  KEY_SET = 0x00040000
  EXPECT_TWO_KEYS = 0x00080000


class OpteeUsage(enum.IntFlag):
  EXTRACTABLE = 0x00000001
  ENCRYPT = 0x00000002
  DECRYPT = 0x00000004
  MAC = 0x00000008
  SIGN = 0x00000010
  VERIFY = 0x00000020
  DERIVE = 0x00000040
  DEFAULT = 0xFFFFFFFF


OPTEE_OBJECT_ID_MAX_LEN = 64


class OpteeStorageId(enum.IntEnum):
  # Storage is provided by the Rich Execution Environment (REE)
  PRIVATE_REE = 0x80000000
  # Storage is the Replay Protected Memory Block partition of an eMMC device
  PRIVATE_RPMB = 0x80000100


class OpteeStorageFlags(enum.IntFlag):
  ACCESS_READ = 0x00000001
  ACCESS_WRITE = 0x00000002
  ACCESS_WRITE_META = 0x00000004
  SHARE_READ = 0x00000010
  SHARE_WRITE = 0x00000020
  OVERWRITE = 0x00000400


class OpteeWhence(enum.IntEnum):
  SEEK_SET = 0
  SEEK_CUR = 1
  SEEK_END = 2

  @classmethod
  def has_value(cls, value):
    return value in cls._value2member_map_


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
    self.obj_type = OpteeObjectType.DATA
    self.object_usage = OpteeUsage.DEFAULT
    self.handle_flags = OpteeHandleFlags.INITIALIZED
    self.max_object_size = OPTEE_OBJECT_ID_MAX_LEN  # max_key_size
    self.object_size = 0  #  can be used as key_size
    self.data_size = 0
    self.data_position = 0

  def data(self):
    return struct.pack('<7I', int(self.obj_type),
                       self.object_size, self.max_object_size,
                       int(self.object_usage), self.data_size,
                       self.data_position, int(self.handle_flags))


class OpteeStorage(abc.ABC):
  """Base class for OPTEE storage."""

  def __init__(self, storage_id, name):
    self.id = storage_id
    self.name = name

  @abc.abstractmethod
  def object_open(self, oid: int, object_id: int,
                  flags: OpteeStorageFlags
                 ) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_create(self, oid, object_id, flags, attr, data
                   ) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_read(self, oid: int, size: int
                 ) -> (optee_error.OpteeErrorCode, bytes):
    raise NotImplementedError()

  @abc.abstractmethod
  def object_close(self, oid: int) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_delete(self, oid: int) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_rename(self, oid: int, object_id: str
                   ) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_trunc(self, oid: int, size: int) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_write(self, oid: int, data: bytes) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_seek(self, oid: int, offset: int, whence: int
                 ) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def object_get_info(self, oid: int) -> (optee_error.OpteeErrorCode,
                                          OpteeObjectInfo):
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_free(self, eid: int) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_reset(self, eid: int) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_start(self, eid: int) -> optee_error.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_next(self, eid: int) -> (optee_error.OpteeErrorCode, bytes):
    raise NotImplementedError()
