"""Base interface for OPTEE storage instances."""

import abc
import tsmok.optee.const as optee_const
import tsmok.optee.types as optee_types


class OpteeStorage(abc.ABC):
  """Base class for OPTEE storage."""

  def __init__(self, storage_id, name):
    self.id = storage_id
    self.name = name

  @abc.abstractmethod
  def obj_open(self, oid: int, obj_id: int,
               flags: optee_const.OpteeStorageFlags
              ) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_create(self, oid, obj_id, flags, attr, data
                ) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_read(self, oid: int, size: int
              ) -> (optee_const.OpteeErrorCode, bytes):
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_close(self, oid: int) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_del(self, oid: int) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_rename(self, oid: int, obj_id: str) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_trunc(self, oid: int, size: int) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_write(self, oid: int, data: bytes) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_seek(self, oid: int, offset: int, whence: int
              ) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def obj_get_info(self, oid: int) -> (optee_const.OpteeErrorCode,
                                       optee_types.OpteeObjectInfo):
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_free(self, eid: int) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_reset(self, eid: int) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_start(self, eid: int) -> optee_const.OpteeErrorCode:
    raise NotImplementedError()

  @abc.abstractmethod
  def enum_next(self, eid: int) -> (optee_const.OpteeErrorCode, bytes):
    raise NotImplementedError()
