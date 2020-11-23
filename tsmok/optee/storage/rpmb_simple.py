"""OPTEE RPMB Storage."""

import logging
import tsmok.common.error as error
import tsmok.optee.const as optee_const
import tsmok.optee.storage.base as storage
import tsmok.optee.types as optee_types


class OpenObject:
  """Defines open Object information."""

  def __init__(self, obj, flags, pos, temp=False):
    self.object = obj
    self.flags = flags
    self.pos = pos
    self.temporary = temp

  def __str__(self):
    return (f'Obj: {self.object}, flag: {self.flags}, pos {self.pos}, '
            f'Temprorary: {self.temporary}')


class StorageObject:
  """Defines Storage Object."""

  def __init__(self, object_id, data, attr=0):
    self.object_id = object_id
    self.data = data
    self.attr = attr

  def __str__(self):
    return f'ID: {self.object_id}; Data(bytes): {self.data.hex()}'


class StorageRpmbSimple(storage.OpteeStorage):
  """Simple implementation of OPTEE RPMB Storage."""

  def __init__(self, log_level=logging.ERROR):
    storage.OpteeStorage.__init__(self, optee_const.OpteeStorageId.PRIVATE_RPMB,
                                  'StorageRPMB')
    self.objects = dict()
    self.open_objects = dict()
    self.enumerators = dict()
    self.log = logging.getLogger('[OPTEE][STORAGE][RPMB]')
    self.log.setLevel(log_level)

  def _check_access(self, oflags, nflags):
    # meta is exclusive
    if ((oflags & optee_const.OpteeStorageFlags.ACCESS_WRITE_META) or
        (nflags & optee_const.OpteeStorageFlags.ACCESS_WRITE_META)):
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    # Excerpt of TEE Internal Core API Specification v1.1:
    # If more than one handle is opened on the same  object, and if any
    # of these object handles was opened with the flag
    # optee_const.OpteeStorageFlags.ACCESS_READ, then all the object
    # handles MUST have been opened with the flag
    # optee_const.OpteeStorageFlags.SHARE_READ
    if (((oflags & optee_const.OpteeStorageFlags.ACCESS_READ) or
         (nflags & optee_const.OpteeStorageFlags.ACCESS_READ)) and
        not ((nflags & optee_const.OpteeStorageFlags.SHARE_READ) and
             (oflags & optee_const.OpteeStorageFlags.SHARE_READ))):
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    # Excerpt of TEE Internal Core API Specification v1.1:
    # An object can be opened with only share flags, which locks the access
    # to an object against a given mode.
    # An object can be opened with no flag set, which completely locks all
    # subsequent attempts to access the object
    if ((nflags & optee_const.OpteeStorageFlags.SHARE_READ) !=
        (oflags & optee_const.OpteeStorageFlags.SHARE_READ)):
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    # Same on WRITE access
    if (((oflags & optee_const.OpteeStorageFlags.ACCESS_WRITE) or
         (nflags & optee_const.OpteeStorageFlags.ACCESS_WRITE)) and
        not ((nflags & optee_const.OpteeStorageFlags.SHARE_WRITE) and
             (oflags & optee_const.OpteeStorageFlags.SHARE_WRITE))):
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT
    if ((nflags & optee_const.OpteeStorageFlags.SHARE_WRITE) !=
        (oflags & optee_const.OpteeStorageFlags.SHARE_WRITE)):
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    return optee_const.OpteeErrorCode.SUCCESS

  def obj_open(
      self, oid: int, obj_id: int,
      flags: optee_const.OpteeStorageFlags
      ) -> optee_const.OpteeErrorCode:
    self.log.debug('Open %s (%d) with %s', obj_id, oid, flags)

    if len(obj_id) > optee_const.OPTEE_OBJECT_ID_MAX_LEN:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if oid in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    for o_obj in self.open_objects.values():
      if o_obj.object.object_id == obj_id:
        if o_obj.temporary:
          return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT
        else:
          self.log.warning('Object %s is openned more than one time!!!',
                           obj_id)
          ret = self._check_access(o_obj.flags, flags)
          if ret != optee_const.OpteeErrorCode.SUCCESS:
            return ret

    if obj_id in self.objects:
      self.open_objects[oid] = OpenObject(self.objects[obj_id], flags, 0)
      return optee_const.OpteeErrorCode.SUCCESS

    return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

  def obj_create(self, oid, obj_id, flags, attr,
                 data) -> optee_const.OpteeErrorCode:
    self.log.debug('Create %s (%d) with %s, data len %d', obj_id, oid, flags,
                   len(data))
    if attr != 0:
      raise error.Error(
          '[STORAGE][RPMB] Object creating is not supported with ATTR != 0')

    if len(obj_id) > optee_const.OPTEE_OBJECT_ID_MAX_LEN:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if oid in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    for o_obj in self.open_objects.values():
      if o_obj.object.object_id == obj_id:
        if not o_obj.temporary:
          return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT
        else:
          self.log.warning('Object %s is already opened for creating!!!',
                           obj_id)
          ret = self._check_access(o_obj.flags, flags)
          if ret != optee_const.OpteeErrorCode.SUCCESS:
            return ret

    if obj_id in self.objects:
      if not flags & optee_const.OpteeStorageFlags.OVERWRITE:
        return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    self.objects[obj_id] = StorageObject(obj_id, data, attr)
    self.open_objects[oid] = OpenObject(self.objects[obj_id], flags, 0, True)

    return optee_const.OpteeErrorCode.SUCCESS

  def obj_read(self, oid: int,
               size: int) -> (optee_const.OpteeErrorCode, bytes):
    self.log.info('Read %s bytes from object handler %d', size, oid)

    if oid not in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    obj = self.open_objects[oid]

    if not obj.flags & optee_const.OpteeStorageFlags.ACCESS_READ:
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT, None

    end_pos = obj.pos + size
    if end_pos > len(obj.object.data):
      end_pos = len(obj.object.data)

    data = obj.object.data[obj.pos:end_pos]
    obj.pos = end_pos

    return optee_const.OpteeErrorCode.SUCCESS, data

  def obj_close(self, oid: int) -> optee_const.OpteeErrorCode:
    self.log.info('Close object handler %d', oid)

    if oid not in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.open_objects[oid]

    return optee_const.OpteeErrorCode.SUCCESS

  def obj_del(self, oid: int) -> optee_const.OpteeErrorCode:
    self.log.info('Delete object handler %d', oid)
    if oid not in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.open_objects[oid]
    if not obj.flags & optee_const.OpteeStorageFlags.ACCESS_WRITE_META:
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    del self.open_objects[oid]
    del self.objects[obj.object.object_id]

    return optee_const.OpteeErrorCode.SUCCESS

  def obj_rename(self, oid: int, obj_id: str) -> optee_const.OpteeErrorCode:
    self.log.info('Rename %d object handler to %s', oid, obj_id)
    if len(obj_id) > optee_const.OPTEE_OBJECT_ID_MAX_LEN:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    try:
      obj = self.open_objects[oid]
    except KeyError:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    opened = []
    for o_obj in self.open_objects.values():
      if o_obj.object.object_id == obj_id:
        if o_obj.temporary:
          return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT
        else:
          self.log.warning('Object %s is already opened', obj_id)
          ret = self._check_access(o_obj.flags, obj.flags)
          if ret != optee_const.OpteeErrorCode.SUCCESS:
            return ret
          opened.append(o_obj)

    if not obj.flags & optee_const.OpteeStorageFlags.ACCESS_WRITE_META:
      return optee_const.OpteeErrorCode.ERROR_BAD_STATE

    del self.objects[obj.object.object_id]
    obj.object.object_id = obj_id
    self.objects[obj_id] = obj.object
    for o in opened:
      o.object = obj.object
      o.pos = 0

    return optee_const.OpteeErrorCode.SUCCESS

  def obj_trunc(self, oid: int, size: int) -> optee_const.OpteeErrorCode:
    self.log.info('Trunc %d object handler to %d', oid, size)
    if oid not in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.open_objects[oid]
    if not obj.flags & optee_const.OpteeStorageFlags.ACCESS_WRITE:
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    obj.object.data = obj.object.data[:size]
    return optee_const.OpteeErrorCode.SUCCESS

  def obj_write(self, oid: int, data: bytes) -> optee_const.OpteeErrorCode:
    self.log.info('[STORAGE][RPMB]: Write %d object handler: data len %d', oid,
                  len(data))
    if oid not in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.open_objects[oid]
    if not obj.flags & optee_const.OpteeStorageFlags.ACCESS_WRITE:
      return optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT

    bdata = bytearray(obj.object.data)

    if obj.pos > len(bdata):
      bdata += b'\x00' * (obj.pos - len(bdata))

    bdata[obj.pos:obj.pos + len(data)] = data
    obj.object.data = bytes(bdata)

    obj.pos += len(data)
    return optee_const.OpteeErrorCode.SUCCESS

  def obj_seek(self, oid: int, offset: int,
               whence: int) -> optee_const.OpteeErrorCode:
    self.log.info(
        '[STORAGE][RPMB]: Seek %d object handler: offset = %d, whence = %s',
        oid, offset, whence)
    if oid not in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.open_objects[oid]
    if not optee_const.OpteeWhence.has_value(whence):
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if whence == optee_const.OpteeWhence.SEEK_SET:
      obj.pos = offset
    elif whence == optee_const.OpteeWhence.SEEK_CUR:
      obj.pos += offset
    else:
      obj.pos = len(obj.object.data) + offset

    if obj.pos < 0:
      obj.pos = 0

    if obj.pos > optee_const.OPTEE_DATA_MAX_POSITION:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return optee_const.OpteeErrorCode.SUCCESS

  def obj_get_info(self, oid: int) -> (optee_const.OpteeErrorCode,
                                       optee_types.OpteeObjectInfo):
    if oid not in self.open_objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.open_objects[oid]

    info = optee_types.OpteeObjectInfo()
    info.obj_type = optee_const.OpteeObjectType.DATA
    info.object_usage = optee_const.OpteeUsage.DEFAULT
    info.handle_flags = optee_const.OpteeHandleFlags.PERSISTENT
    info.max_object_size = optee_const.OPTEE_OBJECT_ID_MAX_LEN
    info.object_size = len(obj.object.object_id)
    info.data_size = len(obj.object.data)
    info.data_position = obj.pos

    return optee_const.OpteeErrorCode.SUCCESS, info

  def enum_free(self, eid: int) -> optee_const.OpteeErrorCode:
    if eid not in self.enumerators:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.enumerators[eid]
    return optee_const.OpteeErrorCode.SUCCESS

  def enum_reset(self, eid: int) -> optee_const.OpteeErrorCode:
    if eid not in self.enumerators:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.enumerators[eid] = None
    return optee_const.OpteeErrorCode.SUCCESS

  def enum_start(self, eid: int) -> optee_const.OpteeErrorCode:
    self.enumerators[eid] = list(self.objects.keys())
    return optee_const.OpteeErrorCode.SUCCESS

  def enum_next(self, eid: int) -> (optee_const.OpteeErrorCode, bytes):
    if eid not in self.enumerators:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    if not self.enumerators[eid]:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND, None

    return optee_const.OpteeErrorCode.SUCCESS, self.enumerators[eid].pop()
