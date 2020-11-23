"""Unittests for storage.StorageRpmbSimple."""

import test.support
import unittest

import tsmok.common.error as error
import tsmok.optee.const as optee_const
import tsmok.optee.storage.rpmb_simple as storage


class TestStorage(unittest.TestCase):

  def test_obj_create(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    obj_id_too_long = b'A' * 100
    data = b'0123456789abcdefghijk'
    attr = 0
    flags = (optee_const.OpteeStorageFlags.ACCESS_WRITE |
             optee_const.OpteeStorageFlags.SHARE_WRITE)

    overwrite_flag = optee_const.OpteeStorageFlags.OVERWRITE

    self.assertEqual(s.obj_create(oid, obj_id_too_long, flags, attr, data),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    with self.assertRaises(error.Error):
      s.obj_create(oid, obj_id, flags, 5, data)

    self.assertEqual(s.obj_create(oid, obj_id, flags, attr, data),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.obj_create(oid, obj_id, flags, attr, data),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertEqual(s.obj_create(oid + 1, obj_id,
                                  optee_const.OpteeStorageFlags.ACCESS_WRITE,
                                  attr, data),
                     optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_open(oid + 1, obj_id,
                                optee_const.OpteeStorageFlags.SHARE_WRITE),
                     optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_create(oid + 1, obj_id, flags | overwrite_flag,
                                  attr, data),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertIn(oid, s.open_objects)
    self.assertEqual(len(s.open_objects), 2)
    self.assertEqual(s.open_objects[oid].pos, 0)
    self.assertEqual(s.open_objects[oid].flags, flags)
    self.assertEqual(s.open_objects[oid].object.object_id, obj_id)

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.obj_close(oid + 1), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(len(s.open_objects), 0)
    self.assertEqual(len(s.objects), 1)
    self.assertIn(obj_id, s.objects)
    self.assertEqual(s.objects[obj_id].data, data)
    self.assertEqual(s.objects[obj_id].object_id, obj_id)
    self.assertEqual(s.objects[obj_id].attr, attr)

    self.assertEqual(s.obj_create(oid, obj_id, flags, attr, data),
                     optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)

    self.assertEqual(s.obj_create(oid, obj_id, overwrite_flag, attr, b'xyz'),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(s.open_objects), 1)
    self.assertEqual(len(s.objects), 1)
    self.assertIn(obj_id, s.objects)
    self.assertEqual(s.objects[obj_id].data, b'xyz')
    self.assertEqual(s.objects[obj_id].object_id, obj_id)

  def test_obj_open(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    obj_id2 = b'bad-id'
    obj_id_too_long = b'A' * 100
    data = b'0123456789abcdefghijk'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, data, attr)
    flags = (optee_const.OpteeStorageFlags.ACCESS_READ |
             optee_const.OpteeStorageFlags.SHARE_READ)

    self.assertEqual(s.obj_open(oid, obj_id_too_long, flags),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    self.assertEqual(s.obj_open(oid, obj_id2, flags),
                     optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND)

    self.assertEqual(s.obj_open(oid, obj_id, flags),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.obj_open(oid + 1, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_WRITE),
                     optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_create(oid + 1, obj_id,
                                  (optee_const.OpteeStorageFlags.SHARE_READ |
                                   optee_const.OpteeStorageFlags.OVERWRITE),
                                  attr, data),
                     optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_open(oid + 1, obj_id,
                                optee_const.OpteeStorageFlags.SHARE_READ),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_open(oid, obj_id2, flags),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    self.assertIn(oid, s.open_objects)
    self.assertEqual(len(s.open_objects), 2)
    self.assertEqual(s.open_objects[oid].pos, 0)
    self.assertEqual(s.open_objects[oid].flags, flags)
    self.assertEqual(s.open_objects[oid].object.object_id, obj_id)

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

  def test_obj_close(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, b'', attr)
    flags = (optee_const.OpteeStorageFlags.ACCESS_READ |
             optee_const.OpteeStorageFlags.ACCESS_WRITE |
             optee_const.OpteeStorageFlags.ACCESS_WRITE_META)

    self.assertEqual(len(s.open_objects), 0)

    self.assertEqual(s.obj_open(oid, obj_id, flags),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(len(s.open_objects), 1)
    self.assertEqual(
        s.obj_close(oid + 1), optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(s.open_objects), 0)

  def test_obj_seek(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    data = b'0123456789abcdefghijk'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, data, attr)
    flags = (optee_const.OpteeStorageFlags.ACCESS_READ |
             optee_const.OpteeStorageFlags.ACCESS_WRITE |
             optee_const.OpteeStorageFlags.ACCESS_WRITE_META)

    self.assertEqual(
        s.obj_open(oid, obj_id, flags), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(s.open_objects), 1)
    self.assertIn(oid, s.open_objects)

    obj = s.open_objects[oid]

    self.assertEqual(s.obj_seek(oid + 1, 0, 0),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    self.assertEqual(s.obj_seek(oid, 0, 10), \
        optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    self.assertEqual(s.obj_seek(oid, 0, optee_const.OpteeWhence.SEEK_SET),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(obj.pos, 0)

    self.assertEqual(s.obj_seek(oid, 10, optee_const.OpteeWhence.SEEK_CUR),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(obj.pos, 10)

    self.assertEqual(s.obj_seek(oid, -10, optee_const.OpteeWhence.SEEK_END),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(obj.pos, len(data) - 10)

    self.assertEqual(s.obj_seek(oid, -100, optee_const.OpteeWhence.SEEK_END),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(obj.pos, 0)

    self.assertEqual(s.obj_seek(oid, 100, optee_const.OpteeWhence.SEEK_SET),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(obj.pos, 100)

    self.assertEqual(s.obj_seek(oid, 0xFFFFFFFFFF,
                                optee_const.OpteeWhence.SEEK_SET),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

  def test_obj_read(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    data_orig = b'0123456789abcdefghijk'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, data_orig, attr)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_WRITE),
                     optee_const.OpteeErrorCode.SUCCESS)
    ret, data = s.obj_read(oid + 1, 10)
    self.assertEqual(ret, optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    ret, data = s.obj_read(oid, 10)
    self.assertEqual(ret, optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_READ),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(len(s.open_objects), 1)
    self.assertIn(oid, s.open_objects)

    ret, data = s.obj_read(oid, 10)
    self.assertEqual(ret, optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(data), 10)
    self.assertEqual(data, data_orig[:10])

    self.assertEqual(s.open_objects[oid].pos, 10)

    ret, data = s.obj_read(oid, 40)
    self.assertEqual(ret, optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(data), 11)
    self.assertEqual(data, data_orig[10:40])

    self.assertEqual(s.open_objects[oid].pos, len(data_orig))

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

  def test_obj_write(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    data = b'0123456789'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, b'', attr)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_READ),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(
        s.obj_write(oid + 1, b''),
        optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertEqual(
        s.obj_write(oid, b''), optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_WRITE),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(len(s.open_objects), 1)
    self.assertIn(oid, s.open_objects)

    self.assertEqual(s.obj_write(oid, data), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.open_objects[oid].pos, 10)
    self.assertEqual(s.open_objects[oid].object.data, data)

    self.assertEqual(s.obj_seek(oid, 5, optee_const.OpteeWhence.SEEK_SET),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.open_objects[oid].pos, 5)
    self.assertEqual(
        s.obj_write(oid, b'abc'), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.open_objects[oid].object.data, b'01234abc89')

    self.assertEqual(s.obj_seek(oid, 20, optee_const.OpteeWhence.SEEK_SET),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.open_objects[oid].pos, 20)
    self.assertEqual(
        s.obj_write(oid, b'abc'), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.open_objects[oid].object.data,
                     b'01234abc89\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00abc')
    self.assertEqual(s.open_objects[oid].pos, 23)

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

  def test_obj_trunc(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    data = b'0123456789'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, data, attr)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_READ),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(
        s.obj_trunc(oid + 1, 5),
        optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertEqual(
        s.obj_trunc(oid, 5), optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_WRITE),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(len(s.open_objects), 1)
    self.assertIn(oid, s.open_objects)

    self.assertEqual(s.obj_trunc(oid, 5), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(s.open_objects[oid].object.data), 5)
    self.assertEqual(s.open_objects[oid].object.data, data[:5])

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

  def test_obj_del(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    data = b'0123456789'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, data, attr)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_READ),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(
        s.obj_del(oid + 1), optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertEqual(
        s.obj_del(oid), optee_const.OpteeErrorCode.ERROR_ACCESS_CONFLICT)
    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_open(oid, obj_id, optee_const.OpteeStorageFlags.
                                ACCESS_WRITE_META),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(len(s.open_objects), 1)
    self.assertIn(oid, s.open_objects)

    self.assertEqual(s.obj_del(oid), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(s.open_objects), 0)
    self.assertEqual(len(s.objects), 0)

    self.assertEqual(
        s.obj_close(oid), optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

  def test_obj_rename(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    data = b'0123456789'
    attr = 0
    s.objects[obj_id] = storage.StorageObject(obj_id, data, attr)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_READ),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.obj_rename(oid + 1, b'id2'),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertEqual(s.obj_rename(oid, b'id2'),
                     optee_const.OpteeErrorCode.ERROR_BAD_STATE)
    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.SHARE_READ),
                     optee_const.OpteeErrorCode.SUCCESS)
    s.objects[b'id2'] = storage.StorageObject(b'id2', b'VALUE', attr)
    self.assertEqual(s.obj_open(oid + 1, b'id2',
                                optee_const.OpteeStorageFlags.SHARE_READ),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_rename(oid, b'id2'),
                     optee_const.OpteeErrorCode.ERROR_BAD_STATE)

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.obj_close(oid + 1), optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(s.obj_open(oid, obj_id, optee_const.OpteeStorageFlags.
                                ACCESS_WRITE_META),
                     optee_const.OpteeErrorCode.SUCCESS)

    self.assertEqual(len(s.open_objects), 1)
    self.assertIn(oid, s.open_objects)

    self.assertEqual(s.obj_rename(oid, b'0'*1024),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    self.assertEqual(
        s.obj_rename(oid, b'id2'), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(s.open_objects), 1)
    self.assertEqual(len(s.objects), 1)

    self.assertIn(oid, s.open_objects)
    self.assertIn(b'id2', s.objects)
    self.assertIs(s.open_objects[oid].object, s.objects[b'id2'])
    self.assertEqual(s.objects[b'id2'].data, data)
    self.assertEqual(s.objects[b'id2'].object_id, b'id2')

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

  def test_obj_get_info(self):
    s = storage.StorageRpmbSimple()
    oid = 1
    obj_id = b'id'
    data = b'0123456789'
    attr = 0
    pos = 7
    s.objects[obj_id] = storage.StorageObject(obj_id, data, attr)

    self.assertEqual(s.obj_open(oid, obj_id,
                                optee_const.OpteeStorageFlags.ACCESS_READ),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.obj_seek(oid, 7, optee_const.OpteeWhence.SEEK_SET),
                     optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(s.obj_get_info(oid + 1),
                     optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)

    ret, info = s.obj_get_info(oid)
    self.assertEqual(ret, optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(info.obj_type, optee_const.OpteeObjectType.DATA)
    self.assertEqual(info.object_usage, optee_const.OpteeUsage.DEFAULT)
    self.assertEqual(info.handle_flags, optee_const.OpteeHandleFlags.PERSISTENT)
    self.assertEqual(info.max_object_size, optee_const.OPTEE_OBJECT_ID_MAX_LEN)
    self.assertEqual(info.object_size, len(obj_id))
    self.assertEqual(info.data_size, len(data))
    self.assertEqual(info.data_position, pos)

    self.assertEqual(s.obj_close(oid), optee_const.OpteeErrorCode.SUCCESS)

  def test_enum_start(self):
    s = storage.StorageRpmbSimple()
    eid = 1
    s.objects[b'id'] = storage.StorageObject(b'id', b'', 0)
    s.objects[b'id1'] = storage.StorageObject(b'id1', b'', 0)

    self.assertEqual(s.enum_start(eid), optee_const.OpteeErrorCode.SUCCESS)
    self.assertIn(eid, s.enumerators)
    self.assertEqual(s.enumerators[eid], [b'id', b'id1'])

  def test_enum_free(self):
    s = storage.StorageRpmbSimple()
    eid = 1

    s.enumerators[eid] = [b'id0', b'id1', b'id2', b'id3']

    self.assertEqual(
        s.enum_free(eid + 1), optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertEqual(s.enum_free(eid), optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(len(s.enumerators), 0)

  def test_enum_reset(self):
    s = storage.StorageRpmbSimple()
    eid = 1

    s.enumerators[eid] = [b'id0', b'id1', b'id2', b'id3']

    self.assertEqual(
        s.enum_reset(eid + 1), optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertEqual(s.enum_reset(eid), optee_const.OpteeErrorCode.SUCCESS)
    self.assertIsNone(s.enumerators[eid])

  def test_enum_next(self):
    s = storage.StorageRpmbSimple()
    eid = 1

    s.enumerators[eid] = [b'id0', b'id1', b'id2', b'id3']

    ret, val = s.enum_next(eid + 1)
    self.assertEqual(ret, optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS)
    self.assertIsNone(val)

    ret, val = s.enum_next(eid)
    self.assertEqual(ret, optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(val, b'id3')
    self.assertEqual(s.enumerators[eid], [b'id0', b'id1', b'id2'])
    ret, val = s.enum_next(eid)
    self.assertEqual(ret, optee_const.OpteeErrorCode.SUCCESS)
    self.assertEqual(val, b'id2')
    self.assertEqual(s.enumerators[eid], [b'id0', b'id1'])

    s.enumerators[eid] = []
    ret, val = s.enum_next(eid)
    self.assertEqual(ret, optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND)
    self.assertIsNone(val)


def test_suite():
  return unittest.makeSuite(TestStorage)


if __name__ == '__main__':
  test.support.run_unittest(test_suite())
