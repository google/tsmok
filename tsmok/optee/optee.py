"""OPTEE TEE implementation."""

import logging
import struct
from typing import Dict, List, Any
import uuid

import tsmok.common.error as error
import tsmok.common.ta_error as ta_error
import tsmok.optee.const as optee_const
import tsmok.optee.crypto_module as crypto_module
import tsmok.optee.ta.base as ta_base
import tsmok.optee.types as optee_types


class Optee:
  """Implementation of OPTEE TEE OS."""

  def __init__(self, crypto: crypto_module.CryptoModule,
               log_level=logging.ERROR):
    self.log = logging.getLogger('[OPTEE]')
    self.log.setLevel(log_level)

    self.syscall_callbacks = dict()

    self.ta_list = dict()
    self.open_sessions = dict()

    self.storage_list = dict()
    self.object_handlers = dict()

    self.enumerators = dict()

    self.crypto_module = crypto

    self.prop_sets = dict()

    self._setup()

  def _setup(self):
    """Setup system call handlers."""

    self.syscall_callbacks[optee_const.OpteeSysCalls.LOG] = self.syscall_log
    self.syscall_callbacks[optee_const.OpteeSysCalls.PANIC] = self.syscall_panic
    self.syscall_callbacks[optee_const.OpteeSysCalls.RETURN] = \
        self.syscall_return
    self.syscall_callbacks[optee_const.OpteeSysCalls.GET_PROPERTY_NAME_TO_INDEX] = \
        self.syscall_get_property_name_to_index
    self.syscall_callbacks[optee_const.OpteeSysCalls.GET_PROPERTY] = \
        self.syscall_get_property

    # TA syscall
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .OPEN_TA_SESSION] = self.syscall_open_ta_session
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .INVOKE_TA_COMMAND] = self.syscall_invoke_ta_command
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CLOSE_TA_SESSION] = self.syscall_close_ta_session

    # Storage object syscall
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_OBJ_OPEN] = self.syscall_storage_obj_open
    self.syscall_callbacks[optee_const.OpteeSysCalls.
                           STORAGE_OBJ_CREATE] = self.syscall_storage_obj_create
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_OBJ_READ] = self.syscall_storage_obj_read
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_OBJ_DEL] = self.syscall_storage_obj_del
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_OBJ_SEEK] = self.syscall_storage_obj_seek
    self.syscall_callbacks[optee_const.OpteeSysCalls.
                           STORAGE_OBJ_RENAME] = self.syscall_storage_obj_rename
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_OBJ_TRUNC] = self.syscall_storage_obj_trunc
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_OBJ_WRITE] = self.syscall_storage_obj_write

    # Storage enumerator syscall
    self.syscall_callbacks[optee_const.OpteeSysCalls.
                           STORAGE_ENUM_ALLOC] = self.syscall_storage_alloc_enum
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_ENUM_FREE] = self.syscall_storage_free_enum
    self.syscall_callbacks[optee_const.OpteeSysCalls.
                           STORAGE_ENUM_RESET] = self.syscall_storage_reset_enum
    self.syscall_callbacks[optee_const.OpteeSysCalls.
                           STORAGE_ENUM_START] = self.syscall_storage_start_enum
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .STORAGE_ENUM_NEXT] = self.syscall_storage_next_enum

    # Crypt
    self.syscall_callbacks[
        optee_const.OpteeSysCalls.CRYP_OBJ_CLOSE] = self.syscall_cryp_obj_close
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_OBJ_GET_INFO] = self.syscall_cryp_obj_get_info
    self.syscall_callbacks[
        optee_const.OpteeSysCalls
        .CRYP_RANDOM_NUMBER_GENERATE] = self.syscall_cryp_random_number_generate
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_STATE_ALLOC] = self.syscall_cryp_state_alloc
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_STATE_FREE] = self.syscall_cryp_state_free
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_OBJ_ALLOC] = self.syscall_cryp_obj_alloc
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_OBJ_POPULATE] = self.syscall_cryp_obj_populate
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_OBJ_RESET] = self.syscall_cryp_obj_reset
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_OBJ_COPY] = self.syscall_cryp_obj_copy
    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_OBJ_GET_ATTR] = self.syscall_cryp_obj_get_attr

    self.syscall_callbacks[optee_const.OpteeSysCalls
                           .CRYP_DERIVE_KEY] = self.syscall_cryp_derive_key

    self.syscall_callbacks[
        optee_const.OpteeSysCalls.HASH_INIT] = self.syscall_hash_init
    self.syscall_callbacks[
        optee_const.OpteeSysCalls.HASH_UPDATE] = self.syscall_hash_update
    self.syscall_callbacks[
        optee_const.OpteeSysCalls.HASH_FINAL] = self.syscall_hash_final

  def property_add(self, prop_type: optee_const.OpteePropsetType,
                   prop: optee_types.OpteeProperty):
    """Set new property.

    Args:
      prop_type: the type of property set, defined by
                 optee_const.OpteePropsetType
      prop: A new property to be set into
    """
    if prop_type not in self.prop_sets:
      self.prop_sets[prop_type] = []

    prop_set = self.prop_sets[prop_type]

    if prop in prop_set:
      prop_set.remove(prop)

    prop_set.append(prop)

  def property_del(self, prop_type: optee_const.OpteePropsetType, name: bytes):
    """Set new property.

    Args:
      prop_type: the type of property set, defined by
                 optee_const.OpteePropsetType
      name: The name of property to be removed.
    """
    if prop_type not in self.prop_sets:
      self.log.warning('Property set %s is not present', prop_type)
      return

    prop_set = self.prop_sets[prop_type]

    if name not in prop_set:
      self.log.warning('Property %s is not present in %s', name, prop_type)
      return

    prop_set.remove(name)

  def ta_add(self, ta) -> None:
    self.ta_list[ta.uuid] = ta

  def storage_add(self, storage) -> None:
    self.storage_list[storage.id] = storage

  def get_empty_key(self, d: Dict[int, Any]) -> int:
    if not d:
      return 1

    r = [ele for ele in range(1, max(d.keys()) + 1) if ele not in d.keys()]

    if not r:
      return max(d.keys()) + 1

    return r[0]

  def gen_sid(self) -> int:
    return self.get_empty_key(self.open_sessions)

  def gen_obj_handler(self) -> int:
    return self.get_empty_key(self.object_handlers)

  def gen_enum_id(self) -> int:
    return self.get_empty_key(self.enumerators)

  def args_dump(self, args: List[int]) -> None:
    self.log.debug('Args:')
    for i in range(len(args)):
      self.log.debug('\targs[%d]: 0x%08x', i, args[i])

  def optee_params_load_from_memory(self, ta: ta_base.Ta,
                                    addr: int) -> List[optee_types.OpteeParam]:
    buf = ta.mem_read(addr, optee_const.OPTEE_PARAMS_DATA_SIZE)
    params = optee_types.optee_params_from_data(buf)
    for p in params:
      if isinstance(p, optee_types.OpteeParamMemref):
        if p.ptr != 0 and p.size != 0:
          p.data = ta.mem_read(p.ptr, p.size)

    return params

  def optee_params_load_to_memory(self, ta: ta_base.Ta, addr: int,
                                  params: List[optee_types.OpteeParam]) -> None:
    """Loads optee_types.OpteeParam list into TA memory.

    Args:
      ta: TA emulator instance
      addr: Address in the TA memory space where parameters will be loaded
      params: the list of optee_types.OpteeParam paramenters

    Returns: None
    """
    buf = optee_types.optee_params_to_data(params)
    for p in params:
      if isinstance(p, optee_types.OpteeParamMemref):
        if p.data:
          if p.ptr == 0 or len(p.data) > p.size:
            raise error.Error(f'wrong format or data size: {str(p)}')
          ta.mem_write(p.ptr, p.data)

    ta.mem_write(addr, buf)

  def syscall_handler(self, ta, syscall, args):
    if syscall not in self.syscall_callbacks:
      raise error.Error(f'Unhandled Syscall {syscall}. Exit')

    self.log.info('.exec. => syscall %s', syscall)
    ret = self.syscall_callbacks[syscall](ta, args)
    self.log.info('.exec. <= syscall %s: %s', syscall, ret)
    return ret

  # SYSTEM CALLS callbacks
  # ===============================================================
  # void syscall_log(const void *buf __maybe_unused, size_t len __maybe_unused)
  def syscall_log(self, ta, args: List[int]) -> optee_const.OpteeErrorCode:
    buf = args[0]
    l = args[1]

    data = ta.mem_read(buf, l)
    self.log.info('[LOG]:> \n\t\t %s', data.decode('utf-8'))
    return optee_const.OpteeErrorCode.SUCCESS

  def syscall_panic(self, ta, args) -> optee_const.OpteeErrorCode:
    raise ta_base.TaPanicError(args[0], f'TA {ta.uuid} PANIC')

  def syscall_return(self, ta, args) -> optee_const.OpteeErrorCode:
    ret = optee_const.OpteeErrorCode(args[0])
    raise ta_error.TaExit(ret, f'TA Exit: ret code: {str(ret)}')

  # TEE_Result syscall_open_ta_session(const TEE_UUID *dest,
  #                           unsigned long cancel_req_to,
  #                           struct utee_params *usr_param,
  #                           uint32_t *ta_sess,
  #                           uint32_t *ret_orig)
  def syscall_open_ta_session(self, ta, args) -> optee_const.OpteeErrorCode:
    """Syscall to open TA session.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: address to TEE_UUID structure
           [1]: 'cancel request to' parameter
           [2]: pointer to OpteeParam list
           [3]: pointer to store TA session
           [4]: pointer to store return code

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.log.info('[External TA] TEE_OpenTASession')
    self.args_dump(args)

    if len(args) < 5:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    data = ta.mem_read(args[0], 16)
    arg0, arg1, arg2 = struct.unpack('I2H', data[:8])
    arg3 = struct.unpack('>Q', data[8:])[0]
    uid = uuid.UUID(int=(arg0 << 96) | (arg1 << 80) | (arg2 << 64) | arg3)
    self.log.info('Open session to TA UUID %s', uid)

    if uid in self.ta_list:
      target_ta = self.ta_list[uid]
      self.log.info('Found external TA: %s', target_ta.get_name())

      sid = self.gen_sid()
      params = self.optee_params_load_from_memory(ta, args[2])
      ret, params = target_ta.open_session(sid, params)
      if ret == optee_const.OpteeErrorCode.SUCCESS:
        self.open_sessions[sid] = target_ta
        self.optee_params_load_to_memory(ta, args[2], params)
        ta.mem_write(args[3], struct.pack('I', sid))
      return ret

    return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

  # TEE_Result syscall_close_ta_session(unsigned long ta_sess)
  def syscall_close_ta_session(self, ta: ta_base.Ta, args: List[int]) -> bool:
    """Syscall to close TA session.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 1 elements:
           [0]: session id to close

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused in this call
    self.log.info('[External TA] TEE_CloseTASession')
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] in self.open_sessions:
      target_ta = self.open_sessions[args[0]]
      self.log.info('Found open session for TA %s', target_ta.get_uuid())
      del self.open_sessions[args[0]]
      return target_ta.close_session(args[0])

    return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

  # TEE_Result syscall_invoke_ta_command(unsigned long ta_sess,
  #                       unsigned long cancel_req_to, unsigned long cmd_id,
  #                       struct utee_params *usr_param, uint32_t *ret_orig)
  def syscall_invoke_ta_command(self, ta, args) -> bool:
    """Syscall to invoke TA command.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: session id
           [1]: 'cancel request to' parameter
           [2]: command id
           [3]: pointer pointer to OpteeParam list
           [4]: pointer to store return code

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.log.info('[External TA] TEE_InvokeTACommand')
    self.args_dump(args)

    if len(args) < 5:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] in self.open_sessions:
      target_ta = self.open_sessions[args[0]]
      self.log.info('Found open session for TA: %s', target_ta.get_uuid())
      params = self.optee_params_load_from_memory(ta, args[3])
      ret, params = target_ta.invoke_command(args[0], args[2], params)
      self.optee_params_load_to_memory(ta, args[3], params)
      return ret

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_storage_obj_open(unsigned long storage_id,
  #                 void *object_id, size_t object_id_len,
  #                 unsigned long flags, uint32_t *obj)
  def syscall_storage_obj_open(self, ta, args):
    """Syscall to open the obhect from the storage.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: storage id
           [1]: pointer to buffer with object id
           [2]: size of the buffer with object id
           [3]: flags to use for open
           [4]: pointer to store object handler id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 5:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    object_id = ta.mem_read(args[1], args[2])
    self.log.info('Open object: %s', object_id)

    if args[0] in self.storage_list:
      storage = self.storage_list[args[0]]
      self.log.info('Found storage: %s', storage.name)

      objh = self.gen_obj_handler()
      flags = optee_const.OpteeStorageFlags(args[3])
      ret = storage.object_open(objh, object_id, flags)
      if ret == optee_const.OpteeErrorCode.SUCCESS:
        self.object_handlers[objh] = storage
        ta.mem_write(args[4], struct.pack('I', objh))
      return ret

    return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

  # TEE_Result syscall_storage_obj_create(unsigned long storage_id,
  #                 void *object_id, size_t object_id_len,
  #                 unsigned long flags, unsigned long attr,
  #                 void *data, size_t len, uint32_t *obj)
  def syscall_storage_obj_create(self, ta, args):
    """Syscall to create an object in the storage.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 8 elements:
           [0]: storage id
           [1]: pointer to buffer with object id
           [2]: size of the buffer with object id
           [3]: flags to use for open
           [4]: attributes to use for open
           [5]: pointer to buffer with object's data
           [6]: size of the object's data buffer
           [7]: pointer to store object handler id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 8:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    object_id = ta.mem_read(args[1], args[2])
    data = ta.mem_read(args[5], args[6])
    self.log.debug('[STORAGE] Create object object_id = %s, data = %s',
                   object_id, data)

    if args[0] in self.storage_list:
      storage = self.storage_list[args[0]]
      self.log.info('[STORAGE] Found: %s', storage.name)

      objh = self.gen_obj_handler()
      flags = optee_const.OpteeStorageFlags(args[3])
      ret = storage.object_create(objh, object_id, flags, args[4], data)
      if ret == optee_const.OpteeErrorCode.SUCCESS:
        self.object_handlers[objh] = storage
        ta.mem_write(args[7], struct.pack('I', objh))
      return ret

    return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

  # TEE_Result syscall_storage_obj_read(unsigned long obj, void *data,
  #               size_t len, uint64_t *count)
  def syscall_storage_obj_read(self, ta, args):
    """Syscall to read from the object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 4 elements:
           [0]: object handler id
           [1]: pointer to bufferd
           [2]: size of the buffer
           [3]: pointer to store read count

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 4:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] in self.object_handlers:
      storage = self.object_handlers[args[0]]
      ret, data = storage.object_read(args[0], args[2])
      if ret == optee_const.OpteeErrorCode.SUCCESS:
        ta.mem_write(args[1], data)
        ta.u32_write(args[3], len(data))
      return ret

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_storage_obj_del(unsigned long obj)
  def syscall_storage_obj_del(self, ta: ta_base.Ta,
                              args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to delete the object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 1 elements:
           [0]: object handler id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] in self.object_handlers:
      storage = self.object_handlers[args[0]]
      del self.object_handlers[args[0]]
      return storage.object_delete(args[0])

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_storage_obj_rename(unsigned long obj, void *object_id,
  #                   size_t object_id_len)
  def syscall_storage_obj_rename(self, ta: ta_base.Ta,
                                 args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to rename the object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 3 elements:
           [0]: object hamdler id
           [1]: pointer to buffer with new object id
           [2]: size of the buffer with mew object id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 3:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    object_id = ta.mem_read(args[1], args[2])
    if args[0] in self.object_handlers:
      storage = self.object_handlers[args[0]]
      return storage.object_rename(args[0], object_id)

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_storage_obj_trunc(unsigned long obj, size_t len)
  def syscall_storage_obj_trunc(self, ta: ta_base.Ta,
                                args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall for truncate the object in a storage.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 2 elements:
           [0]: object handler id
           [1]: new size

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 2:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] in self.object_handlers:
      storage = self.object_handlers[args[0]]
      return storage.object_trunc(args[0], args[1])

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_storage_obj_write(unsigned long obj,
  #                     void *data, size_t len)
  def syscall_storage_obj_write(self, ta: ta_base.Ta,
                                args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall for writing data to the object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 3 elements:
           [0]: object handler id
           [1]: pointer to buffer with data
           [2]: size of the buffer

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 3:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] in self.object_handlers:
      storage = self.object_handlers[args[0]]
      data = ta.mem_read(args[1], args[2])
      return storage.object_write(args[0], data)

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_storage_obj_seek(unsigned long obj, int32_t offset,
  #                   unsigned long whence)
  def syscall_storage_obj_seek(self, ta: ta_base.Ta,
                               args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall for set position in the object data.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 3 elements:
           [0]: object handler id
           [1]: offset
           [2]: whence

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 3:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] in self.object_handlers:
      storage = self.object_handlers[args[0]]
      return storage.object_seek(args[0], args[1], args[2])

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_storage_alloc_enum(uint32_t *obj_enum)
  def syscall_storage_alloc_enum(self, ta: ta_base.Ta,
                                 args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to allocat an object enumerator.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 1 elements:
           [0]: pointer to store object enumerator handler id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    enum = self.gen_enum_id()

    self.enumerators[enum] = None

    ta.u32_write(args[0], enum)

    return optee_const.OpteeErrorCode.SUCCESS

  # TEE_Result syscall_storage_free_enum(unsigned long obj_enum)
  def syscall_storage_free_enum(self, ta: ta_base.Ta,
                                args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to deallocat the object enumerator.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 1 elements:
           [0]: object enumerator handler id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    eid = args[0]

    if eid not in self.enumerators:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ret = optee_const.OpteeErrorCode.SUCCESS
    if self.enumerators[eid]:
      ret = self.enumerators[eid].enum_free(eid)

    del self.enumerators[eid]
    return ret

  # TEE_Result syscall_storage_reset_enum(unsigned long obj_enum)
  def syscall_storage_reset_enum(self, ta: ta_base.Ta,
                                 args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to reset the object enumerator.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 1 elements:
           [0]: object enumerator handler id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    eid = args[0]

    if eid not in self.enumerators:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ret = optee_const.OpteeErrorCode.SUCCESS
    if self.enumerators[eid]:
      ret = self.enumerators[eid].enum_reset(eid)

    return ret

  # TEE_Result syscall_storage_start_enum(unsigned long obj_enum,
  #                       unsigned long storage_id)
  def syscall_storage_start_enum(self, ta: ta_base.Ta,
                                 args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to start objects enumeration.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 2 elements:
           [0]: object enumerator handler id
           [1]: storage id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 2:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    eid = args[0]

    if eid not in self.enumerators:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[1] not in self.storage_list:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

    self.enumerators[eid] = self.storage_list[args[1]]

    return self.storage_list[args[1]].enum_start(eid)

  # TEE_Result syscall_storage_next_enum(unsigned long obj_enum,
  #                      TEE_ObjectInfo *info, void *obj_id, uint64_t *len)
  def syscall_storage_next_enum(self, ta: ta_base.Ta,
                                args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to get a next element from object enumerator.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 4 elements:
           [0]: object enumerator handler id
           [1]: pointer to TEE object info structure. OpteeObjectInfo is
                representation.
           [2]: pointer to buffer to store object id
           [3]" size of the buffer

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 4:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    eid = args[0]
    if args[2] == 0 or args[3] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if eid not in self.enumerators:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ret, obj_id = self.enumerators[eid].enum_next(eid)
    if ret != optee_const.OpteeErrorCode.SUCCESS:
      return ret

    ta.mem_write(args[2], obj_id)
    ta.u32_write(args[3], len(obj_id))

    return optee_const.OpteeErrorCode.SUCCESS

  # TEE_Result syscall_cryp_obj_close(unsigned long obj)
  def syscall_cryp_obj_close(self, ta: ta_base.Ta, args):
    """Syscall to close the object handler.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 1 elements:
           [0]: object handler id

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.log.info('Close object %s', args[0])
    if args[0] in self.object_handlers:
      storage = self.object_handlers[args[0]]
      self.log.info('Found open object handler %d in %s', args[0], storage.name)
      del self.object_handlers[args[0]]
      return storage.object_close(args[0])

    return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

  # TEE_Result syscall_cryp_obj_get_info(unsigned long obj,
  #                     TEE_ObjectInfo *info)
  def syscall_cryp_obj_get_info(self, ta: ta_base.Ta,
                                args) -> optee_const.OpteeErrorCode:
    """Syscall to get the object info.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 2 elements:
           [0]: object handler id
           [1]: pointer to TEE object info structure. OpteeObjectInfo is
                representation.

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)
    if len(args) < 2:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.log.info('Get object info %d', args[0])
    if args[0] not in self.object_handlers:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[1] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    storage = self.object_handlers[args[0]]
    self.log.info('Found open object handler %d in %s', args[0], storage.name)
    ret, info = storage.object_get_info(args[0])
    if ret != optee_const.OpteeErrorCode.SUCCESS:
      return ret

    data = info.data()
    ta.mem_write(args[1], data)

    return optee_const.OpteeErrorCode.SUCCESS

  # TEE_Result syscall_cryp_random_number_generate(void *buf, size_t blen)
  def syscall_cryp_random_number_generate(self, ta, args):
    """Syscall to get secure random byte.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 2 elements:
           [0]: pointer to buffer
           [1]: size of the buffer

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 2:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    buf = args[0]

    if buf == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    data = self.crypto_module.cryp_random_number_generate(args[1])
    ta.mem_write(buf, data)

    return optee_const.OpteeErrorCode.SUCCESS

  # TEE_Result syscall_cryp_state_alloc(unsigned long algo, unsigned long mode,
  #                       unsigned long key1, unsigned long key2,
  #                       uint32_t *state)
  def syscall_cryp_state_alloc(self, ta: ta_base.Ta,
                               args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to allocate crypto module state.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: algorithm
           [1]: mode
           [2]: key 1
           [3]: key 2
           [4]: pointer to a crypto state handler

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 5:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    state = args[4]

    if state == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    algo = optee_const.OpteeCrypAlg(args[0])
    mode = optee_const.OpteeCrypOperation(args[1])

    self.log.debug('Crypto State Allocation: algo = %s, mode = %s', algo, mode)

    ret, st = self.crypto_module.state_alloc(algo, mode, args[2], args[3])
    if ret == optee_const.OpteeErrorCode.SUCCESS:
      ta.u32_write(state, st)

    return ret

  # TEE_Result syscall_cryp_state_free(unsigned long state)
  def syscall_cryp_state_free(self, ta: ta_base.Ta,
                              args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to deallocate crypto module state.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 1 elements:
           [0]: crypto state handler

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return self.crypto_module.state_free(args[0])

  # TEE_Result syscall_cryp_obj_alloc(unsigned long obj_type,
  #           unsigned long max_key_size, uint32_t *obj)
  def syscall_cryp_obj_alloc(self, ta: ta_base.Ta,
                             args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to allocate crypto module object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: type
           [1]: max key size
           [2]: pointer to a crypto object handler

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 3:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[2] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    otype = optee_const.OpteeObjectType(args[0])
    if otype == optee_const.OpteeObjectType.DATA:
      return optee_const.OpteeErrorCode.ERROR_NOT_SUPPORTED

    self.log.debug('Crypto Object Allocation: mode = %s', otype)

    objh = self.gen_obj_handler()
    ret = self.crypto_module.object_alloc(objh, otype, args[1])
    if ret == optee_const.OpteeErrorCode.SUCCESS:
      self.object_handlers[objh] = self.crypto_module
      ta.u32_write(args[2], objh)

    return ret

  # TEE_Result syscall_cryp_obj_populate(unsigned long obj,
  #           struct utee_attribute *usr_attrs,
  #           unsigned long attr_count)
  def syscall_cryp_obj_populate(self, ta: ta_base.Ta,
                                args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to populate crypto module object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: handler id to the crypto object
           [1]: pointer to attributes
           [2]: attributes count

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 3:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.log.info('Get object info %d', args[0])
    if args[0] not in self.object_handlers:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[1] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[2] == 0:
      return optee_const.OpteeErrorCode.SUCCESS

    attr_size = optee_types.OpteeUteeAttribute.size()
    total_size = attr_size * args[2]
    data = ta.mem_read(args[1], total_size)

    attrs = []
    off = 0
    for _ in range(args[2]):
      attr = optee_types.OpteeUteeAttribute.create(data[off:])
      if isinstance(attr, optee_types.OpteeUteeAttributeMemory):
        if attr.ptr and attr.size:
          attr.data = ta.mem_read(attr.ptr, attr.size)
      off += attr_size
      attrs.append(attr)

    storage = self.object_handlers[args[0]]
    self.log.info('Found open object handler %d in %s', args[0], storage.name)
    ret = storage.object_populate(args[0], attrs)
    return ret

  # TEE_Result syscall_cryp_obj_reset(unsigned long obj)
  def syscall_cryp_obj_reset(self, ta: ta_base.Ta,
                             args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to reset crypto module object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: handler id to the crypto object

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.log.info('Get object info %d', args[0])
    if args[0] not in self.object_handlers:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    storage = self.object_handlers[args[0]]
    self.log.info('Found open object handler %d in %s', args[0], storage.name)
    ret = storage.object_reset(args[0])
    return ret

  # TEE_Result syscall_cryp_obj_copy(unsigned long dst, unsigned long src)
  def syscall_cryp_obj_copy(self, ta: ta_base.Ta,
                            args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to copy crypto module object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: handler id to dst the crypto object
           [1]: handler id to src the crypto object

    Returns:
      optee_const.OpteeErrorCode return code
    """
    del ta  # unused
    self.args_dump(args)

    if len(args) < 1:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.log.info('Get object info dst: %d; src: %d', args[0], args[1])
    if args[0] not in self.object_handlers:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    storage = self.object_handlers[args[0]]
    self.log.info('Found open object handler %d in %s', args[0], storage.name)
    ret = storage.object_copy(args[0], args[1])
    return ret

  # TEE_Result syscall_cryp_obj_get_attr(unsigned long obj,
  #           unsigned long attr_id,
  #           void *buffer, uint64_t *size)
  def syscall_cryp_obj_get_attr(self, ta: ta_base.Ta,
                                args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to get specific attribute data from crypto module object.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: handler id to dst the crypto object
           [1]: attribute id
           [2]: buffer ptr
           [3]: buffer size ptr

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 4:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[2] == 0 or args[3] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    attr_id = optee_const.OpteeAttr(args[1])

    self.log.info('Get object id: %d; attr id: %s', args[0], attr_id)
    if args[0] not in self.object_handlers:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    storage = self.object_handlers[args[0]]
    self.log.info('Found open object handler %d in %s', args[0], storage.name)
    ret, data = storage.object_get_attr(args[0], attr_id)
    if ret == optee_const.OpteeErrorCode.SUCCESS:
      buf_size = ta.u32_read(args[3])
      out_size = buf_size
      if buf_size:
        data = data[:buf_size]
        out_size = len(data)
        ta.mem_write(args[2], data)
      ta.u32_write(args[3], out_size)

    return ret

  # TEE_Result syscall_cryp_derive_key(unsigned long state,
  #             const struct utee_attribute *usr_params,
  #             unsigned long param_count, unsigned long derived_key)
  def syscall_cryp_derive_key(self, ta: ta_base.Ta,
                              args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to derive key.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 3 elements:
           [0]: crypto state handler
           [1]: pointer to parameters
           [2]: parameters count
           [3]: derived key

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 4:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.log.info('Get state id %d', args[0])
    if args[1] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    attrs = []
    if args[2]:
      attr_size = optee_types.OpteeUteeAttribute.size()
      total_size = attr_size * args[2]
      data = ta.mem_read(args[1], total_size)

      off = 0
      for _ in range(args[2]):
        attr = optee_types.OpteeUteeAttribute.create(data[off:])
        if isinstance(attr, optee_types.OpteeUteeAttributeMemory):
          if attr.ptr and attr.size:
            attr.data = ta.mem_read(attr.ptr, attr.size)
        off += attr_size
        attrs.append(attr)

    return self.crypto_module.derive_key(args[0], attrs, args[3])

  # TEE_Result syscall_hash_init(unsigned long state,
  #                       const void *iv __maybe_unused,
  #                       size_t iv_len __maybe_unused)
  def syscall_hash_init(self, ta: ta_base.Ta,
                        args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to init hash context.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 3 elements:
           [0]: crypto state handler
           [1]: pointer to IV buffer
           [2]: size of IV buffer

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)

    if len(args) < 3:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    state = args[0]
    iv = b''
    if args[1] != 0 and args[2] != 0:
      iv = ta.mem_read(args[1], args[2])

    return self.crypto_module.hash_init(state, iv)

  # TEE_Result syscall_hash_update(unsigned long state, const void *chunk,
  #               size_t chunk_size)
  def syscall_hash_update(self, ta: ta_base.Ta,
                          args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to hash chunk of data.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 3 elements:
           [0]: crypto state handler
           [1]: pointer to data chunk buffer
           [2]: size of data chunk buffer

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)
    if len(args) < 3:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    state = args[0]
    if args[1] == 0 and args[2]:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[2] == 0:
      return optee_const.OpteeErrorCode.SUCCESS

    chunk = ta.mem_read(args[1], args[2])

    return self.crypto_module.hash_update(state, chunk)

  # TEE_Result syscall_hash_final(unsigned long state, const void *chunk,
  #               size_t chunk_size, void *hash, uint64_t *hash_len)
  def syscall_hash_final(self, ta: ta_base.Ta,
                         args: List[int]) -> optee_const.OpteeErrorCode:
    """Syscall to finalize hash calculation.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 5 elements:
           [0]: crypto state handler
           [1]: pointer to data chunk buffer
           [2]: size of data chunk buffer
           [3]: pointer to result buffer
           [4]: size of result buffer

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)
    if len(args) < 5:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    state = args[0]
    if args[1] == 0 and args[2]:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    out_hash = args[3]
    out_len = args[4]

    if out_hash == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    chunk = ta.mem_read(args[1], args[2])

    ret, h = self.crypto_module.hash_final(state, chunk)
    if ret != optee_const.OpteeErrorCode.SUCCESS:
      return ret

    if len(h) > out_len:
      return optee_const.OpteeErrorCode.ERROR_SHORT_BUFFER

    ta.mem_write(out_hash, h)
    ta.u32_write(out_len, len(h))
    return optee_const.OpteeErrorCode.SUCCESS

  # TEE_Result syscall_get_property_name_to_index(unsigned long prop_set,
  #               void *name,
  #               unsigned long name_len,
  #               uint32_t *index)
  def syscall_get_property_name_to_index(
      self, ta: ta_base.Ta, args: List[int]) -> optee_const.OpteeErrorCode:
    """Get an index of property in the property set.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 4 elements:
        [0]: the type of property set, defined by
                 optee_const.OpteePropsetType
        [1]: pointer to a buffer with  name
        [2]: size of name buffer.
        [3]: pointer to store the index

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)
    if len(args) < 4:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[1] == 0 or args[2] == 0 or args[3] == 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    name = ta.mem_read(args[1], args[2])
    self.log.info('Get index for "%s" property from 0x%08x propset.',
                  name, args[0])
    if args[0] not in self.prop_sets:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

    prop_set = self.prop_sets[args[0]]
    if name not in prop_set:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

    idx = prop_set.index(name)

    ta.u32_write(args[3], idx)
    return optee_const.OpteeErrorCode.SUCCESS

  # TEE_Result syscall_get_property(unsigned long prop_set,
  #      unsigned long index,
  #      void *name, uint32_t *name_len,
  #      void *buf, uint32_t *blen,
  #      uint32_t *prop_type)
  def syscall_get_property(self, ta: ta_base.Ta,
                           args: List[int]) -> optee_const.OpteeErrorCode:
    """Get the property by index.

    Args:
     ta: TA emulator instance
     args: argument list should have at least 7 elements:
        [0]: the type of property set, defined by
                 optee_const.OpteePropsetType
        [1]: property index
        [2]: pointer to a buffer with  name
        [3]: size of name buffer.
        [4]: pointer to data buffer
        [5]: size of data buffer.
        [6]: pointer to store the property type

    Returns:
      optee_const.OpteeErrorCode return code
    """
    self.args_dump(args)
    if len(args) < 7:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if args[0] not in self.prop_sets:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

    prop_set = self.prop_sets[args[0]]
    idx = args[1]
    if idx > (len(prop_set) - 1):
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

    prop = prop_set[idx]

    if args[2] != 0 and args[3] != 0:
      name_buf_size = ta.u32_read(args[3])
      if name_buf_size != 0:
        name_to_write = prop.name[:name_buf_size]
        ta.mem_write(args[2], name_to_write)
        ta.u32_write(args[3], len(name_to_write))

    if args[4] != 0 and args[5] != 0:
      prop_buf_size = ta.u32_read(args[5])
      if prop_buf_size != 0:
        data = prop.data()[:prop_buf_size]
        ta.mem_write(args[4], data)
        ta.u32_write(args[5], len(data))

    if args[6] != 0:
      ta.u32_write(args[6], int(prop.type))

    return optee_const.OpteeErrorCode.SUCCESS
