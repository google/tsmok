"""Module for OPTEE ARM emulator."""

import collections
import enum
import logging
import struct
from typing import List, Dict
import uuid

import tsmok.atf.atf
import tsmok.atf.const as atf_const
import tsmok.common.error as error
import tsmok.common.region_allocator as region_allocator
import tsmok.emu.arm as arm
import tsmok.optee.const as optee_const
import tsmok.optee.types as optee_types


SharedMemoryConfig = collections.namedtuple('SharedMemoryConfig',
                                            ['addr', 'size', 'cached'])


class OpteeArmEmu(arm.ArmEmu):
  """Implimentation of OPTEE Emulator for ARM architecture."""

  ENTRY_VECTOR_SIZE = 9

  EXIT_RETURN_ADDR = 0xFFFFFF00

  class AtfEntryCallType(enum.Enum):
    STD_SMC = 1
    FAST_SMC = 2
    CPU_ON = 3
    CPU_OFF = 4
    CPU_RESUME = 5
    CPU_SUSPEND = 6
    FIQ = 7
    SYSTEM_OFF = 8
    SYSTEM_RESET = 9

  class EntryCallType(enum.Enum):
    RESET = 1
    ABORT = 2
    SYSCALL = 3
    PABORT = 4
    DABORT = 5
    IRQ = 6
    FIQ = 7

  def __init__(self, trusted_firmware: tsmok.atf.atf.Atf,
               log_level=logging.ERROR):
    arm.ArmEmu.__init__(self, '[OPTEE]', log_level)

    self._atf = trusted_firmware
    self._drivers = dict()
    self.exception_handler[self.ExceptionType.SMC] = self._smc_handler
    self._atf_vector = dict()
    self._vector = dict()
    self._ret1 = 0
    self._ret2 = 0
    self._ret3 = 0

    self._memory_pool = None

    self._rpc_hanlers = dict()
    self._rpc_hanlers[optee_const.OpteeSmcReturn.RPC_ALLOC] = self._rpc_alloc
    self._rpc_hanlers[optee_const.OpteeSmcReturn.RPC_FREE] = self._rpc_free
    self._rpc_hanlers[optee_const.OpteeSmcReturn.RPC_CMD] = self._rpc_cmd

    self.shared_memory_setup()

    self.add_mem_write_handler(self._va_writer_HACK_TO_TEST,
                               0x00100000, 0x00100000 + 0x1000000 - 1)
    self.add_mem_unmapped_callback(self._exit_address_callback,
                                   self.EXIT_RETURN_ADDR,
                                   self.EXIT_RETURN_ADDR + 2)

  def _exit_address_callback(self, cls, access: int, addr: int, size: int):
    if addr == self.EXIT_RETURN_ADDR:
      regs = self.get_regs()
      self.exit(regs['R0'])
    return True

  def _va_writer_HACK_TO_TEST(self, emu, addr, size, value):
    if size == 1:
      self.mem_write(addr, struct.pack('<B', value))
    elif size == 2:
      self.mem_write(addr, struct.pack('<H', value))
    elif size == 4:
      self.mem_write(addr, struct.pack('<I', value))
    elif size == 8:
      self.mem_write(addr, struct.pack('<Q', value))

  def _smc_handler(self, regs) -> None:
    call = regs['R0']
    args = self._get_args(regs)
    self._log.debug('SMC call 0x%08x', call)

    if self._atf is None:
      self._log.error('ATF is not set')
      self.uc.emu_stop()

    try:
      ret = self._atf.smc_handler(self, atf_const.SmcCallFlag.SECURE, call,
                                  args)
      self.set_return_code(ret)
      return
    except error.Error as e:
      self._log.error(e.message)
      self.exit_with_exception(e)
    except Exception as e:  # pylint: disable=broad-except
      self._log.error('Exception was fired: %s', e)
      self._log.error(error.PrintException())
      self.exit_with_exception(e)

  def _get_args(self, regs: Dict[str, int]) -> List[int]:
    args = []
    args.append(regs['R1'])
    args.append(regs['R2'])
    args.append(regs['R3'])
    args.append(regs['R4'])
    args.append(regs['R5'])
    args.append(regs['R6'])
    args.append(regs['R7'])

    return args

  def _param_to_memory(self, param: optee_types.OpteeMsgParam):
    if isinstance(param, optee_types.OpteeMsgParamTempMem):
      if param.data:
        sz = max(len(param.data), param.size)
      else:
        sz = param.size
      region = self._memory_pool.allocate(sz)
      self._log.debug('Allocate region %d for param %s: %d addr 0x%08x, '
                      'size %d',
                      region.id, param.attr, region.addr, region.size)
      if param.data:
        self.mem_write(region.addr, param.data)
      param.shm_ref = region.id
      param.addr = region.addr
    if isinstance(param, optee_types.OpteeMsgParamRegMem):
      raise error.Error('optee_types.OpteeMsgParamRegMem is not '
                        'supported for now')
    return param

  def _param_from_memory(self, param: optee_types.OpteeMsgParam):
    if isinstance(param, optee_types.OpteeMsgParamTempMem):
      if param.addr and param.size:
        param.data = self.mem_read(param.addr, param.size)
    if isinstance(param, optee_types.OpteeMsgParamRegMem):
      raise error.Error('optee_types.OpteeMsgParamRegMem is not supported '
                        'for now')
    return param

  def _rpc_alloc(self):
    raise NotImplementedError('RPC ALLOC is not supported')

  def _rpc_free(self):
    raise NotImplementedError('RPC FREE is not supported')

  def _rpc_cmd(self):
    raise NotImplementedError('RPC CMD is not supported')

  def _rpc_process(self):
    while optee_const.OpteeSmcReturn.is_rpc(self._ret0):
      try:
        self._rpc_hanlers[self._ret0]()
      except KeyError:
        raise error.Error('Unsupported RPC request: 0x{self._ret0:08x}')

  def shared_memory_setup(self):
    if not self._atf:
      self._log.debug('No ATL shared memory configuration')
      return

    for mem in self._atf.mem_regions:
      self._log.info('Mapping %s region...', mem.name)
      self.map_memory(mem.start, mem.size, mem.perm)

  def exit(self, ret0: int, ret1: int = 0, ret2: int = 0,
           ret3: int = 0) -> None:
    arm.ArmEmu.exit(self, ret0)
    # aux return code values
    self._ret1 = ret1
    self._ret2 = ret2
    self._ret3 = ret3

  # External API
  # ===============================================================
  def driver_add(self, drv):
    if drv.name in self._drivers:
      raise error.Error(f'Device {drv.name} already present')
    self._drivers[drv.name] = drv

    drv.register(self)

  def set_atf_vector_table_addr(self, addr: int):
    self._log.info('Set Entry Vector table to 0x%08x', addr)
    # ATF Vector table format:
    #      name            | offset
    # -------------------------------
    #   std_smc_entry      |   0
    #   fast_smc_entry     |   4
    #   cpu_on_entry       |   8
    #   cpu_off_entry      |  12
    #   cpu_resume_entry   |  16
    #   cpu_suspend_entry  |  20
    #   fiq_entry          |  24
    #   system_off_entry   |  28
    #   system_reset_entry |  32
    # -------------------------------
    self._atf_vector[self.AtfEntryCallType.STD_SMC] = addr + 0
    self._atf_vector[self.AtfEntryCallType.FAST_SMC] = addr + 4
    self._atf_vector[self.AtfEntryCallType.CPU_ON] = addr + 8
    self._atf_vector[self.AtfEntryCallType.CPU_OFF] = addr + 12
    self._atf_vector[self.AtfEntryCallType.CPU_RESUME] = addr + 16
    self._atf_vector[self.AtfEntryCallType.CPU_SUSPEND] = addr + 20
    self._atf_vector[self.AtfEntryCallType.FIQ] = addr + 24
    self._atf_vector[self.AtfEntryCallType.SYSTEM_OFF] = addr + 28
    self._atf_vector[self.AtfEntryCallType.SYSTEM_RESET] = addr + 32

  def _set_vector_table_addr(self, addr: int):
    self._log.info('Set Entry Vector table to 0x%08x', addr)
    # Vector table format:
    #      name               | offset
    # -------------------------------
    #   reset                 |   0
    #   Undefined instruction |   4
    #   System call           |   8
    #   Prefetch abort        |  12
    #   Data abort            |  16
    #   reserved              |  20
    #   IRQ                   |  24
    #   FIQ                   |  28
    # -------------------------------
    self._vector[self.EntryCallType.RESET] = addr + 0
    self._vector[self.EntryCallType.ABORT] = addr + 4
    self._vector[self.EntryCallType.SYSCALL] = addr + 8
    self._vector[self.EntryCallType.PABORT] = addr + 12
    self._vector[self.EntryCallType.DABORT] = addr + 16
    self._vector[self.EntryCallType.IRQ] = addr + 24
    self._vector[self.EntryCallType.FIQ] = addr + 28

  def init(self):
    self.call(self.image.entry_point, 0, 0, 0, 0)

    # only interested in VBAR_EL1
    _, vbar, _, _ = self.get_vbar_regs()
    self._set_vector_table_addr(vbar)

    cfg = self.get_shm_config()
    self._memory_pool = region_allocator.RegionAllocator(cfg.addr, cfg.size)

  # ATF side calls
  def fast_smc(self, cmd: int, arg0: int, arg1: int, arg2: int,
               arg3: int = None, arg4: int = None, arg5: int = None,
               arg6: int = None):
    try:
      entry = self._atf_vector[self.AtfEntryCallType.FAST_SMC]
    except KeyError:
      raise error.Error('Optee is not initialized')

    if not entry:
      raise error.Error('Optee is not initialized')

    self.call(entry, cmd, arg0, arg1, arg2, arg3, arg4, arg5, arg6)
    return (self._ret0, self._ret1, self._ret2, self._ret3)

  def std_smc(self, cmd: int, arg0: int, arg1: int, arg2: int,
              arg3: int = None, arg4: int = None, arg5: int = None,
              arg6: int = None):
    try:
      entry = self._atf_vector[self.AtfEntryCallType.STD_SMC]
    except KeyError:
      raise error.Error('Optee is not initialized')

    if not entry:
      raise error.Error('Optee is not initialized')

    self.call(entry, cmd, arg0, arg1, arg2, arg3, arg4, arg5, arg6)
    return (self._ret0, self._ret1, self._ret2, self._ret3)

  def get_call_uid(self):
    ret = self.fast_smc(optee_const.OpteeMsgFunc.CALLS_UID, 0, 0, 0)
    return uuid.UUID(int=(ret[0] << 96) | (ret[1] << 64) | (ret[2] << 32) |
                     ret[3])

  def get_call_count(self):
    ret = self.fast_smc(optee_const.OpteeMsgFunc.CALLS_COUNT, 0, 0, 0)
    return ret[0]

  def get_call_revision(self):
    ret = self.fast_smc(optee_const.OpteeMsgFunc.CALLS_REVISION, 0, 0, 0)
    return ret[0], ret[1]

  def get_os_uid(self):
    ret = self.fast_smc(optee_const.OpteeMsgFunc.GET_OS_UUID, 0, 0, 0)
    return uuid.UUID(int=(ret[0] << 96) | (ret[1] << 64) | (ret[2] << 32) |
                     ret[3])

  def get_os_revision(self):
    ret = self.fast_smc(optee_const.OpteeMsgFunc.GET_OS_REVISION, 0, 0, 0)
    return ret[0], ret[1]

  def get_shm_config(self):
    ret = self.fast_smc(optee_const.OpteeMsgFunc.GET_SHM_CONFIG, 0, 0, 0)
    err = optee_const.OpteeSmcReturn(ret[0])

    if err != optee_const.OpteeSmcReturn.OK:
      raise error.Error(f'SMC GET_SHM_CONFIG command failed with {str(err)}')

    return SharedMemoryConfig(ret[1], ret[2], ret[3])

  def open_session(self, uid: uuid.UUID, login: optee_const.OpteeMsgLoginType,
                   params):
    arg = optee_types.OpteeMsgArg(optee_const.OpteeMsgCmd.OPEN_SESSION)

    uuid_param = optee_types.OpteeMsgParamValueInput()
    uuid_param.attr |= optee_const.OPTEE_MSG_ATTR_META
    uuid_param.a, uuid_param.b = struct.unpack('<2Q', uid.bytes)

    client = optee_types.OpteeMsgParamValueInput()
    client.attr |= optee_const.OPTEE_MSG_ATTR_META
    # client UUID is 0
    client.a = 0
    client.b = 0
    client.c = int(login)

    arg.params.append(uuid_param)
    arg.params.append(client)
    for param in params:
      arg.params.append(self._param_to_memory(param))

    reg = self._memory_pool.allocate(arg.size())
    self._log.debug('Allocate region %d for OpteeMsgArg: %d addr 0x%08x, '
                    'size %d',
                    reg.id, reg.addr, reg.size)
    self.mem_write(reg.addr, bytes(arg))
    arg.shm_ref = reg.id

    ret = self.std_smc(optee_const.OpteeMsgFunc.CALL_WITH_ARG,
                       (reg.addr >> 32) & 0xFFFFFFFF,
                       (reg.addr & 0xFFFFFFFF), 0)
    if optee_const.OpteeSmcReturn.is_rpc(ret[0]):
      self._rpc_process()

  def invoke_command(self):
    raise NotImplementedError('invoke_command is not implemented yet')

  def close_session(self):
    raise NotImplementedError('close_session is not implemented yet')

  def cancel(self):
    raise NotImplementedError('cancel is not implemented yet')

  def register_shared_memory(self):
    raise NotImplementedError('register_shared_memory is not implemented yet')

  def unregister_shared_memory(self):
    raise NotImplementedError('unregister_shared_memory is not implemented yet')

  # SYSCALLS

  def syscall(self, call, arg0, arg1, arg2, arg3, num_params=0,
              base_addr=0):
    try:
      entry = self._vector[self.EntryCallType.SYSCALL]
    except KeyError:
      raise error.Error('Optee is not initialized')

    if not entry:
      raise error.Error('Optee is not initialized')

    return self.call(entry, arg0, arg1, arg2, arg3, None, base_addr, num_params,
                     call)

  def _thread_init(self):
    self._log.debug('Init boot thread')
    self.set_return_address(self.EXIT_RETURN_ADDR)
    return self.call(self.image.thread_init, 0, 0, 0, 0)

  def _thread_deinit(self):
    self._log.debug('DeInit boot thread')
    return self.call(self.image.thread_clear, 0, 0, 0, 0)

  def log_syscall(self, data: bytes, size: int = None):
    sz = len(data)
    if size is not None:
      sz = size

    reg = self._memory_pool.allocate(sz)
    self.mem_write(reg.addr, data)

    self._thread_init()
    ret = self.syscall(optee_const.OpteeSysCalls.LOG, reg.addr, sz, None, None)
    self._memory_pool.free(reg.id)
    self._thread_deinit()
    return ret
