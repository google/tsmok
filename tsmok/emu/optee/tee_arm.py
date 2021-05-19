"""Module for OPTEE ARM emulator."""

import collections
import enum
import logging
import struct
from typing import List
import uuid

import tsmok.atf.atf
import tsmok.common.error as error
import tsmok.common.memory as memory
import tsmok.common.region_allocator as region_allocator
import tsmok.common.smc as smc
import tsmok.emu.arm as arm
import tsmok.emu.emu as emu
import tsmok.optee.error as optee_error
import tsmok.optee.message as message
import tsmok.optee.rpmb as optee_rpmb
import tsmok.optee.smc as optee_smc
import tsmok.optee.syscalls as syscalls
import tsmok.optee.ta_param as ta_param


SharedMemoryConfig = collections.namedtuple('SharedMemoryConfig',
                                            ['addr', 'size', 'cached'])


class OpteeArmEmu(arm.ArmEmu):
  """Implimentation of OPTEE Emulator for ARM architecture."""

  MEMORY_ALIGNMENT = 32
  ENTRY_VECTOR_SIZE = 9

  EXIT_RETURN_ADDR = 0xFFFFFF00

  HYP_CNT_ID = 0

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
    self._loaded_ta = dict()

    self.exception_handler[self.ExceptionType.SMC] = self._smc_handler
    self.exception_handler[self.ExceptionType.SWI] = self._swi_handler
    self.exception_handler[self.ExceptionType.PREFETCH_ABORT] = \
        self._prefetch_abort_handler
    self._atf_vector = dict()
    self._vector = dict()
    self._ret1 = 0
    self._ret2 = 0
    self._ret3 = 0

    self._nsec_memory_pool = None

    self._rpc_handlers = dict()
    self._rpc_handlers[optee_smc.OpteeSmcReturn.RPC_ALLOC] = self._rpc_alloc
    self._rpc_handlers[optee_smc.OpteeSmcReturn.RPC_FREE] = self._rpc_free
    self._rpc_handlers[optee_smc.OpteeSmcReturn.RPC_CMD] = self._rpc_cmd

    self._rpc_cmd_handlers = dict()
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.LOAD_TA] = \
        self._rpc_cmd_load_ta
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.RPMB] = \
        self._rpc_cmd_rpmb
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.FS] = \
        self._rpc_cmd_fs
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.GET_TIME] = \
        self._rpc_cmd_get_time
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.WAIT_QUEUE] = \
        self._rpc_cmd_wait_queue
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.SUSPEND] = \
        self._rpc_cmd_suspend
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.SHM_ALLOC] = \
        self._rpc_cmd_shm_alloc
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.SHM_FREE] = \
        self._rpc_cmd_shm_free
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.SQL_FS_RESERVED] = \
        self._rpc_cmd_sql_fs_reserved
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.CMD_GPROF] = \
        self._rpc_cmd_gprof
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.SOCKET] = \
        self._rpc_cmd_socket
    self._rpc_cmd_handlers[message.OpteeMsgRpcCmdType.BENCH_REG] = \
        self._rpc_cmd_bench_reg

    self._memory_setup()

    # self.EXIT_RETURN_ADDR is catched in _prefetch_abort_handler handler
    self.load_to_mem('EXIT_RETURN_ADDR', self.EXIT_RETURN_ADDR,
                     b'\x00'*4, memory.MemAccessPermissions.RX)

  def _smc_handler(self, regs) -> None:
    call = regs.reg0
    args = self._get_args(regs)
    self._log.debug('SMC call 0x%08x', call)

    if self._atf is None:
      self._log.error('ATF is not set')
      self.uc.emu_stop()

    try:
      regs = self._atf.smc_handler(self, smc.SmcCallFlag.SECURE, call,
                                   args)
      self.set_regs(regs)
      return
    except error.Error as e:
      self._log.error(e.message)
      self.exit_with_exception(e)
    except Exception as e:  # pylint: disable=broad-except
      self._log.error('Exception was fired: %s', e)
      self._log.error(error.PrintException())
      self.exit_with_exception(e)

  def _swi_handler(self, regs) -> None:
    try:
      entry = self._vector[self.EntryCallType.SYSCALL]
    except KeyError:
      raise error.Error('Optee is not initialized')

    if not entry:
      raise error.Error('Optee is not initialized')

    self._svc_mode_setup()

    pc = self.get_current_address()
    self.set_current_address(entry)
    self.set_return_address(pc)

  def _prefetch_abort_handler(self, regs) -> None:
    if self.get_current_address() == self.EXIT_RETURN_ADDR:
      self.exit(regs.reg0)
    else:
      self.exit_with_exception(error.Error('Prefetch Abort'))
      self.dump_regs()

  def _get_args(self, regs) -> List[int]:
    args = []
    args.append(regs.reg1)
    args.append(regs.reg2)
    args.append(regs.reg3)
    args.append(regs.reg4)
    args.append(regs.reg5)
    args.append(regs.reg6)
    args.append(regs.reg7)

    return args

  def _param_to_memory(self, param: message.OpteeMsgParam):
    if isinstance(param, message.OpteeMsgParamTempMem):
      if param.data:
        sz = max(len(param.data), param.size)
      else:
        sz = param.size
      region = self._nsec_memory_pool.allocate(sz)
      self._log.debug('Allocate region %d for param %s: addr 0x%08x, '
                      'size %d', region.id, param.attr, region.addr,
                      region.size)
      if param.data:
        self.mem_write(region.addr, param.data)
      param.shm_ref = region.id
      param.addr = region.addr
      param.size = sz
    elif isinstance(param, message.OpteeMsgParamRegMem):
      raise error.Error('message.OpteeMsgParamRegMem is not '
                        'supported for now')
    return param

  def _param_from_memory(self, param: message.OpteeMsgParam):
    if isinstance(param, message.OpteeMsgParamTempMem):
      if param.addr and param.size:
        param.data = self.mem_read(param.addr, param.size)
    if isinstance(param, message.OpteeMsgParamRegMem):
      raise error.Error('message.OpteeMsgParamRegMem is not supported '
                        'for now')
    return param

  def _convert_from_ta_params(self, ta_params: List[ta_param.OpteeTaParam]
                             ) -> List[message.OpteeMsgParam]:
    params = []
    for param in ta_params:
      params.append(param.convert_to_msg_param())
    return params

  def _convert_to_ta_params(self, ta_params: List[ta_param.OpteeTaParam]
                           ) -> List[message.OpteeMsgParam]:
    params = []
    for param in ta_params:
      params.append(param.convert_to_ta_param())
    return params

  def _rpc_cmd_load_ta(self, msg_arg):
    if (len(msg_arg.params) != 2 or
        msg_arg.params[0].attr != message.OpteeMsgAttrType.VALUE_INPUT or
        msg_arg.params[1].attr != message.OpteeMsgAttrType.TMEM_OUTPUT):
      msg_arg.ret = optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
      return bytes(msg_arg)

    uid = uuid.UUID(bytes=struct.pack('<2Q', msg_arg.params[0].a,
                                      msg_arg.params[0].b))

    self._log.debug('Requested TA: %s', uid)
    try:
      data = self._loaded_ta[uid]
    except KeyError:
      self._log.error('RPC CMD load_ta %s: ITEM NOT FOUND', uid)
      msg_arg.ret = optee_error.OpteeErrorCode.ERROR_ITEM_NOT_FOUND
      return bytes(msg_arg)

    if not msg_arg.params[1].addr and not msg_arg.params[1].size:
      self._log.debug('Send Loaded TA size: %d', len(data))
      msg_arg.params[1].size = len(data)
      msg_arg.ret = optee_error.OpteeErrorCode.SUCCESS
      return bytes(msg_arg)

    if not msg_arg.params[1].addr or not msg_arg.params[1].size:
      self._log.debug('Load TA %s: one of the arg is zero: addr %d, size %d',
                      uid, msg_arg.params[1].addr, msg_arg.params[1].size)
      msg_arg.ret = optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
      return bytes(msg_arg)

    self._log.debug('Load TA %s to addr 0x%08x, size %d',
                    uid, msg_arg.params[1].addr, msg_arg.params[1].size)
    self.mem_write(msg_arg.params[1].addr, data)

    msg_arg.ret = optee_error.OpteeErrorCode.SUCCESS
    return bytes(msg_arg)

  def _rpc_cmd_rpmb(self, msg_arg):
    if (len(msg_arg.params) != 2 or
        msg_arg.params[0].attr != message.OpteeMsgAttrType.TMEM_INPUT or
        msg_arg.params[1].attr != message.OpteeMsgAttrType.TMEM_OUTPUT):
      msg_arg.ret = optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
      return bytes(msg_arg)

    try:
      rpmb = self._drivers['RPMB']
    except KeyError:
      msg_arg.ret = optee_error.OpteeErrorCode.ERROR_NOT_SUPPORTED
      return bytes(msg_arg)

    in_data = self.mem_read(msg_arg.params[0].addr, msg_arg.params[0].size)
    req = optee_rpmb.OpteeRpmbRequest(in_data)

    out_data = None
    if req.cmd == optee_rpmb.OpteeRpmbRequestCmd.DATA_REQUEST:
      # support only one request frame for now
      if len(req.frames) != 1:
        self._log.error('More than one request frame is not supported for now.')
        msg_arg.ret = optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
      else:
        frame = req.frames[0]
        out_data = rpmb.process_frame(frame, msg_arg.params[1].size)

    elif req.cmd == optee_rpmb.OpteeRpmbRequestCmd.GET_DEV_INFO:
      info = optee_rpmb.OpteeRpmbDeviceInfo()
      info.cid = rpmb.cid
      info.rpmb_size_multi = rpmb.size_multi
      info.rel_write_sector_count = rpmb.rel_write_sector_count
      info.ret_code = optee_rpmb.OpteeRpmbGetDevInfoReturn.OK
      out_data = bytes(info)
    else:
      raise error.Error(f'Unknown RPMB request cmd {req.cmd}')

    if msg_arg.params[1].size < len(out_data):
      raise error.Error('RPMB GetDevInfo: Not enough space in out buffer')

    if out_data:
      self.mem_write(msg_arg.params[1].addr, out_data)
    msg_arg.ret = optee_error.OpteeErrorCode.SUCCESS

    return bytes(msg_arg)

  def _rpc_cmd_fs(self, msg_arg):
    raise NotImplementedError('RPC CMD fs is not supported')

  def _rpc_cmd_get_time(self, msg_arg):
    raise NotImplementedError('RPC CMD get_time is not supported')

  def _rpc_cmd_wait_queue(self, msg_arg):
    raise NotImplementedError('RPC CMD wait_queue is not supported')

  def _rpc_cmd_suspend(self, msg_arg):
    raise NotImplementedError('RPC CMD suspend is not supported')

  def _rpc_cmd_shm_alloc(self, msg_arg):
    msg_arg.ret_origin = optee_error.OpteeOriginCode.COMMS

    if (len(msg_arg.params) != 1 or
        msg_arg.params[0].attr != message.OpteeMsgAttrType.VALUE_INPUT):
      msg_arg.ret = optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
      return bytes(msg_arg)

    sz = msg_arg.params[0].b

    reg = self._nsec_memory_pool.allocate(sz)
    prm = message.OpteeMsgParamTempMemOutput(reg.addr, sz, reg.id)
    msg_arg.params = []
    msg_arg.params.append(prm)

    msg_arg.ret = optee_error.OpteeErrorCode.SUCCESS
    return bytes(msg_arg)

  def _rpc_cmd_shm_free(self, msg_arg):
    msg_arg.ret_origin = optee_error.OpteeOriginCode.COMMS

    if (len(msg_arg.params) != 1 or
        msg_arg.params[0].attr != message.OpteeMsgAttrType.VALUE_INPUT):
      msg_arg.ret = optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
      return bytes(msg_arg)

    shm_id = msg_arg.params[0].b
    self._nsec_memory_pool.free(shm_id)
    msg_arg.params = []
    msg_arg.ret = optee_error.OpteeErrorCode.SUCCESS
    return bytes(msg_arg)

  def _rpc_cmd_sql_fs_reserved(self, msg_arg):
    raise NotImplementedError('RPC CMD sql_fs_reserved is not supported')

  def _rpc_cmd_gprof(self, msg_arg):
    raise NotImplementedError('RPC CMD cmd_gprof is not supported')

  def _rpc_cmd_socket(self, msg_arg):
    raise NotImplementedError('RPC CMD socket is not supported')

  def _rpc_cmd_bench_reg(self, msg_arg):
    raise NotImplementedError('RPC CMD bench_reg is not supported')

  def _rpc_alloc(self):
    if not self._ret1:
      return (0,)

    reg = self._nsec_memory_pool.allocate(self._ret1)

    return ((reg.addr >> 32) & 0xFFFFFFFF, reg.addr & 0xFFFFFFFF, 0,
            (reg.id >> 32) & 0xFFFFFFFF, reg.id & 0xFFFFFFFF)

  def _rpc_free(self):
    shm_id = self._ret1 << 32 | self._ret2
    self._log.info('RPC Free: shared ragion ID %d', shm_id)
    self._nsec_memory_pool.free(shm_id)
    return (0,)

  def _rpc_cmd(self):
    shm_id = self._ret1 << 32 | self._ret2
    self._log.info('RPC CMD: shared ragion ID %d', shm_id)
    reg = self._nsec_memory_pool.get(shm_id)
    self._log.debug('RPC CMD: SHM addr 0x%08x, size %d', reg.addr, reg.size)

    data = self.mem_read(reg.addr, reg.size)
    msg_arg = message.OpteeMsgArg(data)

    try:
      self._log.info('RPC CMD: %s',
                     message.OpteeMsgRpcCmdType(msg_arg.cmd))
      data = self._rpc_cmd_handlers[msg_arg.cmd](msg_arg)
      if reg.size < len(data):
        raise error.Error('Shared Memory size is too small')

      self.mem_write(reg.addr, data)
      return (0,)
    except KeyError:
      raise error.Error('Unsupported RPC CMD request: '
                        f'{str(message.OpteeMsgRpcCmdType(msg_arg.cmd))}')

  def _rpc_process(self):
    while optee_smc.OpteeSmcReturn.is_rpc(self._ret0):
      try:
        self._log.debug('RPC handler: ret values: '
                        '[ 0x%08x, 0x%08x, 0x%08x, 0x%08x ]',
                        self._ret0, self._ret1,
                        self._ret2, self._ret3)
        regs = self.get_regs()
        thid = regs.reg3
        args = self._rpc_handlers[self._ret0]()
        if len(args) < 7:
          args += (0,) * (6 - len(args))
          args += (self.HYP_CNT_ID,)

        args = list(args)
        args[3] = thid

        ret = self.std_smc(
            emu.RegContext(optee_smc.OpteeSmcMsgFunc.RETURN_FROM_RPC, *args))
      except KeyError:
        self.dump_regs()
        raise error.Error('Unsupported RPC request: 0x{self._ret0:08x}')

  def _memory_setup(self):
    if not self._atf:
      self._log.debug('No ATF shared memory configuration')
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
  @staticmethod
  def check_image_syscall_compliant(img):
    if all([img.thread_init, img.thread_clear, img.push_session,
            img.pop_session]):
      return True
    return False

  def driver_add(self, drv):
    if drv.name in self._drivers:
      raise error.Error(f'Device {drv.name} already present')
    self._drivers[drv.name] = drv

    drv.register(self)

  def driver_get(self, name):
    try:
      drv = self._drivers[name]
    except KeyError:
      raise error.Error(f'Unknown driver name: {name}')

    return drv

  def loaded_ta_add(self, uid: uuid.UUID, data: bytes):
    if uid in self._loaded_ta:
      raise error.Error(f'UUID {str(uid)} already present')
    self._loaded_ta[uid] = data

  def loaded_ta_del(self, uid: uuid.UUID):
    try:
      del self._loaded_ta[uid]
    except KeyError:
      raise error.Error(f'UUID {str(uid)} already present')

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
    self.call(self.image.entry_point, emu.RegContext(0, 0, 0, 0))

    # only interested in VBAR_EL1
    _, vbar, _, _ = self.get_vbar_regs()
    self._set_vector_table_addr(vbar)
    cfg = self.get_shm_config()
    self._nsec_memory_pool = region_allocator.RegionAllocator(
        cfg.addr, cfg.size, self.MEMORY_ALIGNMENT)

  # ATF side calls
  def fast_smc(self, args: emu.RegContext):
    try:
      entry = self._atf_vector[self.AtfEntryCallType.FAST_SMC]
    except KeyError:
      raise error.Error('Optee is not initialized')

    if not entry:
      raise error.Error('Optee is not initialized')

    self.call(entry, args)
    return (self._ret0, self._ret1, self._ret2, self._ret3)

  def std_smc(self, args: emu.RegContext):
    try:
      entry = self._atf_vector[self.AtfEntryCallType.STD_SMC]
    except KeyError:
      raise error.Error('Optee is not initialized')

    if not entry:
      raise error.Error('Optee is not initialized')

    self.call(entry, args)
    return (self._ret0, self._ret1, self._ret2, self._ret3)

  def get_call_uid(self):
    ret = self.fast_smc(emu.RegContext(optee_smc.OpteeSmcMsgFunc.CALLS_UID,
                                       0, 0, 0))
    return uuid.UUID(int=(ret[0] << 96) | (ret[1] << 64) | (ret[2] << 32) |
                     ret[3])

  def get_call_count(self):
    ret = self.fast_smc(emu.RegContext(optee_smc.OpteeSmcMsgFunc.CALLS_COUNT,
                                       0, 0, 0))
    return ret[0]

  def get_call_revision(self):
    ret = self.fast_smc(emu.RegContext(optee_smc.OpteeSmcMsgFunc.CALLS_REVISION,
                                       0, 0, 0))
    return ret[0], ret[1]

  def get_os_uid(self):
    ret = self.fast_smc(emu.RegContext(optee_smc.OpteeSmcMsgFunc.GET_OS_UUID,
                                       0, 0, 0))
    return uuid.UUID(int=(ret[0] << 96) | (ret[1] << 64) | (ret[2] << 32) |
                     ret[3])

  def get_os_revision(self):
    ret = self.fast_smc(
        emu.RegContext(optee_smc.OpteeSmcMsgFunc.GET_OS_REVISION, 0, 0, 0))
    return ret[0], ret[1]

  def get_shm_config(self):
    ret = self.fast_smc(emu.RegContext(optee_smc.OpteeSmcMsgFunc.GET_SHM_CONFIG,
                                       0, 0, 0))
    err = optee_smc.OpteeSmcReturn(ret[0])

    if err != optee_smc.OpteeSmcReturn.OK:
      raise error.Error(f'SMC GET_SHM_CONFIG command failed with {str(err)}')

    return SharedMemoryConfig(ret[1], ret[2], ret[3])

  def open_session(self, uid: uuid.UUID, login: message.OpteeMsgLoginType,
                   ta_params: List[ta_param.OpteeTaParam]):
    arg = message.OpteeMsgArg(message.OpteeMsgCmd.OPEN_SESSION)

    params = self._convert_from_ta_params(ta_params)

    uuid_param = message.OpteeMsgParamValueInput()
    uuid_param.attr |= message.OPTEE_MSG_ATTR_META
    uuid_param.a, uuid_param.b = struct.unpack('<2Q', uid.bytes)

    client = message.OpteeMsgParamValueInput()
    client.attr |= message.OPTEE_MSG_ATTR_META
    # client UUID is 0
    client.a = 0
    client.b = 0
    client.c = int(login)

    arg.params.append(uuid_param)
    arg.params.append(client)
    for param in params:
      arg.params.append(self._param_to_memory(param))

    reg = self._nsec_memory_pool.allocate(arg.size())
    self._log.debug('Allocate region %d for OpteeMsgArg: addr 0x%08x, '
                    'size %d', reg.id, reg.addr, reg.size)
    self.mem_write(reg.addr, bytes(arg))
    arg.shm_ref = reg.id

    regs = emu.RegContext(optee_smc.OpteeSmcMsgFunc.CALL_WITH_ARG,
                          (reg.addr >> 32) & 0xFFFFFFFF,
                          (reg.addr & 0xFFFFFFFF), 0, 0, 0, self.HYP_CNT_ID)

    ret = self.std_smc(regs)
    if optee_smc.OpteeSmcReturn.is_rpc(ret[0]):
      self._rpc_process()

    ret_data = self.mem_read(reg.addr, reg.size)
    arg = message.OpteeMsgArg(ret_data)

    self._nsec_memory_pool.free(reg.id)
    if arg.ret != optee_smc.OpteeSmcReturn.OK:
      self._log.error('OpenSession failed with error 0x%08x, origin 0x%08x',
                      arg.ret, arg.ret_origin)
    else:
      for param in arg.params:
        self._param_from_memory(param)

    return arg.ret, arg.session, self._convert_to_ta_params(arg.params)

  def invoke_command(self, session: int, cmd: int,
                     ta_params: List[ta_param.OpteeTaParam]):
    arg = message.OpteeMsgArg(message.OpteeMsgCmd.INVOKE_COMMAND)
    arg.session = session
    arg.func = cmd

    for param in self._convert_from_ta_params(ta_params):
      arg.params.append(self._param_to_memory(param))

    reg = self._nsec_memory_pool.allocate(arg.size())
    self._log.debug('Allocate region %d for OpteeMsgArg: addr 0x%08x, '
                    'size %d', reg.id, reg.addr, reg.size)
    self.mem_write(reg.addr, bytes(arg))
    arg.shm_ref = reg.id

    regs = emu.RegContext(optee_smc.OpteeSmcMsgFunc.CALL_WITH_ARG,
                          (reg.addr >> 32) & 0xFFFFFFFF,
                          (reg.addr & 0xFFFFFFFF), 0, 0, 0, self.HYP_CNT_ID)

    ret = self.std_smc(regs)
    if optee_smc.OpteeSmcReturn.is_rpc(ret[0]):
      self._rpc_process()

    ret_data = self.mem_read(reg.addr, reg.size)
    arg = message.OpteeMsgArg(ret_data)

    self._nsec_memory_pool.free(reg.id)
    if arg.ret != optee_smc.OpteeSmcReturn.OK:
      self._log.error('Invoke Command failed with error 0x%08x, origin 0x%08x',
                      arg.ret, arg.ret_origin)
    else:
      for param in arg.params:
        self._param_from_memory(param)

    return arg.ret, self._convert_to_ta_params(arg.params)

  def close_session(self, session: int):
    arg = message.OpteeMsgArg(message.OpteeMsgCmd.CLOSE_SESSION)
    arg.session = session

    reg = self._nsec_memory_pool.allocate(arg.size())
    self._log.debug('Allocate region %d for OpteeMsgArg: addr 0x%08x, '
                    'size %d', reg.id, reg.addr, reg.size)
    self.mem_write(reg.addr, bytes(arg))
    arg.shm_ref = reg.id

    regs = emu.RegContext(optee_smc.OpteeSmcMsgFunc.CALL_WITH_ARG,
                          (reg.addr >> 32) & 0xFFFFFFFF,
                          (reg.addr & 0xFFFFFFFF), 0, 0, 0, self.HYP_CNT_ID)

    ret = self.std_smc(regs)
    if optee_smc.OpteeSmcReturn.is_rpc(ret[0]):
      self._rpc_process()

    ret_data = self.mem_read(reg.addr, reg.size)
    arg = message.OpteeMsgArg(ret_data)

    self._nsec_memory_pool.free(reg.id)
    if arg.ret != optee_smc.OpteeSmcReturn.OK:
      self._log.error('Close Command failed with error 0x%08x, origin 0x%08x',
                      arg.ret, arg.ret_origin)
    return arg.ret

  def cancel(self):
    raise NotImplementedError('cancel is not implemented yet')

  def register_shared_memory(self):
    raise NotImplementedError('register_shared_memory is not implemented yet')

  def unregister_shared_memory(self):
    raise NotImplementedError('unregister_shared_memory is not implemented yet')

  # SYSCALLS
  def syscall(self, sid, call, arg0, arg1, arg2, arg3, num_params=0,
              base_addr=0):

    self._svc_mode_setup()
    self._thread_init()
    self._push_session(sid)

    try:
      entry = self._vector[self.EntryCallType.SYSCALL]
    except KeyError:
      raise error.Error('Optee is not initialized')

    if not entry:
      raise error.Error('Optee is not initialized')

    self.set_return_address(self.EXIT_RETURN_ADDR)
    ret = self.call(entry, emu.RegContext(arg0, arg1, arg2, arg3, None,
                                          base_addr, num_params, call))
    self._push_session(sid)
    self._thread_deinit()
    return ret

  def _thread_init(self):
    self._log.debug('Init boot thread')
    self.set_return_address(self.EXIT_RETURN_ADDR)
    return self.call(self.image.thread_init, emu.RegContext(0, 0, 0, 0))

  def _thread_deinit(self):
    self._log.debug('DeInit boot thread')
    self.set_return_address(self.EXIT_RETURN_ADDR)
    return self.call(self.image.thread_clear, emu.RegContext(0, 0, 0, 0))

  def _push_session(self, sid: int):
    self._log.debug('Push session 0x%x', sid)
    self.set_return_address(self.EXIT_RETURN_ADDR)
    return self.call(self.image.push_session, emu.RegContext(sid, 0, 0, 0))

  def _pop_session(self, sid: int):
    self._log.debug('Pop session 0x%x', sid)
    self.set_return_address(self.EXIT_RETURN_ADDR)
    return self.call(self.image.pop_session, emu.RegContext(sid, 0, 0, 0))

  def _get_mem_for_args_from_session_id(self, sid, size):
    mem_info = self.image.get_mem_info_from_session_id(self, sid)
    for m in mem_info:
      if (m.perm & memory.MemAccessPermissions.RW ==
          memory.MemAccessPermissions.RW and m.size >= size):
        return m
    raise error.Error('Failed to get RW mem region from session id')

  def log_syscall(self, sid: int, data: bytes, size: int = None):
    sz = len(data)
    if size:
      sz = size

    if not self.check_image_syscall_compliant(self.image):
      raise NotImplementedError('Provided image is not direct call '
                                'syscalls compliant')

    mem = self._get_mem_for_args_from_session_id(sid, sz)
    self.mem_write(mem.start, data[:sz])
    ret = self.syscall(sid, syscalls.OpteeSysCall.LOG, mem.vaddr, sz,
                       None, None)
    return ret
