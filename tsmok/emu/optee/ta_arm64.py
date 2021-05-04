"""Module for OPTEE TA ARM64 emulator."""

import logging
import struct
from typing import List

import tsmok.common.error as error
import tsmok.common.memory as memory
import tsmok.common.region_allocator as region_allocator
import tsmok.common.ta_error as ta_error
import tsmok.emu.arm64 as arm64
import tsmok.emu.emu as emu
import tsmok.optee.error as optee_error
import tsmok.optee.image_ta as image_ta
import tsmok.optee.syscalls as syscalls
import tsmok.optee.ta.base as ta_base
import tsmok.optee.ta_param as ta_param


class TaArm64Emu(arm64.Arm64Emu, ta_base.Ta):
  """Implimentation of OPTEE TA Emulator for ARM64 architecture."""

  # TODO(dmitryya) figure out more actual values
  BUFFER_PTR = 0xffffffffff000000
  BUFFER_SIZE = 4* 1024 * 1024
  STACK_PTR = 0xffffffffff000000

  def __init__(self, tee_os, log_level=logging.ERROR):
    arm64.Arm64Emu.__init__(self, '[TA]', log_level)
    ta_base.Ta.__init__(self, 'ta_base.TaEMU', None)

    self._enable_vfp()
    self.tee = tee_os
    self.exception_handler[self.ExceptionType.SWI] = self.syscall_handler
    self._buffer_pool = region_allocator.RegionAllocator(
        self.BUFFER_PTR, self.BUFFER_SIZE)

  # Internal API
  # ==============================================
  def syscall_handler(self, regs) -> None:
    try:
      if self.is_pstate_a64_mode():
        syscall = syscalls.OpteeSysCalls(regs.reg8)
        args = self._get_args_x64(regs)
      else:
        syscall = syscalls.OpteeSysCalls(regs.reg7)
        args = self._get_args_x32(regs)

      self._log.debug('[SWI] %s', syscall)

      if self.tee is None:
        self._log.error('TEE is not set')
        self.uc.emu_stop()

      ret = self.tee.syscall_handler(self, syscall, args)
      self.set_return_code(ret)
      return
    except ta_error.TaPanicError as e:
      self._log.error(e.message)
      self.exit_with_exception(e)
    except ta_error.TaExit as e:
      self._log.info(e.message)
      self.exit(e.ret)
    except Exception as e:  # pylint: disable=broad-except
      self._log.error('Exception was fired: %s', e)
      self._log.error(error.PrintException())
      self.exit_with_exception(e)

  def _get_args_x64(self, regs) -> List[int]:
    args = []
    args.append(regs.reg0)
    args.append(regs.reg1)
    args.append(regs.reg2)
    args.append(regs.reg3)
    args.append(regs.reg4)
    args.append(regs.reg5)
    args.append(regs.reg6)
    args.append(regs.reg7)

    return args

  def _get_args_x32(self, regs) -> List[int]:
    args = []
    args.append(regs.reg0)
    args.append(regs.reg1)
    args.append(regs.reg2)
    args.append(regs.reg3)
    args_num = regs.reg6
    base_ptr = regs.reg5

    for i in range(args_num):
      arg = struct.unpack('I', self.mem_read(base_ptr + i * 4, 4))
      args.append(arg[0])

    return args

  # External API
  # ===============================================================
  def reset(self):
    self.stack_reset()
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

  def load(self, image) -> None:
    if not isinstance(image, image_ta.TaImage):
      raise error.Error(f'Unsupported type of the image: {type(image)}')
    arm64.Arm64Emu.load(self, image)

    self.uuid = image.uuid
    self.set_stack(self.STACK_PTR, image.stack_size)
    self.map_memory(self.BUFFER_PTR, self.BUFFER_SIZE,
                    memory.MemAccessPermissions.RW)

  def loader_to_mem(self, regs, addr, data):
    to_addr = addr
    if not to_addr:
      reg = self._buffer_pool.allocate(len(data))
      to_addr = reg.addr
      if regs:
        regs.append(reg)
    self.mem_write(to_addr, data)
    return to_addr

  def loader_from_mem(self, addr, size):
    return self.mem_read(addr, size)

  def open_session(
      self, sid: int,
      params: List[ta_param.OpteeTaParam]
      ) -> (optee_error.OpteeErrorCode, List[ta_param.OpteeTaParam]):
    self._log.info('Open Session: id %d', sid)
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

    regs = []
    param_arg = ta_param.OpteeTaParamArgs(params)
    addr = param_arg.load_to_mem(lambda a, d: self.loader_to_mem(regs, a, d),
                                 None)
    ret = self.call(self.image.entry_point,
                    emu.RegContext(syscalls.OpteeEntryFunc.OPEN_SESSION,
                                   sid, addr, 0))

    if ret == optee_error.OpteeErrorCode.SUCCESS:
      param_arg.load_from_mem(self.loader_from_mem, addr)
      params = param_arg.params

    for reg in regs:
      self._buffer_pool.free(reg.id)

    return ret, params

  def invoke_command(
      self, sid: int, cmd: int,
      params: List[ta_param.OpteeTaParam]
      ) -> (optee_error.OpteeErrorCode, List[ta_param.OpteeTaParam]):
    self._log.info('Invoke Command: id %d', sid)
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

    regs = []
    param_arg = ta_param.OpteeTaParamArgs(params)
    addr = param_arg.load_to_mem(lambda a, d: self.loader_to_mem(regs, a, d),
                                 None)
    self._log.info('Invoke command %s', cmd)
    ret = self.call(self.image.entry_point,
                    emu.RegContext(syscalls.OpteeEntryFunc.INVOKE_COMMAND,
                                   sid, addr, cmd))
    if ret == optee_error.OpteeErrorCode.SUCCESS:
      param_arg.load_from_mem(self.loader_from_mem, addr)
      params = param_arg.params

    for reg in regs:
      self._buffer_pool.free(reg.id)

    return ret, params

  def close_session(self, sid: int):
    self._log.info('Close Session: sid %d', sid)
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

    return self.call(self.image.entry_point,
                     emu.RegContext(syscalls.OpteeEntryFunc.CLOSE_SESSION,
                                    sid, 0, 0))
