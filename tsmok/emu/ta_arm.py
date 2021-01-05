"""Module for OPTEE TA ARM emulator."""

import logging
import struct
from typing import List

import tsmok.common.error as error
import tsmok.common.memory as memory
import tsmok.common.ta_error as ta_error
import tsmok.emu.arm as arm
import tsmok.optee.const as optee_const
import tsmok.optee.ta.base as ta_base
import tsmok.optee.types as optee_types


class TaArmEmu(arm.ArmEmu, ta_base.Ta):
  """Implimentation of OPTEE TA Emulator for ARM architecture."""

  # TODO(dmitryya) figure out more actual values
  BUFFER_PTR = 0xFF000000
  BUFFER_SIZE = 4* 1024 * 1024
  STACK_PTR = 0xff000000

  def __init__(self, tee_os, log_level=logging.ERROR):
    arm.ArmEmu.__init__(self, '[TA]', log_level)
    ta_base.Ta.__init__(self, 'ta_base.TaEMU', None)

    self.tee = tee_os
    self.exception_handler[self.ExceptionType.SWI] = self.syscall_handler

  # Internal API
  # ==============================================
  def syscall_handler(self, regs) -> None:
    syscall = regs.r7
    args = self._get_args(regs)
    self._log.debug('[SWI] %d', syscall)

    if self.tee is None:
      self._log.error('TEE is not set')
      self.uc.emu_stop()

    try:
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

  def _get_args(self, regs) -> List[int]:
    args = []
    args.append(regs.r0)
    args.append(regs.r1)
    args.append(regs.r2)
    args.append(regs.r3)
    args_num = regs.r6
    base_ptr = regs.r5

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
    arm.ArmEmu.load(self, image)

    self.set_stack(self.STACK_PTR, image.stack_size)
    self.map_memory(self.BUFFER_PTR, self.BUFFER_SIZE,
                    memory.MemAccessPermissions.RW)

  def open_session(
      self, sid: int,
      params: List[optee_types.OpteeParam]
      ) -> (optee_const.OpteeErrorCode, List[optee_types.OpteeParam]):
    self._log.info('Open Session: id %d', sid)
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

    params_ptr = self.BUFFER_PTR
    self.tee.optee_params_load_to_memory(self, params_ptr, params)
    ret = self.call(self.image.entry_point,
                    optee_const.OpteeEntryFunc.OPEN_SESSION,
                    sid, params_ptr, 0)

    return ret, params

  def invoke_command(
      self, sid: int, cmd: int,
      params: List[optee_types.OpteeParam]
      ) -> (optee_const.OpteeErrorCode, List[optee_types.OpteeParam]):
    self._log.info('Invoke Command: id %d', sid)
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

    params_ptr = self.BUFFER_PTR
    if params:
      next_ptr = params_ptr + optee_const.OPTEE_PARAMS_DATA_SIZE
      # TODO(dmitryy) make this more readable
      for p in params:
        if isinstance(p, optee_types.OpteeParamMemref):
          if p.data or p.size:
            p.ptr = next_ptr
            if p.data:
              left_ram = self.BUFFER_SIZE - (p.ptr - self.BUFFER_PTR)
              if len(p.data) > left_ram:
                self._log.error('Not enough memory to place parameters!')
                return optee_const.OpteeErrorCode.ERROR_OUT_OF_MEMORY, params
              if not p.size:
                p.size = len(p.data)
              next_ptr += len(p.data)
            else:
              next_ptr += p.size

    self.tee.optee_params_load_to_memory(self, params_ptr, params)

    self._log.info('Invoke command %s', cmd)
    ret = self.call(self.image.entry_point,
                    optee_const.OpteeEntryFunc.INVOKE_COMMAND,
                    sid, params_ptr, cmd)
    if ret == optee_const.OpteeErrorCode.SUCCESS:
      params = self.tee.optee_params_load_from_memory(self, params_ptr)

    return ret, params

  def close_session(self, sid: int):
    self._log.info('Close Session: sid %d', sid)
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

    return self.call(self.image.entry_point,
                     optee_const.OpteeEntryFunc.CLOSE_SESSION, sid,
                     0, 0)
