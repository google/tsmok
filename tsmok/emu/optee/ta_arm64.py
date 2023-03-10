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

"""Module for OPTEE TA ARM64 emulator."""

import logging
import struct
from typing import List, Tuple

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
import tsmok.optee.utee_args as utee_args


class TaArm64Emu(arm64.Arm64Emu, ta_base.Ta):
  """Implimentation of OPTEE TA Emulator for ARM64 architecture."""

  # TODO(dmitryya) figure out more actual values
  BUFFER_PTR = 0xffffffffff000000
  BUFFER_SIZE = 4* 1024 * 1024
  STACK_PTR = 0xffffffffff000000
  MAX_ARGS = 3

  def __init__(self, tee_os, log_level=logging.ERROR):
    arm64.Arm64Emu.__init__(self, '[TA]', log_level)
    ta_base.Ta.__init__(self, 'ta_base.TaEMU', None)

    self._enable_vfp()
    self.tee = tee_os
    self.exception_handler[self.ExceptionType.SWI] = self.syscall_handler
    self._buffer_pool = region_allocator.RegionAllocator(
        self.BUFFER_PTR, self.BUFFER_SIZE)
    self.map_memory(self.BUFFER_PTR, self.BUFFER_SIZE,
                    memory.MemAccessPermissions.N)
    self.guarded_allocator_init(self._buffer_pool)

  # Internal API
  # ==============================================
  def syscall_handler(self, regs) -> None:
    try:
      if self.is_pstate_a64_mode():
        syscall = syscalls.OpteeSysCall(regs.reg8)
        args = self._get_args_x64(regs)
      else:
        syscall = syscalls.OpteeSysCall(regs.reg7)
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

  def _load_args_to_mem(self, regs, addr, data):
    to_addr = addr
    if not to_addr:
      to_addr = self.allocate_shm_region(len(data))
      if regs is not None:
        regs.append(to_addr)
    self.mem_write(to_addr, data)
    return to_addr

  # External API
  # ===============================================================
  def syscall(self, num, *args):
    if len(args) > self.MAX_ARGS:
      raise ValueError('Wrong number of arguments')
    ret = self.call(self.image.entry_point, emu.RegContext(num, *args))
    sp = self.get_stack_address()
    # __ta_entry alloc 0x10 bytes at the beginning of the func to local
    # parameters but did not released them before _utee_return.
    # release manually.
    self.set_stack_address(sp + 0x10)
    return ret

  def allocate_shm_region(self, size):
    addr, _ = self.guarded_allocator_allocate(self._buffer_pool, size)
    return addr

  def free_shm_region(self, addr):
    self.guarded_allocator_free(self._buffer_pool, addr)

  def reset(self):
    self.stack_reset()
    self.mem_clean(self.BUFFER_PTR, self.BUFFER_SIZE)

  def load(self, image) -> None:
    if not isinstance(image, image_ta.TaImage):
      raise error.Error(f'Unsupported type of the image: {type(image)}')
    arm64.Arm64Emu.load(self, image)

    self.uuid = image.uuid
    self.set_stack(self.STACK_PTR, image.stack_size)

  def loader_from_mem(self, addr, size):
    return self.mem_read(addr, size)

  def open_session(
      self, sid: int,
      params: List[utee_args.OpteeUteeParam]
      ) -> Tuple[optee_error.OpteeErrorCode, List[utee_args.OpteeUteeParam]]:
    self._log.info('Open Session: id %d', sid)

    regs = []
    param_arg = utee_args.OpteeUteeParamArgs(params)
    addr = param_arg.load_to_mem(
        lambda a, d: self._load_args_to_mem(regs, a, d), None)
    ret = self.syscall(syscalls.OpteeTaCall.OPEN_SESSION, sid, addr, 0)

    if ret == optee_error.OpteeErrorCode.SUCCESS:
      param_arg.load_from_mem(self.mem_read, addr)
      params = param_arg.params

    for addr in regs:
      self.free_shm_region(addr)

    return ret, params

  def invoke_command(
      self, sid: int, cmd: int,
      params: List[utee_args.OpteeUteeParam]
      ) -> Tuple[optee_error.OpteeErrorCode, List[utee_args.OpteeUteeParam]]:
    self._log.info('Invoke Command: id %d', sid)

    regs = []
    param_arg = utee_args.OpteeUteeParamArgs(params)
    addr = param_arg.load_to_mem(
        lambda a, d: self._load_args_to_mem(regs, a, d), None)
    self._log.info('Invoke command %s', cmd)
    ret = self.syscall(syscalls.OpteeTaCall.INVOKE_COMMAND, sid, addr, cmd)
    if ret == optee_error.OpteeErrorCode.SUCCESS:
      param_arg.load_from_mem(self.mem_read, addr)
      params = param_arg.params

    for addr in regs:
      self.free_shm_region(addr)

    return ret, params

  def close_session(self, sid: int):
    self._log.info('Close Session: sid %d', sid)
    return self.syscall(syscalls.OpteeTaCall.CLOSE_SESSION, sid, 0, 0)
