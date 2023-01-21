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

"""Module for OPTEE ARM emulator."""

import logging
from typing import List

import tsmok.atf.atf
import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.common.ffa as ffa
import tsmok.common.memory as memory
import tsmok.common.region_allocator as region_allocator
import tsmok.common.smc as smc
import tsmok.emu.arm64 as arm64
import tsmok.emu.emu as emu
import tsmok.trusty.ipc as trusty_ipc
import tsmok.trusty.smc as trusty_smc


class TrustyArm64Emu(arm64.Arm64Emu):
  """Implimentation of Trusty Emulator for ARM64 architecture."""

  MEMORY_ALIGNMENT = 8
  IPC_CHAN_SIZE = 1  # size in pages

  def __init__(self, trusted_firmware: tsmok.atf.atf_trusty.AtfTrusty,
               log_level=logging.ERROR):
    arm64.Arm64Emu.__init__(self, '[TRUSTY]', log_level)

    if not trusted_firmware:
      self.exit_with_exception(error.Error('ATF is not set'))

    self._atf = trusted_firmware
    self._drivers = dict()

    self.exception_handler[self.ExceptionType.SMC] = self._smc_handler
    self.exception_handler[self.ExceptionType.SWI] = self._swi_handler
    self.exception_handler[self.ExceptionType.PREFETCH_ABORT] = \
        self._prefetch_abort_handler
    self.exception_handler[self.ExceptionType.UDEF] = \
        self._udef_handler
    self._ret1 = 0
    self._ret2 = 0
    self._ret3 = 0

    self._shared_memory = None

    self._set_el_mode(arm64.PstateElMode.EL1 | arm64.PstateFieldMask.SP)
    self._enable_vfp()
    self._allow_access_to_stimer()
    self._set_aarch64_mode()

  def _smc_handler(self, regs) -> None:
    call = regs.reg0
    args = self._get_args(regs)
    self._log.debug('SMC call 0x%08x', call)

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
    new_el = self._get_excp_target_el_mode(emu.Emu.ExceptionType.UDEF)
    syndrome = self._get_exception_syndrom(new_el)
    regs = self.get_regs()
    self._log.debug('SVC exception: new EL %d, syndrome %s: syscall %d',
                    new_el, syndrome, regs.reg12)

    if (not syndrome or
        (syndrome != arm64.ExceptionSyndrome.AA64_SVC and
         syndrome != arm64.ExceptionSyndrome.AA32_SVC)):
      self.dump_regs()
      self.exit_with_exception(
          error.Error('SVC exception with unhandled syndrome'))
      return

    base = self._save_state_for_exception_call(new_el)
    addr = base + arm64.VectorTableOffset.SYNC
    self.set_current_address(addr)

  def _prefetch_abort_handler(self, regs) -> None:
    self.exit_with_exception(error.Error('Prefetch Abort'))
    self.dump_regs()

  def _udef_handler(self, regs) -> None:
    new_el = self._get_excp_target_el_mode(emu.Emu.ExceptionType.UDEF)
    syndrome = self._get_exception_syndrom(new_el)

    if (not syndrome or
        syndrome != arm64.ExceptionSyndrome.ADVSIMDFPACCESSTRAP):
      self.dump_regs()
      self.exit_with_exception(
          error.Error('UDEF exception with unhandled syndrome'))
      return

    base = self._save_state_for_exception_call(new_el)
    addr = base + arm64.VectorTableOffset.SYNC
    self.set_current_address(addr)

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

  def _ipc_check(self, opcode, cmd: trusty_ipc.IpcCmd) -> bool:
    if cmd.opcode != opcode or not cmd.response:
      return False

    if cmd.status:
      return False
    return True

  # External API
  # ===============================================================
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

  def shared_memory_add(self, addr, pages):
    self._log.info('Mapping SHERED_MEMORY region...')
    self.map_memory(addr, pages * const.PAGE_SIZE,
                    memory.MemAccessPermissions.RW)
    self._shared_memory_pool = region_allocator.RegionAllocator(
        addr, pages * const.PAGE_SIZE, self.MEMORY_ALIGNMENT)

  def init(self, memsize: int):
    self.call(self.image.entry_point, emu.RegContext(memsize, 0, 0, 0))
    if self._ret0 != trusty_smc.SmcError.NOP_DONE:
      raise error.Error(f'Init failed with error 0x{self._ret0:x}')
    self._ctx_init = self._cpu_get_context()

  def smc_call(self, cmd, client_id, arg0=0, arg1=0, arg2=0):
    """Call Trusty SMC call.

    Trusty support only cmd + 3 extra args.
    Args:
      cmd: SMC Call
      client_id: External client identifier
      arg0: 1st arg for SMC call
      arg1: 2nd arg for SMC call
      arg2: 3rd arg for SMC call

    Returns:
      Return code from SMC cal..
    """

    self._cpu_restore_context(self._ctx_init)
    pc = self.get_current_address()

    return self.call(pc, emu.RegContext(cmd, arg0, arg1, arg2, None, None,
                                        None, client_id))

  def syscall(self, *args):
    raise NotImplementedError()

  def smc_call_buf_id(self, cmd, cid, buf_id, size):
    return self.smc_call(cmd, cid, buf_id & 0xFFFFFFFF,
                         (buf_id >> 32) & 0xFFFFFFFF, size)

  def ipc_init(self, client_id, size) -> trusty_ipc.IpcHandler:
    if size & (const.PAGE_SIZE - 1):
      raise error.Error('IPC Init failed: size is not aligned to page size')

    # set API version
    ver = self.smc_call(trusty_smc.SmcCall.API_VERSION, client_id,
                        trusty_smc.TrustyApiVersion.MEM_OBJ)
    self._log.debug('Trusty API version to use: %d', ver)
    if ver != trusty_smc.TrustyApiVersion.MEM_OBJ:
      raise error.Error(f'Trusty version {ver} is not supported for now!')

    mem_region = self._shared_memory_pool.allocate(size)
    eid = self._atf.mem_share(ffa.FFA_NS_CALLER_ID, mem_region.addr,
                              int(mem_region.size / const.PAGE_SIZE),
                              ffa.FfaMemPerm.RW)

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.CREATE_QL_TIPC_DEV,
                               client_id, eid, size)

    self._log.debug('IPC Init: ret 0x%x', ret)
    if ret != trusty_smc.SmcError.SUCCESS:
      self._atf.mem_reclaim(eid)
      self._shared_memory_pool.free(mem_region.addr)
      raise error.Error(f'Failed to Init IPC. Error 0x{ret:x}')

    return trusty_ipc.IpcHandler(client_id, ver, mem_region, eid)

  def ipc_connect(self, ipc, port: str, cookie: int) -> int:
    if not ipc or not ipc.valid():
      raise error.Error('IPC is not initialized!')

    cmd = trusty_ipc.IpcCmd(trusty_ipc.IpcOpCode.CONNECT)
    payload = trusty_ipc.IpcPayloadConnectRequest(cookie, port)
    cmd.payload = payload

    self.mem_write(ipc.shm_mem.addr, bytes(cmd))

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.HANDLE_QL_TIPC_DEV_STD_CMD,
                               ipc.client_id, ipc.mem_obj_id, cmd.size())

    self._log.debug('IPC Create: ret 0x%x', ret)
    if ret != trusty_smc.SmcError.SUCCESS:
      raise error.Error(f'Failed to IPC Connect. Error 0x{ret:x}')

    data = self.mem_read(ipc.shm_mem.addr, trusty_ipc.IpcCmd.size_base())
    resp = trusty_ipc.IpcCmd()
    resp.load(data)

    if not self._ipc_check(trusty_ipc.IpcOpCode.CONNECT, resp):
      raise error.Error('IPC Connect failed!')

    return resp.handle

  def ipc_get_event(self, ipc, handle=None):
    cmd = trusty_ipc.IpcCmd(trusty_ipc.IpcOpCode.GET_EVENT)
    if not ipc or not ipc.valid():
      raise error.Error('IPC is not initialized!')

    if handle:
      cmd.handle = handle
    payload = trusty_ipc.IpcPayloadWaitRequest()
    cmd.payload = payload

    self.mem_write(ipc.shm_mem.addr, bytes(cmd))

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.HANDLE_QL_TIPC_DEV_STD_CMD,
                               ipc.client_id, ipc.mem_obj_id, cmd.size())

    self._log.debug('IPC GetEvent: ret 0x%x', ret)
    if ret != trusty_smc.SmcError.SUCCESS:
      raise error.Error(f'Failed to IPC GetEvent. Error 0x{ret:x}')

    data = self.mem_read(ipc.shm_mem.addr, trusty_ipc.IpcCmd.size_base() +
                         trusty_ipc.IpcPayloadEvent.size())
    resp = trusty_ipc.IpcCmd()
    resp.load(data)
    if not self._ipc_check(trusty_ipc.IpcOpCode.GET_EVENT, resp):
      raise error.Error('IPC GetEvent failed!')

    ev = trusty_ipc.IpcPayloadEvent()
    ev.load(resp.payload)

    return ev

  def ipc_has_event(self, ipc, handle):
    cmd = trusty_ipc.IpcCmd(trusty_ipc.IpcOpCode.HAS_EVENT)
    if not ipc or not ipc.valid():
      raise error.Error('IPC is not initialized!')

    if handle:
      cmd.handle = handle

    self.mem_write(ipc.shm_mem.addr, bytes(cmd))

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.HANDLE_QL_TIPC_DEV_FC_CMD,
                               ipc.client_id, ipc.mem_obj_id, cmd.size())

    self._log.debug('IPC HasEvent: ret 0x%x', ret)
    if ret != trusty_smc.SmcError.SUCCESS:
      raise error.Error(f'Failed to IPC HasEvent. Error 0x{ret:x}')

    data = self.mem_read(ipc.shm_mem.addr, trusty_ipc.IpcCmd.size_base() +
                         trusty_ipc.IpcPayloadHasEvent.size())
    resp = trusty_ipc.IpcCmd()
    resp.load(data)
    if not self._ipc_check(trusty_ipc.IpcOpCode.HAS_EVENT, resp):
      raise error.Error('IPC HasEvent failed!')

    ev = trusty_ipc.IpcPayloadHasEvent()
    ev.load(resp.payload)
    return ev.has_event

  def ipc_send(self, ipc, handle, data):
    if not ipc or not ipc.valid():
      raise error.Error('IPC is not initialized!')

    if not handle:
      raise error.Error('IPC is not connected yet.')

    if len(data) > (ipc.shm_mem.size - trusty_ipc.IpcCmd.size_base()):
      raise error.Error('Ipc Send: data size is too big')

    cmd = trusty_ipc.IpcCmd(trusty_ipc.IpcOpCode.SEND)
    cmd.handle = handle
    cmd.payload = data

    self.mem_write(ipc.shm_mem.addr, bytes(cmd))

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.HANDLE_QL_TIPC_DEV_STD_CMD,
                               ipc.client_id, ipc.mem_obj_id, cmd.size())

    self._log.debug('IPC Send: ret 0x%x', ret)
    if trusty_smc.smc_rc_is_error(ret):
      raise error.Error(f'IPC Send failed! Error: code 0x{ret:x}')

    data = self.mem_read(ipc.shm_mem.addr, trusty_ipc.IpcCmd.size_base())
    resp = trusty_ipc.IpcCmd()
    resp.load(data)
    if not self._ipc_check(trusty_ipc.IpcOpCode.SEND, resp):
      raise error.Error('IPC Send failed!')

  def ipc_recv(self, ipc, handle):
    if not ipc or not ipc.valid():
      raise error.Error('IPC is not initialized!')

    if not handle:
      raise error.Error('IPC is not connected yet.')

    cmd = trusty_ipc.IpcCmd(trusty_ipc.IpcOpCode.RECV)
    cmd.handle = handle

    self.mem_write(ipc.shm_mem.addr, bytes(cmd))

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.HANDLE_QL_TIPC_DEV_STD_CMD,
                               ipc.client_id, ipc.mem_obj_id, cmd.size())

    self._log.debug('IPC Recv: ret 0x%x', ret)
    if trusty_smc.smc_rc_is_error(ret):
      raise error.Error('IPC Recv failed!')

    data = self.mem_read(ipc.shm_mem.addr, trusty_ipc.IpcCmd.size_base())
    resp = trusty_ipc.IpcCmd()
    payload_len = resp.get_payload_size(data)
    data = self.mem_read(ipc.shm_mem.addr, trusty_ipc.IpcCmd.size_base() +
                         payload_len)
    resp.load(data)
    if not self._ipc_check(trusty_ipc.IpcOpCode.RECV, resp):
      raise error.Error('IPC Recv failed!')

    return resp.payload

  def ipc_disconnect(self, ipc, handle):
    if not ipc or not ipc.valid():
      raise error.Error('IPC is not initialized!')

    if not handle:
      raise error.Error('IPC is not connected yet.')

    cmd = trusty_ipc.IpcCmd(trusty_ipc.IpcOpCode.DISCONNECT)
    cmd.handle = handle

    self.mem_write(ipc.shm_mem.addr, bytes(cmd))

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.HANDLE_QL_TIPC_DEV_STD_CMD,
                               ipc.client_id, ipc.mem_obj_id, cmd.size())

    self._log.debug('IPC Disconnect: ret 0x%x', ret)
    if ret != trusty_smc.SmcError.SUCCESS:
      raise error.Error('IPC Disconnect failed!')

    data = self.mem_read(ipc.shm_mem.addr, trusty_ipc.IpcCmd.size_base())
    resp = trusty_ipc.IpcCmd()
    resp.load(data)
    if not self._ipc_check(trusty_ipc.IpcOpCode.DISCONNECT, resp):
      raise error.Error('IPC Disconnect failed!')

  def ipc_shutdown(self, ipc):
    if not ipc or not ipc.valid():
      raise error.Error('IPC is not initialized!')

    ret = self.smc_call_buf_id(trusty_smc.SmcCall.SHUTDOWN_QL_TIPC_DEV,
                               ipc.client_id, ipc.mem_obj_id, ipc.shm_mem.size)

    self._log.debug('IPC Shutdown: ret 0x%x', ret)
    if ret != trusty_smc.SmcError.SUCCESS:
      raise error.Error(f'Failed to shutdown IPC. Error 0x{ret:x}')

    self._atf.mem_reclaim(ipc.mem_obj_id)
    self._shared_memory_pool.free(ipc.shm_mem.addr)

    ipc = trusty_ipc.IpcHandler()
