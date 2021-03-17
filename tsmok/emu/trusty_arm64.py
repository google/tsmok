"""Module for OPTEE ARM emulator."""

import logging
from typing import List

import tsmok.atf.atf
import tsmok.common.error as error
import tsmok.common.region_allocator as region_allocator
import tsmok.common.smc as smc
import tsmok.emu.arm64 as arm64
import tsmok.emu.emu as emu
import tsmok.trusty.smc as trusty_smc


class TrustyArm64Emu(arm64.Arm64Emu):
  """Implimentation of Trusty Emulator for ARM64 architecture."""

  MEMORY_ALIGNMENT = 8

  def __init__(self, trusted_firmware: tsmok.atf.atf.Atf,
               log_level=logging.ERROR):
    arm64.Arm64Emu.__init__(self, '[TRUSTY]', log_level)

    self._atf = trusted_firmware
    self._drivers = dict()

    self._tx_shm_pool = None
    self._rx_shm_pool = None

    self.exception_handler[self.ExceptionType.SMC] = self._smc_handler
    self.exception_handler[self.ExceptionType.SWI] = self._swi_handler
    self.exception_handler[self.ExceptionType.PREFETCH_ABORT] = \
        self._prefetch_abort_handler
    self.exception_handler[self.ExceptionType.UDEF] = \
        self._udef_handler
    self._ret1 = 0
    self._ret2 = 0
    self._ret3 = 0

    self._set_el_mode(arm64.PstateElMode.EL1 | arm64.PstateFieldMask.SP)
    self._enable_vfp()
    self._allow_access_to_stimer()
    self._set_aarch64_mode()

  def _smc_handler(self, regs) -> None:
    call = regs.reg0
    args = self._get_args(regs)
    self._log.debug('SMC call 0x%08x', call)

    if self._atf is None:
      self.exit_with_exception(error.Error('ATF is not set'))

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

  def tx_shm_set(self, addr: int, size: int):
    if size:
      self._tx_shm_pool = region_allocator.RegionAllocator(
          addr, size, self.MEMORY_ALIGNMENT)
    else:
      self._tx_shm_pool = None

  def rx_shm_set(self, addr: int, size: int):
    if size:
      self._rx_shm_pool = region_allocator.RegionAllocator(
          addr, size, self.MEMORY_ALIGNMENT)
    else:
      self._rx_shm_pool = None

  def init(self, memsize: int):
    self.call(self.image.entry_point, memsize, 0, 0, 0)
    if self._ret0 != trusty_smc.SmcError.NOP_DONE:
      raise error.Error(f'Init failed with error 0x{self._ret0:x}')
