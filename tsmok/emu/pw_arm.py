"""Module for PIGWEED ARM emulator."""

import logging

import tsmok.common.error as error
import tsmok.common.memory as memory
import tsmok.emu.arm as arm
import tsmok.pigweed.image_elf_pw as image_elf_pw


class PwArmEmu(arm.ArmEmu):
  """Implimentation of PIGWEED Binary Emulator for ARM architecture."""

  def __init__(self, log_level=logging.ERROR):
    arm.ArmEmu.__init__(self, '[PW]', log_level)
    self._drivers = dict()

  def _exit_call(self, emu, addr: int, size: int):
    self._log.info('Execution reaches end of firmware execution flow. '
                   'Exit emulation.')
    self.exit(0)

  # External API
  # ===============================================================
  def reset(self):
    self.stack_reset()

  def driver_add(self, drv):
    if drv.name in self._drivers:
      raise error.Error(f'Device {drv.name} already present')
    self._drivers[drv.name] = drv
    drv.register(self)

  def load(self, img) -> None:
    if not isinstance(img, image_elf_pw.PwElfImage):
      raise error.AbortError(f'Unsupported image type: {type(img)}')
    arm.ArmEmu.load(self, img)

    self.set_stack(img.stack_addr, img.stack_size)
    self.add_code_block_handler(self._exit_call, img.exit_func,
                                img.exit_func + 3)

  def run(self):
    self.map_memory(0xE000ED00, 0x90, memory.MemAccessPermissions.RW)
    self.call(self.image.entry_point, 0, 0, 0, 0)
