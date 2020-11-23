"""Interface for device class."""

import abc
import logging
import tsmok.emu.arm as arm


class DeviceBase(abc.ABC):
  """Basic class for a specific device HW implementation."""

  def __init__(self, name, log_level=logging.ERROR):
    self.name = name
    self.log = logging.getLogger(f'[DEVICE][{name}]')
    self.log.setLevel(log_level)

  @abc.abstractmethod
  def register(self, emu: arm.ArmEmu):
    raise NotImplementedError()

  def write_trace(self, emu, addr, size, value):
    del emu  # unused in this call
    self.log.debug('Write 0x%08x-0x%08x: 0x%08x',
                   addr, addr + size - 1, value)

  def read_trace(self, emu, addr, size, value):
    del emu  # unused in this call
    self.log.debug('Read 0x%08x-0x%08x: 0x%08x',
                   addr, addr + size - 1, value)

