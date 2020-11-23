"""stm32f429 devices."""

import logging
import struct

import tsmok.common.error as error
import tsmok.common.hw as hw_base
import tsmok.hw.stm32f429.regs as regs


class Ahb1(hw_base.DeviceBase):
  """STM AHB1 implementation."""

  def __init__(self, log_level=logging.ERROR):
    hw_base.DeviceBase.__init__(self, 'SMT-AHB1', log_level)
    self._regs = dict()

  # TODO(dmitryya): add more smart logic around peripheral clock enabling
  def read_enable_reg(self, emu, addr, size, value):
    r = regs.RccReg(addr)
    try:
      val = self._regs[r]
    except KeyError:
      self._regs[r] = 0
      val = 0
    emu.u32_write(addr, val)

  def write_enable_reg(self, emu, addr, size, value):
    r = regs.RccReg(addr)
    self.log.info('Set %s to 0x%08x', r, value)
    self._regs[r] = value

  def register(self, emu):
    self.log.debug('Device %s registring...', self.name)

    emu.add_mem_read_handler(self.read_enable_reg,
                             regs.RccReg.AHB1ENR,
                             regs.RccReg.AHB1ENR + 3)
    emu.add_mem_write_handler(self.write_enable_reg,
                              regs.RccReg.AHB1ENR,
                              regs.RccReg.AHB1ENR + 3)
    emu.add_mem_read_handler(self.read_enable_reg,
                             regs.RccReg.APB2ENR,
                             regs.RccReg.APB2ENR + 3)
    emu.add_mem_write_handler(self.write_enable_reg,
                              regs.RccReg.APB2ENR,
                              regs.RccReg.APB2ENR + 3)


class Gpio(hw_base.DeviceBase):
  """STM GPIO implementation."""

  def __init__(self, base: int, log_level=logging.ERROR):
    try:
      self.base = regs.GpioBaseReg(base)
    except ValueError:
      raise error.Error(f'address 0x{base:08x} is not GPIO base')
    hw_base.DeviceBase.__init__(self, f'SMT-{self.base.name}', log_level)
    self._regs = dict()

  # TODO(dmitryya): add more smart logic handling GPIO regs
  def read_reg(self, emu, addr, size, value):
    off = regs.GpioOffReg(addr - self.base)
    try:
      val = self._regs[off]
    except KeyError:
      self._regs[off] = 0
      val = 0
    emu.u32_write(addr, val)

  def write_reg(self, emu, addr, size, value):
    off = regs.GpioOffReg(addr - self.base)
    self.log.debug('Write 0x%08x to reg %s', value, off)
    self._regs[off] = value

  def register(self, emu):
    self.log.debug('Device %s registring...', self.name)

    emu.add_mem_read_handler(self.read_reg,
                             self.base + regs.GpioOffReg.MODE,
                             self.base + regs.GpioOffReg.PULL_UP_DOWN + 3)
    emu.add_mem_read_handler(self.read_reg,
                             self.base + regs.GpioOffReg.ALT_FUNC_HIGH,
                             self.base + regs.GpioOffReg.ALT_FUNC_HIGH + 3)
    emu.add_mem_write_handler(self.write_reg,
                              self.base + regs.GpioOffReg.MODE,
                              self.base + regs.GpioOffReg.PULL_UP_DOWN + 3)
    emu.add_mem_write_handler(self.write_reg,
                              self.base + regs.GpioOffReg.ALT_FUNC_HIGH,
                              self.base + regs.GpioOffReg.ALT_FUNC_HIGH + 3)


class Uart(hw_base.DeviceBase):
  """STM Uart implementation."""

  def __init__(self, base: int, log_level=logging.ERROR):
    try:
      self.base = regs.UartBaseReg(base)
    except ValueError:
      raise error.Error(f'address 0x{base:08x} is not Uart base')
    hw_base.DeviceBase.__init__(self, f'SMT-{self.base.name}', log_level)
    self._regs = dict()
    self.buf = b''

  def read_status(self, emu, addr, size, value):
    # set TXE bit: always available to transfer data
    emu.u32_write(addr, 1<<7)

  def write_data(self, emu, addr, size, value):
    symb = struct.pack('B', value)
    self.buf += symb
    if symb == b'\n':
      self.log.info('UART>> %s', self.buf.decode())
      self.buf = b''

  # TODO(dmitryya): add more smart logic handling UART regs
  def read_reg(self, emu, addr, size, value):
    off = regs.UartOffReg(addr - self.base)
    try:
      val = self._regs[off]
    except KeyError:
      self._regs[off] = 0
      val = 0
    emu.u32_write(addr, val)

  def write_reg(self, emu, addr, size, value):
    off = regs.UartOffReg(addr - self.base)
    self.log.debug('Write 0x%08x to reg %s', value, off)
    self._regs[off] = value

  def register(self, emu):
    self.log.debug('Device %s registring...', self.name)

    emu.add_mem_read_handler(self.read_reg,
                             self.base + regs.UartOffReg.BAUD_RATE,
                             self.base +
                             regs.UartOffReg.GUARD_TIME_AND_PRESCALE + 3)
    emu.add_mem_write_handler(self.write_reg,
                              self.base + regs.UartOffReg.BAUD_RATE,
                              self.base +
                              regs.UartOffReg.GUARD_TIME_AND_PRESCALE + 3)

    emu.add_mem_read_handler(self.read_status,
                             self.base + regs.UartOffReg.STATUS,
                             self.base + regs.UartOffReg.STATUS + 3)
    emu.add_mem_write_handler(self.write_data,
                              self.base + regs.UartOffReg.DATA,
                              self.base + regs.UartOffReg.DATA + 3)
