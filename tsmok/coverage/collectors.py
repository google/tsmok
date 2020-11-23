"""Coverage collectors."""

import logging
import tsmok.common.error as error
import tsmok.coverage.base as coverage


class BlockCollector(coverage.CoverageCollectorBase):
  """Implementation for drcov coverage collector."""

  def __init__(self, cov: coverage.CoverageFormatBase, log_level=logging.ERROR):
    coverage.CoverageCollectorBase.__init__(self, 'Block Collector', cov,
                                            log_level)
    self._emu = None
    self._handler = None

  def __del__(self):
    self.stop()

  def _block_handler(self, emu, addr, size):
    self.cov.add_block(addr, size)

  def start(self, emu):
    self.log.debug('Start coverage collecting...')
    if self._handler:
      raise error.Error(f'{self.name}: block handler is already set')

    if not emu:
      raise error.Error('Emulator isinstance is None')

    self._emu = emu
    self._handler = self._emu.add_code_block_handler(self._block_handler)

  def stop(self):
    self.log.debug('Stop coverage collecting...')
    if self._handler:
      self._emu.remove_handler(self._handler)
      self._handler = None
      self._emu = None


class InstructionCollector(coverage.CoverageCollectorBase):
  """Implementation for drcov coverage collector."""

  def __init__(self, cov: coverage.CoverageFormatBase, log_level=logging.ERROR):
    coverage.CoverageCollectorBase.__init__(self, 'Instruction Collector', cov)
    self._emu = None
    self._handler = None

  def __del__(self):
    self.stop()

  def _code_handler(self, emu, addr, size):
    self.cov.add_block(addr, size)

  def start(self, emu):
    self.log.debug('Start coverage collecting...')
    if self._handler:
      raise error.Error(f'{self.name}: instruction handler is already set')

    if not emu:
      raise error.Error('Emulator isinstance is None')

    self._emu = emu
    self._handler = self._emu.add_code_instruction_handler(self._code_handler)

  def stop(self):
    self.log.debug('Stop coverage collecting...')
    if self._handler:
      self._emu.remove_handler(self._handler)
      self._handler = None
      self._emu = None

