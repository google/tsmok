"""OPTEE TA ELF binary image."""

import io

import tsmok.common.error as error
import tsmok.common.image_elf as image_elf


class TeeElfImage(image_elf.ElfImage):
  """Defines OPTEE TEE ELF binary file."""

  THREAD_INIT_FUNC = 'thread_init_boot_thread'
  THREAD_CLEAR_FUNC = 'thread_clr_boot_thread'
  START_FUNC = '_start'

  def __init__(self, image: io.BufferedReader):
    image_elf.ElfImage.__init__(self, image)
    self.thread_init = None
    self.thread_clear = None
    self._get_func_addresses()

  def _get_func_addresses(self):
    for addr, name in self.func_symbols.items():
      if name == self.THREAD_INIT_FUNC:
        self.thread_init = self._convert_vaddr_to_paddr(addr)
      elif name == self.THREAD_CLEAR_FUNC:
        self.thread_clear = self._convert_vaddr_to_paddr(addr)
      elif name == self.START_FUNC:
        self.entry_point = self._convert_vaddr_to_paddr(addr)

      if self.thread_init and self.thread_clear and self.entry_point:
        break

    if not (self.thread_init and self.thread_clear and self.entry_point):
      raise error.Error('Wrong TEE Elf: does not have one off needed function')

  def _parse_sections(self, image: io.BufferedReader):
    addr, size = self._get_section_info('.text')
    self.text_start = self._convert_vaddr_to_paddr(addr)
    self.text_end = self.text_start + size - 1
