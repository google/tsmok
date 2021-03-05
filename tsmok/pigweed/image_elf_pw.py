"""PIGWEED ELF binary image."""

import collections
import io
import struct

import tsmok.common.error as error
import tsmok.common.image_elf as image_elf
import tsmok.common.memory as memory

VectorTable = collections.namedtuple('VectorTable',
                                     ['stack_ptr', 'reset_addr', 'nmi_handler',
                                      'hard_fault_addr'])


class PwElfImage(image_elf.ElfImage):
  """Defines Pigweed ELF binary file."""

  VECTOR_TABLE_FMT = '<4I'

  EXIT_FUNC = 'pw_boot_PostMain'

  def __init__(self, image: io.BufferedReader, load_addr: int = None):
    self.stack_addr = None
    image_elf.ElfImage.__init__(self, image, load_addr)
    self._get_exit_call()

  def _get_exit_call(self):
    for symbol in self._symbols():
      if symbol['st_info']['type'] == 'STT_FUNC':
        if symbol.name == self.EXIT_FUNC:
          self.exit_func = self._convert_vaddr_to_paddr(symbol['st_value'])
          self.exit_func &= ~0x1
          break

    if not self.exit_func:
      raise error.Error('Failed to find pw_boot_PostMain function')

  def _parse_vector_table(self, data: bytes):
    sz = struct.calcsize(self.VECTOR_TABLE_FMT)
    values = struct.unpack(self.VECTOR_TABLE_FMT, data[:sz])

    return VectorTable(*values)

  def _parse_sections(self, image: io.BufferedReader):
    vt_data = self._get_section_data('.vector_table')
    vt = self._parse_vector_table(vt_data)
    self.entry_point = self._convert_vaddr_to_paddr(vt.reset_addr)
    self.stack_addr = self._convert_vaddr_to_paddr(vt.stack_ptr - 1) + 1

    addr, size = self._get_section_info('.code')
    self.text_start = self._convert_vaddr_to_paddr(addr)
    self.text_end = self.text_start + size - 1

    addr, size = self._get_section_info('.stack')
    self.stack_size = size

    addr, size = self._get_section_info('.static_init_ram')
    self.mem_regions.append(memory.MemoryRegion('.static_init_ram', addr, size,
                                                memory.MemAccessPermissions.RW))
    addr, size = self._get_section_info('.zero_init_ram')
    self.mem_regions.append(memory.MemoryRegion('.zero_init_ram', addr, size,
                                                memory.MemAccessPermissions.RW))
    addr, size = self._get_section_info('.heap')
    self.mem_regions.append(memory.MemoryRegion('.heap', addr, size,
                                                memory.MemAccessPermissions.RW))
    addr, size = self._get_section_info('.stack')
    self.mem_regions.append(memory.MemoryRegion('.stack', addr, size,
                                                memory.MemAccessPermissions.RW))
