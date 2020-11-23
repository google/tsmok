"""ELF binary image."""

import io

import elftools.elf.constants as elf_const
import elftools.elf.elffile as elf_file
import elftools.elf.sections as elf_sections
import tsmok.common.error as error
import tsmok.common.image as image_base
import tsmok.common.memory as memory


class ElfImage(image_base.Image):
  """ELF Binary Image."""

  def __init__(self, image: io.BufferedReader):
    image_base.Image.__init__(self, image)

  def _symbols(self):
    symbol_tables = [
        s for s in self._elf.iter_sections()
        if isinstance(s, elf_sections.SymbolTableSection)
    ]

    for section in symbol_tables:
      if not isinstance(section, elf_sections.SymbolTableSection):
        continue

      if section['sh_entsize'] == 0:
        continue

      for symbol in section.iter_symbols():
        yield symbol

  def _load_func_symbols(self) -> None:
    for symbol in self._symbols():
      if symbol['st_info']['type'] == 'STT_FUNC':
        self.func_symbols[symbol['st_value']] = symbol.name

  def _convert_flags_to_perm(self, flag):
    perm = 0
    if flag & elf_const.P_FLAGS.PF_R:
      perm |= memory.MemAccessPermissions.R
    if flag & elf_const.P_FLAGS.PF_W:
      perm |= memory.MemAccessPermissions.W
    if flag & elf_const.P_FLAGS.PF_X:
      perm |= memory.MemAccessPermissions.E

    return perm

  def _load_segments(self):
    for i, seg in enumerate(self._elf.iter_segments()):
      if seg['p_type'] == 'PT_LOAD':
        data = seg.data()
        paddr = seg['p_paddr']
        if seg['p_filesz'] != len(data):
          raise error.Error(f'Expected size of segment {i} does not match '
                            f'actual: {seg["p_filesz"]} != {len(data)}')

        gap = seg['p_memsz'] - seg['p_filesz']
        if gap < 0:
          data = data[:gap]
        elif gap > 0:
          data += b'\x00' * gap

        perm = self._convert_flags_to_perm(seg['p_flags'])
        self.mem_regions.append(memory.MemoryRegionData(f'load_segment {i}',
                                                        paddr, data,
                                                        perm))

  def _convert_vaddr_to_paddr(self, addr: int)-> int:
    sec = None
    for s in self._elf.iter_sections():
      s_addr = s.header['sh_addr']
      s_size = s.header['sh_size']
      if s_addr <= addr < s_addr + s_size:
        sec = s
        break

    if sec is None:
      raise error.Error(f'Address 0x{addr:08x} is not belong to any section')

    for seg in self._elf.iter_segments():
      if seg.section_in_segment(sec):
        vaddr = seg['p_vaddr']
        paddr = seg['p_paddr']
        off = addr - vaddr
        return paddr + off

    raise error.Error('Section {section_name} is not belong to any segment')

  def _get_section_by_addr(self, addr: int):
    for sec in self._elf.iter_sections():
      sec_addr = sec.header['sh_addr']
      sec_size = sec.header['sh_size']
      if sec_addr <= addr < sec_addr + sec_size:
        return sec.name

    raise error.Error(f'Address 0x{addr:08x} is not belong to any section')

  def _get_section_data(self, section_name: str) -> bytes:
    sec = self._elf.get_section_by_name(section_name)
    if sec is None:
      raise error.Error(f"Section '{section_name}' is not present in ELF")

    return sec.data()

  def _get_section_info(self, section_name: str) -> (int, int):
    sec = self._elf.get_section_by_name(section_name)
    if sec is None:
      raise error.Error(f"Section '{section_name}' is not present in ELF")

    return sec.header['sh_addr'], sec.header['sh_size']

  def _parse_sections(self, image: io.BufferedReader) -> None:
    pass

  def _load(self, image: io.BufferedReader) -> None:
    self._elf = elf_file.ELFFile(image)
    self._load_func_symbols()
    self._load_segments()
    self._parse_sections(image)
