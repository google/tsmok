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

"""ELF binary image."""

import collections
import enum
import io
import struct

import elftools.elf.constants as elf_const
import elftools.elf.elffile as elf_file
import elftools.elf.sections as elf_sections
import tsmok.common.const as common_const
import tsmok.common.error as error
import tsmok.common.image as image_base
import tsmok.common.memory as memory


RelocationRule = collections.namedtuple('RelocationRule', ['fmt', 'calc'])


class RelType(enum.IntFlag):
  AARCH64_ABS64 = 257
  AARCH64_ABS32 = 258
  AARCH64_RELATIVE = 1027
  ARM_ABS32 = 2
  ARM_REL32 = 3
  ARM_RELATIVE = 23


class ElfImage(image_base.Image):
  """ELF Binary Image."""

  def __init__(self, image: io.BufferedReader, load_addr: int):
    self._rel_rules = {
        'ARM': {
            RelType.ARM_ABS32:
                RelocationRule('I', self._rel_calc_value_plus_sym),
            RelType.ARM_RELATIVE:
                RelocationRule('I', self._rel_calc_value),
        },
        'AArch64': {
            RelType.AARCH64_ABS64:
                RelocationRule('Q', self._rel_calc_value_plus_sym_plus_addend),
            RelType.AARCH64_RELATIVE:
                RelocationRule('Q', self._rel_calc_value_plus_addend),
        },
    }

    image_base.Image.__init__(self, image, load_addr)

  def _rel_calc_value(self, value, sym_value, offset, addend=0):
    return value + self.load_offset

  def _rel_calc_value_plus_sym(self, value, sym_value, offset, addend=0):
    return value + self.load_offset + sym_value

  def _rel_calc_value_plus_addend(self, value, sym_value, offset, addend=0):
    return value + self.load_offset + addend

  def _rel_calc_value_plus_sym_plus_addend(self, value, sym_value, offset,
                                           addend=0):
    return value + self.load_offset + sym_value + addend

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

  def _get_region(self, addr):
    for r in self.mem_regions:
      if r.start <= addr <= r.start + r.size:
        return r
    return None

  def _relocate(self, sec, regions):
    rules = self._rel_rules[self._elf.get_machine_arch()]
    sym_sec = self._elf.get_section(sec['sh_link'])

    for rel in sec.iter_relocations():
      where = self.load_offset + rel['r_offset']
      rule = rules[rel['r_info_type']]

      memr = self._get_region(where)
      if not memr:
        raise ValueError(f'Offset {rel["r_offset"]:x} is not belong '
                         'to any segment')

      off = where - memr.start
      sz = struct.calcsize(rule.fmt)
      value = struct.unpack(rule.fmt, memr.data[off:off+sz])[0]
      sym_value = sym_sec.get_symbol(rel['r_info_sym'])['st_value']
      try:
        addend = rel['r_addend']
      except KeyError:
        # no r_addend
        addend = 0
      new_value = rule.calc(value, sym_value, rel['r_offset'], addend)
      data = bytearray(memr.data)
      data[off:off + sz] = struct.pack(rule.fmt, new_value)
      memr.data = bytes(data)

  def _load_segments(self, load_addr: int):

    # If there are numbers of segments, `load_addr' is corresponding
    # to address of the segment with lower address. other sigments will
    # be located with appropriate offset.
    if load_addr:
      # load_addr has to be PAGE aligned
      if load_addr & (common_const.PAGE_SIZE - 1):
        raise error.Error('Load_addr has to be PAGE aligned')
      # get the lowest segment address
      min_addr = None
      for i, seg in enumerate(self._elf.iter_segments()):
        if seg['p_type'] == 'PT_LOAD':
          if min_addr is None or seg['p_paddr'] < min_addr:
            min_addr = seg['p_paddr']
      if min_addr > load_addr:
        self.load_offset = -(min_addr - load_addr)
      else:
        self.load_offset = load_addr - min_addr

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
        self.mem_regions.append(
            memory.MemoryRegionData(f'load_segment {i}',
                                    paddr + self.load_offset, data, perm))

    if load_addr:
      for sec in self._elf.iter_sections():
        if sec['sh_type'] in ['SHT_REL', 'SHT_RELA']:
          self._relocate(sec, self.mem_regions)

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
        return paddr + off + self.load_offset

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

  def _load(self, image: io.BufferedReader, load_addr: int) -> None:
    self._elf = elf_file.ELFFile(image)
    if self._elf.get_machine_arch() not in ['ARM', 'AArch64']:
      raise ValueError('Unsupported machine type '
                       f'{self._elf.get_machine_arch()}')

    self._load_func_symbols()
    self._load_segments(load_addr)
    self._parse_sections(image)
