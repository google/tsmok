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

"""Disassembles representation of a source of a binary."""

import logging
import os.path
import capstone
import elftools.elf.elffile as elffile
import elftools.elf.sections as elfsections
import sortedcontainers
import tsmok.common.error as error
import tsmok.common.range_dict as range_dict
import tsmok.common.round_up as round_up
import tsmok.coverage.base as coverage


class AsmLine(coverage.Line):
  """Represents disassembled source line."""

  def __init__(self, addr: int, mnemonic: str, op_str: str, size: int,
               ret: bool):
    coverage.Line.__init__(self)
    self.mnemonic = mnemonic
    self.addr = addr
    self.size = size
    self.op_str = op_str
    self.return_instruction = ret

  def __str__(self):
    return f'  0x{self.addr:08x}:\t{self.mnemonic:<8s}\t{self.op_str}'


class BytesLine(coverage.Line):

  def __init__(self, addr: int, size: int, data: bytes):
    coverage.Line.__init__(self)
    self.addr = addr
    self.data = data
    self.return_instruction = False

  def __str__(self):
    return f'  0x{self.addr:08x}: ????    \t{self.data.hex()}h'


class DasmFunction(coverage.Function):
  """Represent function block of code."""

  def __init__(self, name, addr, size):
    coverage.Function.__init__(self, name)
    self.addr = addr
    self.size = size
    self.lines = sortedcontainers.SortedKeyList(key=self._get_line_addr)

  def _get_line_addr(self, value):
    if isinstance(value, coverage.Line):
      return value.addr
    elif isinstance(value, int):
      return value
    else:
      raise KeyError('Unsupported value type')

  def add_line(self, line: coverage.Line):
    if line not in self.lines:
      self.lines.add(line)

  def returned_percent(self):
    ret_count = sum(l.count for l in self.lines if l.return_instruction)
    ret_num = 0
    for l in self.lines:
      if l.return_instruction:
        ret_num += 1
    if self.called:
      return (ret_count / self.called) * 100.0

    return 0

  def update_counters(self, addr, size):
    if addr not in self.lines:
      raise error.Error(f'Addr 0x{addr:08x} is not belong to {self.name}: '
                        f'0x{self.addr:08x} - 0x{self.addr + self.size - 1:08x}'
                        ' function')

    if addr == self.addr:
      self.called += 1

    for line in self.lines.irange(addr, addr + size - 1):
      line.update_counter()

  def __str__(self):
    for line in self.lines:
      out += '  0x{line.addr:08x}' + str(line) + '\n'

    return out


class DisAsmRepresentation(coverage.CoverageRepresentationBase):
  """Represents coverage for disassembled binary."""

  def __init__(self, log_level=logging.ERROR):
    coverage.CoverageRepresentationBase.__init__(self, 'DisAsm', log_level)

    # Initialize disasm
    self.cs_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    self.cs_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

  def _is_return_instruction(self, mnemonic: str, op_str: str, addr: int,
                             size: int):
    return ((mnemonic == 'ret') or
            (mnemonic in ['pop', 'pop.w'] and 'pc' in op_str) or
            (mnemonic == 'ldr' and op_str.startswith('pc')) or
            (mnemonic in ['b', 'b.w'] and not (addr <= int(op_str[1:], 0)
                                               < (addr + size))) or
            (mnemonic.startswith('b') and op_str == 'lr'))

  def _get_func_list(self, elf) -> None:
    symbol_tables = [
        s for s in elf.iter_sections()
        if isinstance(s, elfsections.SymbolTableSection)
    ]

    symbols = []
    for section in symbol_tables:
      if not isinstance(section, elfsections.SymbolTableSection):
        continue

      if section['sh_entsize'] == 0:
        continue

      symbols.extend(section.iter_symbols())

    funcs = []
    for symbol in symbols:
      if symbol['st_info']['type'] == 'STT_FUNC':
        funcs.append((symbol.name, symbol['st_value'], symbol['st_size']))

    return funcs

  def _get_elf_section_data(self, elf: elffile.ELFFile,
                            section_name: str) -> (int, int):

    s = elf.get_section_by_name(section_name)
    if s is None:
      raise error.Error(f"Section '{section_name}' is not present in ELF")

    offset = s.header['sh_offset']
    addr = s.header['sh_addr']
    size = s.header['sh_size']

    return addr, offset, size

  def _generate_source(self, source: coverage.Source):
    out = ''
    cur_line = 1
    for func in sorted(source.funcs.values(), key=lambda f: f.addr):
      for line in func.lines:
        if line.addr == func.addr:
          out += f'; function {func.name}\n'
          func.lineno = cur_line
          cur_line += 1
        out += str(line) + '\n'
        line.lineno = cur_line
        cur_line += 1

    return out

  def load_source(self, image):
    elf = elffile.ELFFile(image)

    src = coverage.Source()
    src.name = os.path.basename(image.name) + '.asm'
    src.path = os.path.abspath(os.path.dirname(image.name))
    src.funcs = range_dict.RangeDict()

    base, offset, size = self._get_elf_section_data(elf, '.text')
    self.log.debug('.text section: addr: 0x%08x, offset 0x%08x,size: %d',
                   base, offset, size)

    funcs = self._get_func_list(elf)

    image.seek(offset)
    data = image.read(size)

    for name, addr, size in funcs:
      thumb = True if addr & 0x1 else False
      self.log.debug('Disassm %40s: 0x%08x size %d. Thumb: %s',
                     name, addr, size, thumb)
      if thumb:
        cs = self.cs_thumb
      else:
        cs = self.cs_arm

      addr = addr & ~0x1

      func = DasmFunction(name, addr, size)
      off = addr - base

      total_size = 0
      for i in cs.disasm(data[off:off + size], addr & ~(0x1)):
        ret = self._is_return_instruction(i.mnemonic, i.op_str, addr, size)
        func.add_line(AsmLine(i.address, i.mnemonic, i.op_str, i.size, ret))
        total_size += i.size

      if total_size != size:
        start = round_up.round_up(addr + total_size, 2)
        end = addr + size
        for a in range(start, end, 2):
          func.add_line(BytesLine(a, 2, data[a - base: a + 2 - base]))

      src.funcs[range(addr, addr + size - 1)] = func
    src.data = self._generate_source(src)

    self.sources.append(src)

  def update_block_coverage(self, addr: int, size: int):
    found = False
    for src in self.sources:
      try:
        src.funcs[addr].update_counters(addr, size)
        found = True
      except KeyError:
        continue
    if not found:
      self.log.error('Address 0x{addr:08x} is not belong to any function')
