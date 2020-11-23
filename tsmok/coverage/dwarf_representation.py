"""DWARF representation of a binary."""

import collections
import logging

import elftools.dwarf.descriptions as elfdescriptions
import elftools.elf.elffile as elffile
import sortedcontainers
import tsmok.common.error as error
import tsmok.coverage.base as coverage


class DwarfLine(coverage.Line):
  """Represents line from DWARF."""

  def __init__(self, lineno, addr):
    coverage.Line.__init__(self)
    self.lineno = lineno
    self.addr = sortedcontainers.SortedList([addr])

  def __eq__(self, other):
    if isinstance(other, int):
      return self.lineno == other
    return self.lineno == other.lineno

  def __lt__(self, other):
    if isinstance(other, int):
      return self.lineno < other
    return self.lineno < other.lineno

  def __str__(self):
    out = ' '.join(hex(addr) for addr in self.addr)
    return f'{self.lineno}: {out}'


class DwarfFunction(coverage.Function):
  """Represent function block of code."""

  def __init__(self, name):
    coverage.Function.__init__(self, name)
    self.lines = sortedcontainers.SortedList()
    self.entry_lineno = None

  def add_line(self, lineno, addr):
    if lineno in self.lines:
      idx = self.lines.index(lineno)
      line = self.lines[idx]
      line.addr.add(addr)
    else:
      line = DwarfLine(lineno, addr)
      self.lines.add(line)
      diff = lineno - self.lineno

      if diff >= 0:
        if ((self.entry_lineno is None) or
            (self.entry_lineno - self.lineno) > diff):
          self.entry_lineno = lineno

    return line


class AddrEntry:
  """Represents addr to line translation."""

  def __init__(self, addr, line, func):
    self.addr = addr
    self.line = line
    self.func = func

  def __eq__(self, other):
    if isinstance(other, int):
      return self.addr == other
    return self.addr == other.addr

  def __lt__(self, other):
    if isinstance(other, int):
      return self.addr < other
    return self.addr < other.addr


class DwarfSource(coverage.Source):
  """Represents source from DWARF."""

  def __init__(self):
    coverage.Source.__init__(self)
    self.entries = sortedcontainers.SortedKeyList(key=self._entry_key)

  def _entry_key(self, value):
    if isinstance(value, int):
      return value
    elif isinstance(value, AddrEntry):
      return value.addr
    else:
      raise error.Error('Unsupported type _entry_key function')

ExecutionBlock = collections.namedtuple('ExecutionBlock',
                                        ['src', 'func', 'lines'])


class DwarfRepresentation(coverage.CoverageRepresentationBase):
  """Coverage representation using DWARF data."""

  def __init__(self, log_level=logging.ERROR):
    coverage.CoverageRepresentationBase.__init__(self, 'DWARF', log_level)

    self.sources = []
    self._blocks = dict()

  def _add_lines_for_address(self, src, addr, lines):
    idx = src.entries.bisect_right(addr)
    if idx == 0 or idx == len(src.entries):
      return None

    entry = src.entries[idx - 1]
    # this is a marker for last entry
    if entry.line is None:
      return None

    func = entry.func
    if entry.line.lineno not in lines:
      lines.append(entry.line)
    for i in reversed(range(idx - 1)):
      if (src.entries[i].addr == entry.addr and
          src.entries[i].line.lineno != entry.line.lineno):
        if src.entries[i].func.name != func.name:
          raise error.Error('All lines in block should belong to one fucntion '
                            f'but {func.name} != {src.entries[i].func.name}')
        if src.entries[i].line.lineno not in lines:
          lines.append(src.entries[i].line)
    return func

  def _get_block_of_lines(self, addr, size):
    self.log.debug('Get lines for block 0x%08x size = %d', addr, size)
    try:
      return self._blocks[(addr, size)]
    except KeyError:
      pass

    for src in self.sources:
      # find a source of this block
      lines = []
      func = self._add_lines_for_address(src, addr, lines)
      if not func:
        continue

      for a in range(addr + 2, addr + size, 2):
        lfunc = self._add_lines_for_address(src, a, lines)
        if not lfunc:
          raise error.Error(f'Failed to find function for address 0x{a:08x}')
        if lfunc.name != func.name:
          raise error.Error('All lines in block should belong to one function '
                            f'but {func.name} != {lfunc.name}')
      block = ExecutionBlock(src, func, lines)
      self._blocks[(addr, size)] = block
      return block

    self.log.warning('Failed to find lines for block 0x%08x size = %d',
                     addr, size)
    self._blocks[(addr, size)] = None
    return None

  def _get_func_info_by_addr_from_cu(self, cu, addr):
    for die in cu.iter_DIEs():
      if die.tag in ['DW_TAG_subprogram', 'DW_TAG_inlined_subroutine']:
        try:
          lowpc = die.attributes['DW_AT_low_pc'].value
          # DWARF v4 in section 2.17 describes how to interpret the
          # DW_AT_high_pc attribute based on the class of its form.
          # For class 'address' it's taken as an absolute address
          # (similarly to DW_AT_low_pc); for class 'constant', it's
          # an offset from DW_AT_low_pc.
          highpc_attr = die.attributes['DW_AT_high_pc']
        except KeyError:
          continue

        highpc_attr_cls = elfdescriptions.describe_form_class(highpc_attr.form)
        if highpc_attr_cls == 'address':
          highpc = highpc_attr.value
        elif highpc_attr_cls == 'constant':
          highpc = lowpc + highpc_attr.value
        else:
          self.log.error('invalid DW_AT_high_pc class: %s',
                         highpc_attr_cls)
          continue

        if not lowpc <= addr < highpc:
          continue

        if 'DW_AT_name' in die.attributes:
          name = die.attributes['DW_AT_name'].value.decode()
          try:
            lineno = die.attributes['DW_AT_decl_line'].value
          except KeyError:
            raise error.Error(f'DWARF DIE for {name} does not '
                              'have DW_AT_decl_line')
          return name, lineno

        if 'DW_AT_abstract_origin' not in die.attributes:
          raise error.Error(f'Wrong DWARF DIE object: {die}')

        orig_die = die.get_DIE_from_attribute('DW_AT_abstract_origin')
        try:
          name = orig_die.attributes['DW_AT_name'].value.decode()
          try:
            lineno = orig_die.attributes['DW_AT_decl_line'].value
          except KeyError:
            raise error.Error(f'Orig DIE for {name} does not '
                              'have DW_AT_decl_line')
          return name, lineno
        except:
          raise error.Error('Origin DIE object does not contain name')

    return None, None

  def _get_cu_name(self, cu):
    die = cu.get_top_DIE()
    if die.tag != 'DW_TAG_compile_unit':
      raise error.Error('Top DIE is not DW_TAG_compile_unit')

    name = die.attributes['DW_AT_name'].value.decode()
    path = die.attributes['DW_AT_comp_dir'].value.decode()

    return name, path

  def _get_cu_range(self, cu):
    die = cu.get_top_DIE()
    if die.tag != 'DW_TAG_compile_unit':
      raise error.Error('Top DIE is not DW_TAG_compile_unit')

    try:
      lowpc = die.attributes['DW_AT_low_pc'].value
      highpc_attr = die.attributes['DW_AT_high_pc']
    except KeyError:
      raise error.Error('top CU DIE without low or high pc attribute')
    highpc_attr_class = elfdescriptions.describe_form_class(highpc_attr.form)
    if highpc_attr_class == 'address':
      highpc = highpc_attr.value
    elif highpc_attr_class == 'constant':
      highpc = lowpc + highpc_attr.value
    else:
      raise error.Error(f'invalid DW_AT_high_pc class: {highpc_attr_class}')

    return lowpc, highpc

  def load_source(self, image):
    elf = elffile.ELFFile(image)

    if not elf.has_dwarf_info():
      raise error.Error(f'Debug data is not present in {image.name}')

    # get_dwarf_info returns a DWARFInfo context object, which is the
    # starting point for all DWARF-based processing in pyelftools.
    dwarf = elf.get_dwarf_info()

    for cu in dwarf.iter_CUs():
      lineprog = dwarf.line_program_for_CU(cu)
      src = DwarfSource()
      name, path = self._get_cu_name(cu)
      src.name = name
      src.path = path
      src.funcs = dict()

      for entry in lineprog.get_entries():
        # We're interested in those entries where a new state is assigned
        if entry.state is None:
          continue

        addr = entry.state.address
        name, lineno = self._get_func_info_by_addr_from_cu(cu, addr)
        if not name:
          # check that it should be the last one
          src.entries.add(AddrEntry(addr, None, None))
          self.log.debug('Unknown function for 0x%08x address', addr)
          continue

        try:
          func = src.funcs[name]
          line = func.add_line(entry.state.line, addr)
        except KeyError:
          self.log.debug('coverage.Function %s for address 0x%08x is not '
                         'present. Create it.', name, addr)
          func = DwarfFunction(name)
          func.lineno = lineno
          line = func.add_line(entry.state.line, addr)
          src.funcs[name] = func
        entry = AddrEntry(addr, line, func)
        src.entries.add(entry)

      self.sources.append(src)

  def source(self) -> str:
    return None

  def update_block_coverage(self, addr: int, size: int):
    self.log.info('Update coverage for block 0x%08x, size = %d', addr, size)
    block = self._get_block_of_lines(addr, size)
    if block:
      for line in block.lines:
        line.count += 1
        if line.lineno == block.func.entry_lineno:
          block.func.called += 1
