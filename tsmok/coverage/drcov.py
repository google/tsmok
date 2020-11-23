"""drcov coverage format."""

import logging
import os.path
import re
import struct

import tsmok.common.error as error
import tsmok.coverage.base as coverage


class BlockEntry:
  """drcov block entry implementation."""
  FORMAT = '<I2H'

  def __init__(self, start, size, mid):
    self.start = start
    self.size = size
    self.module_id = mid

  def __eq__(self, other):
    return (self.start == other.start and
            self.size == other.size and
            self.module_id == other.module_id)

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.start, self.size, self.module_id)

  def __str__(self):
    return (f'{self.module_id}: 0x{self.start:08x}:'
            f'0x{self.start + self.size:08x}\n')


class ModuleEntry:
  """drcov module entry implementation."""

  def __init__(self, name: str, start: int, end: int, mid: int,
               checksum: bytes):
    self.name = name
    self.start = start
    self.end = end
    self.id = mid
    self.checksum = checksum

  def __eq__(self, other):
    return (self.start == other.start and
            self.end == other.end and
            self.checksum == other.checksum)

  def __str__(self):
    return (f'Module {self.id} \'{self.name}\': '
            f'0x{self.start:08x}-0x{self.end:08x}')

  def __bytes__(self):
    return (f'{self.id}, {self.start}, {self.end}, 0, {self.checksum}, 0, '
            f'{self.name}\n').encode()


class DrCov(coverage.CoverageFormatBase):
  """Implementation for drcov coverage format.

  Details: https://dynamorio.org/dynamorio_docs/page_drcov.html
  """

  VERSION = 2
  FLAVOR = 'drcov'
  UNKNOWN_ID = 0xFFFF

  HEADER_LINES_NUM = 7

  def __init__(self, log_level=logging.ERROR):
    coverage.CoverageFormatBase.__init__(self, 'DRCOV', log_level)
    self.blocks = []
    self.modules = dict()

  def add_module(self, name, start, end, checksum: bytes = b'0'):
    mid = len(self.modules)
    name = os.path.basename(name)
    module = ModuleEntry(name, start, end, mid, checksum.hex())
    if module not in self.modules.values():
      self.modules[mid] = module

  def add_block(self, addr, size):
    for module in self.modules.values():
      if module.start <= addr <= module.end:
        block = BlockEntry(addr - module.start, size, module.id)
        self.blocks.append(block)
        return

    # did not find module. use the 'unknown'
    self.blocks.append(BlockEntry(addr, size, self.UNKNOWN_ID))

  def dump(self) -> bytes:
    self.log.debug('Dump coverage information')
    out = b''
    out += f'DRCOV VERSION: {self.VERSION}\n'.encode()
    out += f'DRCOV FLAVOR: {self.FLAVOR}\n'.encode()
    out += (f'Module Table: version {self.VERSION}, '
            f'count {len(self.modules)}\n').encode()
    out += b'Columns: id, base, end, entry, checksum, timestamp, path\n'
    for module in self.modules.values():
      out += bytes(module)
    out += f'BB Table: {len(self.blocks)} bbs\n'.encode()
    for block in self.blocks:
      out += bytes(block)

    return out

  def __str__(self) -> str:
    out = ''
    out += 'DRCOV VERSION: {self.VERSION}\n'
    out += 'DRCOV FLAVOR: {self.FLAVOR}\n'
    out += ('Module Table: version {self.VERSION}, '
            'count {len(self._images)}\n')
    out += 'Columns: id, base, end, entry, checksum, timestamp, path\n'
    for module in self.modules:
      out += str(module)
    out += f'BB Table: {len(self.blocks)} bbs\n'
    for block in self.blocks:
      out += str(block)

    return out

  def clear(self):
    self.blocks.clear()

  def load(self, data):
    lines = data.split(b'\n')
    offset = 0
    if len(lines) < self.HEADER_LINES_NUM:
      raise error.Error('Corrupted data: wrong header.')

    cur = 0
    m = re.search('^DRCOV VERSION: *(\d)$',  # pylint: disable=anomalous-backslash-in-string
                  lines[cur].decode())
    if not m:
      raise error.Error('Corrupted data: version is not present')
    if int(m.group(1)) != self.VERSION:
      raise error.Error('Corrupted data: version mismatch '
                        f'{int(m.group(1))} != {self.VERSION}')
    offset += len(lines[cur]) + 1  # '\n' symbol is not counted
    cur += 1

    m = re.search('^DRCOV FLAVOR: *(\w*)$',  # pylint: disable=anomalous-backslash-in-string
                  lines[cur].decode())
    if not m:
      raise error.Error('Corrupted data: flavor is not present')
    if m.group(1) != self.FLAVOR:
      raise error.Error('Corrupted data: flavor mismatch '
                        f'{m.group(1)} != {self.FLAVOR}')
    offset += len(lines[cur]) + 1  # '\n' symbol is not counted
    cur += 1

    m = re.search('^Module Table: *version *(\d), *count *(\d*)$',  # pylint: disable=anomalous-backslash-in-string
                  lines[cur].decode())
    if not m:
      raise error.Error('Corrupted data: module version is not present')
    if int(m.group(1)) != self.VERSION:
      raise error.Error('Corrupted data: module version mismatch '
                        f'{int(m.group(1))} != {self.VERSION}')
    offset += len(lines[cur]) + 1  # '\n' symbol is not counted
    cur += 1

    module_count = int(m.group(2))

    if lines[cur] != b'Columns: id, base, end, entry, checksum, timestamp, path':
      raise error.Error('Corrupted data: wrong line in the header: '
                        f'{lines[cur].decode()}')
    offset += len(lines[cur]) + 1  # '\n' symbol is not counted
    cur += 1

    for i in range(module_count):
      m = re.search('^(\d*), *(\d*), *(\d*), *(\d*), '  # pylint: disable=anomalous-backslash-in-string
                    '*([a-fA-F0-9]*), *(\d*), (.*)',  # pylint: disable=anomalous-backslash-in-string
                    lines[cur].decode())
      if not m:
        raise error.Error('Corrupted data: module records is wrong formated: '
                          f'{lines[cur].decode()}')
      mid = int(m.group(1))
      start = int(m.group(2))
      size = int(m.group(3))
      sha256 = m.group(5)

      module = ModuleEntry(m.group(7), start, size, mid, sha256)
      self.modules[mid] = module
      offset += len(lines[cur]) + 1  # '\n' symbol is not counted
      cur += 1

    m = re.search('^BB Table: *(\d*) *bbs$',  # pylint: disable=anomalous-backslash-in-string
                  lines[cur].decode())
    if not m:
      raise error.Error('Corrupted data: BB table is not present')
    bb_count = int(m.group(1))
    offset += len(lines[cur]) + 1  # '\n' symbol is not counted

    bb_data = data[offset:]
    bb_size = struct.calcsize(BlockEntry.FORMAT)
    if bb_count * bb_size != len(bb_data):
      raise error.Error('Corrupted data: wrong size of BB section: '
                        f'{bb_count * bb_size} != {len(bb_data)}')

    offset = 0
    for i in range(bb_count):
      start, size, mid = struct.unpack(BlockEntry.FORMAT,
                                       bb_data[offset:offset + bb_size])
      offset += bb_size
      self.blocks.append(BlockEntry(start, size, mid))

  def export(self, rep: coverage.CoverageRepresentationBase):
    rep.runs += 1

    for block in self.blocks:
      mid = block.module_id
      base = 0
      if mid in self.modules:
        base = self.modules[mid].start

      addr = block.start + base
      rep.update_block_coverage(addr, block.size)
