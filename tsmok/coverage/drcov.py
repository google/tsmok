"""drcov coverage format."""

import logging
import os.path
import re
import struct

import tsmok.common.error as error
import tsmok.coverage.base as coverage


class BlockEntry:
  """drcov block entry implementation."""
  FORMAT = '<Q2H'

  def __init__(self, start, size, mid):
    self.start = start
    self.size = size
    self.module_id = mid

    self.count = 1

  def __eq__(self, other):
    return (self.start == other.start and
            self.size == other.size and
            self.module_id == other.module_id)

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.start, self.size,
                       self.module_id) * self.count

  def __str__(self):
    return (f'{self.module_id}: 0x{self.start:08x}:'
            f'0x{self.start + self.size:08x}\n') * self.count


class ModuleEntry:
  """drcov module entry implementation."""

  def __init__(self, name: str, start: int, end: int, mid: int,
               checksum: bytes, load_offset: int = None):
    self.name = name
    self.start = start
    self.end = end
    self.id = mid
    self.checksum = checksum
    self.load_offset = load_offset

  def __eq__(self, other):
    return (self.start == other.start and
            self.end == other.end and
            self.checksum == other.checksum and
            self.load_offset == other.load_offset)

  def __str__(self):
    return (f'Module {self.id} \'{self.name}\': '
            f'0x{self.start:08x}-0x{self.end:08x}')

  def __bytes__(self):
    start = self.start + self.load_offset
    end = self.end + self.load_offset
    return (f'{self.id}, {start}, {end}, 0, {self.checksum}, 0, '
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
    self.modules = dict()
    self._blocks = dict()

  def add_module(self, img, checksum: bytes = b'0'):
    mid = len(self.modules)
    name = os.path.basename(img.name)
    module = ModuleEntry(name, img.text_start, img.text_end, mid,
                         checksum.hex(), img.load_offset)
    if module not in self.modules.values():
      self.modules[mid] = module
    else:
      self.log.warning('Image %s was already added!', img.name)

  def add_block(self, addr, size):
    mid = self.UNKNOWN_ID
    start = addr
    for module in self.modules.values():
      if module.start <= addr <= module.end:
        mid = module.id
        start = addr - module.start
        break

    try:
      bl = self._blocks[(start, size)]
      bl.count += 1
    except KeyError:
      self._blocks[(start, size)] = BlockEntry(start, size, mid)

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
    count = 0
    blocks_out = b''
    for block in self._blocks.values():
      count += block.count
      blocks_out += bytes(block)
    out += f'BB Table: {count} bbs\n'.encode()
    out += blocks_out

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

    count = 0
    blocks_out = b''
    for block in self._blocks.values():
      count += block.count
      blocks_out += str(block)

    out += f'BB Table: {count} bbs\n'
    out += blocks_out
    return out

  def clear(self):
    self._blocks = dict()

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
      try:
        bl = self._blocks[(start, size)]
        bl.count += 1
      except KeyError:
        self._blocks[(start, size)] = BlockEntry(start, size, mid)

  def export(self, rep: coverage.CoverageRepresentationBase):
    rep.runs += 1

    for block in self._blocks.values():
      mid = block.module_id
      base = 0
      if mid in self.modules:
        base = self.modules[mid].start
        if self.modules[mid].load_offset:
          base += self.modules[mid].load_offset

      addr = block.start + base
      for _ in range(block.count):
        rep.update_block_coverage(addr, block.size)
