"""Simple region allocator."""

import collections
from typing import Dict, Any
import portion

import tsmok.common.error as error
import tsmok.common.round_up as round_up


Region = collections.namedtuple('Region', ['id', 'addr', 'size'])


class RegionAllocator:
  """Simple region allocator from continuous space."""

  def __init__(self, addr: int, size: int, aligment: int = 8):
    self.addr = addr
    self.size = size
    self.aligment = aligment

    self._free = portion.closedopen(addr, addr + size)
    self._allocated_by_id = dict()
    self._allocated_by_addr = dict()

  def _get_key(self, d: Dict[int, Any]) -> int:
    if not d:
      return 1

    r = [ele for ele in range(1, max(d.keys()) + 1) if ele not in d.keys()]

    if not r:
      return max(d.keys()) + 1

    return r[0]

  def allocate(self, size: int) -> Region:
    """Allocate range from giving size.

    Args:
      size: Size of range

    Returns:
      Allocated range information in Region isinstance

    Raises:
      Error exception if no enough spece
    """

    addr = None
    # assign max size
    r_size = self.size + 1
    for r in self._free:
      fixed_addr = round_up.round_up(r.lower, self.aligment)
      sz = r.upper - fixed_addr
      if sz >= size and sz < r_size:
        addr = fixed_addr
        r_size = sz
      if sz == size:
        # found exact match
        break

    if not addr:
      raise error.Error('RegionAllocator: failed to find free region for '
                        f'{size} bytes. Not enough space!')

    region = Region(self._get_key(self._allocated_by_id),
                    addr, size)
    self._free -= portion.closedopen(addr, addr + size)
    self._allocated_by_id[region.id] = region
    self._allocated_by_addr[region.addr] = region
    return region

  def free_by_id(self, rid: int):
    try:
      region = self._allocated_by_id[rid]
    except KeyError:
      raise error.Error(f'RegionAllocator: unknown region id: {rid}')

    self._free |= portion.closedopen(region.addr, region.addr + region.size)
    del self._allocated_by_id[region.id]
    del self._allocated_by_addr[region.addr]

  def free(self, addr: int):
    try:
      region = self._allocated_by_addr[addr]
    except KeyError:
      raise error.Error(f'RegionAllocator: unknown region address: {addr}')

    self._free |= portion.closedopen(region.addr, region.addr + region.size)
    del self._allocated_by_id[region.id]
    del self._allocated_by_addr[region.addr]

  def get_by_id(self, rid: int):
    try:
      region = self._allocated_by_id[rid]
    except KeyError:
      raise error.Error(f'RegionAllocator: unknown region id: {rid}')

    return region

  def get_by_addr(self, addr: int):
    try:
      region = self._allocated_by_addr[addr]
    except KeyError:
      raise error.Error(f'RegionAllocator: unknown region address: {addr}')

    return region

  def __str__(self):
    out = f'Region Allocator: region 0x{self.addr:x} - '
    out += f'0x{self.addr + self.size -1:x}\n'
    out += '    allocated:\n'
    for r in self._allocated_by_id.values():
      out += f'     0x{r.addr:x} - 0x{r.addr + r.size - 1:x}\n'

    return out
