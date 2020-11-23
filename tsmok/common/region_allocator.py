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
    self._allocated = dict()

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

    reg = None
    fixed_size = round_up.round_up(size, self.aligment)
    # assign max size
    r_size = self.size + 1
    for r in self._free:
      sz = r.upper - r.lower
      if sz >= fixed_size and sz < r_size:
        reg = r
        r_size = sz
      if sz == fixed_size:
        # found exact match
        break

    if not reg:
      raise error.Error('RegionAllocator: failed to find free region for '
                        f'{size} bytes. Not enough space!')

    region = Region(self._get_key(self._allocated),
                    reg.lower, size)
    self._free -= portion.closedopen(reg.lower, reg.lower + size)
    self._allocated[region.id] = region
    return region

  def free(self, rid: int):
    try:
      region = self._allocated[rid]
    except KeyError:
      raise error.Error(f'RegionAllocator: unknown region id: {rid}')

    self._free |= portion.closedopen(region.addr, region.addr + region.size)
    del self._allocated[rid]
