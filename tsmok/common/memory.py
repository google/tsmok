"""Memory related types."""

import enum


class MemAccessPermissions(enum.IntFlag):
  E = 1
  W = 2
  R = 4
  RX = (R | E)
  RWX = (R | W | E)
  RW = (R | W)


class MemoryRegion:
  """Defines memory region in EMU memory space.."""

  def __init__(self, name: str, start: int, size: int,
               perm: MemAccessPermissions):
    self.name = name
    self.start = start
    self.size = size
    self.perm = perm

  def __str__(self):
    return (f'Name: {self.name}; Start: 0x{self.start:x}; '
            f'Size: 0x{self.size:x}; Permissions: {str(self.perm)}')


class MemoryRegionData(MemoryRegion):

  def __init__(self, name: str, start: int, data: bytes,
               perm: MemAccessPermissions, size: int = None):
    if size is None:
      size = len(data)
    MemoryRegion.__init__(self, name, start, size, perm)
    self.data = data


class MemoryRegionVirtual(MemoryRegion):

  def __init__(self, name: str, start: int, vaddr: int, size: int,
               perm: MemAccessPermissions):
    MemoryRegion.__init__(self, name, start, size, perm)
    self.vaddr = vaddr

  def __str__(self):
    return (f'Name: {self.name}; Start: 0x{self.start:x}; '
            f'Address: 0x{self.vaddr:x}; Size: 0x{self.size:x}; '
            f'Permissions: {str(self.perm)}')
