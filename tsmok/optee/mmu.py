"""Optee MMU types."""

import enum


class MmuAttr(enum.IntFlag):
  """MMU Attributes."""

  VALID_BLOCK = 1 << 0
  HIDDEN_BLOCK = 1 << 1
  HIDDEN_DIRTY_BLOCK = 1 << 2
  TABLE = 1 << 3
  PR = 1 << 4
  PW = 1 << 5
  PX = 1 << 6
  PRW = PR | PW
  PRX = PR | PX
  PRWX = PRW | PX
  UR = 1 << 7
  UW = 1 << 8
  UX = 1 << 9
  URW = UR | UW
  URX = UR | UX
  URWX = URW | UX
  GLOBAL = 1 << 10
  SECURE = 1 << 11
  CACHE = 1 << 12
  LOCKED = 1 << 15


class MmuBaseIdx(enum.IntEnum):
  STACK = 0
  CODE = 1


class CoreMemType(enum.IntEnum):
  CACHED = 0
  NSEC_SHM = 1
  NON_SEC = 2
  SEC = 3
  TEE_RAM = 4
  TA_RAM = 5
  SDP_MEM = 6
  REG_SHM = 7
