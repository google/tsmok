"""SMC common."""

import enum


class SmcCallingConvention(enum.IntEnum):
  FAST_CALL = 0x80000000
  STD_CALL = 0


class SmcType(enum.IntEnum):
  x32 = 0
  x64 = 0x40000000


SMC_OWNER_MASK = 0x3F
SMC_OWNER_SHIFT = 24
SMC_FUNC_MASK = 0xFFFF


class SmcOwner(enum.IntEnum):
  """The recipient/owner of SMC call."""
  ARCH = 0
  CPU = 1
  SIP = 2
  OEM = 3
  STANDARD = 4
  TRUSTED_APP = 48
  TRUSTED_OS = 50
  TRUSTED_OS_TRUSTY = 61
  TRUSTED_OS_OPTEED = 62
  TRUSTED_OS_API = 63


def smc_call_value(ctype, calling_convention, owner, func_num):
  return ((ctype) | (calling_convention) |
          (((owner) & SMC_OWNER_MASK) << SMC_OWNER_SHIFT) |
          ((func_num) & SMC_FUNC_MASK))
