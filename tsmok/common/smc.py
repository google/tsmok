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

"""SMC common."""

import enum


SMC_OWNER_MASK = 0x3F
SMC_FUNC_MASK = 0xFFFF


class SmcCallBitShift(enum.IntEnum):
  FAST_CALL = 31
  X64 = 30
  OWNER = 24
  FUNC = 0


class SmcOwner(enum.IntEnum):
  """The recipient/owner of SMC call."""
  ARCH = 0
  CPU = 1  # CPU Service calls
  SIP = 2  # SIP Service calls
  OEM = 3  # OEM Service calls
  STANDARD = 4  # Standard Service calls
  TRUSTED_APP = 48  # Trusted Application calls
  TRUSTED_OS = 50  # Trusted OS calls
  LOGGING = 51  # Used for secure -> nonsecure logging
  TEST = 52  # Used for secure -> nonsecure tests
  SECURE_MONITOR = 60  # Trusted OS calls internal to secure monitor
  TRUSTED_OS_TRUSTY = 61
  TRUSTED_OS_OPTEED = 62
  TRUSTED_OS_API = 63


class SmcCallFlag(enum.IntFlag):
  SECURE = 1 << 0
  NON_SECURE = 1 << 1


class SmcErrorCode(enum.IntEnum):
  OK = 0
  PREEMPTED = 0xfffffffe
  UNKNOWN = 0xFFFFFFFF


def smc_std_call(owner, func_num):
  return (0 | (((owner) & SMC_OWNER_MASK) << SmcCallBitShift.OWNER) |
          ((func_num) & SMC_FUNC_MASK))


def smc_fast_call(owner, func_num):
  return (0 | (1 << SmcCallBitShift.FAST_CALL) |
          (((owner) & SMC_OWNER_MASK) << SmcCallBitShift.OWNER) |
          ((func_num) & SMC_FUNC_MASK))


def smc_std_x64_call(owner, func_num):
  return ((1 << SmcCallBitShift.X64) |
          (((owner) & SMC_OWNER_MASK) << SmcCallBitShift.OWNER) |
          ((func_num) & SMC_FUNC_MASK))


def smc_fast_x64_call(owner, func_num):
  return ((1 << SmcCallBitShift.X64) | (1 << SmcCallBitShift.FAST_CALL) |
          (((owner) & SMC_OWNER_MASK) << SmcCallBitShift.OWNER) |
          ((func_num) & SMC_FUNC_MASK))
