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
