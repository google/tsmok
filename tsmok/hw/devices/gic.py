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

"""ARM fake Generic Interrupt Controller implementation."""

import enum
import logging

import tsmok.common.hw as hw

MAX_INT = 1020
GIC_BASE = 0xffe20000

GIC_GAP = 0x10000
GICC_SIZE = 0x10000
GICD_SIZE = 0x10000
GICR_SIZE = 0x30000 * 8

GICC_OFFSET = 0x0000
GICD_OFFSET = (GICC_OFFSET + GICC_SIZE + GIC_GAP)
GICR_OFFSET = (GICD_OFFSET + GICD_SIZE + GIC_GAP)


class GicdReg(enum.IntEnum):
  """Distributor registers, as offsets from the distributor base address."""

  CTLR = 0x0000
  TYPER = 0x0004
  IIDR = 0x0008
  STATUSR = 0x0010
  SETSPI_NSR = 0x0040
  CLRSPI_NSR = 0x0048
  SETSPI_SR = 0x0050
  CLRSPI_SR = 0x0058
  SEIR = 0x0068
  IGROUPR = 0x0080
  ISENABLER = 0x0100
  ICENABLER = 0x0180
  ISPENDR = 0x0200
  ICPENDR = 0x0280
  ISACTIVER = 0x0300
  ICACTIVER = 0x0380
  IPRIORITYR = 0x0400
  ITARGETSR = 0x0800
  ICFGR = 0x0C00
  IGRPMODR = 0x0D00
  NSACR = 0x0E00
  SGIR = 0x0F00
  CPENDSGIR = 0x0F10
  SPENDSGIR = 0x0F20
  IROUTER = 0x6000
  IDREGS = 0xFFD0


class GicdCtlrField(enum.IntEnum):
  """GICD_CTLR fields."""

  EN_GRP0 = 1 << 0
  EN_GRP1NS = 1 << 1  # GICv3 5.3.20
  EN_GRP1S = 1 << 2
  EN_GRP1_ALL = EN_GRP1NS | EN_GRP1S
  #  Bit 4 is ARE if the system doesn't support TrustZone, ARE_S otherwise
  ARE = 1 << 4
  ARE_S = 1 << 4
  ARE_NS = 1 << 5
  DS = 1 << 6
  E1NWF = 1 << 7
  RWP = 1 << 31


class GicrReg(enum.IntEnum):
  """Redistributor registers, offsets from RD_base."""
  CTLR = 0x0000
  IIDR = 0x0004
  TYPER = 0x0008
  STATUSR = 0x0010
  WAKER = 0x0014
  SETLPIR = 0x0040
  CLRLPIR = 0x0048
  PROPBASER = 0x0070
  PENDBASER = 0x0078
  INVLPIR = 0x00A0
  INVALLR = 0x00B0
  SYNCR = 0x00C0
  IDREGS = 0xFFD0


# Redistributor frame offsets from RD_base
GICR_SGI_OFFSET = 0x10000


class GicrSgiReg(enum.IntEnum):
  """SGI and PPI Redistributor registers, offsets from RD_base."""
  IGROUPR0 = (GICR_SGI_OFFSET + 0x0080)
  ISENABLER0 = (GICR_SGI_OFFSET + 0x0100)
  ICENABLER0 = (GICR_SGI_OFFSET + 0x0180)
  ISPENDR0 = (GICR_SGI_OFFSET + 0x0200)
  ICPENDR0 = (GICR_SGI_OFFSET + 0x0280)
  ISACTIVER0 = (GICR_SGI_OFFSET + 0x0300)
  ICACTIVER0 = (GICR_SGI_OFFSET + 0x0380)
  IPRIORITYR = (GICR_SGI_OFFSET + 0x0400)
  ICFGR0 = (GICR_SGI_OFFSET + 0x0C00)
  ICFGR1 = (GICR_SGI_OFFSET + 0x0C04)
  IGRPMODR0 = (GICR_SGI_OFFSET + 0x0D00)
  NSACR = (GICR_SGI_OFFSET + 0x0E00)


class GicrCtlrField(enum.IntEnum):
  ENABLE_LPIS = (1 << 0)
  RWP = (1 << 3)
  DPG0 = (1 << 24)
  DPG1NS = (1 << 25)
  DPG1S = (1 << 26)
  UWP = (1 << 31)


class GicrTyper(enum.IntEnum):
  PLPIS = (1 << 0)
  VLPIS = (1 << 1)
  DIRECTLPI = (1 << 3)
  LAST = (1 << 4)
  DPGS = (1 << 5)
  PROCNUM = (0xFFFF << 8)
  COMMONLPIAFF = (0x3 << 24)
  AFFINITYVALUE = (0xFFFFFFFF << 32)


class GicrWaker(enum.IntEnum):
  PROCESSORSLEEP = 1 << 1
  CHILDRENASLEEP = 1 << 2


class GicrPendbaserMask(enum.IntEnum):
  PTZ = (1 << 62)
  OUTER_CACHEABILITY_MASK = (7 << 56)
  ADDR_MASK = (0xfffffffff << 12)
  SHAREABILITY_MASK = (3 << 10)
  CACHEABILITY_MASK = (7 << 7)
  IDBITS_MASK = 0x1f


class GiccCrlrMask(enum.IntEnum):
  EN_GRP0 = 1 << 0
  EN_GRP1 = 1 << 1
  ACK_CTL = 1 << 2
  FIQ_EN = 1 << 3
  CBPR = 1 << 4   # GICv1: SBPR
  EOIMODE = 1 << 9
  EOIMODE_NS = 1 << 10


class GicV3(hw.DeviceBase):
  """Implementation of fake GICv3.

  Dumb implementation for now.
  """

  def __init__(self, base_addr: int = GIC_BASE, log_level=logging.ERROR):
    hw.DeviceBase.__init__(self, 'GICv3', log_level)
    self._base_addr = base_addr

  def gicc_base(self):
    return self._base_addr + GICC_OFFSET

  def gicd_base(self):
    return self._base_addr + GICD_OFFSET

  def gicr_base(self):
    return self._base_addr + GICR_OFFSET

  def register(self, emu):
    self.log.info('Device %s registring...', self.name)

    emu.add_mem_read_handler(self.read_trace,
                             self._base_addr,
                             self._base_addr + GICR_OFFSET + GICR_SIZE + 3)
    emu.add_mem_write_handler(self.write_trace,
                              self._base_addr,
                              self._base_addr + GICR_OFFSET + GICR_SIZE + 3)
