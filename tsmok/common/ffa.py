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

"""Firmware Framework Arm constants and types."""

import collections
import enum
import struct
import tsmok.common.smc as smc


class FfaError(enum.IntEnum):
  """FF-A error code.

    NOT_SUPPORTED:
            Operation is not supported by the current implementation.
    INVALID_PARAMETERS:
            Invalid parameters. Conditions function specific.
    NO_MEMORY:
            Not enough memory.
    DENIED:
            Operation not allowed. Conditions function specific.
  """
  NOT_SUPPORTED = -1,
  INVALID_PARAMETERS = -2,
  NO_MEMORY = -3,
  DENIED = -6,


class FfaFeatures2(enum.IntFlag):
  """FFA_FEATURES values returned in w2.

   RXTX_MAP_BUF_SIZE_4K
    For RXTX_MAP: min buffer size and alignment boundary is 4K.
   RXTX_MAP_BUF_SIZE_64K
    For RXTX_MAP: min buffer size and alignment boundary is 64K.
   RXTX_MAP_BUF_SIZE_16K
    For RXTX_MAP: min buffer size and alignment boundary is 16K.
   MEM_DYNAMIC_BUFFER
    Supports custom buffers for memory transactions.
   MEM_HAS_NS_BIT
       Supports setting the NS bit on retrieved descriptors.
   For all other bits and commands: must be 0.
  """
  RXTX_MAP_BUF_SIZE_4K = 0x0
  RXTX_MAP_BUF_SIZE_64K = 0x1
  RXTX_MAP_BUF_SIZE_16K = 0x2
  MEM_DYNAMIC_BUFFER = 0x1
  MEM_HAS_NS_BIT = 0x2


class FfaSmcCall(enum.IntEnum):
  """FF-A specific SMC Calls."""

  # First 32 bit SMC opcode reserved for FFA
  MIN = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x60)

  # Last 32 bit SMC opcode reserved for FFA
  MAX = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x7F)

  # First 64 bit SMC opcode reserved for FFA
  FFA64_MIN = smc.smc_fast_x64_call(smc.SmcOwner.STANDARD, 0x60)

  # Last 64 bit SMC opcode reserved for FFA
  FFA64_MAX = smc.smc_fast_x64_call(smc.SmcOwner.STANDARD, 0x7F)

  # SMC error return opcode
  #
  # Register arguments:
  #  w1:     VMID in [31:16], vCPU in [15:0]
  #  w2:     Error code (&enum ffa_error)
  ERROR = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x60)

  # 32 bit SMC success return opcode
  #
  # Register arguments:
  #  w1:     VMID in [31:16], vCPU in [15:0]
  #  w2-w7:  Function specific
  SUCCESS = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x61)

  # 64 bit SMC success return opcode
  #
  # Register arguments:
  #  w1:             VMID in [31:16], vCPU in [15:0]
  #  w2/x2-w7/x7:    Function specific
  FFA64_SUCCESS = smc.smc_fast_x64_call(smc.SmcOwner.STANDARD, 0x61)

  # SMC opcode to return supported FF-A version
  #
  # Register arguments:
  #
  #  w1:     Major version bit[30:16] and minor version in bit[15:0] supported
  #           by caller. Bit[31] must be 0.
  # Return:
  #   w0:     Major version bit[30:16], minor version in bit[15:0], bit[31] must
  #            be 0.
  #  or
  #   w0:     FfaError.NOT_SUPPORTED if major version passed in is less than
  #           the minimum major version supported.
  VERSION = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x63)

  # SMC opcode to check optional feature support
  #
  # Register arguments:
  #  w1:     FF-A function ID
  # Return:
  #   w0:     SUCCESS
  #   w2:     FfaFeatures2
  #   w3:     FfaFeatures3
  #  or
  #   w0:     ERROR
  #   w2:     FfaError.NOT_SUPPORTED if function is not implemented, or
  #           FfaError.INVALID_PARAMETERS if function id is not valid.
  FEATURES = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x64)

  # 32 bit SMC opcode to map message buffers
  #
  # Register arguments:
  #  w1:     TX address
  #  w2:     RX address
  #  w3:     RX/TX page count in bit[5:0]
  # Return:
  #  w0:     SUCCESS
  RXTX_MAP = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x66)

  # 64 bit SMC opcode to map message buffers
  #
  # Register arguments:
  #  x1:     TX address
  #  x2:     RX address
  #  x3:     RX/TX page count in bit[5:0]
  # Return:
  #  w0:     SUCCESS
  FFA64_RXTX_MAP = smc.smc_fast_x64_call(smc.SmcOwner.STANDARD, 0x66)

  # SMC opcode to unmap message buffers
  #
  # Register arguments:
  #  w1:     ID in [31:16]
  # Return:
  #  w0:     SUCCESS
  RXTX_UNMAP = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x67)

  # SMC opcode to get endpoint id of caller
  #
  # Return:
  #  w0:     SUCCESS
  #  w2:     ID in bit[15:0], bit[31:16] must be 0.
  ID_GET = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x69)

  # MEM_DONATE - 32 bit SMC opcode to donate memory
  #
  # Not supported.
  MEM_DONATE = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x71)

  # 32 bit SMC opcode to lend memory
  #
  # Not currently supported.
  MEM_LEND = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x72)

  # 32 bit SMC opcode to share memory
  #
  # Register arguments:
  #  w1:     Total length
  #  w2:     Fragment length
  #  w3:     Address
  #  w4:     Page count
  # Return:
  #   w0:     SUCCESS
  #   w2/w3:  Handle
  #  or
  #   w0:     MEM_FRAG_RX
  #   w1-:    See MEM_FRAG_RX
  #  or
  #   w0:     ERROR
  #   w2:     Error code (&enum ffa_error)
  MEM_SHARE = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x73)

  # 64 bit SMC opcode to share memory
  #
  # Register arguments:
  #  w1:     Total length
  #  w2:     Fragment length
  #  x3:     Address
  #  w4:     Page count
  # Return:
  #   w0:     SUCCESS
  #   w2/w3:  Handle
  #  or
  #   w0:     MEM_FRAG_RX
  #   w1-:    See MEM_FRAG_RX
  #  or
  #   w0:     ERROR
  #   w2:     Error code (&enum ffa_error)
  FFA64_MEM_SHARE = smc.smc_fast_x64_call(smc.SmcOwner.STANDARD, 0x73)

  # 32 bit SMC opcode to retrieve shared memory
  #
  # Register arguments:
  #  w1:     Total length
  #  w2:     Fragment length
  #  w3:     Address
  #  w4:     Page count
  # Return:
  #  w0:             MEM_RETRIEVE_RESP
  #  w1/x1-w5/x5:    See MEM_RETRIEVE_RESP
  MEM_RETRIEVE_REQ = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x74)

  # 64 bit SMC opcode to retrieve shared memory
  #
  # Register arguments:
  #  w1:     Total length
  #  w2:     Fragment length
  #  x3:     Address
  #  w4:     Page count
  # Return:
  #  w0:             MEM_RETRIEVE_RESP
  #  w1/x1-w5/x5:    See MEM_RETRIEVE_RESP
  FFA64_MEM_RETRIEVE_REQ = smc.smc_fast_x64_call(smc.SmcOwner.STANDARD, 0x74)

  # MEM_RETRIEVE_RESP - Retrieve 32 bit SMC return opcode
  #
  # Register arguments:
  #  w1:     Total length
  #  w2:     Fragment length
  MEM_RETRIEVE_RESP = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x75)

  # SMC opcode to relinquish shared memory
  #
  # Input in ffa_mem_relinquish_descriptor format in message buffer.
  # Return:
  #  w0:     SUCCESS
  MEM_RELINQUISH = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x76)

  # SMC opcode to reclaim shared memory
  #
  # Register arguments:
  #  w1/w2:  Handle
  #  w3:     Flags
  # Return:
  #  w0:     SUCCESS
  MEM_RECLAIM = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x77)

  # SMC opcode to request next fragment.
  #
  # Register arguments:
  #  w1/w2:  Handle
  #  w3:     Fragment offset.
  #  w4:     Endpoint id ID in [31:16], if client is hypervisor.
  # Return:
  #  w0:             MEM_FRAG_TX
  #  w1/x1-w5/x5:    See MEM_FRAG_TX
  MEM_FRAG_RX = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x7A)

  # SMC opcode to transmit next fragment
  #
  # Register arguments:
  #  w1/w2:  Handle
  #  w3:     Fragment length.
  #  w4:     Sender endpoint id ID in [31:16], if client is hypervisor.
  # Return:
  #  w0:             MEM_FRAG_RX or SUCCESS.
  #  w1/x1-w5/x5:    See opcode in w0.
  MEM_FRAG_TX = smc.smc_fast_call(smc.SmcOwner.STANDARD, 0x7B)


FFA_CURRENT_VERSION_MAJOR = 1
FFA_CURRENT_VERSION_MINOR = 0
FFA_REQ_REFCOUNT = 64
FFA_CALLER_ID = 0x1
FFA_NS_CALLER_ID = 0x0


  # Inner Shareable. Combine with FFA_MEM_ATTR_NORMAL_MEMORY_#.
class FfaMemAttr(enum.IntFlag):
  """Memory region attributes."""
  # Device-nGnRnE.
  DEVICE_NGNRNE = ((1 << 4) | (0x0 << 2))
  # Device-nGnRE.
  DEVICE_NGNRE = ((1 << 4) | (0x1 << 2))
  # Device-nGRE.
  DEVICE_NGRE = ((1 << 4) | (0x2 << 2))
  # Device-GRE.
  DEVICE_GRE = ((1 << 4) | (0x3 << 2))
  # Normal memory. Non-cacheable.
  NORMAL_MEMORY_UNCACHED = ((2 << 4) | (0x1 << 2))
  # Normal memory. Write-back cached.
  NORMAL_MEMORY_CACHED_WB = ((2 << 4) | (0x3 << 2))
  # Non-shareable. Combine with NORMAL_MEMORY_*.
  NON_SHAREABLE = (0x0 << 0)
  # Outer Shareable. Combine with NORMAL_MEMORY_*.
  OUTER_SHAREABLE = (0x2 << 0)
  # Inner Shareable. Combine with NORMAL_MEMORY_*
  INNER_SHAREABLE = (0x3 << 0)
  NONSECURE = 1 << 6


class FfaMtdFlag(enum.IntFlag):
  ZERO_MEMORY = 1 << 0
  TIME_SLICING = 1 << 1
  ZERO_MEMORY_AFTER_RELINQUISH = 1 << 2
  TYPE_SHARE_MEMORY = 1 << 3
  TYPE_LEND_MEMORY = 1 << 4


FFA_MTD_FLAG_TYPE_MASK = 3 << 3
FFA_MTD_FLAG_ADDRESS_RANGE_ALIGNMENT_HINT_MASK = 0x1F << 5


class FfaMemPerm(enum.IntFlag):
  RO = 1 << 0
  RW = 1 << 1
  NX = 1 << 2
  X = 1 << 3


FfaMemoryRegion = collections.namedtuple('FfaMemoryRegion',
                                         ['addr', 'page_count', 'perm',
                                          'sender_id'])


class FfaConstMrd:
  """Constituent memory region descriptor."""

  FORMAT = '<Q2I'

  def __init__(self, addr=0, page_count=0):
    self.addr = addr
    self.page_count = page_count

  @staticmethod
  def size():
    return struct.calcsize(FfaConstMrd.FORMAT)

  def load(self, data):
    """Init FfaConstMrd from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    self.addr, self.page_count, _ = \
        struct.unpack(self.FORMAT, data[:self.size()])

    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.addr, self.page_count, 0)

  def __str__(self):
    out = 'FFA Constituent MRD:\n'
    out += f'\taddress: 0x{self.addr:x}\n'
    out += f'\tpage count: {self.page_count}\n'
    return out


class FfaCompMrd:
  """Composite memory region descriptor."""

  FORMAT = '<2IQ'

  def __init__(self, pages=0, ranges=None):
    self.total_page_count = pages
    self.address_ranges = ranges or []

  @staticmethod
  def size_base():
    return struct.calcsize(FfaCompMrd.FORMAT)

  def size(self):
    return (struct.calcsize(FfaCompMrd.FORMAT) +
            FfaConstMrd.size() * len(self.address_ranges))

  def load(self, data) -> int:
    """Init FfaCompMrd from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    self.total_page_count, count, _ = \
        struct.unpack(self.FORMAT, data[:self.size_base()])

    sz = FfaConstMrd.size() * count
    if len(data[self.size_base():]) < sz:
      raise ValueError(f'Not enough data: {len(data)} < '
                       f'{self.size_base() + sz}')

    off = self.size_base()
    for _ in range(count):
      ar = FfaConstMrd()
      off += ar.load(data[off:])
      self.address_ranges.append(ar)

    return off

  def __bytes__(self):
    out = struct.pack(self.FORMAT, self.total_page_count,
                      len(self.address_ranges), 0)
    for a in self.address_ranges:
      out += bytes(a)
    return out

  def __str__(self):
    out = 'FFA Constituent MRD:\n'
    out += f'\ttotal page count: {self.total_page_count}\n'
    out += f'\tAddress ranges({len(self.address_ranges)}):\n'
    for ar in self.address_ranges:
      out += str(ar)
    return out


class FfaMapd:
  """Memory access permissions descriptor."""

  FORMAT = '<H2B'

  def __init__(self, eid=0, perm=0, flags=0):
    self.endpoint_id = eid
    self.memory_access_permissions = perm
    self.flags = flags

  @staticmethod
  def size():
    return struct.calcsize(FfaMapd.FORMAT)

  def load(self, data):
    """Init FfaMapd from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    self.endpoint_id, self.memory_access_permissions, self.flags = \
        struct.unpack(self.FORMAT, data[:self.size()])

    return self.size()

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.endpoint_id,\
                       self.memory_access_permissions, self.flags)

  def __str__(self):
    out = 'FFA MAPD:\n'
    out += f'\tendpoint id: {self.endpoint_id}\n'
    out += f'\tmemory access permissions: {self.memory_access_permissions}\n'
    out += f'\tflags: {self.flags}\n'
    return out


class FfaEmad:
  """Endpoint memory access descriptor."""

  FORMAT = '<IQ'

  def __init__(self, mapd=None, off=0, comp_mrd=None):
    self.mapd = mapd or FfaMapd()
    self.comp_mrd_offset = off
    self.comp_mrd = comp_mrd

  @staticmethod
  def size():
    return struct.calcsize(FfaMapd.FORMAT) + struct.calcsize(FfaEmad.FORMAT)

  def load(self, data):
    """Init FfaEmad from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    self.mapd = FfaMapd()
    off = self.mapd.load(data)

    self.comp_mrd_offset, _ = \
        struct.unpack(self.FORMAT, data[off:])

    return self.size()

  def __bytes__(self):
    return bytes(self.mapd) + struct.pack(self.FORMAT, self.comp_mrd_offset, 0)

  def __str__(self):
    out = 'FFA EMAD:\n'
    out += f'\t{str(self.mapd)}\n'
    out += '\tOffset of Composite memory region descriptor: '
    out += f'{self.comp_mrd_offset}\n'
    if self.comp_mrd:
      out += '\tCompMRD:\n' + str(self.comp_mrd)
    return out


class FfaMtd:
  """Memory transaction descriptor."""

  FORMAT = '<H2BI2Q2I'

  def __init__(self, sid=0, attr=0, flags=0, handle=0,
               tag=0, emads=None):
    self.sender_id = sid
    self.memory_region_attributes = attr
    self.flags = flags
    self.handle = handle
    self.tag = tag
    self.emads = emads or []

  @staticmethod
  def size_base():
    return struct.calcsize(FfaMtd.FORMAT)

  def size(self):
    return (struct.calcsize(FfaMtd.FORMAT) +
            struct.calcsize(FfaEmad.FORMAT) * len(self.emads))

  def load(self, data):
    """Init FfaMtd from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size()}')

    self.sender_id, self.memory_region_attributes, _, self.flags, self.handle, \
        self.tag, _, emad_count = struct.unpack(self.FORMAT,
                                                data[:self.size_base()])
    sz = FfaEmad.size() * emad_count
    if len(data[self.size_base():]) < sz:
      raise ValueError(f'Not enough data: {len(data)} < '
                       f'{self.size_base() + sz}')

    off = self.size_base()
    for _ in range(emad_count):
      em = FfaEmad()
      off += em.load(data[off:])
      self.emads.append(em)

    return off

  def __bytes__(self):
    out = struct.pack(self.FORMAT, self.sender_id,
                      self.memory_region_attributes, 0, self.flags, self.handle,
                      self.tag, 0, len(self.emads))
    for e in self.emads:
      out += bytes(e)
    return out

  def __str__(self):
    out = 'FFA Mtd:\n'
    out += f'\tsender id: {self.sender_id}\n'
    out += f'\tmemory region attributes: 0x{self.memory_region_attributes:x}\n'
    out += f'\tflags: 0x{self.flags:x}\n'
    out += f'\thandle: 0x{self.handle:x}\n'
    out += f'\ttag: 0x{self.tag:x}\n'
    out += f'\tEMADs({len(self.emads)}):\n'
    for el in self.emads:
      out += str(el)
    return out


class FfaMemRelinquishDescriptor:
  """Relinquish request descriptor.

    handle:
           Id of shared memory object to relinquish.
    flags:
           If bit 0 is set clear memory after unmapping from borrower. Must be 0
           for share. Bit[1]: Time slicing. Not supported, must be 0. All other
           bits are reserved 0.
    endpoints:
           List of endpoint ids.
  """

  FORMAT = '<Q2I'
  FORMAT_ENDPOINT_ID = 'H'

  def __init__(self, handle=0, flags=0, endpoints=None):
    self.handle = handle
    self.flags = flags
    self.endpoints = endpoints or []

  @staticmethod
  def size_base():
    return struct.calcsize(FfaMemRelinquishDescriptor.FORMAT)

  @staticmethod
  def size_endpoint_id():
    return struct.calcsize(FfaMemRelinquishDescriptor.FORMAT_ENDPOINT_ID)

  @staticmethod
  def get_endpoint_count(data):
    sz = FfaMemRelinquishDescriptor.size_base()
    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    _, _, count = struct.unpack(FfaMemRelinquishDescriptor.FORMAT, data[:sz])

    return count

  def size(self):
    return (struct.calcsize(self.FORMAT) +
            struct.calcsize(self.FORMAT_ENDPOINT_ID) * len(self.endpoints))

  def load(self, data):
    """Init FfaMemRelinquishDescriptor from raw data.

    Args:
      data: Raw binary data.

    Returns:
      Length of parsed data.

    Raises:
      ValueError if not enough data is provided.
    """
    if len(data) < self.size_base():
      raise ValueError(f'Not enough data: {len(data)} < {self.size_base()}')

    self.handle, self.flags, count = \
        struct.unpack(self.FORMAT, data[:self.size_base()])

    sz = struct.calcsize(self.FORMAT_ENDPOINT_ID) * count
    if len(data[self.size_base():]) < sz:
      raise ValueError(f'Not enough data: {len(data)} < '
                       f'{self.size_base() + sz}')

    off = self.size_base()
    self.endpoints = list(struct.unpack(self.FORMAT_ENDPOINT_ID * count,
                                        data[off: off + sz]))

    return off + sz

  def __bytes__(self):
    out = struct.pack(self.FORMAT, self.handle, self.flags,
                      len(self.endpoints))
    out += struct.pack(self.FORMAT_ENDPOINT_ID * len(self.endpoints),
                       *self.endpoints)
    return out

  def __str__(self):
    out = 'FFA Memory Relinquish Descriptor:\n'
    out += f'\thandle: 0x{self.handle:x}\n'
    out += f'\tflags: {self.flags}\n'
    for e in self.endpoints:
      out += f'\tendpoint: {e}\n'
    return out
