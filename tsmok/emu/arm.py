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

"""Module for base ARM emulator."""

import enum
import logging
import capstone
import tsmok.emu.emu as emu

import unicornafl as unicorn
import unicornafl.arm_const as unicorn_arm_const


class ArmMode(enum.Enum):
  GENERIC = 0,
  M4CLASS = 1


class CpsrFieldMask(enum.IntEnum):
  """CPSR register fields mask."""

  M = 1 << 0  # 5 bits
  T = 1 << 5
  F = 1 << 6
  I = 1 << 7
  A = 1 << 8
  E = 1 << 9
  GE = 1 << 16  # 4 bits
  DIT = 1 << 21
  PAN = 1 << 22
  SSBS = 1 << 23
  J = 1 << 24
  Q = 1 << 27
  V = 1 << 28
  C = 1 << 29
  Z = 1 << 30
  N = 1 << 31


CPSR_M_MASK = 0x1f


class CpsrPeMode(enum.IntEnum):
  USR = 0x10  # CPSR: M User mode (PL0)
  FIQ = 0x11  # CPSR: M Fast Interrupt mode (PL1)
  IRQ = 0x12  # CPSR: M Interrupt mode (PL1)
  SVC = 0x13  # CPSR: M Supervisor mode (PL1)
  MON = 0x16  # CPSR: M Monitor mode (PL1)
  ABT = 0x17  # CPSR: M Abort mode (PL1)
  HYP = 0x1A  # CPSR: M Hypervisor mode (PL2)
  UND = 0x1B  # CPSR: M Undefined mode (PL1)
  SYS = 0x1F  # CPSR: M System mode (PL1)


class ArmEmu(emu.Emu):
  """Implimentation of base ARM Emulator."""

  def __init__(self, name, log_level=logging.ERROR, mode=ArmMode.GENERIC):
    if mode == ArmMode.GENERIC:
      uc_mode = unicorn.UC_MODE_ARM
    elif mode == ArmMode.M4CLASS:
      uc_mode = unicorn.UC_MODE_THUMB | unicorn.UC_MODE_M4CLASS

    # Initialize emulator in ARM mode
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM, uc_mode)
    # Initialize disasm
    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

    emu.Emu.__init__(self, name, uc, cs, log_level)

    self._cs_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB |
                                 capstone.CS_MODE_MCLASS)

  def _svc_mode_setup(self):
    spsr = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SPSR)
    cpsr = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_CPSR)

    spsr = cpsr

    cpsr &= ~CPSR_M_MASK
    cpsr |= CpsrPeMode.SVC
    cpsr |= CpsrFieldMask.F
    cpsr |= CpsrFieldMask.I

    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_CPSR, cpsr)
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_SPSR, spsr)

  def dump_regs(self) -> None:
    cpsr = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_CPSR)
    n = cpsr >> 31 & 0x1
    z = cpsr >> 30 & 0x1
    c = cpsr >> 29 & 0x1
    v = cpsr >> 28 & 0x1
    self._log.info(
        """  REGs DUMP:
        PC 0x%08x SP  0x%08x LR  0x%08x
        Flags:
        \tN (negative): %d
        \tZ (zero)    : %d
        \tC (carry)   : %d
        \tV (overflow): %d
        Condition Codes:
        \tEQ    : %d    NE      : %d
        \tCS(HS): %d    CC(LO)  : %d
        \tMI    : %d    PL      : %d
        \tVS    : %d    VC      : %d
        \tHI    : %d    LS      : %d
        \tGE    : %d    LT      : %d
        \tGT    : %d    LE      : %d
        R0 0x%08x R4 0x%08x R8  0x%08x R12 0x%08x
        R1 0x%08x R5 0x%08x R9  0x%08x R13 0x%08x
        R2 0x%08x R6 0x%08x R10 0x%08x R14 0x%08x
        R3 0x%08x R7 0x%08x R11 0x%08x
        CPSR 0x%08x, SPSR 0x%08x
        """, self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_PC),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SP),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_LR), n, z, c, v,
        1 if z == 1 else 0, 1 if z == 0 else 1, 1 if c == 1 else 0,
        1 if c == 0 else 1, 1 if n == 1 else 0, 1 if n == 0 else 1,
        1 if v == 1 else 0, 1 if v == 0 else 0, 1 if (c == 1 and z == 0) else 0,
        1 if (c == 0 or z == 1) else 0, 1 if n == v else 0, 1 if n != v else 0,
        1 if z == 0 and n == v else 0, 1 if z == 1 or n != v else 0,
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R0),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R4),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R8),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R12),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R1),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R5),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R9),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R13),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R2),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R6),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R10),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R14),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R3),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R7),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R11),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_CPSR),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SPSR))

  # Internal API
  # ==============================================
  def get_regs(self):
    """Returns current state of genaral registers.

      Returns:
        A dict mapping a register name to its value.
    """
    regs = emu.RegContext(self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R0),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R1),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R2),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R3),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R4),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R5),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R6),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R7),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R8),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R9),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R10),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R11),
                          self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R12))
    return regs

  def set_regs(self, ctx: emu.RegContext) -> None:
    """Set registers to RegContext.

    Args:
      ctx: RegContext to be set

    Returns:
      None.
    """
    if ctx.reg0 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R0, ctx.reg0)
    if ctx.reg1 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R1, ctx.reg1)
    if ctx.reg2 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R2, ctx.reg2)
    if ctx.reg3 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R3, ctx.reg3)
    if ctx.reg4 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R4, ctx.reg4)
    if ctx.reg5 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R5, ctx.reg5)
    if ctx.reg6 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R6, ctx.reg6)
    if ctx.reg7 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R7, ctx.reg7)
    if ctx.reg8 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R8, ctx.reg8)
    if ctx.reg9 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R9, ctx.reg9)
    if ctx.reg10 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R10, ctx.reg10)
    if ctx.reg11 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R11, ctx.reg11)
    if ctx.reg12 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R12, ctx.reg12)

  def get_vbar_regs(self):
    """Returns current state of VBAR registers for EL{0-3}.

      Returns:
        A tuple for all EL{0-3} levels, starting from EL0
    """
    vbar_el0 = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_VBAR_EL0)
    vbar_el1 = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_VBAR_EL1)
    vbar_el2 = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_VBAR_EL2)
    vbar_el3 = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_VBAR_EL3)

    return vbar_el0, vbar_el1, vbar_el2, vbar_el3

  def _func_return_instruction(self, mnemonic: str, op_str: str) -> bool:
    return (mnemonic == 'ret') or \
      (mnemonic == 'pop' and 'pc' in op_str) or \
      (mnemonic.startswith('b') and op_str == 'lr')

  def _branch_instruction(self, mnemonic: str, op_str: str) -> bool:
    return mnemonic.startswith('b')

  def _disasm_instruction(self, paddr: int, vaddr: int, size: int):
    """Disassembles chunk of memeory to instruction.

    Args:
      paddr: physical address of memory
      vaddr: virtual address of memory
      size: size of memory
    """
    cs = None
    if paddr & 0x1:  # THUMB mode
      cs = self._cs_thumb
    else:
      if self._uc.query(unicorn.UC_QUERY_MODE) & unicorn.UC_MODE_THUMB:
        cs = self._cs_thumb
      else:
        cs = self._cs

    data = self._uc.mem_read(paddr & ~0x1, size)

    off = 0
    for (address, size, mnemonic, op_str) in cs.disasm_lite(bytes(data), paddr):
      self._disasm_map[address] = (address, vaddr + off, mnemonic, op_str, size)
      off += size

  def set_return_code(self, ret: int) -> None:
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R0, ret)

  def get_current_address(self) -> int:
    return self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_PC)

  def set_current_address(self, addr: int):
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_PC, addr)

  def set_return_address(self, addr: int) -> None:
    return self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_LR, addr)

  def get_stack_address(self) -> int:
    return self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SP)

  def set_stack_address(self, addr: int):
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_SP, addr)

  def get_instruction_at_address(self, address: int, size: int = 0):
    """Returns an instruction from memory address.

    Args:
      address: address of memory
      size: size of memory

    Returns:
      Address, mnemonic, operators and size as tuble

    Raises:
      Error exception if size is not match the size of single
      instruction at specifed address

    """
    return emu.Emu.get_instruction_at_address(self, address & ~0x1, size)
