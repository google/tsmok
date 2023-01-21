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

"""Module for base AARCH64 emulator."""

import enum
import logging
import capstone
import tsmok.common.error as error
import tsmok.emu.emu as emu

import unicornafl as unicorn   # pylint: disable=g-import-not-at-top
import unicornafl.arm64_const as unicorn_arm64_const  # pylint: disable=g-import-not-at-top


class PstateFieldMask(enum.IntEnum):
  """PSTATE register fields mask."""
  SP = 1 << 0
  M = 3 << 2  # 2 bits
  NRW = 1 << 4
  F = 1 << 6
  I = 1 << 7
  A = 1 << 8
  D = 1 << 9
  IL = 1 << 20
  SS = 1 << 21
  V = 1 << 28
  C = 1 << 29
  Z = 1 << 30
  N = 1 << 31


PSTATE_M_MASK = 0xf
PSTATE_EL_OFFSET = 2


class PstateElMode(enum.IntEnum):
  EL0 = 0 << PSTATE_EL_OFFSET
  EL1 = 1 << PSTATE_EL_OFFSET
  EL2 = 2 << PSTATE_EL_OFFSET
  EL3 = 3 << PSTATE_EL_OFFSET


class CpacrEl1FieldMask(enum.IntEnum):
  """CPACR register bit masks."""
  FPEN = 3 << 20
  TTA = 1 << 28


class ScrEl3(enum.IntEnum):
  """SCR_EL3 register bit mask."""
  NS = 1 << 0
  IRQ = 1 << 1
  FIQ = 1 << 2
  EA = 1 << 3
  SMD = 1 << 7
  HCE = 1 << 8
  SIF = 1 << 9
  RW = 1 << 10
  ST = 1 << 11
  TWI = 1 << 12
  TWE = 1 << 13


class EsrFieldOffset(enum.IntEnum):
  ISS2 = 32
  EC = 26
  IL = 25
  ISS = 0


class EsrFieldMask(enum.IntEnum):
  ISS2 = 0x1f << EsrFieldOffset.ISS2
  EC = 0x3f << EsrFieldOffset.EC
  IL = 1 << EsrFieldOffset.IL
  ISS = 0x1ffffff


class VectorTableBase(enum.IntEnum):
  CUR_EL_SP0 = 0x000
  CUR_EL_SPX = 0x200
  LOWER_EL_A64 = 0x400
  LOWER_EL_A32 = 0x600


class VectorTableOffset(enum.IntEnum):
  SYNC = 0x000
  IRQ = 0x080
  FIQ = 0x100
  SERROR = 0x180


class ExceptionSyndrome(enum.IntEnum):
  """AARCG64 exception syndromes."""
  UNCATEGORIZED = 0x00
  WFX_TRAP = 0x01
  CP15RTTRAP = 0x03
  CP15RRTTRAP = 0x04
  CP14RTTRAP = 0x05
  CP14DTTRAP = 0x06
  ADVSIMDFPACCESSTRAP = 0x07
  FPIDTRAP = 0x08
  CP14RRTTRAP = 0x0c
  ILLEGALSTATE = 0x0e
  AA32_SVC = 0x11
  AA32_HVC = 0x12
  AA32_SMC = 0x13
  AA64_SVC = 0x15
  AA64_HVC = 0x16
  AA64_SMC = 0x17
  SYSTEMREGISTERTRAP = 0x18
  INSNABORT = 0x20
  INSNABORT_SAME_EL = 0x21
  PCALIGNMENT = 0x22
  DATAABORT = 0x24
  DATAABORT_SAME_EL = 0x25
  SPALIGNMENT = 0x26
  AA32_FPTRAP = 0x28
  AA64_FPTRAP = 0x2c
  SERROR = 0x2f
  BREAKPOINT = 0x30
  BREAKPOINT_SAME_EL = 0x31
  SOFTWARESTEP = 0x32
  SOFTWARESTEP_SAME_EL = 0x33
  WATCHPOINT = 0x34
  WATCHPOINT_SAME_EL = 0x35
  AA32_BKPT = 0x38
  VECTORCATCH = 0x3a
  AA64_BKPT = 0x3c


class SctlrField(enum.IntEnum):
  """SCRLR register bit fields."""
  M = 1 << 0
  A = 1 << 1
  C = 1 << 2
  SA = 1 << 3
  SA0 = 1 << 4
  CP15BEN = 1 << 5
  NAA = 1 << 6
  ITD = 1 << 7
  SED = 1 << 8
  UMA = 1 << 9
  ENRCTX = 1 << 10
  EOS = 1 << 11
  I = 1 << 12
  ENDB = 1 << 13
  DZE = 1 << 14
  UCT = 1 << 15
  NTWI = 1 << 16
  NTWE = 1 << 18
  WXN = 1 << 19
  TSCXT = 1 << 20
  IESB = 1 << 21
  EIS = 1 << 22
  SPAN = 1 << 23
  E0E = 1 << 24
  EE = 1 << 25
  UCI = 1 << 26
  ENDA = 1 << 27
  NTLSMD = 1 << 28
  LSMAOE = 1 << 29
  ENIB = 1 << 30
  ENIA = 1 << 31
  BT0 = 1 << 35
  BT1 = 1 << 36
  ITFSB = 1 << 37
  TCF0 = 1 << 38
  TCF = 1 << 40
  ATA0 = 1 << 42
  ATA = 1 << 43
  DSSBS = 1 << 44
  TWEDEN = 1 << 45
  TWEDEL = 1 << 46
  ENASR = 1 << 54
  ENAS0 = 1 << 55
  ENALS = 1 << 56
  EPAN = 1 << 57


class Arm64Emu(emu.Emu):
  """Implimentation of base ARM Emulator."""

  def __init__(self, name, log_level=logging.ERROR):
    # Initialize emulator in ARM64 mode
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    # Initialize disasm
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    emu.Emu.__init__(self, name, uc, cs, log_level)

  def _enable_vfp(self):
    val = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_CPACR_EL1)
    val |= CpacrEl1FieldMask.FPEN
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_CPACR_EL1, val)

  def _svc_mode_setup(self):
    self._set_el_mode(PstateElMode.EL1)

  def _set_el_mode(self, mode: int):
    pstate = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PSTATE)

    pstate &= ~PSTATE_M_MASK
    pstate |= PstateElMode.EL1
    pstate |= PstateFieldMask.D
    pstate |= PstateFieldMask.A
    pstate |= PstateFieldMask.I
    pstate |= PstateFieldMask.F
    pstate |= mode

    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_PSTATE, pstate)

  def _set_aarch64_mode(self):
    scr = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_SCR_EL3)
    scr |= ScrEl3.RW
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_SCR_EL3, scr)

  def _allow_access_to_stimer(self):
    scr = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_SCR_EL3)
    scr |= ScrEl3.ST
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_SCR_EL3, scr)

  def _allow_access_ctr_el0(self):
    sctlr = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_SCTLR)
    sctlr |= SctlrField.UCT
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_SCTLR, sctlr)

  def _get_exception_syndrom(self, el_mode):
    mode_esr = {
        PstateElMode.EL1: unicorn_arm64_const.UC_ARM64_REG_ESR_EL1,
        PstateElMode.EL2: unicorn_arm64_const.UC_ARM64_REG_ESR_EL2,
        PstateElMode.EL3: unicorn_arm64_const.UC_ARM64_REG_ESR_EL3,
    }
    try:
      val = self._uc.reg_read(mode_esr[el_mode & PstateFieldMask.M])
    except KeyError:
      return None

    try:
      return ExceptionSyndrome((val & EsrFieldMask.EC) >> EsrFieldOffset.EC)
    except ValueError:
      return None

  def _get_excp_target_el_mode(self, exc):
    pstate = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PSTATE)

    cur_mode = pstate & PstateFieldMask.M

    target_el = {
        # TODO(dmitryya) add IRQ and FIQ support
        # IRQ: ???,
        # FIQ: ???,
        emu.Emu.ExceptionType.HVC: PstateElMode.EL2,
        emu.Emu.ExceptionType.HYP_TRAP: PstateElMode.EL2,
        emu.Emu.ExceptionType.SMC: PstateElMode.EL3,
        emu.Emu.ExceptionType.VIRQ: PstateElMode.EL1,
        emu.Emu.ExceptionType.VFIQ: PstateElMode.EL1,
    }

    try:
      new_el = target_el[exc]
    except KeyError:  # default value
      new_el = max(cur_mode, PstateElMode.EL1)

    return new_el | PstateFieldMask.SP

  def _save_state_for_exception_call(self, new_el):
    if new_el == PstateElMode.EL0:
      raise error.Error('Unsupported target exception level EL0')

    new_mode_regs = {
        PstateElMode.EL1: (unicorn_arm64_const.UC_ARM64_REG_VBAR_EL1,
                           unicorn_arm64_const.UC_ARM64_REG_SPSR_EL1,
                           unicorn_arm64_const.UC_ARM64_REG_ELR_EL1,
                           unicorn_arm64_const.UC_ARM64_REG_SP_EL1
                          ),
        PstateElMode.EL2: (unicorn_arm64_const.UC_ARM64_REG_VBAR_EL2,
                           unicorn_arm64_const.UC_ARM64_REG_SPSR_EL2,
                           unicorn_arm64_const.UC_ARM64_REG_ELR_EL2,
                           unicorn_arm64_const.UC_ARM64_REG_SP_EL2
                          ),
        PstateElMode.EL3: (unicorn_arm64_const.UC_ARM64_REG_VBAR_EL3,
                           unicorn_arm64_const.UC_ARM64_REG_SPSR_EL3,
                           unicorn_arm64_const.UC_ARM64_REG_ELR_EL3,
                           unicorn_arm64_const.UC_ARM64_REG_SP_EL3
                          ),
    }
    cur_mode_sp = {
        PstateElMode.EL0: unicorn_arm64_const.UC_ARM64_REG_SP_EL0,
        PstateElMode.EL1: unicorn_arm64_const.UC_ARM64_REG_SP_EL1,
        PstateElMode.EL2: unicorn_arm64_const.UC_ARM64_REG_SP_EL2,
        PstateElMode.EL3: unicorn_arm64_const.UC_ARM64_REG_SP_EL3,
    }

    pstate = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PSTATE)
    cur_el_mode = pstate & PstateFieldMask.M
    pstate_sp = pstate & PstateFieldMask.SP
    aarch64 = pstate & PstateFieldMask.NRW == 0
    cur_sp = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_SP)
    cur_pc = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PC)

    regs = new_mode_regs[new_el & PstateFieldMask.M]
    # exception handling base addr from VBAR_EL(new_el)
    addr = self._uc.reg_read(regs[0])

    if cur_el_mode < new_el:
      if aarch64:
        addr += VectorTableBase.LOWER_EL_A64
      else:
        addr += VectorTableBase.LOWER_EL_A32
    elif pstate_sp:
      addr += VectorTableBase.CUR_EL_SPX

    if aarch64:
      # store PSTATE to SPSR_EL(new_el)
      self._uc.reg_write(regs[1], pstate)
      # save current SP
      if pstate_sp:
        self._uc.reg_write(cur_mode_sp[cur_el_mode & PstateFieldMask.M], cur_sp)
      else:
        self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_SP_EL0, cur_sp)

      # store PC to ELR_EL(new_el)
      self._uc.reg_write(regs[2], cur_pc)
    else:
      raise error.Error('ARM32 mode is not supported for now!')

    # restore new SP
    if new_el & PstateFieldMask.SP:
      new_sp = self._uc.reg_read(regs[3])
    else:
      new_sp = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_SP_EL0)

    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_SP, new_sp)

    # set new EL mode
    self._set_el_mode(new_el)

    return addr

  def is_pstate_a64_mode(self):
    pstate = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PSTATE)
    return (pstate & PstateFieldMask.NRW) == 0

  def dump_regs(self) -> None:
    pstate = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PSTATE)
    n = 1 if pstate & PstateFieldMask.N else 0
    z = 1 if pstate & PstateFieldMask.Z else 0
    c = 1 if pstate & PstateFieldMask.C else 0
    v = 1 if pstate & PstateFieldMask.V else 0

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
        X0  0x%016x X1  0x%016x
        X2  0x%016x X3  0x%016x
        X4  0x%016x X5  0x%016x
        X6  0x%016x X7  0x%016x
        X8  0x%016x X9  0x%016x
        X10 0x%016x X11 0x%016x
        X12 0x%016x X13 0x%016x
        X14 0x%016x X15 0x%016x
        X16 0x%016x X17 0x%016x
        X18 0x%016x X19 0x%016x
        X20 0x%016x X21 0x%016x
        X22 0x%016x X23 0x%016x
        X24 0x%016x X25 0x%016x
        X26 0x%016x X27 0x%016x
        X28 0x%016x X29 0x%016x
        X30 0x%016x
        PSTATE 0x%08x
        """, self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PC),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_SP),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_LR), n, z, c, v,
        1 if z == 1 else 0, 1 if z == 0 else 1, 1 if c == 1 else 0,
        1 if c == 0 else 1, 1 if n == 1 else 0, 1 if n == 0 else 1,
        1 if v == 1 else 0, 1 if v == 0 else 0, 1 if (c == 1 and z == 0) else 0,
        1 if (c == 0 or z == 1) else 0, 1 if n == v else 0, 1 if n != v else 0,
        1 if z == 0 and n == v else 0, 1 if z == 1 or n != v else 0,
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X0),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X1),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X2),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X3),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X4),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X5),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X6),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X7),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X8),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X9),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X10),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X11),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X12),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X13),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X14),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X15),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X16),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X17),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X18),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X19),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X20),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X21),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X22),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X23),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X24),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X25),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X26),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X27),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X28),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X29),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X30),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PSTATE))

  # Internal API
  # ==============================================
  def get_regs(self):
    """Returns current state of genaral registers.

      Returns:
        A dict mapping a register name to its value.
    """
    regs = emu.RegContext(
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X0),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X1),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X2),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X3),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X4),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X5),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X6),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X7),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X8),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X9),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X10),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X11),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X12),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X13),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X14),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X15),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X16),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X17),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X18),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X19),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X20),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X21),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X22),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X23),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X24),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X25),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X26),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X27),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X28),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X29),
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X30))
    return regs

  def set_regs(self, ctx: emu.RegContext) -> None:
    """Set registers to RegContext.

    Args:
      ctx: RegContext to be set

    Returns:
      None.
    """
    if ctx.reg0 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X0, ctx.reg0)
    if ctx.reg1 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X1, ctx.reg1)
    if ctx.reg2 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X2, ctx.reg2)
    if ctx.reg3 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X3, ctx.reg3)
    if ctx.reg4 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X4, ctx.reg4)
    if ctx.reg5 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X5, ctx.reg5)
    if ctx.reg6 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X6, ctx.reg6)
    if ctx.reg7 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X7, ctx.reg7)
    if ctx.reg8 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X8, ctx.reg8)
    if ctx.reg9 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X9, ctx.reg9)
    if ctx.reg10 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X10, ctx.reg10)
    if ctx.reg11 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X11, ctx.reg11)
    if ctx.reg12 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X12, ctx.reg12)
    if ctx.reg13 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X13, ctx.reg13)
    if ctx.reg14 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X14, ctx.reg14)
    if ctx.reg15 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X15, ctx.reg15)
    if ctx.reg16 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X16, ctx.reg16)
    if ctx.reg17 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X17, ctx.reg17)
    if ctx.reg18 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X18, ctx.reg18)
    if ctx.reg19 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X19, ctx.reg19)
    if ctx.reg20 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X20, ctx.reg20)
    if ctx.reg21 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X21, ctx.reg21)
    if ctx.reg22 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X22, ctx.reg22)
    if ctx.reg23 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X23, ctx.reg23)
    if ctx.reg24 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X24, ctx.reg24)
    if ctx.reg25 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X25, ctx.reg25)
    if ctx.reg26 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X26, ctx.reg26)
    if ctx.reg27 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X27, ctx.reg27)
    if ctx.reg28 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X28, ctx.reg28)
    if ctx.reg29 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X29, ctx.reg29)
    if ctx.reg30 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X30, ctx.reg30)

  def get_vbar_regs(self):
    """Returns current state of VBAR registers for EL{0-3}.

      Returns:
        A tuple for all EL{0-3} levels, starting from EL0
    """
    vbar_el0 = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_VBAR_EL0)
    vbar_el1 = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_VBAR_EL1)
    vbar_el2 = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_VBAR_EL2)
    vbar_el3 = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_VBAR_EL3)

    return vbar_el0, vbar_el1, vbar_el2, vbar_el3

  def _func_return_instruction(self, mnemonic: str, op_str: str) -> bool:
    return (mnemonic == 'ret') or \
      (mnemonic == 'pop' and 'pc' in op_str) or \
      (mnemonic.startswith('b') and op_str == 'lr')

  def _branch_instruction(self, mnemonic: str, op_str: str) -> bool:
    return mnemonic.startswith('b')

  def set_return_code(self, ret: int) -> None:
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X0, ret)

  def get_current_address(self) -> int:
    return self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PC)

  def set_current_address(self, addr: int):
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_PC, addr)

  def set_return_address(self, addr: int) -> None:
    return self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_LR, addr)

  def get_stack_address(self) -> int:
    return self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_SP)

  def set_stack_address(self, addr: int):
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_SP, addr)
