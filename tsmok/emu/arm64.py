"""Module for base AARCH64 emulator."""

import enum
import logging
import capstone
import tsmok.emu.config as config
import tsmok.emu.emu as emu

# WORKAROUND: use unicornafl module only for fuzzing, because it is less stable
# in complex execution cases
if config.AFL_SUPPORT:
  import unicornafl as unicorn   # pylint: disable=g-import-not-at-top
  import unicornafl.arm64_const as unicorn_arm64_const  # pylint: disable=g-import-not-at-top
else:
  import unicorn as unicorn  # pylint: disable=g-import-not-at-top, disable=useless-import-alias
  import unicorn.arm64_const as unicorn_arm64_const  # pylint: disable=g-import-not-at-top


class PstateFieldMask(enum.IntEnum):
  """PSTATE register fields mask."""

  M = 1 << 2  # 2 bits
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


class PstateElMode(enum.IntEnum):
  EL0 = 0 << 2
  EL1 = 1 << 2
  EL2 = 2 << 2
  EL3 = 3 << 2


class CpacrEl1FieldMask(enum.IntEnum):
  """CPACR register filed masks."""
  FPEN = 3 << 20
  TTA = 1 << 28


class Arm64Emu(emu.Emu):
  """Implimentation of base ARM Emulator."""

  def __init__(self, name, log_level=logging.ERROR):
    # Initialize emulator in ARM64 mode
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    # Initialize disasm
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    emu.Emu.__init__(self, name, uc, cs, log_level)

    self.spsr = 0

  def _enable_vfp(self):
    val = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_CPACR_EL1)
    val |= CpacrEl1FieldMask.FPEN
    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_CPACR_EL1, val)

  def _svc_mode_setup(self):
    self._set_el_mode(PstateElMode.EL1)

  def _set_el_mode(self, mode: PstateElMode):
    pstate = self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_PSTATE)

    self.spsr = pstate

    pstate &= ~PSTATE_M_MASK
    pstate |= PstateElMode.EL1
    pstate |= PstateFieldMask.F
    pstate |= PstateFieldMask.I

    self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_PSTATE, pstate)

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
        X28 0x%016x
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
        self._uc.reg_read(unicorn_arm64_const.UC_ARM64_REG_X11))
    return regs

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

  def reset(self):
    pass

  def _set_args_to_regs(self, arg0: int, arg1: int, arg2: int, arg3: int,
                        arg4: int, arg5: int, arg6: int, arg7: int) -> None:
    """Setup registers based on arguments.

    Args:
      arg0: if not None, a value to set into X0 argegister
      arg1: if not None, a value to set into X1 argegister
      arg2: if not None, a value to set into X2 argegister
      arg3: if not None, a value to set into X3 argegister
      arg4: if not None, a value to set into X4 argegister
      arg5: if not None, a value to set into X5 argegister
      arg6: if not None, a value to set into X6 argegister
      arg7: if not None, a value to set into X7 argegister
    """
    if arg0 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X0, arg0)
    if arg1 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X1, arg1)
    if arg2 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X2, arg2)
    if arg3 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X3, arg3)
    if arg4 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X4, arg4)
    if arg5 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X5, arg5)
    if arg6 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X6, arg6)
    if arg7 is not None:
      self._uc.reg_write(unicorn_arm64_const.UC_ARM64_REG_X7, arg7)
