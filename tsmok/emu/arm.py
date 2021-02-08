"""Module for base ARM emulator."""

import collections
import enum
import logging
import math
import struct
from typing import Dict
import capstone
import portion
import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.common.image as image
import tsmok.common.memory as memory
import tsmok.common.round_up as round_up
import tsmok.coverage.base as coverage
import tsmok.emu.config as config

# WORKAROUND: use unicornafl module only for fuzzing, because it is less stable
# in complex execution cases
if config.AFL_SUPPORT:
  import unicornafl as unicorn   # pylint: disable=g-import-not-at-top
  import unicornafl.arm_const as unicorn_arm_const  # pylint: disable=g-import-not-at-top
  import unicornafl.unicorn_const as unicorn_const  # pylint: disable=g-import-not-at-top
else:
  import unicorn as unicorn  # pylint: disable=g-import-not-at-top, disable=useless-import-alias
  import unicorn.arm_const as unicorn_arm_const  # pylint: disable=g-import-not-at-top
  import unicorn.unicorn_const as unicorn_const  # pylint: disable=g-import-not-at-top


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


RegContext = collections.namedtuple('RegContext', ['r0', 'r1', 'r2', 'r3',
                                                   'r4', 'r5', 'r6', 'r7'])


class ArmEmu:
  """Implimentation of base ARM Emulator."""

  PAGE_SIZE = 4096

  class InstrInfo(enum.Flag):
    BRANCH = enum.auto()
    RET = enum.auto()
    SVC = enum.auto()

  class ExceptionType(enum.IntFlag):
    """Exception types wich can be raised from emulated code."""

    UDEF = 1  # undefined instruction
    SWI = 2  # software interrupt
    PREFETCH_ABORT = 3
    DATA_ABORT = 4
    IRQ = 5
    FIQ = 6
    BKPT = 7
    EXCEPTION_EXIT = 8  # Return from v7M exception.
    KERNEL_TRAP = 9  # Jumped to kernel code page.
    STREX = 10
    HVC = 11  # HyperVisor Call
    HYP_TRAP = 12
    SMC = 13  # Secure Monitor Call
    VIRQ = 14
    VFIQ = 15

  def __init__(self, name, log_level=logging.ERROR, mode=ArmMode.GENERIC):

    logging.addLevelName(const.LogLevelCustom.DEBUG_DISASM, 'DEBUG_DISASM')
    logging.addLevelName(const.LogLevelCustom.DEBUG_MEM, 'DEBUG_MEM')
    logging.addLevelName(const.LogLevelCustom.TRACE, 'TRACE')

    self._log = logging.getLogger(name)
    self._log.setLevel(log_level)
    self._log_level = log_level

    if mode == ArmMode.GENERIC:
      uc_mode = unicorn.UC_MODE_ARM
    elif mode == ArmMode.M4CLASS:
      uc_mode = unicorn.UC_MODE_THUMB | unicorn.UC_MODE_M4CLASS

    # Initialize emulator in ARM mode
    self._uc = unicorn.Uc(unicorn.UC_ARCH_ARM, uc_mode)
    self._ret0 = 0
    self._stack_ptr = 0
    self._stack_size = 0

    self.exception = None

    # Initialize disasm
    self._cs_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    self._cs_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB |
                                 capstone.CS_MODE_MCLASS)

    self._func_stack = []
    self.image = None

    self._disasm_map = {}
    self._mem_mapped_regions = portion.empty()
    self._mem_region_access = portion.IntervalDict()

    self.exception_handler = dict()

    self._coverage_registered = dict()

    self._hooks_handlers = []
    self._mem_unmapped_handlers = portion.IntervalDict()
    self._mem_invalid_handlers = portion.IntervalDict()

    self._hooks_setup()

  def _hooks_setup(self) -> None:
    """Setup Unicorn hooks."""

    # HOOKs for tracing
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_WRITE_INVALID,
                                self._hook_invalid)
    self._hooks_handlers.append(handler)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_READ_INVALID,
                                self._hook_invalid)
    self._hooks_handlers.append(handler)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_FETCH_INVALID,
                                self._hook_invalid)
    self._hooks_handlers.append(handler)

    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_READ_AFTER,
                                self._hook_mem_read_after)
    self._hooks_handlers.append(handler)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_WRITE,
                                self._hook_mem_write)
    self._hooks_handlers.append(handler)

    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_FETCH_UNMAPPED,
                                self._hook_mem_unmapped)
    self._hooks_handlers.append(handler)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_READ_UNMAPPED,
                                self._hook_mem_unmapped)
    self._hooks_handlers.append(handler)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_WRITE_UNMAPPED,
                                self._hook_mem_unmapped)
    self._hooks_handlers.append(handler)

    handler = self._uc.hook_add(unicorn_const.UC_HOOK_INSN_INVALID,
                                self._hook_insn_invalid)
    self._hooks_handlers.append(handler)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_INTR,
                                self._hook_interrupt)
    self._hooks_handlers.append(handler)

    if self._log_level <= logging.INFO:
      handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_READ,
                                  self._hook_mem_read)
      self._hooks_handlers.append(handler)
      handler = self._uc.hook_add(unicorn_const.UC_HOOK_BLOCK,
                                  self._hook_block)
      self._hooks_handlers.append(handler)
      handler = self._uc.hook_add(unicorn_const.UC_HOOK_CODE,
                                  self._hook_code)
      self._hooks_handlers.append(handler)

  # EMU Hooks
  # ===============================================================
  def _hook_interrupt(self, uc: unicorn.Uc, exc_idx: int, udata) -> None:
    """Hook to catch inturrupts from emulated code.

    Calls external interrupt handlers. May stop execution.

    Args:
      uc: [unused] Unicorn instance
      exc_idx: An exception type. Values are in ExceptionType
      udata: [unused] User provided data during registering the hook
    """

    del uc, udata  # unused by the hook
    exc = self.ExceptionType(exc_idx)
    pc = self.get_current_address()
    self._log.debug('0x%08x: interrupted by EXCEPTION %s', pc, exc)

    if exc in self.exception_handler:
      regs = self.get_regs()
      self.exception_handler[exc](regs)
    else:
      self.dump_regs()
      self.exit_with_exception(error.Error(f'Unhandled exception: {exc}'))

  # callback for tracing basic blocks
  def _hook_block(self, uc: unicorn.Uc, addr: int, size: int, udata):
    """Hook for execuded block from emulated code.

    Args:
      uc: [unused] Unicorn instance
      addr: The address of block
      size: Size of the execuded block
      udata: [unused] User provided data during registering the hook
    """

    del uc, udata  # unused by the hook
    self._log.log(
        const.LogLevelCustom.TRACE,
        '\t\t\t\t\t\t>>> Tracing basic block at 0x%08x, block size = 0x%08x',
        addr, size)
    if self._log_level <= logging.DEBUG:
      self._disasm_instruction(addr, size)

  # callback for tracing instructions
  def _hook_code(self, uc: unicorn.Uc, addr: int, size: int, udata):
    """Hook for execuded instruction from emulated code.

    Emulation can be stopped in this hook if |addr| is not belong to any
    memory region or a region does not have execution permission.

    Args:
      uc: [unused] Unicorn instance
      addr: The address of block
      size: Size of the execuded block
      udata: [unused] User provided data during registering the hook
    """

    del uc, udata  # unused by the hook
    self._log.log(const.LogLevelCustom.TRACE,
                  '\t\t\t\t\t\t>>> Code hook 0x%08x size %d SP 0x%08x', addr,
                  size, self.get_stack_pointer())

    pc = self.get_current_address()
    try:
      perm = self._mem_region_access[addr]
      if not perm & memory.MemAccessPermissions.R:
        self.exit_with_exception(error.Error(f'0x{pc:08x}: Unallowed memory '
                                             f'READ access: 0x{addr:08x}'))
    except KeyError:
      self.exit_with_exception(error.Error(f'0x{pc:08x}: Unmapped memory '
                                           f'READ access: 0x{addr:08x}'))

    if self._log_level <= logging.DEBUG:
      info = self._instruction_examination(addr, size)
      self._func_symbols_handler(addr, info)

  # callback for tracing read memory
  def _hook_mem_read(self, uc: unicorn.Uc, access: int, addr: int, size: int,
                     value: int, udata):
    """Hook for read access to memory. Called before actual reading of data.

    Args:
      uc: [unused] Unicorn instance
      access: [unused] type of access to memory: READ, WRITE or FETCH [unused]
      addr: The address of memory
      size: Size of the memory chunk to be read
      value: 0x0 in this hook
      udata: [unused] User provided data during registering the hook
    """

    del uc, access, value, udata  # unused by the hook
    self._log.log(const.LogLevelCustom.TRACE,
                  '\t\t\t\t\t\t[MEM][pc 0x%08x] READ at 0x%08x, '
                  'size = 0x%08x', self.get_current_address(), addr, size)

  def _hook_mem_read_after(self, uc: unicorn.Uc, access: int, addr: int,
                           size: int, value: int, udata):
    """Hook for read access to memory. Called after actual reading of data.

    Args:
      uc: [unused] Unicorn instance
      access: [unused] type of access to memory: READ, WRITE or FETCH [unused]
      addr: The address of memory
      size: Size of the memory chunk to be read
      value: a value which was read from memory
      udata: [unused] User provided data during registering the hook
    """

    del uc, access, udata  # unused by the hook
    self._log.log(
        const.LogLevelCustom.DEBUG_MEM,
        '\t\t\t\t\t\t[MEM][pc 0x%08x] READ AFTER at 0x%08x, '
        'size = 0x%08x, value = 0x%08x', self.get_current_address(), addr,
        size, value)

    try:
      perm = self._mem_region_access[addr]
      if not perm & memory.MemAccessPermissions.R:
        self.exit_with_exception(
            error.Error(f'0x{self.get_current_address():08x}: Unallowed memory '
                        f'READ access: 0x{addr:08x}'))
    except KeyError:
      self.exit_with_exception(
          error.Error(f'0x{self.get_current_address():08x}: Unmapped memory '
                      f'READ access: 0x{addr:08x}'))

  # callback for tracing write memory
  def _hook_mem_write(self, uc: unicorn.Uc, access: int, addr: int, size: int,
                      value: int, udata):
    """Hook for write access to memory.

    Args:
      uc: [unused] Unicorn instance
      access: [unused] type of access to memory: READ, WRITE or FETCH [unused]
      addr: The address of memory
      size: Size of the memory chunk to be read
      value: A value to be written to memory
      udata: [unused] User provided data during registering the hook
    """

    del uc, access, udata  # unused by the hook
    self._log.log(
        const.LogLevelCustom.DEBUG_MEM,
        '\t\t\t\t\t\t[MEM][pc 0x%08x] WRITE at 0x%08x, size = 0x%08x, '
        'value = 0x%08x', self.get_current_address(), addr, size, value)

    try:
      perm = self._mem_region_access[addr]
      if not perm & memory.MemAccessPermissions.W:
        self.exit_with_exception(
            error.Error(f'0x{self.get_current_address():08x}: Unallowed memory '
                        f'WRITE access: 0x{addr:08x}'))
    except KeyError:
      self.exit_with_exception(
          error.Error(f'0x{self.get_current_address():08x}: Unmapped memory '
                      f'WRITE access: 0x{addr:08x}'))

  # callback for tracing invalid instructions
  def _hook_insn_invalid(self, uc: unicorn.Uc, udata) -> bool:
    """Hook for illegal instruction.

    Args:
      uc: [unused] Unicorn instance
      udata: [unused] User provided data during registering the hook

    Returns:
      True if this hook handled the invocation, False, if other hooks have to
      handle.
    """

    del uc, udata  # unused by the hook
    self.exit_with_exception(error.Error('Invalid instruction at addr '
                                         f'0x{self.get_current_address():08x}'))
    self.dump_regs()
    spsr = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SPSR)
    cpsr = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_CPSR)
    self._log.info('CPSR 0x%08x, SPSR 0x%08x', cpsr, spsr)
    return True

  def _hook_invalid(self, uc: unicorn.Uc, access: int, address: int, size: int,
                    value: int, udata) -> bool:
    """Hook for invalid access to memory.

    Args:
      uc: [unused] Unicorn instance
      access: type of access to memory: READ, WRITE or FETCH
      address: The address of memory
      size: Size of the memory chunk to be read
      value: [unused] A value to be read/written from/to memory
      udata: [unused] User provided data during registering the hook

    Returns:
      True if this hook handled the invocation, False, if other hooks have to
      handle.
    """

    del uc, value, udata  # unused by the hook
    ranges = self._mem_invalid_handlers[portion.closedopen(address,
                                                           address + size)]
    if not ranges:
      pc = self.get_current_address()
      self.exit_with_exception(error.Error('[MEM] Invalid memory access at '
                                           f'0x{pc:08x} to 0x{address:08x}, '
                                           f'size {size}.'))
      return True
    if len(ranges) != 1:
      pc = self.get_current_address()
      self.exit_with_exception(error.Error('[MEM] Invalid: Wrong number of '
                                           f'handlers ({len(ranges)}) for at '
                                           f'0x{pc:08x} to 0x{address:08x}, '
                                           f'size = 0x{size:08x}.'))
      return True
    return ranges.values()[0](self, access, address, size)

  def _hook_mem_unmapped(self, uc: unicorn.Uc, access: int, address: int,
                         size: int, value: int, udata) -> bool:
    """Hook for accessing unmapped memory.

    Args:
      uc: [unused] Unicorn instance
      access: type of access to memory: READ, WRITE or FETCH
      address: The address of memory
      size: Size of the memory chunk to be read
      value: [unused] A value to be read/written from/to memory
      udata: [unused] User provided data during registering the hook

    Returns:
      True if this hook handled the invocation, False, if other hooks have to
      handle.
    """

    del uc, value, udata  # unused by the hook
    ranges = self._mem_unmapped_handlers[portion.closedopen(address,
                                                            address + size)]
    if not ranges:
      pc = self.get_current_address()
      self.exit_with_exception(error.Error(f'[MEM] Unmapped at 0x{pc:08x} to '
                                           f'0x{address:08x}, '
                                           f'size = 0x{size:08x}.'))
      return True
    if len(ranges) != 1:
      pc = self.get_current_address()
      self.exit_with_exception(error.Error('[MEM] Unmapped: Wrong number of '
                                           f'handlers ({len(ranges)}) for at '
                                           f'0x{pc:08x} to 0x{address:08x}, '
                                           f'size = 0x{size:08x}.'))
      return True
    return ranges.values()[0](self, access, address, size)

  def _convert_error(self, uc_error: unicorn.UcError):
    """Converts Unicorn exceptions.

    Args:
      uc_error: error from Unicorn engine

    Returns:
      corresponding tsmok.common.error.*Error exception
    """
    mem_errors = [
        unicorn.unicorn_const.UC_ERR_READ_UNMAPPED,
        unicorn.unicorn_const.UC_ERR_READ_PROT,
        unicorn.unicorn_const.UC_ERR_READ_UNALIGNED,
        unicorn.unicorn_const.UC_ERR_WRITE_UNMAPPED,
        unicorn.unicorn_const.UC_ERR_WRITE_PROT,
        unicorn.unicorn_const.UC_ERR_WRITE_UNALIGNED,
        unicorn.unicorn_const.UC_ERR_FETCH_UNMAPPED,
        unicorn.unicorn_const.UC_ERR_FETCH_PROT,
        unicorn.unicorn_const.UC_ERR_FETCH_UNALIGNED,
    ]
    if uc_error.errno in mem_errors:
      # Memory error - throw SIGSEGV
      exc = error.SegfaultError
    elif uc_error.errno == unicorn.unicorn_const.UC_ERR_INSN_INVALID:
      # Invalid instruction - throw SIGILL
      exc = error.SigIllError
    else:
      # Not sure what happened - throw SIGABRT
      exc = error.AbortError
    return exc(f'Emulation failed with error code: {str(uc_error)}')

  # ELF calls
  # ===============================================================
  def dump_regs(self) -> None:
    cpsr = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_CPSR)
    n = cpsr >> 31 & 0x1
    z = cpsr >> 30 & 0x1
    c = cpsr >> 29 & 0x1
    v = cpsr >> 28 & 0x1
    self._log.info(
        """  REGs DUMP:
        SP 0x%08x PC  0x%08x LR  0x%08x
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
        """, self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SP),
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_PC),
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
        self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R11))

  # Internal API
  # ==============================================
  def get_regs(self) -> Dict[str, int]:
    """Returns current state of genaral registers.

      Returns:
        A dict mapping a register name to its value.
    """

    regs = RegContext(self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R0),
                      self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R1),
                      self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R2),
                      self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R3),
                      self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R4),
                      self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R5),
                      self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R6),
                      self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R7))

    return regs

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

  def _get_disasm_str(self, addr: int) -> str:
    s = ''
    if addr in self._disasm_map:
      address, mnemonic, op_str, _ = self._disasm_map[addr]
      s = '0x{:08x}:  {:8s}    {}'.format(address, mnemonic, op_str)

    return s

  def _disasm_instruction(self, addr: int, size: int):
    """Disassembles chunk of memeory to instruction.

    Args:
      addr: address of memory
      size: size of memory
    """

    cs = None
    if addr & 0x1:  # THUMB mode
      cs = self._cs_thumb
    else:
      if self._uc.query(unicorn.UC_QUERY_MODE) & unicorn.UC_MODE_THUMB:
        cs = self._cs_thumb
      else:
        cs = self._cs_arm

    data = self._uc.mem_read(addr & ~0x1, size)

    for (address, size, mnemonic, op_str) in cs.disasm_lite(bytes(data), addr):
      self._disasm_map[address] = (address, mnemonic, op_str, size)

  def _instruction_examination(self, addr: int, size: int):
    """Examines an instruction.

    Examinas an instruction by given address (dissassembles memory if needed)
    and returns information in InstrInfo format.

    Args:
      addr: The address of an instruction
      size: The size of the instruction.

    Returns:
      InstrInfo is returned with information
    """
    info = self.InstrInfo(0)

    if addr not in self._disasm_map:
      self._disasm_instruction(addr, size)

    if addr not in self._disasm_map:
      return info

    instr_str = self._get_disasm_str(addr)
    self._log.log(const.LogLevelCustom.DEBUG_DISASM, '\t\t\t %s', instr_str)

    addr, mnemonic, op_str, _ = self._disasm_map[addr]
    if self._func_return_instruction(mnemonic, op_str):
      info |= self.InstrInfo.RET

    if mnemonic.startswith('b'):
      info |= self.InstrInfo.BRANCH

    return info

  def _func_symbols_handler(self, addr: int, info: InstrInfo):
    """Tracks function call stack.

    Args:
      addr: address of current executed instruction
      info: Information about current instruction in InstrInfo format
    """

    func = ''
    if self.image.func_symbols:
      if addr in self.image.func_symbols:
        func = self.image.func_symbols[addr]
      # symtab may have address in THUMB mode
      elif addr + 1 in self.image.func_symbols:
        func = self.image.func_symbols[addr + 1]

    macro = self.InstrInfo.BRANCH in info and self.InstrInfo.RET not in info

    if func:  # entrance into function is detected
      if not macro:
        self._func_stack.insert(0, func)
      self._log.debug(".exec. => '%s' %s", func, '(macro)' if macro else '')
    else:  # we somewhere in the body of a function
      if self.InstrInfo.RET in info:
        if self._func_stack:
          func = self._func_stack[0]
          del self._func_stack[0]
        self._log.debug(".exec. <= '%s'", func)

  def set_return_code(self, ret: int) -> None:
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R0, ret)

  def get_current_address(self) -> int:
    return self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_PC)

  def get_stack_pointer(self) -> int:
    return self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SP)

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
    if (address & ~0x1) not in self._disasm_map:
      self._disasm_instruction(address, size if size else 4)

    if (address & ~0x1) not in self._disasm_map:
      raise error.Error(f'Failed to get instruction info at 0x{address:08x}')

    addr, mnemonic, op_str, sz = self._disasm_map[address & ~0x1]
    if size and size != sz:
      raise error.Error('Requested size does not match instruction size: '
                        f'{size} != {sz}. More than one instcruction '
                        'are there.')
    return addr, mnemonic, op_str, sz

  def set_return_address(self, addr: int) -> None:
    return self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_LR, addr)

  def mem_read(self, addr: int, size: int) -> bytearray:
    self._log.log(const.LogLevelCustom.DEBUG_MEM,
                  '\t\t\t\t\t\tMEM read 0x%08x - 0x%08x, size %d', addr,
                  addr + size - 1, size)
    return bytes(self._uc.mem_read(addr, size))

  def mem_write(self, addr: int, value: bytearray) -> None:
    end_addr = addr + len(value) - 1
    self._log.log(const.LogLevelCustom.DEBUG_MEM,
                  '\t\t\t\t\t\tMEM write 0x%08x - 0x%08x, size %d', addr,
                  end_addr, len(value))
    self._uc.mem_write(addr, value)

  def u32_write(self, addr: int, value: int) -> None:
    self.mem_write(addr, struct.pack('I', value))

  def u32_read(self, addr: int) -> int:
    values = struct.unpack('I', self.mem_read(addr, 4))
    return values[0]

  def mem_clean(self, addr: int, size: int) -> None:
    self._uc.mem_write(addr, b'\x00' * size)

  def map_memory(self, addr: int, size: int, perm: memory.MemAccessPermissions
                ):
    """Map memory range to EMU address space.

    Args:
      addr: The start address of memory range
      size: The size of memory range
      perm: memory range permissions.
    """
    self._log.debug('Map region (in): 0x%08x - 0x%08x', addr,
                    addr + size - 1)

    addr_fixed = math.floor(addr / self.PAGE_SIZE) * self.PAGE_SIZE
    size_fixed = round_up.round_up(size + addr - addr_fixed, self.PAGE_SIZE)

    self._log.debug('Map region (fixed): 0x%08x - 0x%08x', addr_fixed,
                    addr_fixed + size_fixed - 1)

    res = (portion.closedopen(addr_fixed, addr_fixed + size_fixed)
           - self._mem_mapped_regions)

    for i in res:
      if i.empty:
        continue
      if not isinstance(i, portion.interval.Interval):
        continue
      a = i.lower
      if i.left == portion.OPEN:
        a += 1
      s = i.upper - a
      if i.right == portion.CLOSED:
        s += 1
      self._log.debug('Map region (left): 0x%08x - 0x%08x', a, a+s)
      if s:
        self._uc.mem_map(a, s)

    self._mem_mapped_regions |= res
    chunk = portion.IntervalDict({portion.closedopen(addr, addr + size): perm})
    combine_perm = lambda orig, new: orig | new
    self._mem_region_access = self._mem_region_access.combine(chunk,
                                                              how=combine_perm)

  def load_to_mem(self, name: str, addr: int, data: bytes,
                  perm: memory.MemAccessPermissions) -> None:
    self._log.debug("Load '%s' to addr 0x%08x, size %d", name, addr, len(data))
    self.map_memory(addr, len(data), perm)
    self._uc.mem_write(addr, data)

  def set_stack(self, addr: int, size: int):
    self.map_memory(addr - size, size, memory.MemAccessPermissions.RW)
    self.mem_clean(addr - size, size)
    self._stack_ptr = addr
    self._stack_size = size

    self._log.debug('Set stack(SP) to 0x%08x', addr)
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_SP, addr)

  def stack_reset(self):
    self.mem_clean(self._stack_ptr - self._stack_size, self._stack_size)
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_SP, self._stack_ptr)

  def reset(self):
    pass

  def exit(self, ret: int) -> None:
    self.exception = None
    self._ret0 = ret
    self._uc.emu_stop()

  def exit_with_exception(self, exception: Exception) -> None:
    self.exception = exception
    self._ret0 = 0
    self._uc.emu_stop()
    if self._log_level <= logging.DEBUG:
      self._log.error('Function call stack:\n\t%s',
                      '\n\t'.join(self._func_stack))

  def add_mem_read_handler(self, func, start=1, end=0):
    self._log.debug('Add Mem Read handler: 0x%08x-0x%08x', start, end)
    if start < end:
      self.map_memory(start, end - start + 1, memory.MemAccessPermissions.R)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_READ,
                                lambda uc, c, a, s, v, u: func(self, a, s, v),
                                begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def add_mem_write_handler(self, func, start=1, end=0):
    self._log.debug('Add Mem Write handler: 0x%08x-0x%08x', start, end)
    if start < end:
      self.map_memory(start, end - start + 1, memory.MemAccessPermissions.W)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_MEM_WRITE,
                                lambda uc, c, a, s, v, u: func(self, a, s, v),
                                begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def add_code_block_handler(self, func, start=1, end=0):
    self._log.debug('Add code block handler: 0x%08x-0x%08x', start, end)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_BLOCK,
                                lambda uc, ad, sz, u: func(self, ad, sz),
                                begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def add_code_instruction_handler(self, func, start=1, end=0):
    self._log.debug('Add code instruction handler: 0x%08x-0x%08x', start, end)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_CODE,
                                lambda uc, ad, sz, u: func(self, ad, sz),
                                begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def remove_handler(self, handler):
    if handler not in self._hooks_handlers:
      raise error.Error(f'Handler is not registered: {handler}')
    self._uc.hook_del(handler)
    self._hooks_handlers.remove(handler)

  def add_mem_unmapped_callback(self, func, start, end):
    self._log.debug('Add mem unmapped handler: 0x%08x-0x%08x', start, end)

    ranges = self._mem_unmapped_handlers[portion.closedopen(start, end)]
    if ranges:
      raise error.Error('Range overlapping is not supported for MEM unmapped '
                        'callbacks')
    self._mem_unmapped_handlers[portion.closedopen(start, end)] = func

  def add_mem_invalid_callback(self, func, start, end):
    self._log.debug('Add mem unmapped handler: 0x%08x-0x%08x', start, end)
    ranges = self._mem_invalid_handlers[portion.closedopen(start, end)]
    if ranges:
      raise error.Error('Range overlapping is not supported for MEM invalid '
                        'callbacks')
    self._mem_invalid_handlers[portion.closedopen(start, end)] = func

  # External API
  # ===============================================================
  def coverage_register(self, cov: coverage.CoverageCollectorBase):
    self._log.info('Registering coverage engine: %s', cov.name)
    if cov.name in self._coverage_registered:
      raise error.Error(f'Coverage engine {cov.name} is already registered')
    cov.start(self)
    self._coverage_registered[cov.name] = cov

  def coverage_del(self, name: str):
    self._log.info('Removing coverage engine: %s', name)
    if name in self._coverage_registered:
      self._coverage_registered[name].stop()
      del self._coverage_registered[name]

  def load(self, img) -> None:
    """Loads Image object into emu memory.

    Args:
      img: Image to be loaded

    Returns:
      None

    Raises:
      Exception Error is raised in case of error.
    """

    if not isinstance(img, image.Image):
      raise error.Error(f'Unsupported type of the image: {type(image)}')

    self.image = img

    for reg in img.mem_regions:
      if isinstance(reg, memory.MemoryRegionData):
        self.load_to_mem(reg.name, reg.start, reg.data, reg.perm)
      elif isinstance(reg, memory.MemoryRegion):
        self.map_memory(reg.start, reg.size, reg.perm)
      else:
        raise error.Error('Unsupported type in memory region list')

  def forkserver_start(self):
    """Starts AFL fork server.

    Returns:
      True, if returns from child process

    Raises:
      Exception Error is raised in case of error.
    """

    if not (hasattr(self._uc, 'afl_forkserver_start') and
            callable(getattr(self._uc, 'afl_forkserver_start'))):
      raise error.Error('afl_forkserver_start is not supported by '
                        'Unicorn Engine')

    ret = self._uc.afl_forkserver_start([self.image.text_end])
    if ret in [unicorn_const.UC_AFL_RET_ERROR,
               unicorn_const.UC_AFL_RET_CALLED_TWICE]:
      raise error.Error(f'afl_forkserver_start failed with error: {ret}')
    return ret == unicorn_const.UC_AFL_RET_CHILD

  def call(self, entry_point: int, r0: int, r1: int, r2: int, r3: int,
           r4: int = None, r5: int = None, r6: int = None, r7: int = None
           ) -> int:
    """Start emulation.

    Args:
      entry_point: the address to start execution from
      r0: if not None, a value to set into R0 register
      r1: if not None, a value to set into R1 register
      r2: if not None, a value to set into R2 register
      r3: if not None, a value to set into R3 register
      r4: if not None, a value to set into R4 register
      r5: if not None, a value to set into R5 register
      r6: if not None, a value to set into R6 register
      r7: if not None, a value to set into R7 register

    Returns:
      Return value or R0 register
    """

    if not self.image:
      raise error.Error('Binary image for emulation was not loaded')

    if r0 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R0, r0)
    if r1 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R1, r1)
    if r2 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R2, r2)
    if r3 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R3, r3)
    if r4 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R4, r4)
    if r5 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R5, r5)
    if r6 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R6, r6)
    if r7 is not None:
      self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_R7, r7)

    sp = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_SP)
    self._log.info('Start execution from 0x%08x, SP 0x%08x',
                   entry_point, sp)
    try:
      self._uc.emu_start(entry_point, self.image.text_end)
    except unicorn.UcError as e:
      raise self._convert_error(e)
    self._log.debug('Current SP = 0x%08x', self.get_stack_pointer())
    if self.exception:
      raise self.exception
    return self._ret0
