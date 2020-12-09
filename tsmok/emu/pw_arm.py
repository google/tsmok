"""Module for PIGWEED ARM emulator."""

import collections
import enum
import logging
import re
import struct

import tsmok.common.error as error
import tsmok.common.memory as memory
import tsmok.emu.arm as arm
import tsmok.pigweed.image_elf_pw as image_elf_pw
import unicorn.arm_const as unicorn_arm_const


class ArmV7mException(enum.IntEnum):
  """Arm V7m specific exceptions."""

  RESET = 1
  NMI = 2
  HARD = 3
  MEM = 4
  BUS = 5
  USAGE = 6
  SECURE = 7
  SVC = 11
  DEBUG = 12
  PENDSV = 14
  SYSTICK = 15


class UsageExcTypes(enum.Enum):
  UNDEFINSTR = 0
  INVSTATE = 1
  INVPC = 2
  NOCP = 3
  UNALIGNED = 4
  DIVBYZERO = 5

# Actual number of exception is 16 + N, where N is number of
# external interrupts. Let's ignore external interrupts for
# now for simplicity.
ARM_V7M_MAX_EXCEPTION_CNT = 16


class ArmV7MReg(enum.IntEnum):
  ICSR = 0xE000ED04
  VTOR = 0xE000ED08
  CCR = 0xE000ED14
  SHCSR = 0xE000ED24
  CFSR = 0xE000ED28
  HFSR = 0xE000ED2C
  MMFAR = 0xE000ED34
  BFAR = 0xE000ED38
  CPACR = 0xE000ED88


class CcrFieldMask(enum.IntEnum):
  NONBASETHRDENA = 1 << 0
  USERSETMPEND = 1 << 1
  UNALIGN_TRP = 1 << 3
  DIV_0_TRP = 1 << 4
  BFHFNMIGN = 1 << 8
  STKALIGN = 1 << 9
  DC = 1 << 16
  IC = 1 << 17
  BP = 1 << 18


class ShcsrFieldMask(enum.IntEnum):
  """SHCSR register field masks."""

  USGFAULTENA = 1 << 18
  BUSFAULTENA = 1 << 17
  MEMFAULTENA = 1 << 16

  SVCALLPENDED = 1 << 15
  BUSFAULTPENDED = 1 << 14
  MEMFAULTPENDED = 1 << 13
  USGFAULTPENDED = 1 << 12

  SYSTICKACT = 1 << 11
  PENDSVACT = 1 << 10
  MONITORACT = 1 << 8
  SVCALLACT = 1 << 7
  USGFAULTACT = 1 << 3
  BUSFAULTACT = 1 << 1
  MEMFAULTACT = 1 << 0


class FpexcFieldMask(enum.IntEnum):
  EX = 1 << 31
  EN = 1 << 30


class ControlFieldMask(enum.IntEnum):
  NPRIV = 1 << 0
  SPSEL = 1 << 1
  FPCA = 1 << 2


class CpacrFieldMask(enum.IntEnum):
  """CPACR register filed masks."""

  CP0 = 3 << 0
  CP1 = 3 << 2
  CP2 = 3 << 4
  CP3 = 3 << 6
  CP4 = 3 << 8
  CP5 = 3 << 10
  CP6 = 3 << 12
  CP7 = 3 << 14
  CP10 = 3 << 20
  CP11 = 3 << 22


class CfsrFieldMask(enum.IntEnum):
  """Configurable Fault Status Register Field Mask.

  Contains the three Configurable Fault Status Registers.

  UsageFault, bits[31:16] Provides information on UsageFault exceptions.
  BusFault, bits[15:8] Provides information on BusFault exceptions.
  MemManage, bits[7:0] Provides information on MemManage exceptions.
  """
  # MemManage Status Register, MMFSR
  # Shows the status of MPU faults
  IACCVIOL = 1 << 0
  DACCVIOL = 1 << 1
  MUNSTKERR = 1 << 3
  MSTKERR = 1 << 4
  MLSPERR = 1 << 5
  MMARVALID = 1 << 7

  # BusFault Status Register, BFSR
  # Shows the status of bus errors resulting from instruction prefetches
  # and data accesses.
  IBUSERR = 1 << 8
  PRECISERR = 1 << 9
  IMPRECISERR = 1 << 10
  UNSTKERR = 1 << 11
  STKERR = 1 << 12
  LSPERR = 1 << 13
  BFARVALID = 1 << 15

  # UsageFault Status Register, UFSR
  # Contains the status for some instruction execution faults, and for
  # data access faults.
  UNDEFINSTR = 1 << 16
  INVSTATE = 1 << 17
  INVPC = 1 << 18
  NOCP = 1 << 19
  UNALIGNED = 1 << 24
  DIVBYZERO = 1 << 25


VTOR_DEFAULT = 0x0
VTOR_SIZE = 0x200


class ArmV7ExcReturn(enum.IntEnum):
  HANDLER_MAIN_EXT = 0xFFFFFFE1
  THREAD_MAIN_EXT = 0xFFFFFFE9
  THREAD_PROCESS_EXT = 0xFFFFFFED

  HANDLER_MAIN = 0xFFFFFFF1
  THREAD_MAIN = 0xFFFFFFF9
  THREAD_PROCESS = 0xFFFFFFFD


ExceptionContext = collections.namedtuple('ExceptionContext',
                                          ['ctx', 'exc', 'exc_aux'])


class PwArmV7mEmu(arm.ArmEmu):
  """Implimentation of PIGWEED Binary Emulator for ARM architecture."""

  EXC_FRAME_FMT = '<8I'
  STKALIGN_SIZE = 8
  MEM_HALFWORD_ALIGNMENT = 2
  MEM_WORD_ALIGNMENT = 4

  class Mode(enum.Enum):
    THREAD = 1
    HANDLER = 2

  def __init__(self, log_level=logging.ERROR):
    arm.ArmEmu.__init__(self, '[PW]', log_level, arm.ArmMode.M4CLASS)
    self._drivers = dict()
    self._regs = dict()

    # reset values for regs
    self._regs[ArmV7MReg.ICSR] = 0
    self._regs[ArmV7MReg.VTOR] = VTOR_DEFAULT
    self._regs[ArmV7MReg.CCR] = 0x00000200
    self._regs[ArmV7MReg.SHCSR] = 0
    self._regs[ArmV7MReg.CFSR] = 0
    self._regs[ArmV7MReg.HFSR] = 0
    self._regs[ArmV7MReg.MMFAR] = 0
    self._regs[ArmV7MReg.BFAR] = 0

    self.error_cnt = 0

    # allow access to FPU by default
    val = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_C1_C0_2)
    val |= (0xf << CpacrFieldMask.CP10)
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_C1_C0_2, val)

    ## enable FPU by default
    enable_vfp = FpexcFieldMask.EN
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_FPEXC, enable_vfp)

    self._pre_exc_handlers = dict()
    self._pre_exc_handlers[ArmV7mException.USAGE] = self._pre_usage_exc_handler

    self._post_exc_handlers = dict()
    self._post_exc_handlers[ArmV7mException.USAGE] = \
        self._post_usage_exc_handler

    self._div_0_trp_handler = None
    self._unalign_read_trp_handler = None
    self._unalign_write_trp_handler = None

    self._mode = self.Mode.THREAD
    self._context_stack = list()

    self.exception_handler[arm.ArmEmu.ExceptionType.EXCEPTION_EXIT] = \
        self._exception_exit

    self._setup()

  def _setup(self):
    self.add_mem_read_handler(self.cpacr_read, ArmV7MReg.CPACR,
                              ArmV7MReg.CPACR + 3)
    self.add_mem_write_handler(self.cpacr_write, ArmV7MReg.CPACR,
                               ArmV7MReg.CPACR + 3)

    self.add_mem_read_handler(self.reg_read, ArmV7MReg.ICSR,
                              ArmV7MReg.VTOR + 3)
    self.add_mem_write_handler(self.reg_write, ArmV7MReg.ICSR,
                               ArmV7MReg.VTOR + 3)

    self.add_mem_read_handler(self.reg_read, ArmV7MReg.CCR,
                              ArmV7MReg.CCR + 3)
    self.add_mem_write_handler(self.ccr_write, ArmV7MReg.CCR,
                               ArmV7MReg.CCR + 3)

    self.add_mem_read_handler(self.reg_read, ArmV7MReg.SHCSR,
                              ArmV7MReg.HFSR + 3)
    self.add_mem_write_handler(self.reg_write, ArmV7MReg.SHCSR,
                               ArmV7MReg.SHCSR + 3)
    self.add_mem_write_handler(self.cfsr_write, ArmV7MReg.CFSR,
                               ArmV7MReg.CFSR + 3)
    self.add_mem_write_handler(self.reg_write, ArmV7MReg.HFSR,
                               ArmV7MReg.HFSR + 3)

    self.add_mem_read_handler(self.reg_read, ArmV7MReg.MMFAR,
                              ArmV7MReg.BFAR + 3)
    self.add_mem_write_handler(self.reg_write, ArmV7MReg.MMFAR,
                               ArmV7MReg.BFAR + 3)

    # allow access to area of default vector table
    self.map_memory(VTOR_DEFAULT, VTOR_SIZE,
                    memory.MemAccessPermissions.RW)
    # map exception return address range otherwise UC_ERR_FETCH_UNMAPPED
    # will be raised
    self.map_memory(0xFFFFFFE0, 32, memory.MemAccessPermissions.RX)

  def _exit_call(self, emu, addr: int, size: int):
    self._log.info('Execution reaches end of firmware execution flow. '
                   'Exit emulation.')
    self.exit(0)

  def _pre_usage_exc_handler(self, exc_aux):
    if exc_aux == UsageExcTypes.DIVBYZERO:
      self._regs[ArmV7MReg.CFSR] |= CfsrFieldMask.DIVBYZERO
    elif exc_aux == UsageExcTypes.UNALIGNED:
      self._regs[ArmV7MReg.CFSR] |= CfsrFieldMask.UNALIGNED
    else:  # do nothing for now
      self._log.warning('Unhandled Usage exception subtype: %d', exc_aux)

  def _post_usage_exc_handler(self, exc_aux):
    if exc_aux == UsageExcTypes.DIVBYZERO:
      self._regs[ArmV7MReg.CFSR] &= ~CfsrFieldMask.DIVBYZERO
    elif exc_aux == UsageExcTypes.UNALIGNED:
      self._regs[ArmV7MReg.CFSR] &= ~CfsrFieldMask.UNALIGNED
    else:  # do nothing for now
      self._log.warning('Unhandled Usage exception subtype: %d', exc_aux)

  def _exc_return_addr(self, exc, addr, size):
    if exc == ArmV7mException.NMI:
      ret = addr + size
    elif exc == ArmV7mException.HARD:
      ret = addr
    elif exc == ArmV7mException.MEM:
      ret = addr
    elif exc == ArmV7mException.BUS:
      ret = addr
    elif exc == ArmV7mException.USAGE:
      ret = addr
    elif exc == ArmV7mException.SVC:
      ret = addr + size
    elif exc == ArmV7mException.DEBUG:
      ret = addr
    elif exc == ArmV7mException.PENDSV:
      ret = addr + size
    elif exc == ArmV7mException.SYSTICK:
      ret = addr + size
    else:  # exc >= 16:
      ret = addr + size

    return ret

  def _have_fp_ext(self):
    fpexc = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_FPEXC)
    cpacr = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_C1_C0_2)

    # TODO(dmitryya): figure out more correct way
    return fpexc & FpexcFieldMask.EN and cpacr & CpacrFieldMask.CP10

  def _write_exc_frame_to_stack(self, exc, addr, size):
    ctrl = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_CONTROL)
    msp = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_MSP)

    # TODO(dmitryya): ControlFieldMask.FPCA should also be checked but for some
    # reasons it always 0. Figure out this.
    if self._have_fp_ext():
      force_alignment = True
    else:
      force_alignment = (self._regs[ArmV7MReg.CCR] & CcrFieldMask.STKALIGN) != 0

    self._log.debug('Current state: MSP 0x%08x, CONTROL 0x%08x, '
                    'stack alignment %s, HaveFPExt %d.',
                    msp, ctrl, force_alignment, self._have_fp_ext())

    # check if we need to align the SP pointer
    if msp & (self.STKALIGN_SIZE - 1) and force_alignment:
      stack_align = True
    else:
      stack_align = False

    data = struct.pack(self.EXC_FRAME_FMT,
                       self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R0),
                       self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R1),
                       self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R2),
                       self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R3),
                       self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_R12),
                       self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_LR),
                       self._exc_return_addr(exc, addr, size),
                       # do not care about actual value of XPSR.
                       # just set alignment bit if needed
                       0x200 if stack_align else 0x0
                      )

    # TODO(dmitryya): ControlFieldMask.FPCA should also be checked but for some
    # reasons it always 0. Figure out this.
    if self._have_fp_ext():
      for i in range(0, 16):
        data += struct.pack('<I',
                            self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_S0 +
                                              i))
      # store FPSCR as 0x0 for now
      # TODO(dmitryy): store actual value
      data += b'\x00' * 4
      # reserved value
      data += b'\x00' * 4

    if stack_align:
      data += b'\x00' * 4

    new_msp = msp - len(data)
    self.mem_write(new_msp, data)
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_MSP, new_msp)

  def _exception_raise(self, exc, exc_aux, addr, size):
    self._log.debug('Raise exception: %s %s', exc, exc_aux)
    if exc not in ArmV7mException:
      self.exit_with_exception(error.Error(f'Unknown exception: {exc}'))

    data = self.mem_read(self._regs[ArmV7MReg.VTOR],
                         ARM_V7M_MAX_EXCEPTION_CNT * 4)
    vector_table = struct.unpack(f'<{ARM_V7M_MAX_EXCEPTION_CNT}I', data)

    handler_ptr = vector_table[exc]

    if handler_ptr == 0:
      self.exit_with_exception(error.Error(f'Unhandled exception: {str(exc)}'))
      return

    # add current context at the end
    self._context_stack.insert(len(self._context_stack),
                               ExceptionContext(self._uc.context_save(), exc,
                                                exc_aux))

    # prepare registers state
    self._pre_exc_handlers[exc](exc_aux)

    self._write_exc_frame_to_stack(exc, addr, size)

    # TODO(dmitryya): ControlFieldMask.FPCA should also be checked but for some
    # reasons it always 0. Figure out this.
    if self._have_fp_ext():
      if self._mode == self.Mode.THREAD:
        exc_return = ArmV7ExcReturn.THREAD_MAIN_EXT
      else:
        exc_return = ArmV7ExcReturn.HANDLER_MAIN_EXT
    else:
      if self._mode == self.Mode.THREAD:
        exc_return = ArmV7ExcReturn.THREAD_MAIN
      else:
        exc_return = ArmV7ExcReturn.HANDLER_MAIN

    # set exception return address
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_LR,
                       exc_return)
    if self._mode == self.Mode.HANDLER:
      # nested exception
      active_exc = self._regs[ArmV7MReg.ICSR] & 0x1FF
      pending_exc = (self._regs[ArmV7MReg.ICSR] >> 12) & 0xFFFFFE00
      if pending_exc:
        self.exit_with_exception(error.Error('Do not support more than 1 '
                                             'nested exception'))
        return
      self._regs[ArmV7MReg.ICSR] &= 0xFFE00E00
      # move current active exception to pending
      self._regs[ArmV7MReg.ICSR] |= active_exc << 12
    else:
      # change state to exception handler mode
      self._mode = self.Mode.HANDLER

    self._regs[ArmV7MReg.ICSR] &= 0xFFFFFE00
    self._regs[ArmV7MReg.ICSR] |= exc
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_PC, handler_ptr)

  def _exception_exit(self, regs):
    self._log.debug('Exit from exception.')

    if not self._context_stack:
      self.exit_with_exception(error.Error('No saved contexts'))
      return

    # do not care about exception frame. just restore the context
    exc_ctx = self._context_stack.pop(-1)
    self._uc.context_restore(exc_ctx.ctx)

    if not self._context_stack:
      self.mode = self.Mode.THREAD
    else:
      pending_exc = (self._regs[ArmV7MReg.ICSR] >> 12) & 0x1FF
      self._regs[ArmV7MReg.ICSR] &= 0xFFE00E00
      # move current active exception to pending
      self._regs[ArmV7MReg.ICSR] |= pending_exc

    exc = self._regs[ArmV7MReg.ICSR] & 0x1FF
    if exc != exc_ctx.exc:
      self.exit_with_exception(error.Error('Exception from contex does not '
                                           f'match from ICSR: {exc_ctx.exc} '
                                           f'!= {exc}'))
      return

    self._post_exc_handlers[exc](exc_ctx.exc_aux)

  def _div_0_trp(self, emu, addr, size):
    _, mnemonic, op_str, _ = self.get_instruction_at_address(addr, size)

    div_mnemonics = ['udiv', 'sdiv', 'fdiv']

    # check that current instruction is div one
    if not any(mnemonic.startswith(m) for m in div_mnemonics):
      return

    # we need to check the last operand. so let's extract it
    op = op_str[op_str.rfind(',') + 1:].strip()

    # a register can be from R, D or S group
    # So, stplit the name to group and number
    m = re.search('^^([r,s,d])(\d)', op.lower())  # pylint: disable=anomalous-backslash-in-string
    if not m:
      self._log.warning('Unknown mnemonic for last operand: %s', op)
      return

    rname = m.group(1)
    idx = int(m.group(2))

    if rname == 'r':
      reg = unicorn_arm_const.UC_ARM_REG_R0
    elif rname == 's':
      reg = unicorn_arm_const.UC_ARM_REG_S0
    else:
      reg = unicorn_arm_const.UC_ARM_REG_D0

    reg += idx
    val = self._uc.reg_read(reg)
    if val == 0:
      self._log.debug('Caught DIVBYZERO exception.')
      self._exception_raise(ArmV7mException.USAGE, UsageExcTypes.DIVBYZERO,
                            addr, size)

  def _unalign_trp(self, emu, addr, size, value):
    if addr & (self.MEM_WORD_ALIGNMENT - 1):
      pc = self.get_current_address()
      _, mnemonic, _, sz = self.get_instruction_at_address(pc)
      word_fault_mnemonic = ['ldr', 'ldrt', 'str', 'strt']

      # remove .x tail
      if mnemonic.find('.') != -1:
        mnemonic = mnemonic[:mnemonic.find('.')]
      if mnemonic in word_fault_mnemonic:
        self._log.debug('[pc 0x%08x]: Memory unalign access to address '
                        '0x%08x from %s instruction!!!',
                        pc, addr, mnemonic)
        self._exception_raise(ArmV7mException.USAGE, UsageExcTypes.UNALIGNED,
                              pc, sz)

      elif addr & (self.MEM_HALFWORD_ALIGNMENT - 1):
        halfword_fault_mnemonic = ['ldrh', 'ldrsh', 'ldrsht', 'strh',
                                   'strht', 'tbh']

        if mnemonic in halfword_fault_mnemonic:
          self._log.debug('[pc 0x%08x]: Memory unalign access to address '
                          '0x%08x from %s instruction!!!',
                          pc, addr, mnemonic)
          self._exception_raise(ArmV7mException.USAGE, UsageExcTypes.UNALIGNED,
                                pc, sz)

  def cpacr_write(self, emu, addr, size, value):
    self._uc.reg_write(unicorn_arm_const.UC_ARM_REG_C1_C0_2, value)

  def cpacr_read(self, emu, addr, size, value):
    val = self._uc.reg_read(unicorn_arm_const.UC_ARM_REG_C1_C0_2)
    self.u32_write(addr, val)

  def reg_write(self, emu, addr, size, value):
    try:
      self._log.debug('Set %s: 0x%08x', ArmV7MReg(addr), value)
      self._regs[addr] = value
    except (KeyError, ValueError):
      self.exit_with_exception(error.Error('Write to unhandled register: '
                                           f'0x{addr:08x}'))

  def reg_read(self, emu, addr, size, value):
    try:
      self._log.debug('Read %s value 0x%08x', ArmV7MReg(addr), self._regs[addr])
      self.u32_write(addr, self._regs[addr])
    except (KeyError, ValueError):
      self.exit_with_exception(error.Error('Write from unhandled register: '
                                           f'0x{addr:08x}'))

  def cfsr_write(self, emu, addr, size, value):
    self._log.debug('Clear CFSR bits: 0x%08x', value)
    self._regs[ArmV7MReg.CFSR] &= ~value

  def ccr_write(self, emu, addr, size, value):
    self._log.debug('Set CCR: 0x%08x', value)
    self._regs[ArmV7MReg.CCR] = value

    if value & CcrFieldMask.DIV_0_TRP and not self._div_0_trp_handler:
      self._div_0_trp_handler = self.add_code_instruction_handler(
          self._div_0_trp)
    elif not (value & CcrFieldMask.DIV_0_TRP) and self._div_0_trp_handler:
      self.remove_handler(self._div_0_trp_handler)
      self._div_0_trp_handler = None

    if value & CcrFieldMask.UNALIGN_TRP and not self._unalign_read_trp_handler:
      self._unalign_read_trp_handler = self.add_mem_read_handler(
          self._unalign_trp)
      self._unalign_write_trp_handler = self.add_mem_write_handler(
          self._unalign_trp)
    elif (not (value & CcrFieldMask.UNALIGN_TRP) and
          self._unalign_read_trp_handler):
      self.remove_handler(self._unalign_read_trp_handler)
      self.remove_handler(self._unalign_write_trp_handler)
      self._unalign_read_trp_handler = None
      self._unalign_write_trp_handler = None

  # External API
  # ===============================================================
  def reset(self):
    self.stack_reset()

  def driver_add(self, drv):
    if drv.name in self._drivers:
      raise error.Error(f'Device {drv.name} already present')
    self._drivers[drv.name] = drv
    drv.register(self)

  def load(self, img) -> None:
    if not isinstance(img, image_elf_pw.PwElfImage):
      raise error.AbortError(f'Unsupported image type: {type(img)}')
    arm.ArmEmu.load(self, img)

    self.set_stack(img.stack_addr, img.stack_size)
    self.add_code_block_handler(self._exit_call, img.exit_func,
                                img.exit_func + 3)

  def run(self):
    self.call(self.image.entry_point, 0, 0, 0, 0)
