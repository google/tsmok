"""Base emulator."""

import abc
import collections
import enum
import logging
import math
import struct
import capstone
import portion
import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.common.image as image
import tsmok.common.memory as memory
import tsmok.common.round_up as round_up
import tsmok.coverage.base as coverage

import unicornafl as unicorn
import unicornafl.unicorn_const as unicorn_const

RegContext = collections.namedtuple('RegContext',  # pylint: disable=unexpected-keyword-arg
                                    ['reg0', 'reg1', 'reg2', 'reg3',
                                     'reg4', 'reg5', 'reg6', 'reg7',
                                     'reg8', 'reg9', 'reg10', 'reg11',
                                     'reg12', 'reg13', 'reg14', 'reg15',
                                     'reg16', 'reg17', 'reg18', 'reg19',
                                     'reg20', 'reg21', 'reg22', 'reg23',
                                     'reg24', 'reg25', 'reg26', 'reg27',
                                     'reg28', 'reg29', 'reg30'],
                                    defaults=(None,)*31)


class Emu(abc.ABC):
  """Implimentation of base ARM Emulator."""

  class MemoryAccessType(enum.IntEnum):
    """Memory Access Type in memory callbacks from Unicorn Engine."""
    READ = 16  # Memory is read from
    WRITE = 17  # Memory is written to
    FETCH = 18  # Memory is fetched
    READ_UNMAPPED = 19  # Unmapped memory is read from
    WRITE_UNMAPPED = 20  # Unmapped memory is written to
    FETCH_UNMAPPED = 21   # Unmapped memory is fetched
    WRITE_PROT = 22  # Write to write protected but mapped memory
    READ_PROT = 23  # Read from read protected but mapped memory
    FETCH_PROT = 24  # Fetch from non-executable but mapped memory
    READ_AFTER = 25  # Memory is read from (successful access)

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

  def __init__(self, name, uc: unicorn.Uc, cs: capstone.Cs, log_level):
    abc.ABC.__init__(self)

    logging.addLevelName(const.LogLevelCustom.DEBUG_DISASM, 'DEBUG_DISASM')
    logging.addLevelName(const.LogLevelCustom.DEBUG_MEM, 'DEBUG_MEM')
    logging.addLevelName(const.LogLevelCustom.TRACE, 'TRACE')

    self._log = logging.getLogger(name)
    self._log.setLevel(log_level)
    self._log_level = log_level

    self._uc = uc
    self._ret0 = 0
    self._stack_ptr = 0
    self._stack_size = 0

    self.exception = None

    self._cs = cs

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
    self._log.debug('%s: interrupted by EXCEPTION %s',
                    self._format_addr_str(self.get_current_address()), exc)

    if exc in self.exception_handler:
      regs = self.get_regs()
      self.exception_handler[exc](regs)
    else:
      self.dump_regs()
      self.exit_with_exception(error.Error(f'Unhandled exception: {exc}'))

  # callback for tracing basic blocks
  def _hook_block(self, uc: unicorn.Uc, vaddr: int, size: int, udata,
                  paddr: int):
    """Hook for execuded block from emulated code.

    Args:
      uc: [unused] Unicorn instance
      vaddr: The address of block
      size: Size of the execuded block
      udata: [unused] User provided data during registering the hook
      paddr: physical address of block
    """

    del uc, udata  # unused by the hook
    self._log.log(
        const.LogLevelCustom.TRACE,
        '\t\t\t\t\t\t>>> Tracing basic block at %s, '
        'block size = 0x%x',
        self._format_addr_str(paddr, vaddr), size)
    if self._log_level <= logging.DEBUG:
      self._disasm_instruction(paddr, vaddr, size)

  # callback for tracing instructions
  def _hook_code(self, uc: unicorn.Uc, vaddr: int, size: int, udata,
                 paddr: int):
    """Hook for execuded instruction from emulated code.

    Emulation can be stopped in this hook if |vaddr| is not belong to any
    memory region or a region does not have execution permission.

    Args:
      uc: [unused] Unicorn instance
      vaddr: The address of block
      size: Size of the execuded block
      udata: [unused] User provided data during registering the hook
      paddr: physical address of code
    """

    del uc, udata  # unused by the hook
    self._log.log(const.LogLevelCustom.TRACE,
                  '\t\t\t\t\t\t>>> Code hook %s size %d SP %s',
                  self._format_addr_str(paddr, vaddr), size,
                  self._format_addr_str(self.get_stack_address()))
    try:
      perm = self._mem_region_access[paddr]
      if not perm & memory.MemAccessPermissions.R:
        self.exit_with_exception(
            error.Error('{}: Unallowed memory FETCH access: {}'.format(
                self._format_addr_str(self.get_current_address()),
                self._format_addr_str(paddr, vaddr))))
    except KeyError:
      self.exit_with_exception(
          error.Error('{}: Unmapped memory FETCH access: {}'.format(
              self._format_addr_str(self.get_current_address()),
              self._format_addr_str(paddr, vaddr))))

    if self._log_level <= logging.DEBUG:
      info = self._instruction_examination(paddr, vaddr, size)
      self._func_symbols_handler(paddr, info)

  # callback for tracing read memory
  def _hook_mem_read(self, uc: unicorn.Uc, access: int, vaddr: int, size: int,
                     value: int, udata, paddr: int):
    """Hook for read access to memory. Called before actual reading of data.

    Args:
      uc: [unused] Unicorn instance
      access: [unused] type of access to memory: READ, WRITE or FETCH [unused]
      vaddr: The address of memory
      size: Size of the memory chunk to be read
      value: 0x0 in this hook
      udata: [unused] User provided data during registering the hook
      paddr: The physical address of memory
    """

    del uc, access, value, udata  # unused by the hook
    self._log.log(const.LogLevelCustom.TRACE,
                  '\t\t\t\t\t\t[MEM][pc %s] READ at %s, size = 0x%x',
                  self._format_addr_str(self.get_current_address()),
                  self._format_addr_str(paddr, vaddr), size)

  def _hook_mem_read_after(self, uc: unicorn.Uc, access: int, vaddr: int,
                           size: int, value: int, udata, paddr: int):
    """Hook for read access to memory. Called after actual reading of data.

    Args:
      uc: [unused] Unicorn instance
      access: [unused] type of access to memory: READ, WRITE or FETCH [unused]
      vaddr: The address of memory
      size: Size of the memory chunk to be read
      value: a value which was read from memory
      udata: [unused] User provided data during registering the hook
      paddr: The physical address of memory
    """

    del uc, access, udata  # unused by the hook
    self._log.log(
        const.LogLevelCustom.DEBUG_MEM,
        '\t\t\t\t\t\t[MEM][pc %s] READ AFTER at %s, size = 0x%x, value = 0x%x',
        self._format_addr_str(self.get_current_address()),
        self._format_addr_str(paddr, vaddr), size, value)

    try:
      perm = self._mem_region_access[paddr]
      if not perm & memory.MemAccessPermissions.R:
        self.exit_with_exception(
            error.Error('{}: Unallowed memory READ access: {}'.format(
                self._format_addr_str(self.get_current_address()),
                self._format_addr_str(paddr, vaddr))))
    except KeyError:
      self.exit_with_exception(
          error.Error('{}: READ unmapped memory: {}'.format(
              self._format_addr_str(self.get_current_address()),
              self._format_addr_str(paddr, vaddr))))

  # callback for tracing write memory
  def _hook_mem_write(self, uc: unicorn.Uc, access: int, vaddr: int, size: int,
                      value: int, udata, paddr: int):
    """Hook for write access to memory.

    Args:
      uc: [unused] Unicorn instance
      access: [unused] type of access to memory: READ, WRITE or FETCH [unused]
      vaddr: The address of memory
      size: Size of the memory chunk to be read
      value: A value to be written to memory
      udata: [unused] User provided data during registering the hook
      paddr: The physical address of memory
    """

    del uc, access, udata  # unused by the hook
    self._log.log(
        const.LogLevelCustom.DEBUG_MEM,
        '\t\t\t\t\t\t[MEM][pc %s] WRITE at %s, size = 0x%x, value = 0x%x',
        self._format_addr_str(self.get_current_address()),
        self._format_addr_str(paddr, vaddr), size, value)

    try:
      perm = self._mem_region_access[paddr]
      if not perm & memory.MemAccessPermissions.W:
        self.exit_with_exception(
            error.Error('{}: Unallowed memory WRITE access: {}'.format(
                self._format_addr_str(self.get_current_address()),
                self._format_addr_str(paddr, vaddr))))
    except KeyError:
      self.exit_with_exception(
          error.Error('{}: WRITE unmapped memory: {}'.format(
              self._format_addr_str(self.get_current_address()),
              self._format_addr_str(paddr, vaddr))))

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
    self.exit_with_exception(
        error.Error('Invalid instruction at addr '
                    f'{self._format_addr_str(self.get_current_address())}'))
    self.dump_regs()
    return True

  def _hook_invalid(self, uc: unicorn.Uc, access: int, vaddr: int, size: int,
                    value: int, udata, paddr: int) -> bool:
    """Hook for invalid access to memory.

    Args:
      uc: [unused] Unicorn instance
      access: type of access to memory: READ, WRITE or FETCH
      vaddr: The address of memory
      size: Size of the memory chunk to be read
      value: [unused] A value to be read/written from/to memory
      udata: [unused] User provided data during registering the hook
      paddr: The physical address of memory

    Returns:
      True if this hook handled the invocation, False, if other hooks have to
      handle.
    """

    del uc, value, udata  # unused by the hook
    ranges = self._mem_invalid_handlers[portion.closedopen(paddr,
                                                           paddr + size)]
    self._log.error('Invalid memory access %s at %s to %s',
                    access, self._format_addr_str(self.get_current_address()),
                    self._format_addr_str(paddr, vaddr))
    if not ranges:
      access = self.MemoryAccessType(access)
      self.exit_with_exception(
          error.Error(
              '[MEM] Invalid memory access ({}) at {} to {}, size {}'.format(
                  str(access),
                  self._format_addr_str(self.get_current_address()),
                  self._format_addr_str(paddr, vaddr), size)))
      return True
    if len(ranges) != 1:
      self.exit_with_exception(
          error.Error('[MEM] Invalid memory access: Wrong number of handlers '
                      f'({len(ranges)}) for at '
                      f'{self._format_addr_str(self.get_current_address())} '
                      f'to {self._format_addr_str(paddr, vaddr)}, '
                      f'size = 0x{size:x}'))
      return True
    return ranges.values()[0](self, access, paddr, size)

  def _hook_mem_unmapped(self, uc: unicorn.Uc, access: int, vaddr: int,
                         size: int, value: int, udata, paddr: int) -> bool:
    """Hook for accessing unmapped memory.

    Args:
      uc: [unused] Unicorn instance
      access: type of access to memory: READ, WRITE or FETCH
      vaddr: The address of memory
      size: Size of the memory chunk to be read
      value: [unused] A value to be read/written from/to memory
      udata: [unused] User provided data during registering the hook
      paddr: The physical address of memory

    Returns:
      True if this hook handled the invocation, False, if other hooks have to
      handle.
    """

    del uc, value, udata  # unused by the hook
    ranges = self._mem_unmapped_handlers[portion.closedopen(paddr,
                                                            paddr + size)]
    if not ranges:
      self.exit_with_exception(
          error.Error('[MEM] Unmapped at {} to {}, size = 0x{:x}'.format(
              self._format_addr_str(self.get_current_address()),
              self._format_addr_str(paddr, vaddr), size)))
      return True
    if len(ranges) != 1:
      self.exit_with_exception(
          error.Error('[MEM] Unmapped: Wrong number of handlers '
                      '({}) for at {} to {}, size = 0x{:x}'.format(
                          len(ranges),
                          self._format_addr_str(self.get_current_address()),
                          self._format_addr_str(paddr, vaddr), size)))

      return True
    return ranges.values()[0](self, access, paddr, size)

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

  def _cpu_get_context(self):
    return self._uc.context_save()

  def _cpu_restore_context(self, ctx):
    if not ctx:
      raise error.Error('CPU context is not present')
    self._uc.context_restore(ctx)

  @abc.abstractmethod
  def dump_regs(self) -> None:
    raise NotImplementedError()

  @abc.abstractmethod
  def get_regs(self) -> RegContext:
    """Returns current state of genaral registers.

      Returns:
        A dict mapping a register name to its value.
    """
    raise NotImplementedError()

  @abc.abstractmethod
  def set_regs(self, ctx: RegContext) -> None:
    """Set registers to RegContext.

    Args:
      ctx: RegContext to be set

    Returns:
      None.
    """
    raise NotImplementedError()

  @abc.abstractmethod
  def _func_return_instruction(self, mnemonic: str, op_str: str) -> bool:
    raise NotImplementedError()

  @abc.abstractmethod
  def _branch_instruction(self, mnemonic: str, op_str: str) -> bool:
    raise NotImplementedError()

  @abc.abstractmethod
  def _svc_mode_setup(self):
    raise NotImplementedError()

  def _format_addr_str(self, paddr: int, vaddr: int = None) -> str:
    """Convert virtual and physical addresses into string.

    Args:
      paddr: physical address
      vaddr: virtual address

    Returns:
      String representation of addresses.
    """
    fmt = '0x{:08x}'
    if paddr >= (1<<32):
      fmt = '0x{:016x}'

    if vaddr and paddr != vaddr:
      vfmt = '0x{:08x}'
      if paddr >= (1<<32):
        vfmt = '0x{:016x}'
      return f'{vfmt}({fmt})'.format(vaddr, paddr)
    else:
      return f'{fmt}'.format(paddr)

  def _format_disasm_str(self, paddr: int, vaddr, mnemonic, op_str) -> str:
    return self._format_addr_str(paddr, vaddr) + f':  {mnemonic:8s}    {op_str}'

  def _disasm_instruction(self, paddr: int, vaddr: int, size: int):
    """Disassembles chunk of memeory to instruction.

    Args:
      paddr: physical address of memory
      vaddr: vma address of memory (physical address if MMU is not enabled)
      size: size of memory
    """

    data = self._uc.mem_read(paddr, size)

    off = 0
    for (p_addr, size, mnemonic, op_str) in self._cs.disasm_lite(bytes(data),
                                                                 paddr):
      self._disasm_map[p_addr] = (p_addr, vaddr + off, mnemonic, op_str, size)
      off += size

  def _instruction_examination(self, paddr: int, vaddr: int, size: int):
    """Examines an instruction.

    Examinas an instruction by given address (dissassembles memory if needed)
    and returns information in InstrInfo format.

    Args:
      paddr: The physical address of an instruction
      vaddr: The address of an instruction
      size: The size of the instruction.

    Returns:
      InstrInfo is returned with information
    """
    info = self.InstrInfo(0)

    if paddr not in self._disasm_map:
      self._disasm_instruction(paddr, vaddr, size)

    if paddr not in self._disasm_map:
      self._log.error('No addr %s in disasm map',
                      self._format_addr_str(paddr, vaddr))
      return info

    pa, va, mnemonic, op_str, sz = self._disasm_map[paddr]
    # update if previously virtual address was not set
    if pa == va and paddr != vaddr:
      self._disasm_map[paddr] = (paddr, vaddr, mnemonic, op_str, sz)

    instr_str = self._format_disasm_str(paddr, vaddr, mnemonic, op_str)
    self._log.log(const.LogLevelCustom.DEBUG_DISASM, '\t\t\t %s', instr_str)

    if self._func_return_instruction(mnemonic, op_str):
      info |= self.InstrInfo.RET

    if self._branch_instruction(mnemonic, op_str):
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

  @abc.abstractmethod
  def set_return_code(self, ret: int) -> None:
    raise NotImplementedError()

  @abc.abstractmethod
  def get_current_address(self) -> int:
    raise NotImplementedError()

  @abc.abstractmethod
  def set_current_address(self, addr: int):
    raise NotImplementedError()

  @abc.abstractmethod
  def set_return_address(self, addr: int) -> None:
    raise NotImplementedError()

  @abc.abstractmethod
  def get_stack_address(self) -> int:
    raise NotImplementedError()

  @abc.abstractmethod
  def set_stack_address(self, addr: int) -> None:
    raise NotImplementedError()

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
    if address not in self._disasm_map:
      self._disasm_instruction(address, address, size if size else 4)

    if address not in self._disasm_map:
      raise error.Error(f'Failed to get instruction info at 0x{address:x}')

    paddr, _, mnemonic, op_str, sz = self._disasm_map[address]
    if size and size != sz:
      raise error.Error('Requested size does not match instruction size: '
                        f'{size} != {sz}. More than one instcruction '
                        'are there.')
    return paddr, mnemonic, op_str, sz

  def mem_read(self, addr: int, size: int) -> bytearray:
    self._log.log(const.LogLevelCustom.DEBUG_MEM,
                  '\t\t\t\t\t\tMEM read 0x%x - 0x%x, size %d', addr,
                  addr + size - 1, size)
    return bytes(self._uc.mem_read(addr, size))

  def mem_write(self, addr: int, value: bytearray) -> None:
    end_addr = addr + len(value) - 1
    self._log.log(const.LogLevelCustom.DEBUG_MEM,
                  '\t\t\t\t\t\tMEM write 0x%x - 0x%x, size %d', addr,
                  end_addr, len(value))
    self._uc.mem_write(addr, value)

  def u32_write(self, addr: int, value: int) -> None:
    self.mem_write(addr, struct.pack('<I', value))

  def u32_read(self, addr: int) -> int:
    values = struct.unpack('<I', self.mem_read(addr, 4))
    return values[0]

  def u64_write(self, addr: int, value: int) -> None:
    self.mem_write(addr, struct.pack('<Q', value))

  def u64_read(self, addr: int) -> int:
    values = struct.unpack('<Q', self.mem_read(addr, 8))
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
    self._log.debug('Map region (in): 0x%x - 0x%x', addr,
                    addr + size - 1)

    addr_fixed = math.floor(addr / const.PAGE_SIZE) * const.PAGE_SIZE
    size_fixed = round_up.round_up(size + addr - addr_fixed, const.PAGE_SIZE)

    self._log.debug('Map region (fixed): 0x%x - 0x%x', addr_fixed,
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
      self._log.debug('Map region (left): 0x%x - 0x%x', a, a+s)
      if s:
        self._uc.mem_map(a, s)

    self._mem_mapped_regions |= res
    chunk = portion.IntervalDict({portion.closedopen(addr, addr + size): perm})
    combine_perm = lambda orig, new: orig | new
    self._mem_region_access = self._mem_region_access.combine(chunk,
                                                              how=combine_perm)

  def load_to_mem(self, name: str, addr: int, data: bytes,
                  perm: memory.MemAccessPermissions) -> None:
    self._log.debug("Load '%s' to addr 0x%x, size %d", name, addr, len(data))
    self.map_memory(addr, len(data), perm)
    self._uc.mem_write(addr, data)

  def set_stack(self, addr: int, size: int):
    self.map_memory(addr - size, size, memory.MemAccessPermissions.RW)
    self.mem_clean(addr - size, size)
    self._stack_ptr = addr
    self._stack_size = size

    self._log.debug('Set stack(SP) to %s', self._format_addr_str(addr))
    self.set_stack_address(addr)

  def stack_reset(self):
    self.mem_clean(self._stack_ptr - self._stack_size, self._stack_size)
    self.set_stack_address(self._stack_ptr)

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
    self._log.debug('Add Mem Read handler: 0x%x-0x%x', start, end)
    if start < end:
      self.map_memory(start, end - start + 1, memory.MemAccessPermissions.R)
    handler = self._uc.hook_add(
        unicorn_const.UC_HOOK_MEM_READ,
        lambda uc, c, a, s, v, u, p: func(self, p, s, v),
        begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def add_mem_write_handler(self, func, start=1, end=0):
    self._log.debug('Add Mem Write handler: 0x%x-0x%x', start, end)
    if start < end:
      self.map_memory(start, end - start + 1, memory.MemAccessPermissions.W)
    handler = self._uc.hook_add(
        unicorn_const.UC_HOOK_MEM_WRITE,
        lambda uc, c, a, s, v, u, p: func(self, p, s, v),
        begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def add_code_block_handler(self, func, start=1, end=0):
    self._log.debug('Add code block handler: 0x%x-0x%x', start, end)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_BLOCK,
                                lambda uc, ad, sz, u, p: func(self, p, sz),
                                begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def add_code_instruction_handler(self, func, start=1, end=0):
    self._log.debug('Add code instruction handler: 0x%x-0x%x', start, end)
    handler = self._uc.hook_add(unicorn_const.UC_HOOK_CODE,
                                lambda uc, ad, sz, u, p: func(self, p, sz),
                                begin=start, end=end)
    self._hooks_handlers.append(handler)
    return handler

  def remove_handler(self, handler):
    if handler not in self._hooks_handlers:
      raise error.Error(f'Handler is not registered: {handler}')
    self._uc.hook_del(handler)
    self._hooks_handlers.remove(handler)

  def add_mem_unmapped_callback(self, func, start, end):
    self._log.debug('Add mem unmapped handler: 0x%x-0x%x', start, end)

    ranges = self._mem_unmapped_handlers[portion.closedopen(start, end)]
    if ranges:
      raise error.Error('Range overlapping is not supported for MEM unmapped '
                        'callbacks')
    self._mem_unmapped_handlers[portion.closedopen(start, end)] = func

  def add_mem_invalid_callback(self, func, start, end):
    self._log.debug('Add mem unmapped handler: 0x%x-0x%x', start, end)
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

  def call(self, entry_point: int, regs: RegContext):
    """Start emulation.

    Args:
      entry_point: the address to start execution from
      regs: RegContext to be set in registers

    Returns:
      Return value of specific entry point call
    """

    if not self.image:
      raise error.Error('Binary image for emulation was not loaded')

    self.set_regs(regs)

    self._log.debug('Start execution from %s, SP %s',
                    self._format_addr_str(entry_point),
                    self._format_addr_str(self.get_stack_address()))
    try:
      self._uc.emu_start(entry_point, self.image.text_end)
    except unicorn.UcError as e:
      self._log.error('UC failed at 0x%x with error %s',
                      self.get_current_address(), e)
      raise self._convert_error(e)

    self._log.debug('Current SP = %s',
                    self._format_addr_str(self.get_stack_address()))
    if self.exception:
      raise self.exception
    return self._ret0

  @abc.abstractmethod
  def syscall(self, *args):
    raise NotImplementedError()

  def allocate_shm_region(self, size: int):
    raise NotImplementedError()

  def free_shm_region(self, rid: int):
    raise NotImplementedError()

