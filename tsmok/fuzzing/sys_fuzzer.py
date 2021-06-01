"""OPTEE TA fuzzing."""

import logging

import tsmok.common.syscall_decl.syscall as syscall
import tsmok.common.ta_error as ta_error
import tsmok.optee.error as optee_error


class SysFuzzer:
  """AFLPlusPlus compatible Syscall fuzzer wrapper."""

  def __init__(self, emu, syscalls=None, log_level=logging.INFO):
    self.log = logging.getLogger('[TaFuzzer]')
    self.log.setLevel(log_level)
    self._emu = emu
    self._syscalls = syscalls or dict()

  def init(self):
    """Starts AFL forkserver.

    After this call all commands will be executed for each *child*

    Args:
      None

    Returns:
      True, if returns from child process.

    Raises:
      Error exception in case of unknown or unsupported mode.
    """
    return self._emu.forkserver_start()

  def load_args_to_mem(self, regs, addr, data):
    to_addr = addr
    if not to_addr:
      reg = self._emu.allocate_shm_region(len(data))
      to_addr = reg.addr
      if regs:
        regs.append(reg)
    self._emu.mem_write(to_addr, data)
    return to_addr

  def run(self, data: bytes):
    """Runs Ta emulation.

    Args:
      data: bytes of input which will be parsed and converted to input for
            Emu.

    Returns:
      return status as defined in OpteeErrorCode

    Raises:
      Error exception in case of unexpected error.
    """
    args_data = data.split(syscall.Syscall.CALLDELIM)
    regs = []
    for adata in args_data:
      if not adata:
        continue
      nr = syscall.Syscall.parse_call_number(adata)
      ret = optee_error.OpteeErrorCode.SUCCESS
      try:
        scall = self._syscalls[nr]
        call = scall.create(adata)
      except (KeyError, TypeError, IndexError):
        continue
      try:
        call.load_args_to_mem(lambda a, d: self.load_args_to_mem(regs, a, d))
        self._emu.syscall(call.NR, *call.args())
        for r in regs:
          self._emu.free_shm_region(r.id)
        regs = []
      except ta_error.TaPanicError as e:
        logging.error(e.message)
        ret = e.ret
      except ta_error.TaExit as e:
        logging.error(e.message)
        ret = e.ret

    return ret

  def stop(self):
    self._ta.exit(0)
