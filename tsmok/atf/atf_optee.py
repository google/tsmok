"""ATF TEE implementation."""

import enum
import logging

import tsmok.atf.atf as atf
import tsmok.common.error as error
import tsmok.common.smc as smc
import tsmok.emu.emu as emu


class SmcOpteeCall(enum.IntEnum):
  """SMC function IDs used when returning from TEE to the secure monitor.

  All SMC Function IDs indicates SMC32 Calling Convention but will carry
  full 64 bit values in the argument registers if invoked from Aarch64
  mode. This violates the SMC Calling Convention, but since this
  convention only coveres API towards Normwal World it's something that
  only concerns the OP-TEE Dispatcher in ARM Trusted Firmware and OP-TEE
  OS at Secure EL1.
  """

  # Issued when returning from initial entry.
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_ENTRY_DONE
  # r1/x1	Pointer to entry vector
  OS_RETURN_ENTRY_DONE = 0xbe000000

  # Issued when returning from "cpu_on" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_ON_DONE
  # r1/x1	0 on success and anything else to indicate error condition
  OS_RETURN_ON_DONE = 0xbe000001

  # Issued when returning from "cpu_off" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_OFF_DONE
  # r1/x1	0 on success and anything else to indicate error condition
  OS_RETURN_OFF_DONE = 0xbe000002

  # Issued when returning from "cpu_suspend" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_SUSPEND_DONE
  # r1/x1	0 on success and anything else to indicate error condition
  OS_RETURN_SUSPEND_DONE = 0xbe000003

  # Issued when returning from "cpu_resume" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_RESUME_DONE
  # r1/x1	0 on success and anything else to indicate error condition
  OS_RETURN_RESUME_DONE = 0xbe000004

  # Issued when returning from "std_smc" or "fast_smc" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_CALL_DONE
  # r1-4/x1-4	Return value 0-3 which will passed to normal world in
  #		r0-3/x0-3
  OS_RETURN_CALL_DONE = 0xbe000005

  # Issued when returning from "fiq" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_FIQ_DONE
  OS_RETURN_FIQ_DONE = 0xbe000006

  # Issued when returning from "system_off" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_SYSTEM_OFF_DONE
  OS_RETURN_SYSTEM_OFF_DONE = 0xbe000007

  # Issued when returning from "system_reset" vector
  # Register usage:
  # r0/x0	SMC Function ID, OS_RETURN_SYSTEM_RESET_DONE
  OS_RETURN_SYSTEM_RESET_DONE = 0xbe000008


class AtfOptee(atf.Atf):
  """Implementation of OPTEE Atf."""

  def __init__(self, name='OPTEE-ATF',
               log_level=logging.ERROR):
    atf.Atf.__init__(self, name, log_level)

  def _setup(self):
    # Trustes OS calls
    self._callbacks[SmcOpteeCall.OS_RETURN_ENTRY_DONE] = \
        self.os_return_entry_done

    self._callbacks[SmcOpteeCall.OS_RETURN_CALL_DONE] = \
        self.os_return_call_done

  def os_return_entry_done(self, tee, flag, args):
    if not flag & smc.SmcCallFlag.SECURE:
      raise error.Error('OS return calls are not supported in NS mode')

    tee.set_atf_vector_table_addr(args[0])

    tee.exit(smc.SmcErrorCode.OK)
    return emu.RegContext(smc.SmcErrorCode.OK)

  def os_return_call_done(self, tee, flag, args):
    del flag  # not used in this call
    tee.exit(args[0], args[1], args[2], args[3])
    return emu.RegContext(smc.SmcErrorCode.OK)
