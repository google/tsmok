"""ATF specific constants."""

import enum
import tsmok.common.smc as smc


class SmcErrorCode(enum.IntEnum):
  OK = 0
  PREEMPTED = 0xfffffffe
  UNKNOWN = 0xFFFFFFFF


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


class SmcCallFlag(enum.IntFlag):
  SECURE = 1 << 0
  NON_SECURE = 1 << 1


class SmcTrustyCall(enum.IntEnum):
  DEBUG_PUTC = smc.smc_call_value(smc.SmcType.x32,
                                  smc.SmcCallingConvention.FAST_CALL,
                                  smc.SmcOwner.TRUSTED_OS_TRUSTY, 0)
  GET_REG_BASE = smc.smc_call_value(smc.SmcType.x32,
                                    smc.SmcCallingConvention.FAST_CALL,
                                    smc.SmcOwner.TRUSTED_OS_TRUSTY, 1)
  GET_REG_BASE_X64 = smc.smc_call_value(smc.SmcType.x64,
                                        smc.SmcCallingConvention.FAST_CALL,
                                        smc.SmcOwner.TRUSTED_OS_TRUSTY, 1)
