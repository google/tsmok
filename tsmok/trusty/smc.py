"""Trusty SMC Calls."""

import enum
import tsmok.common.smc as smc


class TrustyIrqType(enum.IntEnum):
  NORMAL = 0
  PER_CPU = 1
  DOORBELL = 2


class SmcError(enum.IntEnum):
  """Errors from the secure monitor."""
  SUCCESS = 0
  # Unknown SMC (defined by ARM DEN 0028A(0.9.0) */
  UNDEFINED_SMC = 0xffffffffffffffff  # -1
  INVALID_PARAMETERS = 0xfffffffffffffffe  # -2
  # Got interrupted. Call back with restart SMC */
  INTERRUPTED = 0xfffffffffffffffd  # -3
  # Got an restart SMC when we didn't expect it */
  UNEXPECTED_RESTART = 0xfffffffffffffffc  # -4
  # Temporarily busy. Call back with original args */
  BUSY = 0xfffffffffffffffb  # -5
  # Got a trusted_service SMC when a restart SMC is required */
  INTERLEAVED_SMC = 0xfffffffffffffffa  # -6
  # Unknown error */
  INTERNAL_FAILURE = 0xfffffffffffffff9  # -7
  NOT_SUPPORTED = 0xfffffffffffffff8  # -8
  # SMC call not allowed */
  NOT_ALLOWED = 0xfffffffffffffff7  # -9
  END_OF_INPUT = 0xfffffffffffffff6  # -10
  # Secure OS crashed */
  PANIC = 0xfffffffffffffff5  # -11
  # Got interrupted by FIQ. Call back with SMC_SC_RESTART_FIQ on same CPU */
  FIQ_INTERRUPTED = 0xfffffffffffffff4  # -12
  # SMC call waiting for another CPU */
  CPU_IDLE = 0xfffffffffffffff3  # -13
  # Got interrupted. Call back with new SMC_SC_NOP */
  NOP_INTERRUPTED = 0xfffffffffffffff2  # -14
  # Cpu idle after SMC_SC_NOP (not an error) */
  NOP_DONE = 0xfffffffffffffff1  # -15


def smc_rc_is_error(rc):
  return rc & (1<<63)


class TrustyApiVersion(enum.IntEnum):
  RESTART_FIQ = 1
  SMP = 2
  SMP_NOP = 3
  PHYS_MEM_OBJ = 4
  MEM_OBJ = 5
  CURRENT = 5


class SmcCall(enum.IntEnum):
  """Trusty specific SMC Calls."""

  # FC = Fast call, SC = Standard call
  RESTART_LAST = smc.smc_std_call(smc.SmcOwner.SECURE_MONITOR, 0)
  LOCKED_NOP = smc.smc_std_call(smc.SmcOwner.SECURE_MONITOR, 1)

  # RESTART_FIQ - Re-enter trusty after it was interrupted by an fiq
  #
  # No arguments, no return value.
  #
  # Re-enter trusty after returning to ns to process an fiq. Must be called iff
  # trusty returns SmcError.FIQ_INTERRUPTED.
  #
  # Enable by selecting api version TRUSTY_API_VERSION_RESTART_FIQ (1) or later.
  RESTART_FIQ = smc.smc_std_call(smc.SmcOwner.SECURE_MONITOR, 2)

  # NOP - Enter trusty to run pending work.
  #
  # No arguments.
  #
  # Returns SmcError.NOP_INTERRUPTED or SmcError.NOP_DONE.
  # If SmcError.NOP_INTERRUPTED is returned, the call must be repeated.
  #
  # Enable by selecting api version TRUSTY_API_VERSION_SMP (2) or later.
  NOP = smc.smc_std_call(smc.SmcOwner.SECURE_MONITOR, 3)

  RESERVED = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 0)
  FIQ_EXIT = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 1)
  REQUEST_FIQ = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 2)
  GET_NEXT_IRQ = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 3)
  FIQ_ENTER = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 4)
  SET_FIQ_HANDLER = smc.smc_fast_x64_call(smc.SmcOwner.SECURE_MONITOR, 5)
  GET_FIQ_REGS = smc.smc_fast_x64_call(smc.SmcOwner.SECURE_MONITOR, 6)
  CPU_SUSPEND = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 7)
  CPU_RESUME = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 8)
  AARCH_SWITCH = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 9)
  GET_VERSION_STR = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 10)

  # API_VERSION - Find and select supported API version.
  # r1: Version supported by client.
  # Returns version supported by trusty.
  # If multiple versions are supported, the client should start by calling
  # API_VERSION with the largest version it supports. Trusty will then
  # return a version it supports. If the client does not support the version
  # returned by trusty and the version returned is less than the version
  # requested, repeat the call with the largest supported version less than the
  # last returned version.
  # This call must be made before any calls that are affected by the
  # api version.
  API_VERSION = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 11)
  FIQ_RESUME = smc.smc_fast_call(smc.SmcOwner.SECURE_MONITOR, 12)

  # TRUSTED_OS entity calls
  VIRTIO_GET_DESCR = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 20)
  VIRTIO_START = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 21)
  VIRTIO_STOP = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 22)
  VDEV_RESET = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 23)
  VDEV_KICK_VQ = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 24)
  VDEV_KICK_VQ_NC = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 25)

  # Simplified (Queueless) IPC interface
  CREATE_QL_TIPC_DEV = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 30)
  SHUTDOWN_QL_TIPC_DEV = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 31)
  HANDLE_QL_TIPC_DEV_STD_CMD = smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, 32)
  HANDLE_QL_TIPC_DEV_FC_CMD = smc.smc_fast_call(smc.SmcOwner.TRUSTED_OS, 32)
