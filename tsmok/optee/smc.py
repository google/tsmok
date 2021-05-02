"""OPTEE SMC constants."""

import enum
import uuid
import tsmok.common.smc as smc


OPTEE_API_UID = uuid.UUID(int=0x384fb3e0e7f811e3af630002a5d5c51b)
OPTEE_OS_UUID = uuid.UUID(int=0x486178e0e7f811e3bc5e0002a5d5c51b)


def optee_smc_std_call(func_num):
  return smc.smc_std_call(smc.SmcOwner.TRUSTED_OS, func_num)


def optee_smc_fast_call_os(func_num):
  return smc.smc_fast_call(smc.SmcOwner.TRUSTED_OS, func_num)


def optee_smc_fast_call_api(func_num):
  return smc.smc_fast_call(smc.SmcOwner.TRUSTED_OS_API, func_num)


class OpteeSmcMsgFunc(enum.IntEnum):
  """OPTEE SMC message call types."""

  CALLS_COUNT = optee_smc_fast_call_api(0xFF00)
  # Return the following UID if using API specified in this file without
  # further extensions:
  # 384fb3e0-e7f8-11e3-af63-0002a5d5c51b.
  # Represented in OPTEE_API_UID
  CALLS_UID = optee_smc_fast_call_api(0xFF01)
  # Returns 2.0 if using API specified in this file without further
  # extensions. represented in 2 32-bit words in optee call revision major
  # and minor
  CALLS_REVISION = optee_smc_fast_call_api(0xFF03)
  # Get UUID of Trusted OS.
  # Used by non-secure world to figure out which Trusted OS is installed.
  # Note that returned UUID is the UUID of the Trusted OS, not of the API.
  # Returns OPTEE_OS_UUID
  GET_OS_UUID = optee_smc_fast_call_os(0)
  # Get revision of Trusted OS.
  # Used by non-secure world to figure out which version of the Trusted OS
  # is installed. Note that the returned revision is the revision of the
  # Trusted OS, not of the API.
  # Returns revision in 2 32-bit words
  GET_OS_REVISION = optee_smc_fast_call_os(1)
  # Resume from RPC (for example after processing a foreign interrupt)
  # Call register usage:
  #   a0   SMC Function ID, RETURN_FROM_RPC
  #   a1-3 Value of a1-3 when CALL_WITH_ARG returned OpteeSmcReturn.RPC in a0
  # Return register usage is the same as for CALL_WITH_ARG above.
  # Possible return values:
  #   OpteeSmcReturn.UNKNOWN_FUNCTION, Trusted OS does not recognize this
  #                  function.
  #   OpteeSmcReturn.OK, Original call completed, result updated in the
  #                  previously supplied.
  #   OpteeSmcReturn.RPC, Call suspended by RPC call to normal world.
  #   OpteeSmcReturn.ERESUME, Resume failed, the opaque resume
  #                  information was corrupt.
  RETURN_FROM_RPC = optee_smc_std_call(3)
  # Call with struct optee_msg_arg as argument
  # Call register usage:
  #   a0   SMC Function ID, CALL_WITH_ARG
  #   a1   Upper 32 bits of a 64-bit physical pointer to a struct optee_msg_arg
  #   a2   Lower 32 bits of a 64-bit physical pointer to a struct optee_msg_arg
  #   a3   Cache settings, not used if physical pointer is in a predefined
  #        shared memory area else per OPTEE_SMC_SHM_*
  #   a4-6 Not used
  #   a7   Hypervisor Client ID register
  # Normal return register usage:
  #   a0   Return value, OpteeSmcReturn.*
  #   a1-3 Not used
  #   a4-7 Preserved
  # OpteeSmcReturn.ETHREAD_LIMIT return register usage:
  #   a0   Return value, OpteeSmcReturn.ETHREAD_LIMIT
  #   a1-3 Preserved
  #   a4-7 Preserved
  # RPC return register usage:
  #   a0   Return value, OpteeSmcReturn.IS_RPC(val)
  #   a1-2 RPC parameters
  #   a3-7 Resume information, must be preserved
  # Possible return values:
  #   OpteeSmcReturn.UNKNOWN_FUNCTION, Trusted OS does not recognize this
  #                  function.
  #   OpteeSmcReturn.OK, Call completed, result updated in
  #                  the previously supplied struct
  #                  optee_msg_arg.
  #   OpteeSmcReturn.ETHREAD_LIMIT, Number of Trusted OS threads exceeded,
  #                  try again later.
  #   OpteeSmcReturn.EBADADDR, Bad physical pointer to struct
  #                  optee_msg_arg.
  #   OpteeSmcReturn.EBADCMD, Bad/unknown cmd in struct optee_msg_arg
  #   OpteeSmcReturn.IS_RPC(), Call suspended by RPC call to normal world.
  CALL_WITH_ARG = optee_smc_std_call(4)
  # Get Shared Memory Config
  # Returns the Secure/Non-secure shared memory config.
  # Call register usage:
  #   a0   SMC Function ID, GET_SHM_CONFIG
  #   a1-6 Not used
  #   a7   Hypervisor Client ID register
  # Have config return register usage:
  #   a0   OpteeSmcReturn.OK
  #   a1   Physical address of start of SHM
  #   a2   Size of of SHM
  #   a3   Cache settings of memory, as defined by the OPTEE_SMC_SHM_*
  #        values above
  #   a4-7 Preserved
  # Not available register usage:
  #   a0   OpteeSmcReturn.ENOTAVAIL
  #   a1-3 Not used
  #   a4-7 Preserved
  GET_SHM_CONFIG = optee_smc_fast_call_os(7)
  # Configures L2CC mutex
  # Disables, enables usage of L2CC mutex. Returns or sets physical address
  # of L2CC mutex.
  # Call register usage:
  #   a0   SMC Function ID, L2CC_MUTEX
  #   a1   OpteeSmcL2ccMutex value
  #   a2   if a1 == OpteeSmcL2ccMutex.SET_ADDR, upper 32bit of a 64bit
  #        physical address of mutex
  #   a3   if a1 == OpteeSmcL2ccMutex.SET_ADDR, lower 32bit of a 64bit
  #        physical address of mutex
  #   a3-6 Not used
  #   a7   Hypervisor Client ID register
  # Have config return register usage:
  #   a0   OpteeSmcReturn.OK
  #   a1   Preserved
  #   a2   if a1 == OpteeSmcL2ccMutex.GET_ADDR, upper 32bit of a 64bit
  #        physical address of mutex
  #   a3   if a1 == OpteeSmcL2ccMutex.GET_ADDR, lower 32bit of a 64bit
  #        physical address of mutex
  #   a3-7 Preserved
  # Error return register usage:
  #   a0   OpteeSmcReturn.ENOTAVAIL  Physical address not available
  #        OpteeSmcReturn.EBADADDR   Bad supplied physical address
  #        OpteeSmcReturn.EBADCMD    Unsupported value in a1
  #   a1-7 Preserved
  L2CC_MUTEX = optee_smc_fast_call_os(8)
  # Exchanges capabilities between normal world and secure world
  # Call register usage:
  #   a0   SMC Function ID, EXCHANGE_CAPABILITIES
  #   a1   bitfield of normal world capabilities OPTEE_SMC_NSEC_CAP_*
  #   a2-6 Not used
  #   a7   Hypervisor Client ID register
  # Normal return register usage:
  #   a0   OpteeSmcReturn.OK
  #   a1   bitfield of secure world capabilities OpteeSmcSecCap
  #   a2-7 Preserved
  # Error return register usage:
  #   a0   OpteeSmcReturn.ENOTAVAIL, can't use the capabilities from normal
  #        world
  #   a1   bitfield of secure world capabilities OpteeSmcSecCap
  #   a2-7 Preserved
  EXCHANGE_CAPABILITIES = optee_smc_fast_call_os(9)
  # Disable and empties cache of shared memory objects
  # Secure world can cache frequently used shared memory objects, for
  # example objects used as RPC arguments. When secure world is idle this
  # function returns one shared memory reference to free. To disable the
  # cache and free all cached objects this function has to be called until
  # it returns OpteeSmcReturn.ENOTAVAIL.
  # Call register usage:
  #   a0   SMC Function ID, DISABLE_SHM_CACHE
  #   a1-6 Not used
  #   a7   Hypervisor Client ID register
  # Normal return register usage:
  #   a0   OpteeSmcReturn.OK
  #   a1   Upper 32 bits of a 64-bit Shared memory cookie
  #   a2   Lower 32 bits of a 64-bit Shared memory cookie
  #   a3-7 Preserved
  # Cache empty return register usage:
  #   a0   OpteeSmcReturn.ENOTAVAIL
  #   a1-7 Preserved
  # Not idle return register usage:
  #   a0   OpteeSmcReturn.EBUSY
  #   a1-7 Preserved
  DISABLE_SHM_CACHE = optee_smc_fast_call_os(10)
  # Enable cache of shared memory objects
  # Secure world can cache frequently used shared memory objects, for
  # example objects used as RPC arguments. When secure world is idle this
  # function returns OpteeSmcReturn.OK and the cache is enabled. If
  # secure world isn't idle OpteeSmcReturn.EBUSY is returned.
  # Call register usage:
  #   a0   SMC Function ID, ENABLE_SHM_CACHE
  #   a1-6 Not used
  #   a7   Hypervisor Client ID register
  # Normal return register usage:
  #   a0   OpteeSmcReturn.OK
  #   a1-7 Preserved
  # Not idle return register usage:
  #   a0   OpteeSmcReturn.EBUSY
  #   a1-7 Preserved
  ENABLE_SHM_CACHE = optee_smc_fast_call_os(11)
  # Release of secondary cores
  # OP-TEE in secure world is in charge of the release process of secondary
  # cores. The Rich OS issue the this request to ask OP-TEE to boot up the
  # secondary cores, go through the OP-TEE per-core initialization, and then
  # switch to the Non-seCure world with the Rich OS provided entry address.
  # The secondary cores enter Non-Secure world in SVC mode, with Thumb, FIQ,
  # IRQ and Abort bits disabled.
  # Call register usage:
  #   a0   SMC Function ID, BOOT_SECONDARY
  #   a1   Index of secondary core to boot
  #   a2   Upper 32 bits of a 64-bit Non-Secure world entry physical address
  #   a3   Lower 32 bits of a 64-bit Non-Secure world entry physical address
  #   a4-7 Not used
  # Normal return register usage:
  #   a0   OpteeSmcReturn.OK
  #   a1-7 Preserved
  # Error return:
  #   a0   OpteeSmcReturn.EBADCMD  Core index out of range
  #   a1-7 Preserved
  # Not idle return register usage:
  #   a0   OpteeSmcReturn.EBUSY
  #   a1-7 Preserved
  BOOT_SECONDARY = optee_smc_fast_call_os(12)
  # Configure secure property of devices
  # Call register usage:
  #   a0   SMC Function ID, CONFIG_DEVICE_SECURE
  #   a1   Device ID
  #   a2   Secure flag
  #   a3-6 Not used
  #   a7   Hypervisor Client ID register
  # Normal return register usage:
  #   a0   OpteeSmcReturn.OK
  #   a1-7 Preserved
  # Not idle return register usage:
  #   a0   OpteeSmcReturn.EBUSY
  #   a1-7 Preserved
  CONFIG_DEVICE_SECURE = optee_smc_fast_call_os(14)


class OpteeSmcNsecCap(enum.IntEnum):
  # Normal world works as a uniprocessor system
  UNIPROCESSOR = (1 << 0)


class OpteeSmcSecCap(enum.IntEnum):
  # Secure world has reserved shared memory for normal world to use/
  HAVE_RESERVED_SHM = (1 << 0)
  # Secure world can communicate via previously unregistered shared memory
  UNREGISTERED_SHM = (1 << 1)


class OpteeSmcL2ccMutex(enum.IntEnum):
  GET_ADDR = 0
  SET_ADDR = 1
  ENABLE = 2
  DISABLE = 3


OPTEE_SMC_SHM_CACHED = 1


OPTEE_SMC_RETURN_RPC_PREFIX_MASK = 0xFFFF0000
OPTEE_SMC_RETURN_RPC_PREFIX = 0xFFFF0000
OPTEE_SMC_RETURN_RPC_FUNC_MASK = 0x0000FFFF


class OpteeSmcReturn(enum.IntEnum):
  """OPTEE SMC return codes."""

  OK = 0x0
  ETHREAD_LIMIT = 0x1
  EBUSY = 0x2
  ERESUME = 0x3
  EBADADDR = 0x4
  EBADCMD = 0x5
  ENOMEM = 0x6
  ENOTAVAIL = 0x7
  # Allocate memory for RPC parameter passing. The memory is used to hold a
  # struct optee_msg_arg.
  # "Call" register usage:
  #   a0   This value, OpteeSmcReturn.RPC_ALLOC
  #   a1   Size in bytes of required argument memory
  #   a2   Not used
  #   a3   Resume information, must be preserved
  #   a4-5 Not used
  #   a6-7 Resume information, must be preserved
  # "Return" register usage:
  #   a0   SMC Function ID, OpteeMsgFunc.RETURN_FROM_RPC.
  #   a1   Upper 32 bits of 64-bit physical pointer to allocated
  #        memory, (a1 == 0 && a2 == 0) if size was 0 or if memory can't
  #        be allocated.
  #   a2   Lower 32 bits of 64-bit physical pointer to allocated
  #        memory, (a1 == 0 && a2 == 0) if size was 0 or if memory can't
  #        be allocated
  #   a3   Preserved
  #   a4   Upper 32 bits of 64-bit Shared memory cookie used when freeing
  #        the memory or doing an RPC
  #   a5   Lower 32 bits of 64-bit Shared memory cookie used when freeing
  #        the memory or doing an RPC
  #   a6-7 Preserved
  RPC_ALLOC = 0xFFFF0000
  # Free memory previously allocated by OpteeSmcReturn.RPC_ALLOC
  # "Call" register usage:
  #   a0   This value, OpteeSmcReturn.RPC_FREE
  #   a1   Upper 32 bits of 64-bit shared memory cookie belonging to this
  #        argument memory
  #   a2   Lower 32 bits of 64-bit shared memory cookie belonging to this
  #        argument memory
  #   a3-7 Resume information, must be preserved
  # "Return" register usage:
  #   a0   SMC Function ID, OpteeMsgFunc.RETURN_FROM_RPC.
  #   a1-2 Not used
  #   a3-7 Preserved
  RPC_FREE = 0xFFFF0002
  # Deliver a foreign interrupt in normal world.
  # "Call" register usage:
  #   a0   RPC_FOREIGN_INTR
  #   a1-7 Resume information, must be preserved
  # "Return" register usage:
  #   a0   SMC Function ID, OpteeMsgFunc.RETURN_FROM_RPC.
  #   a1-7 Preserved
  RPC_FOREIGN_INTR = 0xFFFF0004
  # Do an RPC request. The supplied struct optee_msg_arg tells which
  # request to do and the parameters for the request. The following fields
  # are used (the rest are unused):
  #   - cmd        the Request ID
  #   - ret        return value of the request, filled in by normal world
  #   - num_params     number of parameters for the request
  #   - params     the parameters
  #   - param_attrs    attributes of the parameters
  # "Call" register usage:
  #   a0   OpteeSmcReturn.RPC_CMD
  #   a1   Upper 32 bits of a 64-bit Shared memory cookie holding a
  #        struct optee_msg_arg, must be preserved, only the data should
  #        be updated
  #   a2   Lower 32 bits of a 64-bit Shared memory cookie holding a
  #        struct optee_msg_arg, must be preserved, only the data should
  #        be updated
  #   a3-7 Resume information, must be preserved
  # "Return" register usage:
  #   a0   SMC Function ID, OpteeMsgFunc.RETURN_FROM_RPC.
  #   a1-2 Not used
  #   a3-7 Preserved
  RPC_CMD = 0xFFFF0005
  UNKNOWN_FUNCTION = 0xFFFFFFFF

  @staticmethod
  def is_rpc(value):
    return ((value != OpteeSmcReturn.UNKNOWN_FUNCTION) and
            ((value & OPTEE_SMC_RETURN_RPC_PREFIX_MASK) ==
             OPTEE_SMC_RETURN_RPC_PREFIX))






