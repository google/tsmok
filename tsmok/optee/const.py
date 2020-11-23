"""Main OPTEE constants."""
import enum
import struct
import uuid


class OpteeSysCalls(enum.IntEnum):
  """Syscall numbers to OPTEE TEE."""
  RETURN = 0
  LOG = 1
  PANIC = 2
  GET_PROPERTY = 3
  GET_PROPERTY_NAME_TO_INDEX = 4
  OPEN_TA_SESSION = 5
  CLOSE_TA_SESSION = 6
  INVOKE_TA_COMMAND = 7
  CHECK_ACCESS_RIGHTS = 8
  GET_CANCELLATION_FLAG = 9
  UNMASK_CANCELLATION = 10
  MASK_CANCELLATION = 11
  WAIT = 12
  GET_TIME = 13
  SET_TA_TIME = 14
  CRYP_STATE_ALLOC = 15
  CRYP_STATE_COPY = 16
  CRYP_STATE_FREE = 17
  HASH_INIT = 18
  HASH_UPDATE = 19
  HASH_FINAL = 20
  CIPHER_INIT = 21
  CIPHER_UPDATE = 22
  CIPHER_FINAL = 23
  CRYP_OBJ_GET_INFO = 24
  CRYP_OBJ_RESTRICT_USAGE = 25
  CRYP_OBJ_GET_ATTR = 26
  CRYP_OBJ_ALLOC = 27
  CRYP_OBJ_CLOSE = 28
  CRYP_OBJ_RESET = 29
  CRYP_OBJ_POPULATE = 30
  CRYP_OBJ_COPY = 31
  CRYP_DERIVE_KEY = 32
  CRYP_RANDOM_NUMBER_GENERATE = 33
  AUTHENC_INIT = 34
  AUTHENC_UPDATE_AAD = 35
  AUTHENC_UPDATE_PAYLOAD = 36
  AUTHENC_ENC_FINAL = 37
  AUTHENC_DEC_FINAL = 38
  ASYMM_OPERATE = 39
  ASYMM_VERIFY = 40
  STORAGE_OBJ_OPEN = 41
  STORAGE_OBJ_CREATE = 42
  STORAGE_OBJ_DEL = 43
  STORAGE_OBJ_RENAME = 44
  STORAGE_ENUM_ALLOC = 45
  STORAGE_ENUM_FREE = 46
  STORAGE_ENUM_RESET = 47
  STORAGE_ENUM_START = 48
  STORAGE_ENUM_NEXT = 49
  STORAGE_OBJ_READ = 50
  STORAGE_OBJ_WRITE = 51
  STORAGE_OBJ_TRUNC = 52
  STORAGE_OBJ_SEEK = 53
  CRYP_OBJ_GENERATE_KEY = 54
  # Deprecated Secure Element API syscalls return TEE_ERROR_NOT_SUPPORTED
  SE_SERVICE_OPEN__DEPRECATED = 55
  SE_SERVICE_CLOSE__DEPRECATED = 56
  SE_SERVICE_GET_READERS__DEPRECATED = 57
  SE_READER_GET_PROP__DEPRECATED = 58
  SE_READER_GET_NAME__DEPRECATED = 59
  SE_READER_OPEN_SESSION__DEPRECATED = 60
  SE_READER_CLOSE_SESSIONS__DEPRECATED = 61
  SE_SESSION_IS_CLOSED__DEPRECATED = 62
  SE_SESSION_GET_ATR__DEPRECATED = 63
  SE_SESSION_OPEN_CHANNEL__DEPRECATED = 64
  SE_SESSION_CLOSE__DEPRECATED = 65
  SE_CHANNEL_SELECT_NEXT__DEPRECATED = 66
  SE_CHANNEL_GET_SELECT_RESP__DEPRECATED = 67
  SE_CHANNEL_TRANSMIT__DEPRECATED = 68
  SE_CHANNEL_CLOSE__DEPRECATED = 69
  # End of deprecated Secure Element API syscalls
  CACHE_OPERATION = 70


class OpteePropsetType(enum.IntEnum):
  TEE_IMPLEMENTATION = 0xFFFFFFFD
  CURRENT_CLIENT = 0xFFFFFFFE
  CURRENT_TA = 0xFFFFFFFF


class OpteePropertyType(enum.IntEnum):
  BOOL = 0
  U32 = 1
  UUID = 2
  IDENTITY = 3,  # TEE_Identity
  STRING = 4,  # zero terminated string of char
  BINARY_BLOCK = 5,  # zero terminated base64 coded string


class OpteeEntryFunc(enum.IntEnum):
  OPEN_SESSION = 0
  CLOSE_SESSION = 1
  INVOKE_COMMAND = 2


class OpteeParamType(enum.IntEnum):
  NONE = 0
  VALUE_INPUT = 1
  VALUE_OUTPUT = 2
  VALUE_INOUT = 3
  MEMREF_INPUT = 5
  MEMREF_OUTPUT = 6
  MEMREF_INOUT = 7


class OpteeErrorCode(enum.IntEnum):
  """Defines OPTEE return code."""

  SUCCESS = 0x00000000
  ERROR_CORRUPT_OBJECT = 0xF0100001
  ERROR_CORRUPT_OBJECT_2 = 0xF0100002
  ERROR_STORAGE_NOT_AVAILABLE = 0xF0100003
  ERROR_STORAGE_NOT_AVAILABLE_2 = 0xF0100004
  ERROR_GENERIC = 0xFFFF0000
  ERROR_ACCESS_DENIED = 0xFFFF0001
  ERROR_CANCEL = 0xFFFF0002
  ERROR_ACCESS_CONFLICT = 0xFFFF0003
  ERROR_EXCESS_DATA = 0xFFFF0004
  ERROR_BAD_FORMAT = 0xFFFF0005
  ERROR_BAD_PARAMETERS = 0xFFFF0006
  ERROR_BAD_STATE = 0xFFFF0007
  ERROR_ITEM_NOT_FOUND = 0xFFFF0008
  ERROR_NOT_IMPLEMENTED = 0xFFFF0009
  ERROR_NOT_SUPPORTED = 0xFFFF000A
  ERROR_NO_DATA = 0xFFFF000B
  ERROR_OUT_OF_MEMORY = 0xFFFF000C
  ERROR_BUSY = 0xFFFF000D
  ERROR_COMMUNICATION = 0xFFFF000E
  ERROR_SECURITY = 0xFFFF000F
  ERROR_SHORT_BUFFER = 0xFFFF0010
  ERROR_EXTERNAL_CANCEL = 0xFFFF0011
  ERROR_TA_VERSION_INVALID = 0xFFFF0012
  ERROR_TA_NUM_REACH_MAX = 0xFFFF0013
  ERROR_OVERFLOW = 0xFFFF300F
  ERROR_TARGET_DEAD = 0xFFFF3024
  ERROR_STORAGE_NO_SPACE = 0xFFFF3041
  ERROR_MAC_INVALID = 0xFFFF3071
  ERROR_SIGNATURE_INVALID = 0xFFFF3072
  ERROR_TIME_NOT_SET = 0xFFFF5000
  ERROR_TIME_NEEDS_RESET = 0xFFFF5001
  ERROR_ARGUMENT_INVALID = 0xF57E0011
  ERROR_INPUT_LENGTH_INVALID = 0xF57E0012


class OpteeOriginCode(enum.IntEnum):
  API = 0x00000001
  COMMS = 0x00000002
  TEE = 0x00000003
  TRUSTED_APP = 0x00000004


OPTEE_CMD_TIMEOUT_INFINITE = 0xFFFFFFFF
OPTEE_DATA_MAX_POSITION = 0xFFFFFFFF

OPTEE_NUM_PARAMS = 4
# struct utee_params {
#   uint64_t types;
#       /* vals[n * 2]     corresponds to either value.a or memref.buffer
#        * vals[n * 2 + ]  corresponds to either value.b or memref.size
#        * when converting to/from struct tee_ta_param
#        */
#   uint64_t vals[TEE_NUM_PARAMS * 2];
# };
OPTEE_PARAMS_PARSE_FORMAT = '<9Q'

OPTEE_PARAMS_DATA_SIZE = struct.calcsize(OPTEE_PARAMS_PARSE_FORMAT)


class OpteeObjectType(enum.IntEnum):
  """Defines main OPTEE object types."""

  AES = 0xA0000010
  DES = 0xA0000011
  DES3 = 0xA0000013
  HMAC_MD5 = 0xA0000001
  HMAC_SHA1 = 0xA0000002
  HMAC_SHA224 = 0xA0000003
  HMAC_SHA256 = 0xA0000004
  HMAC_SHA384 = 0xA0000005
  HMAC_SHA512 = 0xA0000006
  RSA_PUBLIC_KEY = 0xA0000030
  RSA_KEYPAIR = 0xA1000030
  DSA_PUBLIC_KEY = 0xA0000031
  DSA_KEYPAIR = 0xA1000031
  DH_KEYPAIR = 0xA1000032
  ECDSA_PUBLIC_KEY = 0xA0000041
  ECDSA_KEYPAIR = 0xA1000041
  ECDH_PUBLIC_KEY = 0xA0000042
  ECDH_KEYPAIR = 0xA1000042
  GENERIC_SECRET = 0xA0000000
  CORRUPTED_OBJECT = 0xA00000BE
  DATA = 0xA00000BF
  RSA_FROM_PKCS8 = 0xA2000001
  EXPORT_FROM_RSA = 0xA2000002
  EXPORT_FROM_DSA = 0xA2000003
  IMPORT_DSA_KEY = 0xA2000004


class OpteeHandleFlags(enum.IntFlag):
  PERSISTENT = 0x00010000
  INITIALIZED = 0x00020000
  KEY_SET = 0x00040000
  EXPECT_TWO_KEYS = 0x00080000


class OpteeUsage(enum.IntFlag):
  EXTRACTABLE = 0x00000001
  ENCRYPT = 0x00000002
  DECRYPT = 0x00000004
  MAC = 0x00000008
  SIGN = 0x00000010
  VERIFY = 0x00000020
  DERIVE = 0x00000040
  DEFAULT = 0xFFFFFFFF


OPTEE_OBJECT_ID_MAX_LEN = 64


class OpteeStorageId(enum.IntEnum):
  # Storage is provided by the Rich Execution Environment (REE)
  PRIVATE_REE = 0x80000000
  # Storage is the Replay Protected Memory Block partition of an eMMC device
  PRIVATE_RPMB = 0x80000100


class OpteeStorageFlags(enum.IntFlag):
  ACCESS_READ = 0x00000001
  ACCESS_WRITE = 0x00000002
  ACCESS_WRITE_META = 0x00000004
  SHARE_READ = 0x00000010
  SHARE_WRITE = 0x00000020
  OVERWRITE = 0x00000400


class OpteeWhence(enum.IntEnum):
  SEEK_SET = 0
  SEEK_CUR = 1
  SEEK_END = 2

  @classmethod
  def has_value(cls, value):
    return value in cls._value2member_map_


class OpteeCrypOperation(enum.IntEnum):
  CIPHER = 1
  MAC = 3
  AE = 4
  DIGEST = 5
  ASYMMETRIC_CIPHER = 6
  ASYMMETRIC_SIGNATURE = 7
  KEY_DERIVATION = 8


class OpteeCrypOperationMode(enum.IntEnum):
  ENCRYPT = 0
  DECRYPT = 1
  SIGN = 2
  VERIFY = 3
  MAC = 4
  DIGEST = 5
  DERIVE = 6


class OpteeCrypAlg(enum.IntFlag):
  """Defines OPTEE crypto algorithm."""
  AES_ECB_NOPAD = 0x10000010
  AES_CBC_NOPAD = 0x10000110
  AES_CTR = 0x10000210
  AES_CTS = 0x10000310
  AES_XTS = 0x10000410
  AES_CBC_MAC_NOPAD = 0x30000110
  AES_CBC_MAC_PKCS5 = 0x30000510
  AES_CMAC = 0x30000610
  AES_CCM = 0x40000710
  AES_GCM = 0x40000810
  AES_GCM_SCP = 0x40000910
  DES_ECB_NOPAD = 0x10000011
  DES_CBC_NOPAD = 0x10000111
  DES_CBC_MAC_NOPAD = 0x30000111
  DES_CBC_MAC_PKCS5 = 0x30000511
  DES3_ECB_NOPAD = 0x10000013
  DES3_CBC_NOPAD = 0x10000113
  DES3_CBC_MAC_NOPAD = 0x30000113
  DES3_CBC_MAC_PKCS5 = 0x30000513
  RSASSA_PKCS1_V1_5_NODIGEST = 0x70000830
  RSASSA_PKCS1_V1_5_MD5 = 0x70001830
  RSASSA_PKCS1_V1_5_SHA1 = 0x70002830
  RSASSA_PKCS1_V1_5_SHA224 = 0x70003830
  RSASSA_PKCS1_V1_5_SHA256 = 0x70004830
  RSASSA_PKCS1_V1_5_SHA384 = 0x70005830
  RSASSA_PKCS1_V1_5_SHA512 = 0x70006830
  RSASSA_PKCS1_V1_5_MD5SHA1 = 0x7000F830
  RSASSA_PKCS1_PSS_MGF1_NODIGEST = 0x70010930
  RSASSA_PKCS1_PSS_MGF1_MD5 = 0x70111930
  RSASSA_PKCS1_PSS_MGF1_SHA1 = 0x70212930
  RSASSA_PKCS1_PSS_MGF1_SHA224 = 0x70313930
  RSASSA_PKCS1_PSS_MGF1_SHA256 = 0x70414930
  RSASSA_PKCS1_PSS_MGF1_SHA384 = 0x70515930
  RSASSA_PKCS1_PSS_MGF1_SHA512 = 0x70616930
  RSAES_PKCS1_V1_5 = 0x60000130
  RSAES_PKCS1_OAEP_MGF1_MD5 = 0x60110230
  RSAES_PKCS1_OAEP_MGF1_SHA1 = 0x60210230
  RSAES_PKCS1_OAEP_MGF1_SHA224 = 0x60310230
  RSAES_PKCS1_OAEP_MGF1_SHA256 = 0x60410230
  RSAES_PKCS1_OAEP_MGF1_SHA384 = 0x60510230
  RSAES_PKCS1_OAEP_MGF1_SHA512 = 0x60610230
  RSA_NOPAD = 0x60000030
  DSA_SHA1 = 0x70002131
  DSA_SHA224 = 0x70003131
  DSA_SHA256 = 0x70004131
  DH_DERIVE_SHARED_SECRET = 0x80000032
  DIGEST_NONE = 0x50000000
  MD5 = 0x50000001
  SHA1 = 0x50000002
  SHA224 = 0x50000003
  SHA256 = 0x50000004
  SHA384 = 0x50000005
  SHA512 = 0x50000006
  MD5SHA1 = 0x5000000F
  HMAC_MD5 = 0x30000001
  HMAC_SHA1 = 0x30000002
  HMAC_SHA224 = 0x30000003
  HMAC_SHA256 = 0x30000004
  HMAC_SHA384 = 0x30000005
  HMAC_SHA512 = 0x30000006


def optee_cryp_algo_get_operation(algo: int) -> OpteeCrypOperation:
  return OpteeCrypOperation(((algo) >> 28) & 0xF)


class OpteeSmcCallingConvention(enum.IntEnum):
  FAST_CALL = 0x80000000
  STD_CALL = 0


class OpteeSmcType(enum.IntEnum):
  x32 = 0
  x64 = 0x40000000


OPTEE_SMC_OWNER_MASK = 0x3F
OPTEE_SMC_OWNER_SHIFT = 24
OPTEE_SMC_FUNC_MASK = 0xFFFF


class OpteeSmcOwner(enum.IntEnum):
  ARCH = 0
  CPU = 1
  SIP = 2
  OEM = 3
  STANDARD = 4
  TRUSTED_APP = 48
  TRUSTED_OS = 50
  TRUSTED_OS_OPTEED = 62
  TRUSTED_OS_API = 63


def optee_smc_call_val(ctype, calling_convention, owner, func_num):
  return ((ctype) | (calling_convention) |
          (((owner) & OPTEE_SMC_OWNER_MASK) << OPTEE_SMC_OWNER_SHIFT) |
          ((func_num) & OPTEE_SMC_FUNC_MASK))


def optee_smc_std_call_val(func_num):
  return optee_smc_call_val(OpteeSmcType.x32,
                            OpteeSmcCallingConvention.STD_CALL,
                            OpteeSmcOwner.TRUSTED_OS, func_num)


def optee_smc_fast_call_val(func_num):
  return optee_smc_call_val(OpteeSmcType.x32,
                            OpteeSmcCallingConvention.FAST_CALL,
                            OpteeSmcOwner.TRUSTED_OS, func_num)


class OpteeMsgFunc(enum.IntEnum):
  """OPTEE SMC message call types."""

  CALLS_COUNT = optee_smc_call_val(OpteeSmcType.x32,
                                   OpteeSmcCallingConvention.FAST_CALL,
                                   OpteeSmcOwner.TRUSTED_OS_API, 0xFF00)
  # Return the following UID if using API specified in this file without
  # further extensions:
  # 384fb3e0-e7f8-11e3-af63-0002a5d5c51b.
  # Represented in OPTEE_API_UID
  CALLS_UID = optee_smc_call_val(OpteeSmcType.x32,
                                 OpteeSmcCallingConvention.FAST_CALL,
                                 OpteeSmcOwner.TRUSTED_OS_API, 0xFF01)
  # Returns 2.0 if using API specified in this file without further
  # extensions. represented in 2 32-bit words in optee call revision major
  # and minor
  CALLS_REVISION = optee_smc_call_val(OpteeSmcType.x32,
                                      OpteeSmcCallingConvention.FAST_CALL,
                                      OpteeSmcOwner.TRUSTED_OS_API, 0xFF03)
  # Get UUID of Trusted OS.
  # Used by non-secure world to figure out which Trusted OS is installed.
  # Note that returned UUID is the UUID of the Trusted OS, not of the API.
  # Returns OPTEE_OS_UUID
  GET_OS_UUID = optee_smc_fast_call_val(0)
  # Get revision of Trusted OS.
  # Used by non-secure world to figure out which version of the Trusted OS
  # is installed. Note that the returned revision is the revision of the
  # Trusted OS, not of the API.
  # Returns revision in 2 32-bit words
  GET_OS_REVISION = optee_smc_fast_call_val(1)
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
  RETURN_FROM_RPC = optee_smc_std_call_val(3)
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
  CALL_WITH_ARG = optee_smc_std_call_val(4)
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
  GET_SHM_CONFIG = optee_smc_fast_call_val(7)
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
  L2CC_MUTEX = optee_smc_fast_call_val(8)
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
  EXCHANGE_CAPABILITIES = optee_smc_fast_call_val(9)
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
  DISABLE_SHM_CACHE = optee_smc_fast_call_val(10)
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
  ENABLE_SHM_CACHE = optee_smc_fast_call_val(11)
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
  BOOT_SECONDARY = optee_smc_fast_call_val(12)
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
  CONFIG_DEVICE_SECURE = optee_smc_fast_call_val(14)
  VIDEO_LOAD_FW = optee_smc_fast_call_val(15)


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


OPTEE_API_UID = uuid.UUID(int=0x384fb3e0e7f811e3af630002a5d5c51b)
OPTEE_OS_UUID = uuid.UUID(int=0x486178e0e7f811e3bc5e0002a5d5c51b)


OPTEE_SMC_SHM_CACHED = 1


class OpteeMsgCmd(enum.IntEnum):
  """OPTEE OpteeMsgFunc.CALL_WITH_ARG commands types."""

  # OPEN_SESSION opens a session to a Trusted Application.
  # The first two parameters are tagged as meta, holding two value
  # parameters to pass the following information:
  # param[0].u.value.a-b uuid of Trusted Application
  # param[1].u.value.a-b uuid of Client
  # param[1].u.value.c Login class of client OpteeMsgLoginType
  OPEN_SESSION = 0
  # INVOKE_COMMAND invokes a command a previously opened
  # session to a Trusted Application.  struct optee_msg_arg::func is Trusted
  # Application function, specific to the Trusted Application.
  INVOKE_COMMAND = 1
  # CLOSE_SESSION closes a previously opened session to
  # Trusted Application.
  CLOSE_SESSION = 2
  # CANCEL cancels a currently invoked command.
  CANCEL = 3
  # REGISTER_SHM registers a shared memory reference. The
  # information is passed as:
  # [in] param[0].attr     OpteeMsgAttrType.TMEM_INPUT
  #          [| OPTEE_MSG_ATTR_FRAGMENT]
  # [in] param[0].u.tmem.buf_ptr   physical address (of first fragment)
  # [in] param[0].u.tmem.size    size (of first fragment)
  # [in] param[0].u.tmem.shm_ref   holds shared memory reference
  # The shared memory can optionally be fragmented, temp memrefs can follow
  # each other with all but the last with the OPTEE_MSG_ATTR_FRAGMENT bit set.
  REGISTER_SHM = 4
  # UNREGISTER_SHM unregisteres a previously registered shared
  # memory reference. The information is passed as:
  # [in] param[0].attr     OpteeMsgAttrType.RMEM_INPUT
  # [in] param[0].u.rmem.shm_ref   holds shared memory reference
  # [in] param[0].u.rmem.offs    0
  # [in] param[0].u.rmem.size    0
  UNREGISTER_SHM = 5


class OpteeMsgAttrType(enum.IntEnum):
  """OPTEE SMC OpteeMsgFunc.CALL_WITH_ARG argument types."""

  NONE = 0x0
  VALUE_INPUT = 0x1
  VALUE_OUTPUT = 0x2
  VALUE_INOUT = 0x3
  RMEM_INPUT = 0x5
  RMEM_OUTPUT = 0x6
  RMEM_INOUT = 0x7
  TMEM_INPUT = 0x9
  TMEM_OUTPUT = 0xa
  TMEM_INOUT = 0xb


# Meta parameter to be absorbed by the Secure OS and not passed
# to the Trusted Application.
# Currently only used with OpteeMsgCmd.OPEN_SESSION.
OPTEE_MSG_ATTR_META = (1 << 8)

# Pointer to a list of pages used to register user-defined SHM buffer.
# Used with OpteeMsgAttrType.TMEM_*.
# buf_ptr should point to the beginning of the buffer. Buffer will contain
# list of page addresses. OP-TEE core can reconstruct contiguous buffer from
# that page addresses list. Page addresses are stored as 64 bit values.
# Last entry on a page should point to the next page of buffer.
# Every entry in buffer should point to a 4k page beginning (12 least
# significant bits must be equal to zero).
OPTEE_MSG_ATTR_NONCONTIG = (1 << 9)


class OpteeMsgLoginType(enum.IntEnum):
  PUBLIC = 0x0
  USER = 0x1
  GROUP = 0x2
  APPLICATION = 0x4
  APPLICATION_USER = 0x5
  APPLICATION_GROUP = 0x6
  TRUSTED_APP = 0xF0000000


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

