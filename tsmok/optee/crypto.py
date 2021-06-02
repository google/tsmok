"""OPTEE Crypto implementation."""

import abc
import enum
import hashlib
import hmac
import math
import os
import struct
from typing import Dict, Any
import tsmok.common.error as error
import tsmok.optee.error as optee_error
import tsmok.optee.storage as storage


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
  HKDF_MD5_DERIVE_KEY = 0x800010C0
  HKDF_SHA1_DERIVE_KEY = 0x800020C0
  HKDF_SHA224_DERIVE_KEY = 0x800030C0
  HKDF_SHA256_DERIVE_KEY = 0x800040C0
  HKDF_SHA384_DERIVE_KEY = 0x800050C0
  HKDF_SHA512_DERIVE_KEY = 0x800060C0
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


class OpteeTypeAttr(enum.IntEnum):
  OPTIONAL = 0x0
  REQUIRED = 0x1
  OPTIONAL_GROUP = 0x2
  SIZE_INDICATOR = 0x4
  GEN_KEY_OPT = 0x8
  GEN_KEY_REQ = 0x10


class OpteeAttr(enum.IntEnum):
  """Defibes OPTEE Attribute types."""

  SECRET_VALUE = 0xC0000000
  RSA_MODULUS = 0xD0000130
  RSA_PUBLIC_EXPONENT = 0xD0000230
  RSA_PRIVATE_EXPONENT = 0xC0000330
  RSA_PRIME1 = 0xC0000430
  RSA_PRIME2 = 0xC0000530
  RSA_EXPONENT1 = 0xC0000630
  RSA_EXPONENT2 = 0xC0000730
  RSA_COEFFICIENT = 0xC0000830
  DSA_PRIME = 0xD0001031
  DSA_SUBPRIME = 0xD0001131
  DSA_BASE = 0xD0001231
  DSA_PUBLIC_VALUE = 0xD0000131
  DSA_PRIVATE_VALUE = 0xC0000231
  DH_PRIME = 0xD0001032
  DH_SUBPRIME = 0xD0001132
  DH_BASE = 0xD0001232
  DH_X_BITS = 0xF0001332
  DH_PUBLIC_VALUE = 0xD0000132
  DH_PRIVATE_VALUE = 0xC0000232
  RSA_OAEP_LABEL = 0xD0000930
  RSA_PSS_SALT_LENGTH = 0xF0000A30
  RSA_OAEP_MGF1_USE_SHA1 = 0xF0000B30
  ECC_PUBLIC_VALUE_X = 0xD0000141
  ECC_PUBLIC_VALUE_Y = 0xD0000241
  ECC_PRIVATE_VALUE = 0xC0000341
  ECC_CURVE = 0xF0000441
  PKCS8_BASE = 0xD0001233
  PKCS1_BASE = 0xD0001234
  PKCS1_TYPE = 0xD0001235
  DSA_DATA = 0xD0001236
  DSA_TYPE = 0xD0001237
  ECC_RAW_DATA = 0xD0001238
  ASN1_ENCODED = 0xF0001239
  HKDF_IKM = 0xC00001C0
  HKDF_SALT = 0xD00002C0
  HKDF_INFO = 0xD00003C0
  HKDF_OKM_LENGTH = 0xF00004C0


class OpteeAttrOpsIndex(enum.IntEnum):
  # Handle storing of generic secret keys of varying lengths
  SECRET = 0
  # Convert to/from big-endian byte array and provider-specific bignum
  BIGNUM = 1
  # Convert to/from value attribute depending on direction
  VALUE = 2


def optee_cryp_algo_get_operation(algo: int) -> OpteeCrypOperation:
  return OpteeCrypOperation(((algo) >> 28) & 0xF)


def optee_cryp_alg_get_digest_hash(algo: int):
  return OpteeCrypAlg.DIGEST_NONE | ((algo >> 12) & 0xF)


class OpteeCrypObjTypeAttr:
  """Defines OPTEE Object type attributes."""

  FORMAT = '<I4H'

  def __init__(self, data=None):
    if data:
      if isinstance(data, bytes):
        self.load(data)
      else:
        raise ValueError('Wrong type of data')
    else:
      self.attr_id = 0
      self.flags = 0
      self.ops_index = 0
      self.raw_offs = 0
      self.raw_size = 0

  def load(self, data):
    sz = struct.calcsize(self.FORMAT)

    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    self.attr_id, self.flags, self.ops_index, self.raw_offs, self.raw_size = \
        struct.unpack(self.FORMAT, data[:sz])
    return sz

  @staticmethod
  def size():
    return struct.calcsize(OpteeCrypObjTypeAttr.FORMAT)

  def __bytes__(self):
    return struct.pack(self.FORMAT, self.attr_id, self.flags, self.ops_index,
                       self.raw_offs, self.raw_size)

  def __str__(self):
    out = 'OpteeCrypObjTypeAttribute:\n'
    out += f'attr id:     {str(self.attr_id)}\n'
    out += f'flags:       {self.flags}\n'
    out += f'ops index:   {self.ops_index}\n'
    out += f'raw offset:  {self.raw_offs}\n'
    out += f'raw size:    {self.raw_size}\n'

    return out


class OpteeCrypObjTypeProperty:
  """Defines OPTEE Crypto object type property."""

  FORMAT = '<I3H2B'

  def __init__(self, data=None):
    if data:
      if isinstance(data, bytes):
        self.load(data)
      else:
        raise ValueError('Wrong type of data')
    else:
      self.obj_type = 0
      self.min_size = 0
      self.max_size = 0
      self.alloc_size = 0
      self.quanta = 0
      self.attrs = []

  def load(self, data):
    """Loads OpteeCrypObjTypeProperty object from raw data.

    Args:
      data: raw binary data to be parsed

    Returns:
      The size of parsed data.

    Raises:
      ValueError exception is raised if size of data is not enough for parsing.
    """

    sz = struct.calcsize(self.FORMAT)
    if len(data) < sz:
      raise ValueError(f'Not enough data: {len(data)} < {sz}')

    self.obj_type, self.min_size, self.max_size, self.alloc_size, self.quanta, num = \
        struct.unpack(self.FORMAT, data[:sz])

    attr_sz = OpteeCrypObjTypeAttr.size()
    if len(data[sz:]) < attr_sz * num:
      raise ValueError(f'Not enough data: {len(data)} < {sz + attr_sz * num}')

    off = sz
    for _ in range(num):
      attr = OpteeCrypObjTypeAttr()
      off += attr.load(data[off:])
      self.attrs.append(attr)

    return sz + attr_sz * num

  def __str__(self):
    out = 'OpteeCrypObjTypeProperty:\n'
    out += f'obj type:   {str(self.obj_type)}\n'
    out += f'min size:   {self.min_size}\n'
    out += f'max size:   {self.max_size}\n'
    out += f'alloc size: {self.alloc_size}\n'
    out += f'quanta:     {self.quanta}\n'
    out += 'Attributes:\n'
    for a in self.attrs:
      out += str(a) + '\n'

    return out

  @staticmethod
  def min_size():
    return struct.calcsize(OpteeCrypObjTypeProperty.FORMAT)

  @staticmethod
  def get_needed_total_size(data):
    _, _, _, _, _, num = struct.unpack(OpteeCrypObjTypeProperty.FORMAT, data)
    return (struct.calcsize(OpteeCrypObjTypeProperty.FORMAT) +
            OpteeCrypObjTypeAttr.size() * num)


class CryptoStateContext:
  """Implementation of crypto context."""

  def __init__(self, algo, mode, key1, key2):
    self.algo = algo
    self.operation = optee_cryp_algo_get_operation(algo)
    self.mode = mode
    self.key1 = key1
    self.key2 = key2
    self.handler = None


class CryptoObject(abc.ABC):
  """CryptoObject base implementation."""

  def __init__(self, otype, max_key_size):
    self.otype = otype
    self.max_key_size = max_key_size
    self.data = None
    self.obj_size = 0
    self.flags = 0
    self.set_attr_handlers = {}
    self.get_attr_handlers = {}

  def populate(self, attrs):
    """Populates the object with attributes.

    Args:
      attrs: the list of attributes to be populate into the object.

    Returns:
       optee_error.OpteeErrorCode return code
    """

    required_attrs = self.get_required_attrs()

    for attr in attrs:
      try:
        required_attrs.remove(attr.atype)
      except ValueError:
        pass

      try:
        ret = self.set_attr_handlers[attr.atype](attr)
      except ValueError:
        return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

      if ret != optee_error.OpteeErrorCode.SUCCESS:
        return ret

    if required_attrs:
      return optee_error.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

    self.flags |= storage.OpteeHandleFlags.INITIALIZED
    return optee_error.OpteeErrorCode.SUCCESS

  def get_info(self):
    info = storage.OpteeObjectInfo()
    info.obj_type = self.otype
    info.object_usage = storage.OpteeUsage.DEFAULT
    info.handle_flags = self.flags
    info.max_object_size = self.max_key_size
    info.obj_size = self.obj_size

    return optee_error.OpteeErrorCode.SUCCESS, info

  def get_attr(self, attr_id):
    try:
      ret, data = self.get_attr_handlers[attr_id]()
    except ValueError:
      return optee_error.OpteeErrorCode.ERROR_ITEM_NOT_FOUND, None

    return ret, data

  def copy(self, obj):
    self.data = obj.data
    self.obj_size = obj.obj_size
    self.flags |= storage.OpteeHandleFlags.INITIALIZED

    return optee_error.OpteeErrorCode.SUCCESS

  def reset(self):
    self.obj_size = 0
    self.data = None
    self.flags &= ~storage.OpteeHandleFlags.INITIALIZED

    return optee_error.OpteeErrorCode.SUCCESS

  @abc.abstractmethod
  def get_required_attrs(self):
    raise NotImplementedError()


class CryptoHDRFObject(CryptoObject):
  """HKDF IKM object implementation."""

  REQUIRED_ATTRS = [OpteeAttr.HKDF_IKM]

  def __init__(self, max_key_size):
    CryptoObject.__init__(self, storage.OpteeObjectType.HKDF_IKM,
                          max_key_size)
    self.set_attr_handlers = {
        OpteeAttr.HKDF_IKM: self._ikm_handler,
        }

  def _ikm_handler(self, attr):
    if not attr.data:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.data = attr.data
    self.obj_size = attr.size * 8
    return optee_error.OpteeErrorCode.SUCCESS

  def get_required_attrs(self):
    return self.REQUIRED_ATTRS.copy()


class CryptoGenericSecretObject(CryptoObject):
  """Generic Secret object implementation."""

  REQUIRED_ATTRS = [OpteeAttr.SECRET_VALUE]

  def __init__(self, max_key_size):
    CryptoObject.__init__(self, storage.OpteeObjectType.GENERIC_SECRET,
                          max_key_size)
    self.set_attr_handlers = {
        OpteeAttr.SECRET_VALUE: self._set_secret_value_handler,
        }
    self.get_attr_handlers = {
        OpteeAttr.SECRET_VALUE: self._get_secret_value_handler,
        }

  def _set_secret_value_handler(self, attr):
    if not attr.data:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.data = attr.data
    self.obj_size = attr.size * 8
    return optee_error.OpteeErrorCode.SUCCESS

  def _get_secret_value_handler(self):
    if not self.data:
      return optee_error.OpteeErrorCode.ERROR_ITEM_NOT_FOUND, None

    return optee_error.OpteeErrorCode.SUCCESS, self.data

  def get_required_attrs(self):
    return self.REQUIRED_ATTRS.copy()


class CryptoModule:
  """Implementation of crypto module of OTEE TEE."""

  def __init__(self):
    self.states = dict()
    self.objects = dict()
    self.operation_check = dict()
    self.algo = dict()
    self.name = 'CryptoModule'

    self.object_types = dict()

    self._setup()

  def _setup(self) -> None:
    """Internal Crypto Module setup function."""

    # Operation check setup
    self.operation_check[OpteeCrypOperation.DIGEST] = \
        self.digest_op_check

    self.operation_check[OpteeCrypOperation.KEY_DERIVATION] = \
        self.key_derivation_op_check

    # Algo setup
    self.algo = {
        OpteeCrypAlg.MD5: hashlib.md5,
        OpteeCrypAlg.SHA1: hashlib.sha1,
        OpteeCrypAlg.SHA224: hashlib.sha224,
        OpteeCrypAlg.SHA256: hashlib.sha256,
        OpteeCrypAlg.SHA384: hashlib.sha384,
        }
    self.algo[OpteeCrypAlg.HKDF_SHA256_DERIVE_KEY] = self.hkdf_calc

    # Object types which are supported
    self.object_types[storage.OpteeObjectType.HKDF_IKM] = CryptoHDRFObject
    self.object_types[storage.OpteeObjectType.GENERIC_SECRET] = \
        CryptoGenericSecretObject

  def hkdf_calc(self, ctx, params, dkey):
    """Key derivation function."""

    hash_types = {
        OpteeCrypAlg.MD5: hashlib.md5,
        OpteeCrypAlg.SHA1: hashlib.sha1,
        OpteeCrypAlg.SHA224: hashlib.sha224,
        OpteeCrypAlg.SHA256: hashlib.sha256,
        OpteeCrypAlg.SHA384: hashlib.sha384,
        }
    hash_op = optee_cryp_alg_get_digest_hash(ctx.algo)

    try:
      hash_type = hash_types[hash_op]
    except ValueError:
      raise NotImplementedError(f'{str(hash_op)} is not supported for HKDF')

    hash_len = hash_type().digest_size

    salt = b''
    info = b''
    okm_length = 0
    for param in params:
      if param.atype == OpteeAttr.HKDF_SALT:
        salt = param.data
      elif param.atype == OpteeAttr.HKDF_INFO:
        info = param.data
      elif param.atype == OpteeAttr.HKDF_OKM_LENGTH:
        okm_length = param.a

    if not isinstance(ctx.key1, CryptoHDRFObject):
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ikm = ctx.key1.data

    if not salt:
      salt = bytes([0] * hash_len)
    prk = hmac.new(salt, ikm, hash_type).digest()
    t = b''
    okm = b''
    for i in range(math.ceil(okm_length / hash_len)):
      t = hmac.new(prk, t + info + bytes([1 + i]), hash_type).digest()
      okm += t

    if not isinstance(dkey, CryptoGenericSecretObject):
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    dkey.data = okm[:okm_length]
    dkey.flags |= storage.OpteeHandleFlags.INITIALIZED
    dkey.obj_size = okm_length

    return optee_error.OpteeErrorCode.SUCCESS

  def cryp_random_number_generate(self, size: int):
    return os.urandom(size)

  def get_empty_key(self, d: Dict[int, Any]) -> int:
    if not d:
      return 1

    r = [ele for ele in range(1, max(d.keys()) + 1) if ele not in d.keys()]

    if not r:
      return max(d.keys()) + 1

    return r[0]

  def digest_op_check(self, key1, key2) -> optee_error.OpteeErrorCode:
    if key1 != 0 or key2 != 0:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
    return optee_error.OpteeErrorCode.SUCCESS

  def key_derivation_op_check(self, key1, key2) -> optee_error.OpteeErrorCode:
    if key1 == 0 or key2 != 0:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS
    return optee_error.OpteeErrorCode.SUCCESS

  def state_alloc(self, algo: OpteeCrypAlg,
                  mode: OpteeCrypOperationMode, key1: int,
                  key2: int) -> (optee_error.OpteeErrorCode, int):
    """Allocates crypto context for future operations.

    Args:
      algo: crypto algorithm type.
      mode: crypto operation mode.
      key1: first key for some crypto operations.
      key2: second key for some crypto operations.

    Returns:
      A pair of OpteeError code and an identifier of allocated context.

    Raise:
      error.Error: if crypto operation or algorithm are not supported.
    """
    op = optee_cryp_algo_get_operation(algo)

    if op not in self.operation_check:
      raise error.Error(
          f'Cryp {str(op)} is not supported for now! Please add support')

    if algo not in self.algo:
      raise error.Error(
          f'Cryp {str(algo)} is not supported for now! Please add support')

    op_check = self.operation_check[op]
    ret = op_check(key1, key2)
    if ret != optee_error.OpteeErrorCode.SUCCESS:
      return ret

    key1_obj = None
    if key1:
      if key1 not in self.objects:
        return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS, None
      key1_obj = self.objects[key1]

    key2_obj = None
    if key2:
      if key2 not in self.objects:
        return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS, None
      key2_obj = self.objects[key2]

    cid = self.get_empty_key(self.states)
    self.states[cid] = CryptoStateContext(algo, mode, key1_obj, key2_obj)

    return optee_error.OpteeErrorCode.SUCCESS, cid

  def state_free(self, cid: int) -> optee_error.OpteeErrorCode:
    if cid not in self.states:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.states[cid]
    return optee_error.OpteeErrorCode.SUCCESS

  def hash_init(self, cid: int, _: bytes) -> optee_error.OpteeErrorCode:
    """Initializes hash operation.

    Args:
      cid: the identifier of allocated crypto context
      _: (unused) initialisation vector for some hash operations.

    Returns:
      OpteeErrorCode code
    """
    if cid not in self.states:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    if ctx.operation not in [
        OpteeCrypOperation.DIGEST,
        OpteeCrypOperation.MAC
    ]:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if ctx.algo not in self.algo:
      return optee_error.OpteeErrorCode.ERROR_NOT_SUPPORTED

    ctx.handler = self.algo[ctx.algo]()

    return optee_error.OpteeErrorCode.SUCCESS

  def hash_update(self, cid: int, chunk: bytes) -> optee_error.OpteeErrorCode:
    if cid not in self.states:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    ctx.handler.update(chunk)

    return optee_error.OpteeErrorCode.SUCCESS

  def hash_final(self, cid: int,
                 chunk: bytes) -> (optee_error.OpteeErrorCode, bytes):
    """Finalizes hash operation and returns .

    Args:
      cid: the identifier of allocated crypto context
      chunk: the last chunk of the data which has to be included to calculation
        the hash sum. Can be empty.

    Returns:
      A pair of OpteeErrorCode code and a hash digest if code is
      OpteeErrorCode.SUCCESS, or None
    """
    if cid not in self.states:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    if chunk:
      ctx.handler.update(chunk)

    digest = ctx.handler.digest()

    return optee_error.OpteeErrorCode.SUCCESS, digest

  def object_alloc(self, oid: int, otype: storage.OpteeObjectType,
                   max_key_size: int) -> (optee_error.OpteeErrorCode, int):
    """Allocates crypto object for future operations.

    Args:
      oid: the indentifier of allocated object
      otype: crypto object type.
      max_key_size: max key size

    Returns:
      A pair of OpteeError code and an identifier of allocated context.

    Raise:
      error.Error: if crypto operation or algorithm are not supported.
    """
    if otype not in self.object_types:
      # Shoult be next line here, but raise exception instead to catch
      # what types need te be supported
      # return optee_error.OpteeErrorCode.ERROR_NOT_IMPLEMENTED
      raise NotImplementedError(f'Type {str(otype)} is not supported yet.')

    self.objects[oid] = self.object_types[otype](max_key_size)
    return optee_error.OpteeErrorCode.SUCCESS

  def object_free(self, oid: int) -> optee_error.OpteeErrorCode:
    if oid not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.objects[oid]
    return optee_error.OpteeErrorCode.SUCCESS

  def object_get_info(self, oid: int) -> (optee_error.OpteeErrorCode,
                                          storage.OpteeObjectInfo):
    if oid not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    obj = self.objects[oid]

    return obj.get_info()

  def object_populate(self, oid: int, attrs) -> optee_error.OpteeErrorCode:
    """Populates an object with attributes.

    Args:
      oid: the object id to be populated.
      attrs: the list of utee_args.OpteeUteeAttribute attributes
             to be populate into the object.

    Returns:
       optee_error.OpteeErrorCode return code
    """

    if oid not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.objects[oid]

    #  Must be a transient object
    if obj.flags & storage.OpteeHandleFlags.PERSISTENT:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    # Must not be initialized already
    if obj.flags & storage.OpteeHandleFlags.INITIALIZED:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return obj.populate(attrs)

  def object_reset(self, oid: int):
    if oid not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.objects[oid]
    if obj.flags & storage.OpteeHandleFlags.PERSISTENT:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return obj.reset()

  def object_copy(self, dst_oid: int, src_oid: int):
    """Copy one object into another.

    Args:
      dst_oid: the destination object
      src_oid: the source object

    Returns:
       optee_error.OpteeErrorCode return code
    """

    if dst_oid not in self.objects or src_oid not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    src_obj = self.objects[src_oid]
    dst_obj = self.objects[dst_oid]

    if not src_obj.flags & storage.OpteeHandleFlags.INITIALIZED:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if dst_obj.flags & storage.OpteeHandleFlags.PERSISTENT:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if dst_obj.flags & storage.OpteeHandleFlags.INITIALIZED:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if src_obj.otype != dst_obj.otype:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return dst_obj.copy(src_obj)

  def object_close(self, oid: int):
    if oid not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.objects[oid]
    return optee_error.OpteeErrorCode.SUCCESS

  def object_get_attr(self, oid: int, attr_id: int):
    if oid not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    obj = self.objects[oid]
    if not obj.flags & storage.OpteeHandleFlags.INITIALIZED:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    return obj.get_attr(attr_id)

  def derive_key(self, cid: int, params, derived_key
                ) -> optee_error.OpteeErrorCode:
    """Derives a key using a crypto context and parameters.

    Args:
      cid: the context id
      params: the list of utee_args.OpteeUteeAttribute parameters
             to be used for a key deriving.
      derived_key: the object id for storing the derived key

    Returns:
       optee_error.OpteeErrorCode return code
    """
    if cid not in self.states:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    if ctx.operation != OpteeCrypOperation.KEY_DERIVATION:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if not derived_key or derived_key not in self.objects:
      return optee_error.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if ctx.algo not in self.algo:
      return optee_error.OpteeErrorCode.ERROR_NOT_SUPPORTED

    dkey = self.objects[derived_key]

    return self.algo[ctx.algo](ctx, params, dkey)
