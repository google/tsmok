"""Crypto sub-module of OPTEE TEE."""
import abc
import hashlib
import hmac
import math
import os
from typing import Dict, Any, List
import tsmok.common.error as error
import tsmok.optee.const as optee_const
import tsmok.optee.types as optee_types


class CryptoStateContext:
  """Implementation of crypto context."""

  def __init__(self, algo, mode, key1, key2):
    self.algo = algo
    self.operation = optee_const.optee_cryp_algo_get_operation(algo)
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
       optee_const.OpteeErrorCode return code
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
        return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

      if ret != optee_const.OpteeErrorCode.SUCCESS:
        return ret

    if required_attrs:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND

    self.flags |= optee_const.OpteeHandleFlags.INITIALIZED
    return optee_const.OpteeErrorCode.SUCCESS

  def get_info(self):
    info = optee_types.OpteeObjectInfo()
    info.obj_type = self.otype
    info.object_usage = optee_const.OpteeUsage.DEFAULT
    info.handle_flags = self.flags
    info.max_object_size = self.max_key_size
    info.obj_size = self.obj_size

    return optee_const.OpteeErrorCode.SUCCESS, info

  def get_attr(self, attr_id):
    try:
      ret, data = self.get_attr_handlers[attr_id]()
    except ValueError:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND, None

    return ret, data

  def copy(self, obj):
    self.data = obj.data
    self.obj_size = obj.obj_size
    self.flags |= optee_const.OpteeHandleFlags.INITIALIZED

    return optee_const.OpteeErrorCode.SUCCESS

  def reset(self):
    self.obj_size = 0
    self.data = None
    self.flags &= ~optee_const.OpteeHandleFlags.INITIALIZED

    return optee_const.OpteeErrorCode.SUCCESS

  @abc.abstractmethod
  def get_required_attrs(self):
    raise NotImplementedError()


class CryptoHDRFObject(CryptoObject):
  """HKDF IKM object implementation."""

  REQUIRED_ATTRS = [optee_const.OpteeAttr.HKDF_IKM]

  def __init__(self, max_key_size):
    CryptoObject.__init__(self, optee_const.OpteeObjectType.HKDF_IKM,
                          max_key_size)
    self.set_attr_handlers = {
        optee_const.OpteeAttr.HKDF_IKM: self._ikm_handler,
        }

  def _ikm_handler(self, attr):
    if not attr.data:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.data = attr.data
    self.obj_size = attr.size * 8
    return optee_const.OpteeErrorCode.SUCCESS

  def get_required_attrs(self):
    return self.REQUIRED_ATTRS.copy()


class CryptoGenericSecretObject(CryptoObject):
  """Generic Secret object implementation."""

  REQUIRED_ATTRS = [optee_const.OpteeAttr.SECRET_VALUE]

  def __init__(self, max_key_size):
    CryptoObject.__init__(self, optee_const.OpteeObjectType.GENERIC_SECRET,
                          max_key_size)
    self.set_attr_handlers = {
        optee_const.OpteeAttr.SECRET_VALUE: self._set_secret_value_handler,
        }
    self.get_attr_handlers = {
        optee_const.OpteeAttr.SECRET_VALUE: self._get_secret_value_handler,
        }

  def _set_secret_value_handler(self, attr):
    if not attr.data:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    self.data = attr.data
    self.obj_size = attr.size * 8
    return optee_const.OpteeErrorCode.SUCCESS

  def _get_secret_value_handler(self):
    if not self.data:
      return optee_const.OpteeErrorCode.ERROR_ITEM_NOT_FOUND, None

    return optee_const.OpteeErrorCode.SUCCESS, self.data

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
    self.operation_check[optee_const.OpteeCrypOperation.DIGEST] = \
        self.digest_op_check

    self.operation_check[optee_const.OpteeCrypOperation.KEY_DERIVATION] = \
        self.key_derivation_op_check

    # Algo setup
    self.algo = {
        optee_const.OpteeCrypAlg.MD5: hashlib.md5,
        optee_const.OpteeCrypAlg.SHA1: hashlib.sha1,
        optee_const.OpteeCrypAlg.SHA224: hashlib.sha224,
        optee_const.OpteeCrypAlg.SHA256: hashlib.sha256,
        optee_const.OpteeCrypAlg.SHA384: hashlib.sha384,
        }
    self.algo[optee_const.OpteeCrypAlg.HKDF_SHA256_DERIVE_KEY] = self.hkdf_calc

    # Object types which are supported
    self.object_types[optee_const.OpteeObjectType.HKDF_IKM] = CryptoHDRFObject
    self.object_types[optee_const.OpteeObjectType.GENERIC_SECRET] = \
        CryptoGenericSecretObject

  def hkdf_calc(self, ctx, params, dkey):
    """Key derivation function."""

    hash_types = {
        optee_const.OpteeCrypAlg.MD5: hashlib.md5,
        optee_const.OpteeCrypAlg.SHA1: hashlib.sha1,
        optee_const.OpteeCrypAlg.SHA224: hashlib.sha224,
        optee_const.OpteeCrypAlg.SHA256: hashlib.sha256,
        optee_const.OpteeCrypAlg.SHA384: hashlib.sha384,
        }
    hash_op = optee_const.optee_cryp_alg_get_digest_hash(ctx.algo)

    try:
      hash_type = hash_types[hash_op]
    except ValueError:
      raise NotImplementedError(f'{str(hash_op)} is not supported for HKDF')

    hash_len = hash_type().digest_size

    salt = b''
    info = b''
    okm_length = 0
    for param in params:
      if param.atype == optee_const.OpteeAttr.HKDF_SALT:
        salt = param.data
      elif param.atype == optee_const.OpteeAttr.HKDF_INFO:
        info = param.data
      elif param.atype == optee_const.OpteeAttr.HKDF_OKM_LENGTH:
        okm_length = param.a

    if not isinstance(ctx.key1, CryptoHDRFObject):
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

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
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    dkey.data = okm[:okm_length]
    dkey.flags |= optee_const.OpteeHandleFlags.INITIALIZED
    dkey.obj_size = okm_length

    return optee_const.OpteeErrorCode.SUCCESS

  def cryp_random_number_generate(self, size: int):
    return os.urandom(size)

  def get_empty_key(self, d: Dict[int, Any]) -> int:
    if not d:
      return 1

    r = [ele for ele in range(1, max(d.keys()) + 1) if ele not in d.keys()]

    if not r:
      return max(d.keys()) + 1

    return r[0]

  def digest_op_check(self, key1, key2) -> optee_const.OpteeErrorCode:
    if key1 != 0 or key2 != 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS
    return optee_const.OpteeErrorCode.SUCCESS

  def key_derivation_op_check(self, key1, key2) -> optee_const.OpteeErrorCode:
    if key1 == 0 or key2 != 0:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS
    return optee_const.OpteeErrorCode.SUCCESS

  def state_alloc(self, algo: optee_const.OpteeCrypAlg,
                  mode: optee_const.OpteeCrypOperationMode, key1: int,
                  key2: int) -> (optee_const.OpteeErrorCode, int):
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
    op = optee_const.optee_cryp_algo_get_operation(algo)

    if op not in self.operation_check:
      raise error.Error(
          f'Cryp {str(op)} is not supported for now! Please add support')

    if algo not in self.algo:
      raise error.Error(
          f'Cryp {str(algo)} is not supported for now! Please add support')

    op_check = self.operation_check[op]
    ret = op_check(key1, key2)
    if ret != optee_const.OpteeErrorCode.SUCCESS:
      return ret

    key1_obj = None
    if key1:
      if key1 not in self.objects:
        return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS, None
      key1_obj = self.objects[key1]

    key2_obj = None
    if key2:
      if key2 not in self.objects:
        return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS, None
      key2_obj = self.objects[key2]

    cid = self.get_empty_key(self.states)
    self.states[cid] = CryptoStateContext(algo, mode, key1_obj, key2_obj)

    return optee_const.OpteeErrorCode.SUCCESS, cid

  def state_free(self, cid: int) -> optee_const.OpteeErrorCode:
    if cid not in self.states:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.states[cid]
    return optee_const.OpteeErrorCode.SUCCESS

  def hash_init(self, cid: int, _: bytes) -> optee_const.OpteeErrorCode:
    """Initializes hash operation.

    Args:
      cid: the identifier of allocated crypto context
      _: (unused) initialisation vector for some hash operations.

    Returns:
      OpteeErrorCode code
    """
    if cid not in self.states:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    if ctx.operation not in [
        optee_const.OpteeCrypOperation.DIGEST,
        optee_const.OpteeCrypOperation.MAC
    ]:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if ctx.algo not in self.algo:
      return optee_const.OpteeErrorCode.ERROR_NOT_SUPPORTED

    ctx.handler = self.algo[ctx.algo]()

    return optee_const.OpteeErrorCode.SUCCESS

  def hash_update(self, cid: int, chunk: bytes) -> optee_const.OpteeErrorCode:
    if cid not in self.states:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    ctx.handler.update(chunk)

    return optee_const.OpteeErrorCode.SUCCESS

  def hash_final(self, cid: int,
                 chunk: bytes) -> (optee_const.OpteeErrorCode, bytes):
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
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    if chunk:
      ctx.handler.update(chunk)

    digest = ctx.handler.digest()

    return optee_const.OpteeErrorCode.SUCCESS, digest

  def object_alloc(self, oid: int, otype: optee_const.OpteeObjectType,
                   max_key_size: int) -> (optee_const.OpteeErrorCode, int):
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
      # return optee_const.OpteeErrorCode.ERROR_NOT_IMPLEMENTED
      raise NotImplementedError(f'Type {str(otype)} is not supported yet.')

    self.objects[oid] = self.object_types[otype](max_key_size)
    return optee_const.OpteeErrorCode.SUCCESS

  def object_free(self, oid: int) -> optee_const.OpteeErrorCode:
    if oid not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.objects[oid]
    return optee_const.OpteeErrorCode.SUCCESS

  def object_get_info(self, oid: int) -> (optee_const.OpteeErrorCode,
                                          optee_types.OpteeObjectInfo):
    if oid not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    obj = self.objects[oid]

    return obj.get_info()

  def object_populate(self, oid: int,
                      attrs: List[optee_types.OpteeUteeAttribute]
                     ) -> optee_const.OpteeErrorCode:
    """Populates an object with attributes.

    Args:
      oid: the object id to be populated.
      attrs: the list of optee_types.OpteeUteeAttribute attributes
             to be populate into the object.

    Returns:
       optee_const.OpteeErrorCode return code
    """

    if oid not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.objects[oid]

    #  Must be a transient object
    if obj.flags & optee_const.OpteeHandleFlags.PERSISTENT:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    # Must not be initialized already
    if obj.flags & optee_const.OpteeHandleFlags.INITIALIZED:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return obj.populate(attrs)

  def object_reset(self, oid: int):
    if oid not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    obj = self.objects[oid]
    if obj.flags & optee_const.OpteeHandleFlags.PERSISTENT:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return obj.reset()

  def object_copy(self, dst_oid: int, src_oid: int):
    """Copy one object into another.

    Args:
      dst_oid: the destination object
      src_oid: the source object

    Returns:
       optee_const.OpteeErrorCode return code
    """

    if dst_oid not in self.objects or src_oid not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    src_obj = self.objects[src_oid]
    dst_obj = self.objects[dst_oid]

    if not src_obj.flags & optee_const.OpteeHandleFlags.INITIALIZED:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if dst_obj.flags & optee_const.OpteeHandleFlags.PERSISTENT:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if dst_obj.flags & optee_const.OpteeHandleFlags.INITIALIZED:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if src_obj.otype != dst_obj.otype:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    return dst_obj.copy(src_obj)

  def object_close(self, oid: int):
    if oid not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.objects[oid]
    return optee_const.OpteeErrorCode.SUCCESS

  def object_get_attr(self, oid: int, attr_id: int):
    if oid not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    obj = self.objects[oid]
    if not obj.flags & optee_const.OpteeHandleFlags.INITIALIZED:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS, None

    return obj.get_attr(attr_id)

  def derive_key(self, cid: int, params, derived_key
                ) -> optee_const.OpteeErrorCode:
    """Derives a key using a crypto context and parameters.

    Args:
      cid: the context id
      params: the list of optee_types.OpteeUteeAttribute parameters
             to be used for a key deriving.
      derived_key: the object id for storing the derived key

    Returns:
       optee_const.OpteeErrorCode return code
    """
    if cid not in self.states:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.states[cid]

    if ctx.operation != optee_const.OpteeCrypOperation.KEY_DERIVATION:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if not derived_key or derived_key not in self.objects:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    if ctx.algo not in self.algo:
      return optee_const.OpteeErrorCode.ERROR_NOT_SUPPORTED

    dkey = self.objects[derived_key]

    return self.algo[ctx.algo](ctx, params, dkey)
