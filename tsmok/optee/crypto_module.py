"""Crypto sub-module of OPTEE TEE."""
import hashlib
import os
from typing import Dict, Any
import tsmok.common.error as error
import tsmok.optee.const as optee_const


class CryptoContext:
  """Implementation of crypto context."""

  def __init__(self, algo, mode, key1, key2):
    self.algo = algo
    self.operation = optee_const.optee_cryp_algo_get_operation(algo)
    self.mode = mode
    self.key1 = key1
    self.key2 = key2
    self.handler = None


class CryptoModule:
  """Implementation of crypto module of OTEE TEE."""

  def __init__(self):
    self.contexts = dict()
    self.operation_check = dict()
    self.algo = dict()

    self.setup()

  def setup(self) -> None:
    # Operation check setup
    self.operation_check[optee_const.OpteeCrypOperation.DIGEST] = \
        self.digest_op_check

    # Algo setup
    self.algo[optee_const.OpteeCrypAlg.SHA256] = hashlib.sha256

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
          f"Cryp {str(op)} is not supported for now! Please add support")

    if algo not in self.algo:
      raise error.Error(
          f"Cryp {str(algo)} is not supported for now! Please add support")

    op_check = self.operation_check[op]
    ret = op_check(key1, key2)
    if ret != optee_const.OpteeErrorCode.SUCCESS:
      return ret

    cid = self.get_empty_key(self.contexts)
    self.contexts[cid] = CryptoContext(algo, mode, key1, key2)

    return optee_const.OpteeErrorCode.SUCCESS, cid

  def state_free(self, cid: int) -> optee_const.OpteeErrorCode:
    if cid not in self.contexts:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    del self.contexts[cid]
    return optee_const.OpteeErrorCode.SUCCESS

  def hash_init(self, cid: int, _: bytes) -> optee_const.OpteeErrorCode:
    """Initializes hash operation.

    Args:
      cid: the identifier of allocated crypto context
      _: (unused) initialisation vector for some hash operations.

    Returns:
      OpteeErrorCode code
    """
    if cid not in self.contexts:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.contexts[cid]

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
    if cid not in self.contexts:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.contexts[cid]

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
    if cid not in self.contexts:
      return optee_const.OpteeErrorCode.ERROR_BAD_PARAMETERS

    ctx = self.contexts[cid]

    if chunk:
      ctx.handler.update(chunk)

    digest = ctx.handler.digest()

    return optee_const.OpteeErrorCode.SUCCESS, digest
