"""OPTEE TA fuzzing."""

import enum
import io
import logging
import os
import signal
import struct

import tsmok.common.error as error
import tsmok.common.ta_error as ta_error
import tsmok.coverage.collectors as cov_collectors
import tsmok.coverage.drcov as cov_drcov
# WORKAROUND: use unicornafl module only for fuzzing because it is
# not as stable as upstream unicorn module. emu.config should be before
# emu.arm or emu.ta_arm modules
import tsmok.emu.config as config
config.AFL_SUPPORT = True
import tsmok.emu.ta_arm as ta_arm   # pylint: disable=g-bad-import-order disable=g-import-not-at-top
import tsmok.optee.const as optee_const
import tsmok.optee.crypto_module as crypto_module
import tsmok.optee.image_elf_ta as image_elf_ta
import tsmok.optee.optee
import tsmok.optee.storage.rpmb_simple as rpmb_simple
import tsmok.optee.types as optee_types


def convert_error_to_crash(exc):
  """Converts *Error exception to application crash with corresponding signal.

  This function should be called to indicate to AFL that a crash occurred
  during emulation.

  Args:
    exc: tsmok.common.error.*Error exception
  """
  if isinstance(exc, error.SegfaultError):
    os.kill(os.getpid(), signal.SIGSEGV)
  if isinstance(exc, error.SigIllError):
    # Invalid instruction - throw SIGILL
    os.kill(os.getpid(), signal.SIGILL)
  else:
    # Not sure what happened - throw SIGABRT
    os.kill(os.getpid(), signal.SIGABRT)


class TaFuzzer:
  """AFLPlusPlus compatible TA fuzzer wrapper."""

  SESSION_ID = 1

  FUNC_FMT = '<2I'
  HDR_FMT = '<IH'
  PARAM_INT_FMT = '<2I'
  PARAM_BUFFER_FMT = '<I'

  class Mode(enum.Enum):
    OPEN_SESSION = 1,
    INVOKE_COMMAND = 2,
    CLOSES_ESSION = 3

  def __init__(self, img_file: io.BufferedReader,
               log_level=logging.INFO):
    self.log = logging.getLogger('[TaFuzzer]')
    self.log.setLevel(log_level)

    self._param_actions = {
        optee_const.OpteeTaParamType.NONE: self._setup_none_param,
        optee_const.OpteeTaParamType.VALUE_INPUT: self._setup_int_param,
        optee_const.OpteeTaParamType.VALUE_OUTPUT: self._setup_int_param,
        optee_const.OpteeTaParamType.VALUE_INOUT: self._setup_int_param,
        optee_const.OpteeTaParamType.MEMREF_INPUT: self._setup_buffer_param,
        optee_const.OpteeTaParamType.MEMREF_OUTPUT: self._setup_buffer_param,
        optee_const.OpteeTaParamType.MEMREF_INOUT: self._setup_buffer_param,
    }

    self.storage = rpmb_simple.StorageRpmbSimple(log_level=self.log.level)
    self.tee = tsmok.optee.optee.Optee(extension=None,
                                       crypto=crypto_module.CryptoModule(),
                                       log_level=self.log.level)
    self.tee.storage_add(self.storage)

    self.ta = ta_arm.TaArmEmu(self.tee, log_level=self.log.level)
    img = image_elf_ta.TaElfImage(img_file)
    self.ta.load(img)

    cov = cov_drcov.DrCov(log_level=log_level)
    cov.add_module(img.name, img.text_start, img.text_end)
    self.coverage_collector = cov_collectors.BlockCollector(
        cov, log_level=log_level)

  def _setup_int_param(self, param, data):
    sz = struct.calcsize(self.PARAM_INT_FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    a, b = struct.unpack(self.PARAM_INT_FMT, data[:sz])
    param.a = a
    param.b = b
    return sz

  def _setup_buffer_param(self, param, data):
    sz = struct.calcsize(self.PARAM_BUFFER_FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    size = struct.unpack(self.PARAM_BUFFER_FMT, data[:sz])[0]
    param.size = size & 0xFFFFF
    param.data = data[sz:param.size + sz]
    return len(param.data) + sz

  def _setup_none_param(self, param, data):
    del param, data  # unused in this function
    return 0

  def coverage_enable(self):
    self.ta.coverage_register(self.coverage_collector)

  def coverage_disable(self):
    self.ta.coverage_del(self.coverage_collector.name)

  def coverage_dump(self):
    return self.coverage_collector.cov.dump()

  def init(self, mode):
    """Starts AFL forkserver.

    After this call all commands will be executed for each *child*

    Args:
      mode: fuzzing mode as defined in TaFuzzer.Mode.

    Returns:
      True, if returns from child process.

    Raises:
      Error exception in case of unknown or unsupported mode.
    """

    if mode != self.Mode.INVOKE_COMMAND:
      raise error.Error('Sorry, but mode != InvokeCommand is not '
                        'supported for now!')

    self.mode = mode
    # optee session before starting forkserver for performance
    if mode == self.Mode.INVOKE_COMMAND:
      self.ta.open_session(self.SESSION_ID, [])

    return self.ta.forkserver_start()

  def run(self, data: bytes):
    """Runs Ta emulation.

    Args:
      data: bytes of input which will be parsed and converted to input for
            Ta.

    Returns:
      return status as defined in OpteeErrorCode

    Raises:
      Error exception in case of unexpected error.
    """

    sz = struct.calcsize(self.HDR_FMT)

    if len(data) < sz:
      data += b'\x00' * (sz - len(data))

    cmd, types = struct.unpack(self.HDR_FMT, data[:sz])

    offset = sz
    param_list = []
    for i in range(optee_const.OPTEE_NUM_PARAMS):
      try:
        t = optee_const.OpteeTaParamType((types >> (i * 4)) & 0x7)
      except ValueError:
        continue
      param = optee_types.OpteeTaParam.get_type(t)()
      off = self._param_actions[t](param, data[offset:])
      offset += off
      param_list.append(param)

    ret = optee_const.OpteeErrorCode.SUCCESS
    try:
      ret, _ = self.ta.invoke_command(self.SESSION_ID, cmd, param_list)
      self.ta.close_session(self.SESSION_ID)
    except ta_error.TaPanicError as e:
      logging.error(e.message)
      ret = e.ret
    except ta_error.TaExit as e:
      logging.error(e.message)
      ret = e.ret

    return ret

  def stop(self):
    self.ta.exit(0)
