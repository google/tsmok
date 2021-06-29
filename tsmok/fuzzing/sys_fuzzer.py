"""OPTEE TA fuzzing."""

import collections
import enum
import logging

import tsmok.common.syscall_decl.syscall as syscall
import tsmok.common.ta_error as ta_error
import tsmok.optee.error as optee_error


class Feature(enum.IntFlag):
  NONE = 0
  RESOURCE_SMART = 1<<0
  ARRAY_SMART = 1<<1


OpsCtx = collections.namedtuple(
    'CallbackCtx', ['init', 'syscall', 'stop', 'loader_to_mem',
                    'loader_from_mem', 'cleanup'])


class SysFuzzer:
  """AFLPlusPlus compatible Syscall fuzzer wrapper."""

  def __init__(self, ops: OpsCtx, syscalls=None, features=Feature.NONE,
               log_level=logging.INFO):
    self.log = logging.getLogger('[SysFuzzer]')
    self.log.setLevel(log_level)
    self._features = features
    self._syscalls = syscalls or dict()
    self._resources = dict()
    self._ops = ops

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
    return self._ops.init()

  def _create_syscall(self, cls, data):
    """Creates Syscall object and fill arguments from raw data.

    Args:
     cls: Syscall class
     data: Raw data to fill arguments

    Returns:
      Syscall object instance.
    """
    values = []
    args_data = cls.parse_args_data(data)
    arrays = dict()
    for info in cls.ARGS_INFO:
      if self._features == Feature.RESOURCE_SMART:
        if syscall.ArgFlags.RES_IN in info.options:
          try:
            val = self._resources[info.name]
            values.append(val)
            continue
          except KeyError:
            pass

      if self._features == Feature.ARRAY_SMART:
        if (syscall.ArgFlags.ARRAY_LEN in info.options and
            info.name.endswith('_len')):
          try:
            val = self.arrays[info.name[:-len('_len')]]
            values.append(len(val))
            continue
          except KeyError:
            pass

      try:
        val = cls.parse_arg_value(info, args_data.pop(0))
        values.append(val)
        if syscall.ArgFlags.ARRAY in info.options:
          arrays[info.name] = val
      except (ValueError, IndexError):
        # Not enough data for all args.
        break
    return cls(*values)

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
    for adata in args_data:
      if not adata:
        continue
      nr = syscall.Syscall.parse_call_number(adata)
      ret = optee_error.OpteeErrorCode.SUCCESS
      try:
        scall = self._syscalls[nr]
        call = self._create_syscall(scall, adata)
      except (KeyError, TypeError, IndexError) as e:
        continue
      try:
        call.load_args_to_mem(self._ops.loader_to_mem)
        self._ops.syscall(call.NR, *call.args())
        call.load_args_from_mem(self._ops.loader_from_mem)

        if self._features == Feature.RESOURCE_SMART:
          for key, value in call.args_out_resources():
            self._resources[key] = value
        self._ops.cleanup()
      except ta_error.TaPanicError as e:
        logging.error(e.message)
        ret = e.ret
      except ta_error.TaExit as e:
        logging.error(e.message)
        ret = e.ret

    return ret

  def stop(self):
    self._ops.stop()
