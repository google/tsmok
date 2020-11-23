"""ATF TEE implementation."""

import logging
from typing import List

import tsmok.atf.const as atf_const
import tsmok.common.error as error


class Atf:
  """Implementation of Atf."""

  def __init__(self, name='ATF',
               log_level=logging.ERROR):
    self.name = name
    self.mem_regions = list()

    self._log = logging.getLogger(f'[{name}]')
    self._log.setLevel(log_level)
    self._callbacks = dict()

    self._setup()

  def _setup(self):
    # Trustes OS calls
    self._callbacks[atf_const.SmcCall.OS_RETURN_ENTRY_DONE] = \
        self.os_return_entry_done

    self._callbacks[atf_const.SmcCall.OS_RETURN_CALL_DONE] = \
        self.os_return_call_done

  def _args_dump(self, args: List[int]) -> None:
    self._log.debug('Args:')
    for i in range(len(args)):
      self._log.debug('\targs[%d]: 0x%08x', i, args[i])

  def smc_handler(self, os, flag, call, args):
    try:
      self._log.info('.exec. => SMC call 0x%08x', call)
      ret = self._callbacks[call](os, flag, args)
      self._log.info('.exec. <= SMC call 0x%08x: 0x%08x', call, ret)
    except KeyError:
      raise error.Error(f'Unhandled Smc call (0x{call:08x}).')

    return ret

  def os_return_entry_done(self, os, flag, args):
    if not flag & atf_const.SmcCallFlag.SECURE:
      raise error.Error('OS return calls are not supported in NS mode')

    self._args_dump(args)
    os.set_atf_vector_table_addr(args[0])

    os.exit(atf_const.SmcErrorCode.OK)
    return atf_const.SmcErrorCode.OK

  def os_return_call_done(self, os, flag, args):
    del flag  # not used in this call
    self._args_dump(args)
    os.exit(args[0], args[1], args[2], args[3])
    return args[0]
