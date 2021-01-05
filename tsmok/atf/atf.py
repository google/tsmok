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
    self._log.info('Args:')
    for i in range(len(args)):
      self._log.info('\targs[%d]: 0x%08x', i, args[i])

  def smc_handler(self, tee, flag, call, args):
    try:
      self._log.info('.exec. => SMC: 0x%08x', call)
      ret = self._callbacks[call](tee, flag, args)
      self._log.info('.exec. <= SMC: 0x%08x ret 0x%08x', call, ret)
    except KeyError:
      raise error.Error(f'Unhandled Smc call (0x{call:08x}).')

    return ret

  def os_return_entry_done(self, tee, flag, args):
    if not flag & atf_const.SmcCallFlag.SECURE:
      raise error.Error('OS return calls are not supported in NS mode')

    tee.set_atf_vector_table_addr(args[0])

    tee.exit(atf_const.SmcErrorCode.OK)
    return atf_const.SmcErrorCode.OK

  def os_return_call_done(self, tee, flag, args):
    del flag  # not used in this call
    tee.exit(args[0], args[1], args[2], args[3])
    return atf_const.SmcErrorCode.OK
