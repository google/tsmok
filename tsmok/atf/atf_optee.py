"""ATF TEE implementation."""

import logging

import tsmok.atf.atf as atf
import tsmok.atf.const as atf_const
import tsmok.common.error as error


class AtfOptee(atf.Atf):
  """Implementation of OPTEE Atf."""

  def __init__(self, name='OPTEE-ATF',
               log_level=logging.ERROR):
    atf.Atf.__init__(self, name, log_level)

  def _setup(self):
    # Trustes OS calls
    self._callbacks[atf_const.SmcOpteeCall.OS_RETURN_ENTRY_DONE] = \
        self.os_return_entry_done

    self._callbacks[atf_const.SmcOpteeCall.OS_RETURN_CALL_DONE] = \
        self.os_return_call_done

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
