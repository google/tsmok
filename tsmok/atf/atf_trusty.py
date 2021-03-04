"""ATF TEE implementation."""

import logging
import struct

import tsmok.atf.atf as atf
import tsmok.atf.const as atf_const


class AtfTrusty(atf.Atf):
  """Implementation of Trusty Atf."""

  def __init__(self, name='Trusty-ATF',
               log_level=logging.ERROR):
    atf.Atf.__init__(self, name, log_level)
    self._buf = b''

  def _setup(self):
    # Trustes OS calls
    self._callbacks[atf_const.SmcTrustyCall.DEBUG_PUTC] = \
        self._debug_putc

  def _debug_putc(self, tee, flag, args):
    del flag  # not used in this call
    symb = struct.pack('B', args[0] & 0xff)
    self._buf += symb
    if symb == b'\n':
      self._log.info('UART>> %s', self._buf.decode())
      self._buf = b''
    return atf_const.SmcErrorCode.OK
