"""ATF Trusty implementation."""

import enum
import logging
import struct

import tsmok.atf.atf_ffa as atf
import tsmok.common.error as error
import tsmok.common.ffa as ffa
import tsmok.common.smc as smc
import tsmok.emu.emu as emu


class SmcGetGicReg(enum.IntEnum):
  GICD_BASE = 0
  GICC_BASE = 1
  GICR_BASE = 2


class SmcTrustyCall(enum.IntEnum):
  DEBUG_PUTC = smc.smc_fast_call(smc.SmcOwner.TRUSTED_OS_TRUSTY, 0)
  GET_REG_BASE = smc.smc_fast_call(smc.SmcOwner.TRUSTED_OS_TRUSTY, 1)
  GET_REG_BASE_X64 = smc.smc_fast_x64_call(smc.SmcOwner.TRUSTED_OS_TRUSTY, 1)

  # Return from secure os to non-secure os with return value in r1
  NS_RETURN = smc.smc_std_call(smc.SmcOwner.SECURE_MONITOR, 0)


class AtfTrusty(atf.AtfFfa):
  """Implementation of Trusty Atf."""

  def __init__(self, name='Trusty-ATF',
               rxtx_buf_size=ffa.FfaFeatures2.RXTX_MAP_BUF_SIZE_4K,
               log_level=logging.ERROR):
    atf.AtfFfa.__init__(self, name, rxtx_buf_size, log_level)
    self._buf = b''

  def _setup(self):
    atf.AtfFfa._setup(self)

    # Trustes OS calls
    self._callbacks[SmcTrustyCall.DEBUG_PUTC] = \
        self._debug_putc
    self._callbacks[SmcTrustyCall.GET_REG_BASE] = \
        self._get_reg_base
    self._callbacks[SmcTrustyCall.GET_REG_BASE_X64] = \
        self._get_reg_base
    self._callbacks[SmcTrustyCall.NS_RETURN] = \
        self._ns_return

  def _debug_putc(self, tee, flag, args):
    del flag  # not used in this call
    symb = struct.pack('B', args[0] & 0xff)
    self._buf += symb
    if symb == b'\n':
      self._log.info('UART>> %s', self._buf.decode())
      self._buf = b''
    return emu.RegContext(smc.SmcErrorCode.OK)

  def _get_reg_base(self, tee, flag, args):
    del flag  # not used in this call
    reg = args[0]
    gic = tee.driver_get('GICv3')
    func = {
        SmcGetGicReg.GICD_BASE: gic.gicd_base,
        SmcGetGicReg.GICC_BASE: gic.gicc_base,
        SmcGetGicReg.GICR_BASE: gic.gicr_base,
        }
    try:
      base = func[reg]()
    except KeyError:
      raise error.Error(f'Unsupported register requested: {reg}')
    return emu.RegContext(base)

  def _ns_return(self, tee, flag, args):
    del flag  # not used in this call
    tee.exit(args[0])
    return emu.RegContext(smc.SmcErrorCode.OK)
