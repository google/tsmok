"""ATF TEE implementation."""

import enum
import logging
import struct

import tsmok.atf.atf as atf
import tsmok.common.const as consts
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


class AtfTrusty(atf.Atf):
  """Implementation of Trusty Atf."""

  def __init__(self, name='Trusty-ATF',
               log_level=logging.ERROR):
    atf.Atf.__init__(self, name, log_level)
    self._buf = b''

  def _setup(self):
    # Trustes OS calls
    self._callbacks[SmcTrustyCall.DEBUG_PUTC] = \
        self._debug_putc
    self._callbacks[SmcTrustyCall.GET_REG_BASE] = \
        self._get_reg_base
    self._callbacks[SmcTrustyCall.GET_REG_BASE_X64] = \
        self._get_reg_base
    self._callbacks[SmcTrustyCall.NS_RETURN] = \
        self._ns_return

    # FFA call handlers
    self._callbacks[ffa.FfaSmcCall.VERSION] = \
        self._ffa_version
    self._callbacks[ffa.FfaSmcCall.FEATURES] = \
        self._ffa_features
    self._callbacks[ffa.FfaSmcCall.MEM_SHARE] = \
        self._ffa_mem_share
    self._callbacks[ffa.FfaSmcCall.MEM_RETRIEVE_REQ] = \
        self._ffa_mem_retrieve_req
    self._callbacks[ffa.FfaSmcCall.RXTX_MAP] = \
        self._ffa_rxtx_map
    self._callbacks[ffa.FfaSmcCall.ID_GET] = \
        self._ffa_id_get

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

  def _ffa_version(self, tee, flag, args):
    del flag  # not used in this call
    ver = args[0]
    self._log.debug('FFA: Version request: caller version 0x%x', ver)
    return emu.RegContext(ffa.FFA_CURRENT_VERSION_MAJOR << 16 |
                          ffa.FFA_CURRENT_VERSION_MINOR)

  def _ffa_features(self, tee, flag, args):
    del flag  # not used in this call
    feature = args[0]
    self._log.debug('FFA: Features: 0x%x', feature)

    ret = ffa.FfaSmcCall.ERROR
    f2 = 0
    f3 = 0
    if feature in self._callbacks:
      ret = ffa.FfaSmcCall.SUCCESS
      if feature == ffa.FfaSmcCall.MEM_RETRIEVE_REQ:
        f3 = ffa.FFA_REQ_REFCOUNT
      elif feature == ffa.FfaSmcCall.RXTX_MAP:
        f2 = ffa.FfaFeatures2.RXTX_MAP_BUF_SIZE_64K

    return emu.RegContext(ret, None, f2, f3)

  def _ffa_mem_share(self, tee, flag, args):
    del flag  # not used in this call
    self._args_dump(args)
    raise NotImplementedError()

  def _ffa_mem_retrieve_req(self, tee, flag, args):
    del flag  # not used in this call
    self._args_dump(args)
    raise NotImplementedError()

  def _ffa_rxtx_map(self, tee, flag, args):
    del flag  # not used in this call
    tx_addr = args[0]
    rx_addr = args[1]
    size = args[2] * consts.PAGE_SIZE
    self._log.debug('FFA: RXTX MAP: tx addr 0x%x, rx addr 0x%x, size %d',
                    tx_addr, rx_addr, size)
    tee.tx_shm_set(tx_addr, size)
    tee.rx_shm_set(rx_addr, size)

    return emu.RegContext(ffa.FfaSmcCall.SUCCESS)

  def _ffa_id_get(self, tee, flag, args):
    del flag, args, tee  # not used in this call
    return emu.RegContext(ffa.FfaSmcCall.SUCCESS, None, ffa.FFA_CALLER_ID)

  def _ns_return(self, tee, flag, args):
    del flag  # not used in this call
    tee.exit(args[0])
    return emu.RegContext(smc.SmcErrorCode.OK)
