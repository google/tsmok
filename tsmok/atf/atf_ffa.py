# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""ATF FFA implementation."""

import collections
import logging

import tsmok.atf.atf as atf
import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.common.ffa as ffa
import tsmok.common.misc as misc
import tsmok.emu.emu as emu


FfaMemRegion = collections.namedtuple('FfaMemRegion',
                                      ['tx_addr', 'rx_addr', 'page_count'])


class AtfFfa(atf.Atf):
  """Implementation of Trusty Atf."""

  def __init__(self, name, rxtx_buf_size,
               log_level=logging.ERROR):
    atf.Atf.__init__(self, name, log_level)
    self._rxts_map_buf_size = ffa.FfaFeatures2(rxtx_buf_size)

    self._tee_mem_region = None

    self._shm_mem_mapped = dict()

  def _setup(self):
    # FFA call handlers
    self._callbacks[ffa.FfaSmcCall.VERSION] = \
        self._ffa_version
    self._callbacks[ffa.FfaSmcCall.FEATURES] = \
        self._ffa_features
    self._callbacks[ffa.FfaSmcCall.MEM_SHARE] = \
        self._ffa_mem_share
    self._callbacks[ffa.FfaSmcCall.MEM_RETRIEVE_REQ] = \
        self._ffa_mem_retrieve_req
    self._callbacks[ffa.FfaSmcCall.MEM_RELINQUISH] = \
        self._ffa_mem_relinquish
    self._callbacks[ffa.FfaSmcCall.RXTX_MAP] = \
        self._ffa_rxtx_map
    self._callbacks[ffa.FfaSmcCall.ID_GET] = \
        self._ffa_id_get

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
        f2 = self._rxts_map_buf_size

    return emu.RegContext(ret, None, f2, f3)

  def _ffa_mem_share(self, tee, flag, args):
    del flag  # not used in this call
    self._args_dump(args)
    raise NotImplementedError()

  def _ffa_mem_retrieve_req(self, tee, flag, args):
    del flag  # not used in this call
    total_length = args[0]
    fragment_length = args[1]
    addr = args[2]
    page_count = args[3]

    if addr == 0:
      addr = self._tee_mem_region.tx_addr

    if page_count == 0:
      page_count = self._tee_mem_region.page_count

    if total_length != fragment_length:
      tee.exit_with_exception(
          error.Error('FFA_MEM_RETRIEVE_REQ fails: '
                      'no support for more than one fragment'))
      return

    if ((fragment_length > total_length) or
        (total_length > page_count * const.PAGE_SIZE)):
      self._log.error('FFA_MEM_RETRIEVE_REQ error: invalid parameters')
      return emu.RegContext(ffa.FfaSmcCall.ERROR, 0,
                            ffa.FfaError.INVALID_PARAMETERS)

    data = tee.mem_read(addr, total_length)
    req = ffa.FfaMtd()
    req.load(data)

    if not req.emads:
      self._log.error('FFA_MEM_RETRIEVE_REQ error: no EMAD')
      return emu.RegContext(ffa.FfaSmcCall.ERROR, 0,
                            ffa.FfaError.INVALID_PARAMETERS)

    for e in req.emads:
      if e.comp_mrd_offset:
        comp_mrd = ffa.FfaCompMrd()
        try:
          comp_mrd.load(data[e.comp_mrd_offset:])
        except error.Error as er:
          self._log.error('FFA_MEM_RETRIEVE_REQ error: %s', er.message)
          return emu.RegContext(ffa.FfaSmcCall.ERROR, 0,
                                ffa.FfaError.INVALID_PARAMETERS)
        e.comp_mrd = comp_mrd
    self._log.debug('FFA_MEM_RETRIEVE_REQ: MTD req:\n%s', str(req))

    shm = None
    try:
      shm = self._shm_mem_mapped[req.handle]
    except KeyError:
      self._log.error('FFA_MEM_RETRIEVE_REQ: can\'t find 0x%x handler',
                      req.handle)
      return emu.RegContext(ffa.FfaSmcCall.ERROR, 0,
                            ffa.FfaError.INVALID_PARAMETERS)

    resp = ffa.FfaMtd()
    resp.sender_id = shm.sender_id
    resp.memory_region_attributes = ffa.FfaMemAttr.NORMAL_MEMORY_UNCACHED
    resp.flags = ffa.FfaMtdFlag.TYPE_SHARE_MEMORY
    resp.handle = req.handle

    emad = ffa.FfaEmad()
    emad.mapd.endpoint_id = req.emads[0].mapd.endpoint_id
    emad.mapd.memory_access_permissions = shm.perm
    emad.mapd.flags = 0

    emad.comp_mrd = ffa.FfaCompMrd(shm.page_count,
                                   [ffa.FfaConstMrd(shm.addr, shm.page_count)])
    resp.emads.append(emad)
    resp.total_length = resp.size() +  emad.comp_mrd.size()
    resp.fragment_length = resp.total_length

    emad.comp_mrd_offset = resp.size()

    self._log.debug('FFA_MEM_RETRIEVE_REQ: MTD resp:\n%s', str(resp))

    tee.mem_write(self._tee_mem_region.rx_addr, bytes(resp))
    tee.mem_write(self._tee_mem_region.rx_addr + resp.size(),
                  bytes(emad.comp_mrd))

    return emu.RegContext(ffa.FfaSmcCall.MEM_RETRIEVE_RESP, resp.total_length,
                          resp.fragment_length)

  def _ffa_mem_relinquish(self, tee, flag, args):
    del flag  # not used in this call
    addr = self._tee_mem_region.tx_addr
    data = tee.mem_read(addr, ffa.FfaMemRelinquishDescriptor.size_base())
    count = ffa.FfaMemRelinquishDescriptor.get_endpoint_count(data)
    data = tee.mem_read(
        addr, ffa.FfaMemRelinquishDescriptor.size_base() +
        ffa.FfaMemRelinquishDescriptor.size_endpoint_id() * count)

    desc = ffa.FfaMemRelinquishDescriptor()
    desc.load(data)
    self._log.debug('MemRelinquish: handler 0x%x for endpoints %s',
                    desc.handle, desc.endpoints)
    return emu.RegContext(ffa.FfaSmcCall.SUCCESS)

  def _ffa_rxtx_map(self, tee, flag, args):
    del flag  # not used in this call
    self._tee_mem_region = FfaMemRegion(args[0], args[1], args[2])
    self._log.debug('FFA: RXTX MAP: tx addr 0x%x, rx addr 0x%x, size %d',
                    self._tee_mem_region.tx_addr,
                    self._tee_mem_region.rx_addr,
                    self._tee_mem_region.page_count)

    return emu.RegContext(ffa.FfaSmcCall.SUCCESS)

  def _ffa_id_get(self, tee, flag, args):
    del flag, args, tee  # not used in this call
    return emu.RegContext(ffa.FfaSmcCall.SUCCESS, None, ffa.FFA_CALLER_ID)

  def get_rxtx_buf_size(self):
    return self._rxts_map_buf_size

  def mem_share(self, sender_id, addr, page_count, perm):
    eid = misc.get_next_available_key(self._shm_mem_mapped)
    self._shm_mem_mapped[eid] = ffa.FfaMemoryRegion(addr, page_count, perm,
                                                    sender_id)
    return eid

  def mem_reclaim(self, eid):
    try:
      del self._shm_mem_mapped[eid]
    except KeyError:
      self._log.warning('There is not shared memory region with handler 0x%x',
                        eid)
